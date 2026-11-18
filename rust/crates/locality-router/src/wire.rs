// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MySQL packet framing and the handful of protocol messages the router reads
//! or writes itself. Everything else is relayed unchanged.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// Largest payload of one physical packet.
pub const MAX_PACKET: usize = 0x00ff_ffff;
/// Upper bound for one logical packet the router materializes.
pub const MAX_LOGICAL: usize = 256 << 20;

/// Capability flags used by the router.
pub mod cap {
    /// `CLIENT_CONNECT_WITH_DB`.
    pub const CONNECT_WITH_DB: u32 = 0x0000_0008;
    /// `CLIENT_COMPRESS`.
    pub const COMPRESS: u32 = 0x0000_0020;
    /// `CLIENT_PROTOCOL_41`.
    pub const PROTOCOL_41: u32 = 0x0000_0200;
    /// `CLIENT_SSL`.
    pub const SSL: u32 = 0x0000_0800;
    /// `CLIENT_SECURE_CONNECTION`.
    pub const SECURE_CONNECTION: u32 = 0x0000_8000;
    /// `CLIENT_PLUGIN_AUTH`.
    pub const PLUGIN_AUTH: u32 = 0x0008_0000;
    /// `CLIENT_CONNECT_ATTRS`.
    pub const CONNECT_ATTRS: u32 = 0x0010_0000;
    /// `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA`.
    pub const PLUGIN_AUTH_LENENC: u32 = 0x0020_0000;
    /// `CLIENT_DEPRECATE_EOF`.
    pub const DEPRECATE_EOF: u32 = 0x0100_0000;
    /// `CLIENT_ZSTD_COMPRESSION_ALGORITHM`.
    pub const ZSTD: u32 = 0x0400_0000;
    /// `CLIENT_QUERY_ATTRIBUTES`.
    pub const QUERY_ATTRIBUTES: u32 = 0x0800_0000;
}

/// Server status flags used by the router.
pub mod status {
    /// `SERVER_STATUS_IN_TRANS`.
    pub const IN_TRANS: u16 = 0x0001;
    /// `SERVER_STATUS_AUTOCOMMIT`.
    pub const AUTOCOMMIT: u16 = 0x0002;
    /// `SERVER_MORE_RESULTS_EXISTS`.
    pub const MORE_RESULTS: u16 = 0x0008;
    /// `SERVER_STATUS_CURSOR_EXISTS`.
    pub const CURSOR_EXISTS: u16 = 0x0040;
}

/// Command bytes used by the router.
pub mod cmd {
    /// `COM_QUIT`.
    pub const QUIT: u8 = 0x01;
    /// `COM_INIT_DB`.
    pub const INIT_DB: u8 = 0x02;
    /// `COM_QUERY`.
    pub const QUERY: u8 = 0x03;
    /// `COM_FIELD_LIST`.
    pub const FIELD_LIST: u8 = 0x04;
    /// `COM_STATISTICS`.
    pub const STATISTICS: u8 = 0x09;
    /// `COM_PING`.
    pub const PING: u8 = 0x0e;
    /// `COM_CHANGE_USER`.
    pub const CHANGE_USER: u8 = 0x11;
    /// `COM_STMT_PREPARE`.
    pub const STMT_PREPARE: u8 = 0x16;
    /// `COM_STMT_EXECUTE`.
    pub const STMT_EXECUTE: u8 = 0x17;
    /// `COM_STMT_SEND_LONG_DATA`.
    pub const STMT_SEND_LONG_DATA: u8 = 0x18;
    /// `COM_STMT_CLOSE`.
    pub const STMT_CLOSE: u8 = 0x19;
    /// `COM_STMT_RESET`.
    pub const STMT_RESET: u8 = 0x1a;
    /// `COM_SET_OPTION`.
    pub const SET_OPTION: u8 = 0x1b;
    /// `COM_STMT_FETCH`.
    pub const STMT_FETCH: u8 = 0x1c;
    /// `COM_RESET_CONNECTION`.
    pub const RESET_CONNECTION: u8 = 0x1f;
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

/// One side of a MySQL connection with buffered, sequence-tracked framing.
pub struct PacketConn {
    reader: BufReader<OwnedReadHalf>,
    writer: BufWriter<OwnedWriteHalf>,
    /// Sequence number of the next packet to write.
    pub seq: u8,
    /// Remote address, for logging.
    pub peer: String,
}

impl PacketConn {
    /// Wraps a connected socket.
    pub fn new(stream: TcpStream) -> Self {
        let peer = stream
            .peer_addr()
            .map_or_else(|_| "?".to_owned(), |a| a.to_string());
        let _ = stream.set_nodelay(true);
        let (r, w) = stream.into_split();
        Self {
            reader: BufReader::with_capacity(64 << 10, r),
            writer: BufWriter::with_capacity(64 << 10, w),
            seq: 0,
            peer,
        }
    }

    /// Reads one logical packet and returns its payload.
    pub async fn read(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let len = read_physical(&mut self.reader, &mut out, &mut self.seq).await?;
            if len < MAX_PACKET {
                return Ok(out);
            }
            if out.len() > MAX_LOGICAL {
                return Err(invalid("logical packet too large"));
            }
        }
    }

    /// Queues one logical packet; call [`PacketConn::flush`] to send.
    pub async fn write(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut rest = payload;
        loop {
            let n = rest.len().min(MAX_PACKET);
            let len = u32::try_from(n).map_err(|_| invalid("packet length"))?;
            let header = [
                (len & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                ((len >> 16) & 0xff) as u8,
                self.seq,
            ];
            self.seq = self.seq.wrapping_add(1);
            self.writer.write_all(&header).await?;
            self.writer.write_all(&rest[..n]).await?;
            rest = &rest[n..];
            if n < MAX_PACKET {
                return Ok(());
            }
        }
    }

    /// Flushes queued packets.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.writer.flush().await
    }

    /// Writes one packet and flushes.
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write(payload).await?;
        self.flush().await
    }

    /// Starts a new command exchange (sequence 0).
    pub fn reset_seq(&mut self) {
        self.seq = 0;
    }
}

async fn read_physical<R: AsyncRead + Unpin>(
    r: &mut R,
    out: &mut Vec<u8>,
    seq: &mut u8,
) -> io::Result<usize> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;
    let len = usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
    // Follow the peer's sequence, like Go TiProxy: resynchronize on mismatch.
    *seq = header[3].wrapping_add(1);
    let start = out.len();
    out.resize(start + len, 0);
    r.read_exact(&mut out[start..]).await?;
    Ok(len)
}

/// Writes all bytes to an async writer (used for raw relays).
pub async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, b: &[u8]) -> io::Result<()> {
    w.write_all(b).await
}

/// Reads a length-encoded integer at `*pos`.
pub fn lenenc_int(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    *pos += 1;
    let width = match first {
        0..=0xfa => return Some(u64::from(first)),
        0xfc => 2,
        0xfd => 3,
        0xfe => 8,
        _ => return None,
    };
    let bytes = b.get(*pos..*pos + width)?;
    *pos += width;
    let mut v = 0u64;
    for (i, x) in bytes.iter().enumerate() {
        v |= u64::from(*x) << (8 * i);
    }
    Some(v)
}

/// Reads a length-encoded string at `*pos`.
pub fn lenenc_bytes<'a>(b: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let n = usize::try_from(lenenc_int(b, pos)?).ok()?;
    let s = b.get(*pos..*pos + n)?;
    *pos += n;
    Some(s)
}

/// Appends a length-encoded integer.
pub fn put_lenenc_int(out: &mut Vec<u8>, v: u64) {
    if v < 251 {
        out.push(v as u8);
    } else if v < 1 << 16 {
        out.push(0xfc);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v < 1 << 24 {
        out.push(0xfd);
        out.extend_from_slice(&(v as u32).to_le_bytes()[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Reads a NUL-terminated string at `*pos`.
pub fn nul_str<'a>(b: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let rest = b.get(*pos..)?;
    let end = rest.iter().position(|&c| c == 0)?;
    *pos += end + 1;
    Some(&rest[..end])
}

/// Kind of a response packet by its first byte and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// OK packet.
    Ok,
    /// ERR packet.
    Err,
    /// EOF packet, or the OK packet that replaces it under `DEPRECATE_EOF`.
    Eof,
    /// `LOCAL INFILE` request.
    LocalInfile,
    /// Anything else (column count, column definition, row).
    Data,
}

/// Classifies a response packet.
pub fn kind(p: &[u8]) -> PacketKind {
    match p.first() {
        Some(0x00) if p.len() >= 7 => PacketKind::Ok,
        Some(0xff) => PacketKind::Err,
        Some(0xfe) if p.len() < MAX_PACKET => PacketKind::Eof,
        Some(0xfb) => PacketKind::LocalInfile,
        _ => PacketKind::Data,
    }
}

/// Status flags of an OK packet (header 0x00 or 0xfe).
pub fn ok_status(p: &[u8]) -> Option<u16> {
    let mut pos = 1;
    lenenc_int(p, &mut pos)?;
    lenenc_int(p, &mut pos)?;
    let s = p.get(pos..pos + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

/// Status flags of a terminator: classic EOF, or OK-as-EOF under `DEPRECATE_EOF`.
pub fn eof_status(p: &[u8], deprecate_eof: bool) -> Option<u16> {
    if deprecate_eof {
        ok_status(p)
    } else {
        let s = p.get(3..5)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
}

/// Builds an OK packet.
pub fn ok_packet(status: u16) -> Vec<u8> {
    vec![0x00, 0, 0, (status & 0xff) as u8, (status >> 8) as u8, 0, 0]
}

/// Builds an ERR packet.
pub fn err_packet(code: u16, state: &[u8; 5], msg: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(9 + msg.len());
    p.push(0xff);
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    p.extend_from_slice(state);
    p.extend_from_slice(msg.as_bytes());
    p
}

/// The parsed part of a server greeting (protocol 10).
#[derive(Debug, Clone)]
pub struct Greeting {
    /// Capability flags.
    pub capabilities: u32,
    /// Auth plugin data (salt).
    pub salt: Vec<u8>,
    /// Offsets of the low and high capability words, for rewriting.
    cap_low_at: usize,
    cap_high_at: Option<usize>,
}

impl Greeting {
    /// Parses a server greeting.
    pub fn parse(p: &[u8]) -> Option<Self> {
        if *p.first()? != 10 {
            return None;
        }
        let mut pos = 1;
        nul_str(p, &mut pos)?; // server version
        pos += 4; // connection id
        let mut salt = p.get(pos..pos + 8)?.to_vec();
        pos += 9; // salt part 1 + filler
        let cap_low_at = pos;
        let low = u32::from(u16::from_le_bytes([*p.get(pos)?, *p.get(pos + 1)?]));
        pos += 2;
        if pos >= p.len() {
            return Some(Self { capabilities: low, salt, cap_low_at, cap_high_at: None });
        }
        pos += 3; // charset + status
        let cap_high_at = pos;
        let high = u32::from(u16::from_le_bytes([*p.get(pos)?, *p.get(pos + 1)?]));
        pos += 2;
        let capabilities = low | high << 16;
        let auth_len = usize::from(*p.get(pos)?);
        pos += 11;
        if capabilities & cap::SECURE_CONNECTION != 0 {
            let n = auth_len.saturating_sub(8).max(13);
            if let Some(part2) = p.get(pos..pos + n) {
                let part2 = part2.strip_suffix(&[0]).unwrap_or(part2);
                salt.extend_from_slice(part2);
            }
        }
        Some(Self { capabilities, salt, cap_low_at, cap_high_at: Some(cap_high_at) })
    }

    /// Rewrites the capability flags of the greeting packet `p` in place.
    pub fn set_capabilities(&self, p: &mut [u8], caps: u32) {
        let low = (caps & 0xffff) as u16;
        p[self.cap_low_at..self.cap_low_at + 2].copy_from_slice(&low.to_le_bytes());
        if let Some(at) = self.cap_high_at {
            let high = (caps >> 16) as u16;
            p[at..at + 2].copy_from_slice(&high.to_le_bytes());
        }
    }
}

/// The parts of a `HandshakeResponse41` the router needs.
#[derive(Debug, Clone, Default)]
pub struct HandshakeResponse {
    /// Client capability flags.
    pub capabilities: u32,
    /// Max packet size.
    pub max_packet: u32,
    /// Collation id.
    pub collation: u8,
    /// User name.
    pub user: Vec<u8>,
    /// Initial database.
    pub db: Option<Vec<u8>>,
}

impl HandshakeResponse {
    /// Parses a `HandshakeResponse41`.
    pub fn parse(p: &[u8]) -> Option<Self> {
        let caps = u32::from_le_bytes(p.get(0..4)?.try_into().ok()?);
        if caps & cap::PROTOCOL_41 == 0 {
            return None;
        }
        let max_packet = u32::from_le_bytes(p.get(4..8)?.try_into().ok()?);
        let collation = *p.get(8)?;
        let mut pos = 32;
        let user = nul_str(p, &mut pos)?.to_vec();
        if caps & cap::PLUGIN_AUTH_LENENC != 0 {
            lenenc_bytes(p, &mut pos)?;
        } else if caps & cap::SECURE_CONNECTION != 0 {
            let n = usize::from(*p.get(pos)?);
            pos += 1 + n;
        } else {
            nul_str(p, &mut pos)?;
        }
        let db = if caps & cap::CONNECT_WITH_DB != 0 {
            nul_str(p, &mut pos).map(<[u8]>::to_vec).filter(|d| !d.is_empty())
        } else {
            None
        };
        Some(Self { capabilities: caps, max_packet, collation, user, db })
    }

    /// Encodes a response that authenticates with `plugin` and `auth`.
    pub fn encode(&self, caps: u32, plugin: &str, auth: &[u8], db: Option<&[u8]>) -> Vec<u8> {
        let mut caps = caps | cap::PROTOCOL_41 | cap::SECURE_CONNECTION | cap::PLUGIN_AUTH | cap::PLUGIN_AUTH_LENENC;
        caps &= !(cap::SSL | cap::COMPRESS | cap::ZSTD | cap::CONNECT_ATTRS);
        if db.is_some() {
            caps |= cap::CONNECT_WITH_DB;
        } else {
            caps &= !cap::CONNECT_WITH_DB;
        }
        let mut p = Vec::with_capacity(64 + auth.len());
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&self.max_packet.to_le_bytes());
        p.push(self.collation);
        p.extend_from_slice(&[0u8; 23]);
        p.extend_from_slice(&self.user);
        p.push(0);
        put_lenenc_int(&mut p, auth.len() as u64);
        p.extend_from_slice(auth);
        if let Some(db) = db {
            p.extend_from_slice(db);
            p.push(0);
        }
        p.extend_from_slice(plugin.as_bytes());
        p.push(0);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenenc_roundtrip() {
        for v in [0u64, 250, 251, 65535, 65536, (1 << 24) - 1, 1 << 24, u64::MAX] {
            let mut b = Vec::new();
            put_lenenc_int(&mut b, v);
            let mut pos = 0;
            assert_eq!(lenenc_int(&b, &mut pos), Some(v));
            assert_eq!(pos, b.len());
        }
    }

    #[test]
    fn handshake_roundtrip() {
        let base = HandshakeResponse {
            capabilities: cap::PROTOCOL_41,
            max_packet: 1 << 24,
            collation: 45,
            user: b"root".to_vec(),
            db: None,
        };
        let p = base.encode(cap::PROTOCOL_41 | cap::DEPRECATE_EOF, "tidb_session_token", b"tok", Some(b"test"));
        let parsed = HandshakeResponse::parse(&p).unwrap_or_default();
        assert_eq!(parsed.user, b"root");
        assert_eq!(parsed.db.as_deref(), Some(&b"test"[..]));
        assert_ne!(parsed.capabilities & cap::DEPRECATE_EOF, 0);
    }

    #[test]
    fn packet_kinds() {
        assert_eq!(kind(&ok_packet(status::AUTOCOMMIT)), PacketKind::Ok);
        assert_eq!(ok_status(&ok_packet(3)), Some(3));
        assert_eq!(kind(&err_packet(1105, b"HY000", "x")), PacketKind::Err);
        assert_eq!(kind(&[0xfe, 0, 0, 2, 0]), PacketKind::Eof);
        assert_eq!(eof_status(&[0xfe, 0, 0, 2, 0], false), Some(2));
    }
}
