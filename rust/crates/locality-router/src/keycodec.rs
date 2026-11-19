// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `TiDB` key encoding needed to find the Region of a row.

use std::fmt::Write as _;

/// Encodes an `i64` in `TiDB`'s memcomparable form (sign bit flipped, big endian).
#[must_use]
pub fn encode_i64(v: i64) -> [u8; 8] {
    (v.cast_unsigned() ^ (1u64 << 63)).to_be_bytes()
}

/// Raw record key `t{table_id}_r{handle}` for an integer handle.
#[must_use]
pub fn record_key(table_id: i64, handle: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(19);
    k.push(b't');
    k.extend_from_slice(&encode_i64(table_id));
    k.extend_from_slice(b"_r");
    k.extend_from_slice(&encode_i64(handle));
    k
}

/// Raw record-range prefix `t{table_id}_r`.
#[must_use]
pub fn record_prefix(table_id: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(11);
    k.push(b't');
    k.extend_from_slice(&encode_i64(table_id));
    k.extend_from_slice(b"_r");
    k
}

/// Raw key just after the record range of `table_id` (`t{table_id}_s`).
#[must_use]
pub fn record_end(table_id: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(11);
    k.push(b't');
    k.extend_from_slice(&encode_i64(table_id));
    k.extend_from_slice(b"_s");
    k
}

/// Raw key just after every key of `table_id` (`t{table_id+1}`).
#[must_use]
pub fn table_end(table_id: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(b't');
    k.extend_from_slice(&encode_i64(table_id.saturating_add(1)));
    k
}

/// Raw table prefix `t{table_id}`.
#[must_use]
pub fn table_prefix(table_id: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(b't');
    k.extend_from_slice(&encode_i64(table_id));
    k
}

/// Memcomparable bytes encoding used for `TiKV` transactional keys
/// (`codec.EncodeBytes`): 8-byte groups, each followed by `0xFF - padding`.
/// Region boundaries in PD are stored in this form.
#[must_use]
pub fn encode_bytes(raw: &[u8]) -> Vec<u8> {
    const GROUP: usize = 8;
    let mut out = Vec::with_capacity((raw.len() / GROUP + 1) * (GROUP + 1));
    let mut i = 0;
    loop {
        let remain = raw.len() - i;
        if remain >= GROUP {
            out.extend_from_slice(&raw[i..i + GROUP]);
            out.push(0xff);
            i += GROUP;
        } else {
            out.extend_from_slice(&raw[i..]);
            let pad = GROUP - remain;
            out.extend(std::iter::repeat_n(0u8, pad));
            out.push(0xff - u8::try_from(pad).unwrap_or(0));
            return out;
        }
    }
}

/// Parses an upper- or lower-case hex string.
#[must_use]
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Percent-encodes bytes for a URL query value.
#[must_use]
pub fn url_escape(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 3);
    for &c in b {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            s.push(char::from(c));
        } else {
            let _ = write!(s, "%{c:02X}");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_bytes_matches_tidb() {
        // codec.EncodeBytes(nil, []byte("t")) in TiDB.
        assert_eq!(encode_bytes(b"t"), vec![b't', 0, 0, 0, 0, 0, 0, 0, 0xf8]);
        assert_eq!(encode_bytes(b""), vec![0, 0, 0, 0, 0, 0, 0, 0, 0xf7]);
        let e = encode_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(e.len(), 18);
        assert_eq!(e[8], 0xff);
        assert_eq!(e[17], 0xf7);
    }

    #[test]
    fn record_key_layout() {
        let k = record_key(112, 5);
        assert_eq!(k[0], b't');
        assert_eq!(&k[1..9], &[0x80, 0, 0, 0, 0, 0, 0, 112]);
        assert_eq!(&k[9..11], b"_r");
        assert_eq!(&k[11..19], &[0x80, 0, 0, 0, 0, 0, 0, 5]);
        assert!(encode_bytes(&record_key(112, -1)) < encode_bytes(&record_key(112, 0)));
    }

    #[test]
    fn hex_and_escape() {
        assert_eq!(from_hex("7480ff"), Some(vec![0x74, 0x80, 0xff]));
        assert_eq!(url_escape(&[b't', 0x80, b' ']), "t%80%20");
    }
}
