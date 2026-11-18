// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One client session with transaction-level backend routing.
//!
//! The client authenticates against one backend (relayed byte for byte, so
//! every auth plugin works). At each transaction boundary the first statement
//! of the next transaction picks the backend next to the Region leader of its
//! first table (by primary-key Region, else the table's affinity leader). A
//! `BEGIN` is held until that statement arrives. Switching to another backend
//! reuses an open connection when the session state has not changed since it
//! was synchronized; otherwise the session is migrated with
//! `SHOW SESSION_STATES` / `tidb_session_token` / `SET SESSION_STATES`, the
//! same mechanism TiProxy uses for rebalancing.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::classify::{self, Classified, Kind, Value};
use crate::router::{Reason, Router};
use crate::wire::{self, HandshakeResponse, PacketConn, PacketKind, cap, cmd, status};

const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

struct BackendConn {
    addr: String,
    conn: PacketConn,
    status: u16,
    /// `state_version` this connection is in sync with.
    synced: u64,
    /// Statements whose parameter types this connection has received.
    typed: HashSet<u32>,
}

struct Stmt {
    sql: Arc<Classified>,
    insert_candidates: Vec<(String, Value)>,
    num_params: usize,
    types: Option<Vec<u8>>,
}

/// A routed client session.
pub struct Session {
    router: Arc<Router>,
    client: PacketConn,
    hs: HandshakeResponse,
    caps: u32,
    db: Option<String>,
    backends: Vec<BackendConn>,
    cur: usize,
    state_version: u64,
    stmts: HashMap<u32, Stmt>,
    pending_begin: Option<Vec<u8>>,
    sticky: bool,
}

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

async fn dial(addr: &str) -> io::Result<PacketConn> {
    let s = timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| other(format!("dial {addr} timed out")))??;
    Ok(PacketConn::new(s))
}

impl Session {
    /// Authenticates `client` through `backend_addr` and returns the session.
    pub async fn handshake(router: Arc<Router>, client: TcpStream, backend_addr: String) -> io::Result<Option<Self>> {
        let mut client = PacketConn::new(client);
        let mut backend = dial(&backend_addr).await?;
        let mut greeting = backend.read().await?;
        let g = wire::Greeting::parse(&greeting).ok_or_else(|| other("bad backend greeting"))?;
        // The router speaks plain, uncompressed MySQL to both sides.
        let server_caps = g.capabilities & !(cap::SSL | cap::COMPRESS | cap::ZSTD | cap::QUERY_ATTRIBUTES);
        g.set_capabilities(&mut greeting, server_caps);
        client.seq = 0;
        client.send(&greeting).await?;
        let resp = client.read().await?;
        let hs = HandshakeResponse::parse(&resp).ok_or_else(|| other("unsupported handshake response"))?;
        backend.seq = 1;
        backend.send(&resp).await?;
        // Relay the authentication exchange until the backend decides.
        let status = loop {
            let p = backend.read().await?;
            client.seq = backend.seq.wrapping_sub(1);
            client.send(&p).await?;
            match p.first() {
                Some(0x00) => break wire::ok_status(&p).unwrap_or(status::AUTOCOMMIT),
                Some(0xff) => return Ok(None),
                Some(0x01) if p.get(1) == Some(&0x03) => {} // fast auth OK, server continues
                _ => {
                    let reply = client.read().await?;
                    backend.seq = client.seq.wrapping_sub(1);
                    backend.send(&reply).await?;
                }
            }
        };
        let caps = hs.capabilities & server_caps;
        let db = hs.db.as_ref().map(|d| String::from_utf8_lossy(d).to_lowercase());
        router.counters.connections.fetch_add(1, Ordering::Relaxed);
        Ok(Some(Self {
            router,
            client,
            hs,
            caps,
            db,
            backends: vec![BackendConn { addr: backend_addr, conn: backend, status, synced: 0, typed: HashSet::new() }],
            cur: 0,
            state_version: 0,
            stmts: HashMap::new(),
            pending_begin: None,
            sticky: false,
        }))
    }

    fn deprecate_eof(&self) -> bool {
        self.caps & cap::DEPRECATE_EOF != 0
    }

    fn at_boundary(&self) -> bool {
        !self.sticky && self.backends[self.cur].status & status::IN_TRANS == 0
    }

    fn touch_state(&mut self) {
        self.state_version += 1;
        self.backends[self.cur].synced = self.state_version;
    }

    /// Serves commands until the client quits or a connection fails.
    pub async fn run(mut self) -> io::Result<()> {
        loop {
            self.client.reset_seq();
            let pkt = match self.client.read().await {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };
            let Some(&command) = pkt.first() else { continue };
            match command {
                cmd::QUIT => break,
                cmd::QUERY => self.on_query(pkt).await?,
                cmd::STMT_EXECUTE => self.on_execute(pkt).await?,
                cmd::STMT_PREPARE => self.on_prepare(pkt).await?,
                cmd::STMT_CLOSE => self.on_close(&pkt).await?,
                cmd::STMT_SEND_LONG_DATA => {
                    self.flush_begin_or_reply().await?;
                    self.sticky = true;
                    self.forward(&pkt).await?;
                }
                cmd::CHANGE_USER => self.on_change_user(pkt).await?,
                _ => {
                    if command != cmd::PING && !self.flush_begin_or_reply().await? {
                        continue;
                    }
                    if matches!(command, cmd::INIT_DB | cmd::RESET_CONNECTION | cmd::SET_OPTION) {
                        self.touch_state();
                    }
                    if command == cmd::INIT_DB {
                        self.db = Some(String::from_utf8_lossy(&pkt[1..]).to_lowercase());
                    }
                    self.forward(&pkt).await?;
                    match command {
                        cmd::FIELD_LIST | cmd::STMT_FETCH => self.relay_until_eof().await?,
                        _ => self.relay_one().await?,
                    }
                }
            }
        }
        for b in &mut self.backends {
            b.conn.reset_seq();
            let _ = b.conn.send(&[cmd::QUIT]).await;
        }
        Ok(())
    }

    // ---- routing -------------------------------------------------------

    fn route(&self, c: &Classified, point_value: Option<i64>, candidates: &[(String, Value)], exec: Option<&[i64]>) -> (Option<String>, Reason) {
        let Some((db, table)) = &c.table else {
            return (None, Reason::Default);
        };
        let Some(db) = db.clone().or_else(|| self.db.clone()) else {
            return (None, Reason::Default);
        };
        let point = c.point.as_ref().and_then(|p| point_value.map(|v| (p.column.as_str(), v)));
        let (addr, reason) = self.router.locate(&db, table, point);
        if addr.is_none() && !candidates.is_empty() {
            // INSERT: the first column may not be the handle; try the others.
            for (col, v) in candidates {
                let value = match v {
                    Value::Literal(n) => Some(*n),
                    Value::Param(i) => exec.and_then(|e| e.get(*i).copied()),
                };
                if let Some(value) = value {
                    let (a, r) = self.router.locate(&db, table, Some((col, value)));
                    if r == Reason::Point {
                        return (a, r);
                    }
                }
            }
        }
        (addr, reason)
    }

    /// Moves the session to `addr` if it is not already there.
    async fn switch_to(&mut self, addr: Option<String>) {
        let Some(addr) = addr else { return };
        if self.backends[self.cur].addr == addr {
            return;
        }
        if let Some(i) = self.backends.iter().position(|b| b.addr == addr)
            && self.backends[i].synced == self.state_version
            && self.backends[i].status & status::IN_TRANS == 0
        {
            self.cur = i;
            self.router.counters.switch_warm.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match self.migrate_to(&addr).await {
            Ok(i) => {
                self.cur = i;
                self.router.counters.switch_migrate.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                eprintln!("locality-router: switch to {addr} failed, staying on {}: {e}", self.backends[self.cur].addr);
                self.router.counters.switch_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn migrate_to(&mut self, addr: &str) -> io::Result<usize> {
        let (states, token) = self.show_session_states().await?;
        let mut conn = dial(addr).await?;
        let greeting = conn.read().await?;
        let g = wire::Greeting::parse(&greeting).ok_or_else(|| other("bad greeting"))?;
        let caps = self.caps & g.capabilities;
        let db = self.db.as_ref().map(|d| d.as_bytes().to_vec());
        let resp = self.hs.encode(caps, "tidb_session_token", &token, db.as_deref());
        conn.seq = 1;
        conn.send(&resp).await?;
        loop {
            let p = conn.read().await?;
            match p.first() {
                Some(0x00) => break,
                Some(0xfe) => {
                    // Auth switch: answer with the token again.
                    conn.send(&token).await?;
                }
                _ => return Err(other(format!("session token rejected by {addr}: {}", err_text(&p)))),
            }
        }
        let mut sql = b"\x03SET SESSION_STATES '".to_vec();
        for &c in states.as_bytes() {
            match c {
                b'\\' => sql.extend_from_slice(b"\\\\"),
                b'\'' => sql.extend_from_slice(b"\\'"),
                0 => sql.extend_from_slice(b"\\0"),
                _ => sql.push(c),
            }
        }
        sql.push(b'\'');
        conn.reset_seq();
        conn.send(&sql).await?;
        let p = conn.read().await?;
        if wire::kind(&p) != PacketKind::Ok {
            return Err(other(format!("SET SESSION_STATES on {addr}: {}", err_text(&p))));
        }
        let st = wire::ok_status(&p).unwrap_or(status::AUTOCOMMIT);
        let fresh = BackendConn { addr: addr.to_owned(), conn, status: st, synced: self.state_version, typed: HashSet::new() };
        if let Some(i) = self.backends.iter().position(|b| b.addr == addr) {
            let mut old = std::mem::replace(&mut self.backends[i], fresh);
            old.conn.reset_seq();
            let _ = old.conn.send(&[cmd::QUIT]).await;
            Ok(i)
        } else {
            self.backends.push(fresh);
            Ok(self.backends.len() - 1)
        }
    }

    async fn show_session_states(&mut self) -> io::Result<(String, Vec<u8>)> {
        let deprecate_eof = self.deprecate_eof();
        let b = &mut self.backends[self.cur].conn;
        b.reset_seq();
        b.send(b"\x03SHOW SESSION_STATES").await?;
        let first = b.read().await?;
        if wire::kind(&first) == PacketKind::Err {
            return Err(other(format!("SHOW SESSION_STATES: {}", err_text(&first))));
        }
        let mut pos = 0;
        let ncols = wire::lenenc_int(&first, &mut pos).unwrap_or(0);
        for _ in 0..ncols {
            b.read().await?;
        }
        if !deprecate_eof {
            b.read().await?;
        }
        let mut row = None;
        loop {
            let p = b.read().await?;
            match wire::kind(&p) {
                PacketKind::Eof => break,
                PacketKind::Err => return Err(other(format!("SHOW SESSION_STATES: {}", err_text(&p)))),
                _ => row = Some(p),
            }
        }
        let row = row.ok_or_else(|| other("SHOW SESSION_STATES returned no row"))?;
        let mut pos = 0;
        let states = wire::lenenc_bytes(&row, &mut pos).ok_or_else(|| other("bad session states"))?;
        let token = wire::lenenc_bytes(&row, &mut pos).ok_or_else(|| other("bad session token"))?;
        Ok((String::from_utf8_lossy(states).into_owned(), token.to_vec()))
    }

    /// Sends a held `BEGIN` to the current backend. Returns false if it failed
    /// and the error was already sent to the client as the reply to the
    /// current command.
    async fn flush_begin_or_reply(&mut self) -> io::Result<bool> {
        let Some(begin) = self.pending_begin.take() else { return Ok(true) };
        let b = &mut self.backends[self.cur];
        b.conn.reset_seq();
        b.conn.send(&begin).await?;
        let p = b.conn.read().await?;
        match wire::kind(&p) {
            PacketKind::Ok => {
                b.status = wire::ok_status(&p).unwrap_or(b.status | status::IN_TRANS);
                Ok(true)
            }
            _ => {
                self.client.send(&p).await?;
                Ok(false)
            }
        }
    }

    // ---- commands ------------------------------------------------------

    async fn on_query(&mut self, pkt: Vec<u8>) -> io::Result<()> {
        let c = classify::classify(&pkt[1..]);
        let held = self.pending_begin.is_some();
        if self.at_boundary() || held {
            match c.kind {
                Kind::Begin => {
                    // Hold the BEGIN until the first statement names a table.
                    let autocommit = self.backends[self.cur].status & status::AUTOCOMMIT;
                    self.pending_begin = Some(pkt);
                    return self.client.send(&wire::ok_packet(autocommit | status::IN_TRANS)).await;
                }
                Kind::Commit | Kind::Rollback if held => {
                    self.pending_begin = None;
                    let autocommit = self.backends[self.cur].status & status::AUTOCOMMIT;
                    return self.client.send(&wire::ok_packet(autocommit)).await;
                }
                _ => {}
            }
            let point = c.point.as_ref().and_then(|p| match p.value {
                Value::Literal(v) => Some(v),
                Value::Param(_) => None,
            });
            let candidates = if c.kind == Kind::Insert { classify::insert_candidates(&pkt[1..]) } else { Vec::new() };
            let (addr, _) = self.route(&c, point, &candidates, None);
            if addr.is_some() {
                self.router.counters.txn_routed.fetch_add(1, Ordering::Relaxed);
            }
            self.switch_to(addr).await;
            if !self.flush_begin_or_reply().await? {
                return Ok(());
            }
        }
        if c.dirty {
            self.touch_state();
        }
        if let Some(db) = &c.use_db {
            self.db = Some(db.clone());
        }
        self.forward(&pkt).await?;
        self.relay_result(false).await
    }

    async fn on_prepare(&mut self, pkt: Vec<u8>) -> io::Result<()> {
        if !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        self.touch_state();
        self.forward(&pkt).await?;
        let deprecate_eof = self.deprecate_eof();
        let b = &mut self.backends[self.cur].conn;
        let first = b.read().await?;
        self.client.write(&first).await?;
        if wire::kind(&first) == PacketKind::Ok && first.len() >= 9 {
            let id = u32::from_le_bytes([first[1], first[2], first[3], first[4]]);
            let ncols = usize::from(u16::from_le_bytes([first[5], first[6]]));
            let nparams = usize::from(u16::from_le_bytes([first[7], first[8]]));
            for n in [nparams, ncols] {
                for _ in 0..n {
                    let p = b.read().await?;
                    self.client.write(&p).await?;
                }
                if n > 0 && !deprecate_eof {
                    let p = b.read().await?;
                    self.client.write(&p).await?;
                }
            }
            let sql = Arc::new(classify::classify(&pkt[1..]));
            let insert_candidates =
                if sql.kind == Kind::Insert { classify::insert_candidates(&pkt[1..]) } else { Vec::new() };
            self.stmts.insert(id, Stmt { sql, insert_candidates, num_params: nparams, types: None });
        }
        self.client.flush().await
    }

    async fn on_close(&mut self, pkt: &[u8]) -> io::Result<()> {
        if pkt.len() >= 5 {
            let id = u32::from_le_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
            self.stmts.remove(&id);
        }
        // Every synchronized connection holds the statement; close it on all.
        for b in &mut self.backends {
            b.conn.reset_seq();
            b.conn.send(pkt).await?;
        }
        Ok(())
    }

    async fn on_change_user(&mut self, pkt: Vec<u8>) -> io::Result<()> {
        if !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        // Keep only the current connection; the user changes under it.
        let keep = self.backends.swap_remove(self.cur);
        for mut b in self.backends.drain(..) {
            b.conn.reset_seq();
            let _ = b.conn.send(&[cmd::QUIT]).await;
        }
        self.backends.push(keep);
        self.cur = 0;
        self.stmts.clear();
        self.touch_state();
        self.forward(&pkt).await?;
        loop {
            let p = self.backends[0].conn.read().await?;
            self.client.seq = self.backends[0].conn.seq.wrapping_sub(1);
            self.client.send(&p).await?;
            match p.first() {
                Some(0x00) => {
                    self.backends[0].status = wire::ok_status(&p).unwrap_or(status::AUTOCOMMIT);
                    return Ok(());
                }
                Some(0xff) => return Ok(()),
                Some(0x01) if p.get(1) == Some(&0x03) => {}
                _ => {
                    let reply = self.client.read().await?;
                    self.backends[0].conn.seq = self.client.seq.wrapping_sub(1);
                    self.backends[0].conn.send(&reply).await?;
                }
            }
        }
    }

    async fn on_execute(&mut self, mut pkt: Vec<u8>) -> io::Result<()> {
        if pkt.len() < 10 {
            self.forward(&pkt).await?;
            return self.relay_result(false).await;
        }
        let id = u32::from_le_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
        let cursor = pkt[5] != 0;
        if cursor {
            self.sticky = true;
        }
        let mut layout = None; // (bound_flag_at, num_params)
        if let Some(st) = self.stmts.get_mut(&id)
            && st.num_params > 0
        {
            let at = 10 + st.num_params.div_ceil(8);
            if pkt.get(at) == Some(&1)
                && let Some(t) = pkt.get(at + 1..at + 1 + 2 * st.num_params)
            {
                st.types = Some(t.to_vec());
            }
            layout = Some((at, st.num_params));
        }
        let held = self.pending_begin.is_some();
        if self.at_boundary() || held {
            // Prepared BEGIN / COMMIT / ROLLBACK (sysbench prepares them):
            // same holding rules as for COM_QUERY.
            let kind = self.stmts.get(&id).map(|st| st.sql.kind);
            match kind {
                Some(Kind::Begin) => {
                    let autocommit = self.backends[self.cur].status & status::AUTOCOMMIT;
                    self.pending_begin = Some(pkt);
                    return self.client.send(&wire::ok_packet(autocommit | status::IN_TRANS)).await;
                }
                Some(Kind::Commit | Kind::Rollback) if held => {
                    self.pending_begin = None;
                    let autocommit = self.backends[self.cur].status & status::AUTOCOMMIT;
                    return self.client.send(&wire::ok_packet(autocommit)).await;
                }
                _ => {}
            }
            if let Some(st) = self.stmts.get(&id) {
                let values = layout.and_then(|(at, n)| int_params(&pkt, at, n, st.types.as_deref()));
                let point = st.sql.point.as_ref().and_then(|p| match p.value {
                    Value::Literal(v) => Some(v),
                    Value::Param(i) => values.as_ref().and_then(|v| v.get(i).copied()),
                });
                let sql = Arc::clone(&st.sql);
                let candidates = st.insert_candidates.clone();
                let (addr, _) = self.route(&sql, point, &candidates, values.as_deref());
                if addr.is_some() {
                    self.router.counters.txn_routed.fetch_add(1, Ordering::Relaxed);
                }
                self.switch_to(addr).await;
            }
            if !self.flush_begin_or_reply().await? {
                return Ok(());
            }
        }
        // A connection that has not seen this statement's parameter types
        // needs them even when the client omitted them.
        if let Some((at, n)) = layout {
            let cur = &mut self.backends[self.cur];
            if pkt.get(at) == Some(&1) {
                cur.typed.insert(id);
            } else if !cur.typed.contains(&id)
                && let Some(types) = self.stmts.get(&id).and_then(|s| s.types.clone())
                && types.len() == 2 * n
            {
                pkt[at] = 1;
                pkt.splice(at + 1..at + 1, types);
                cur.typed.insert(id);
            }
        }
        self.forward(&pkt).await?;
        self.relay_result(cursor).await
    }

    // ---- relaying ------------------------------------------------------

    async fn forward(&mut self, pkt: &[u8]) -> io::Result<()> {
        let b = &mut self.backends[self.cur].conn;
        b.reset_seq();
        b.send(pkt).await
    }

    async fn relay_one(&mut self) -> io::Result<()> {
        let b = &mut self.backends[self.cur];
        let p = b.conn.read().await?;
        if matches!(wire::kind(&p), PacketKind::Ok)
            && let Some(s) = wire::ok_status(&p)
        {
            b.status = s;
        }
        self.client.send(&p).await
    }

    async fn relay_until_eof(&mut self) -> io::Result<()> {
        let deprecate_eof = self.deprecate_eof();
        loop {
            let b = &mut self.backends[self.cur];
            let p = b.conn.read().await?;
            self.client.write(&p).await?;
            match wire::kind(&p) {
                PacketKind::Eof => {
                    if let Some(s) = wire::eof_status(&p, deprecate_eof) {
                        b.status = s;
                    }
                    break;
                }
                PacketKind::Err => break,
                _ => {}
            }
        }
        self.client.flush().await
    }

    /// Relays a full command response (OK, ERR, result sets, LOAD DATA).
    async fn relay_result(&mut self, cursor: bool) -> io::Result<()> {
        let deprecate_eof = self.deprecate_eof();
        'results: loop {
            let p = self.backends[self.cur].conn.read().await?;
            self.client.write(&p).await?;
            match wire::kind(&p) {
                PacketKind::Ok | PacketKind::Eof => {
                    let s = if wire::kind(&p) == PacketKind::Eof {
                        wire::eof_status(&p, deprecate_eof)
                    } else {
                        wire::ok_status(&p)
                    }
                    .unwrap_or(status::AUTOCOMMIT);
                    self.backends[self.cur].status = s;
                    if s & status::MORE_RESULTS != 0 {
                        continue;
                    }
                    break;
                }
                PacketKind::Err => break,
                PacketKind::LocalInfile => {
                    self.client.flush().await?;
                    loop {
                        let data = self.client.read().await?;
                        let b = &mut self.backends[self.cur].conn;
                        b.seq = self.client.seq.wrapping_sub(1);
                        b.write(&data).await?;
                        if data.is_empty() {
                            b.flush().await?;
                            break;
                        }
                    }
                    self.client.seq = self.backends[self.cur].conn.seq;
                }
                PacketKind::Data => {
                    let mut pos = 0;
                    let ncols = wire::lenenc_int(&p, &mut pos).unwrap_or(0);
                    for _ in 0..ncols {
                        let c = self.backends[self.cur].conn.read().await?;
                        self.client.write(&c).await?;
                    }
                    if !deprecate_eof || cursor {
                        let e = self.backends[self.cur].conn.read().await?;
                        self.client.write(&e).await?;
                        if let Some(s) = wire::eof_status(&e, deprecate_eof && !cursor) {
                            self.backends[self.cur].status = s;
                            if cursor && s & status::CURSOR_EXISTS != 0 {
                                break 'results;
                            }
                        }
                    }
                    loop {
                        let r = self.backends[self.cur].conn.read().await?;
                        self.client.write(&r).await?;
                        match wire::kind(&r) {
                            PacketKind::Eof => {
                                let s = wire::eof_status(&r, deprecate_eof).unwrap_or(status::AUTOCOMMIT);
                                self.backends[self.cur].status = s;
                                if s & status::MORE_RESULTS != 0 {
                                    continue 'results;
                                }
                                break 'results;
                            }
                            PacketKind::Err => break 'results,
                            _ => {}
                        }
                    }
                }
            }
        }
        self.client.flush().await
    }
}

fn err_text(p: &[u8]) -> String {
    if p.first() == Some(&0xff) && p.len() > 9 {
        String::from_utf8_lossy(&p[9..]).into_owned()
    } else {
        format!("unexpected packet 0x{:02x}", p.first().copied().unwrap_or(0))
    }
}

/// Decodes the integer parameters of a `COM_STMT_EXECUTE` (`None` for others).
/// Returns `None` if any parameter has a type it cannot skip.
fn int_params(pkt: &[u8], bound_at: usize, n: usize, cached_types: Option<&[u8]>) -> Option<Vec<i64>> {
    let bitmap = pkt.get(10..10 + n.div_ceil(8))?;
    let bound = *pkt.get(bound_at)?;
    let (types, mut pos) = if bound == 1 {
        (pkt.get(bound_at + 1..bound_at + 1 + 2 * n)?, bound_at + 1 + 2 * n)
    } else {
        (cached_types?, bound_at + 1)
    };
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if bitmap[i / 8] & (1 << (i % 8)) != 0 {
            out.push(i64::MIN);
            continue;
        }
        let tp = types[2 * i];
        let unsigned = types[2 * i + 1] & 0x80 != 0;
        let (v, width): (Option<i64>, usize) = match tp {
            0x01 => {
                let b = *pkt.get(pos)?;
                (Some(if unsigned { i64::from(b) } else { i64::from(b as i8) }), 1)
            }
            0x02 | 0x0d => {
                let b = pkt.get(pos..pos + 2)?;
                let raw = u16::from_le_bytes([b[0], b[1]]);
                (Some(if unsigned { i64::from(raw) } else { i64::from(raw as i16) }), 2)
            }
            0x03 | 0x09 => {
                let b = pkt.get(pos..pos + 4)?;
                let raw = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                (Some(if unsigned { i64::from(raw) } else { i64::from(raw as i32) }), 4)
            }
            0x08 => {
                let b = pkt.get(pos..pos + 8)?;
                let raw = u64::from_le_bytes(b.try_into().ok()?);
                (i64::try_from(raw).ok().or(if unsigned { None } else { Some(raw as i64) }), 8)
            }
            0x04 => (None, 4),
            0x05 => (None, 8),
            0x06 => (None, 0),
            0x07 | 0x0a | 0x0b | 0x0c => (None, 1 + usize::from(*pkt.get(pos)?)),
            _ => {
                // Length-encoded (strings, decimals, blobs, JSON).
                let mut p2 = pos;
                let len = usize::try_from(wire::lenenc_int(pkt, &mut p2)?).ok()?;
                (None, p2 - pos + len)
            }
        };
        out.push(v.unwrap_or(i64::MIN));
        pos += width;
        if pos > pkt.len() {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_execute_params() {
        // COM_STMT_EXECUTE id=1, flags=0, iter=1, 2 params, no nulls, bound,
        // types LONG, VAR_STRING, values 42, "ab".
        let mut p = vec![0x17, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0x00, 1, 0x03, 0, 0xfd, 0];
        p.extend_from_slice(&42i32.to_le_bytes());
        p.extend_from_slice(&[2, b'a', b'b']);
        let at = 10 + 1;
        assert_eq!(int_params(&p, at, 2, None), Some(vec![42, i64::MIN]));
    }
}
