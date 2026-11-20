// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One client session with transaction-level backend routing.
//!
//! The client authenticates against one backend (relayed byte for byte, so
//! every auth plugin works). At each transaction boundary the first statement
//! of the next transaction picks the backend next to the Region leader of its
//! first table (by primary-key Region, else the table's affinity leader). A
//! `BEGIN` is held until that statement arrives.
//!
//! # Session state
//!
//! The session keeps one connection per backend it has used. State is kept
//! consistent between them by category, after `OBProxy`'s per-category
//! versions:
//!
//! * **Durable state** (everything `SHOW SESSION_STATES` carries: variables,
//!   current database, text-protocol prepared statements, sequences, ...)
//!   has a version. With tidb-one session tracking
//!   (`tidb_one_session_track = ON`) `TiDB` reports in the server status of each
//!   response whether the statement may have changed it; otherwise the
//!   router's SQL classifier decides. A connection behind the current version
//!   is re-synchronized with `SHOW SESSION_STATES` on the current connection,
//!   then `COM_RESET_CONNECTION` + `SET SESSION_STATES` on the target (two
//!   round trips, no new TCP connection).
//! * **`LAST_INSERT_ID()`** is reported by tracking in the OK packet; a
//!   connection that is behind gets `DO LAST_INSERT_ID(n)` in the same write
//!   as the next statement (no extra round trip).
//! * **Binary-protocol prepared statements** are owned by the router: it gives
//!   the client its own statement IDs and prepares a statement on a backend
//!   the first time it executes there.
//! * **Unmigratable state** (temporary tables, advisory locks, `LOCK TABLES`,
//!   a pending `SET TRANSACTION`, which any catch-up statement would consume)
//!   is reported by tracking and pins the session to its connection.
//! * Values that describe the previous statement (`ROW_COUNT()`,
//!   `FOUND_ROWS()`, warnings) are not migrated; a statement that reads them
//!   does not switch backends.
//!
//! `KILL` with any connection ID of a routed session is rewritten to the
//! connection that runs the session now (see `kill.rs`).
//!
//! When a backend drains (see `router.rs`), the session closes its idle
//! connections to it and moves off it at the next transaction boundary, also
//! while the client is idle. A session that cannot move (open transaction,
//! unmigratable state) stays until it can, or until the backend goes away.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value as Json;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::classify::{self, Classified, Kill, Kind, Value};
use crate::kill::{self, SessionHandle};
use crate::router::{Reason, Router};
use crate::wire::{self, HandshakeResponse, PacketConn, PacketKind, cap, cmd, status};

const DIAL_TIMEOUT: Duration = Duration::from_secs(3);
const CLASSIFY_CACHE_LIMIT: usize = 512;
/// A classified statement and its INSERT point candidates.
type Entry = (Classified, Vec<(String, Value)>);

/// `BackendConn::synced` of a connection whose state is unknown.
const UNSYNCED: u64 = u64::MAX;
const ENABLE_TRACKING: &[u8] = b"\x03SET SESSION tidb_one_session_track = ON";

/// Switch kinds, index into `Counters::switch_seconds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwitchKind {
    Warm = 0,
    Delta = 1,
    Migrate = 2,
    Dial = 3,
}

struct BackendConn {
    addr: String,
    conn: PacketConn,
    /// Server status of the last response (tracking bits removed).
    status: u16,
    /// `TiDB` connection ID from the greeting.
    conn_id: u32,
    /// tidb-one session tracking is on for this connection.
    tracking: bool,
    /// `Session::durable_version` this connection is in sync with.
    synced: u64,
    /// `LAST_INSERT_ID()` of this connection, if known.
    lii: Option<u64>,
    /// `Session::option_version` this connection has applied.
    option_synced: u64,
    /// Client statement ID → statement ID on this connection.
    stmt_ids: HashMap<u32, u32>,
    /// Client statement IDs whose parameter types this connection has received.
    typed: HashSet<u32>,
    /// Open connections to `addr` across sessions (`Router::conn_counter`).
    count: Arc<AtomicI64>,
}

impl Drop for BackendConn {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl BackendConn {
    fn new(addr: &str, conn: PacketConn, conn_id: u32, status: u16, count: Arc<AtomicI64>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self {
            addr: addr.to_owned(),
            conn,
            status,
            conn_id,
            tracking: false,
            synced: 0,
            lii: Some(0),
            option_synced: 0,
            stmt_ids: HashMap::new(),
            typed: HashSet::new(),
            count,
        }
    }

    fn in_trans(&self) -> bool {
        self.status & status::IN_TRANS != 0
    }
}

/// A binary-protocol prepared statement, owned by the router.
struct Stmt {
    sql: Vec<u8>,
    /// Classification and INSERT point candidates.
    entry: Arc<Entry>,
    num_params: usize,
    /// Parameter types from the last `COM_STMT_EXECUTE` that sent them.
    types: Option<Vec<u8>>,
}

/// What tidb-one session tracking reported for one statement.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent flags read from server status bits.
struct Observed {
    /// A status-bearing packet was seen.
    status_seen: bool,
    changed: bool,
    blocked: bool,
    /// `LAST_INSERT_ID()` reported in an OK packet.
    lii: Option<u64>,
    /// `LAST_INSERT_ID()` changed in a packet without the value.
    lii_unknown: bool,
    /// Last-insert-id field of the last OK packet (for untracked backends).
    header_lii: u64,
    err: bool,
}

/// What an internal (router-issued) command expects as its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// One OK / EOF / ERR packet.
    Ok,
    /// The held `BEGIN`: an error is the client's reply.
    Begin,
    /// A `COM_STMT_PREPARE` for this client statement ID.
    Prepare(u32),
}

struct Internal {
    pkt: Vec<u8>,
    expect: Expect,
    /// Its response must be read before anything after it is sent.
    barrier: bool,
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
    /// Version of the durable session state (what `SHOW SESSION_STATES` carries).
    durable_version: u64,
    /// `LAST_INSERT_ID()` of the session, when tracking reports it.
    lii: Option<u64>,
    /// The session holds unmigratable state (reported by tracking).
    blocked: bool,
    stmts: HashMap<u32, Stmt>,
    next_stmt_id: u32,
    /// Held `BEGIN` as a `COM_QUERY` packet, and whether it has no options.
    pending_begin: Option<(Vec<u8>, bool)>,
    /// Catch-up commands for `cur`, sent before the next statement.
    prelude: Vec<Internal>,
    /// Compare session states with this connection before the next statement.
    verify_from: Option<usize>,
    sticky: bool,
    /// Last `COM_SET_OPTION` (connection-level, not in the session states).
    set_option: Option<Vec<u8>>,
    option_version: u64,
    observed: Observed,
    cache: HashMap<Vec<u8>, Arc<Entry>>,
    handle: Arc<SessionHandle>,
    /// Connection ID the client saw in the handshake.
    client_conn_id: u32,
    /// Changes when backends start or stop draining.
    drain_rx: watch::Receiver<u64>,
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

fn query_packet(sql: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(sql.len() + 1);
    p.push(cmd::QUERY);
    p.extend_from_slice(sql);
    p
}

fn stmt_id(pkt: &[u8]) -> Option<u32> {
    pkt.get(1..5)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn set_stmt_id(pkt: &mut [u8], id: u32) {
    if pkt.len() >= 5 {
        pkt[1..5].copy_from_slice(&id.to_le_bytes());
    }
}

impl Session {
    /// Authenticates `client` through `backend_addr` and returns the session,
    /// or `None` if the backend rejected the login.
    ///
    /// # Errors
    ///
    /// Network and protocol errors on either connection.
    pub async fn handshake(
        router: Arc<Router>,
        client: TcpStream,
        backend_addr: String,
    ) -> io::Result<Option<Self>> {
        let mut client = PacketConn::new(client);
        let mut backend = dial(&backend_addr).await?;
        let mut greeting = backend.read().await?;
        let g = wire::Greeting::parse(&greeting).ok_or_else(|| other("bad backend greeting"))?;
        // The router speaks plain, uncompressed MySQL to both sides.
        let server_caps =
            g.capabilities & !(cap::SSL | cap::COMPRESS | cap::ZSTD | cap::QUERY_ATTRIBUTES);
        g.set_capabilities(&mut greeting, server_caps);
        client.seq = 0;
        client.send(&greeting).await?;
        let resp = client.read().await?;
        let hs = HandshakeResponse::parse(&resp)
            .ok_or_else(|| other("unsupported handshake response"))?;
        backend.seq = 1;
        backend.send(&resp).await?;
        // Relay the authentication exchange until the backend decides.
        let st = loop {
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
        let db = hs
            .db
            .as_ref()
            .map(|d| String::from_utf8_lossy(d).to_lowercase());
        router.counters.connections.fetch_add(1, Ordering::Relaxed);
        router
            .counters
            .backend_conns
            .fetch_add(1, Ordering::Relaxed);
        let handle = SessionHandle::new(&backend_addr, g.conn_id);
        let drain_rx = router.subscribe_drain();
        let count = router.conn_counter(&backend_addr);
        let mut s = Self {
            router,
            client,
            hs,
            caps,
            db,
            backends: vec![BackendConn::new(
                &backend_addr,
                backend,
                g.conn_id,
                st,
                count,
            )],
            cur: 0,
            durable_version: 0,
            lii: Some(0),
            blocked: false,
            stmts: HashMap::new(),
            next_stmt_id: 1,
            pending_begin: None,
            prelude: Vec::new(),
            verify_from: None,
            sticky: false,
            set_option: None,
            option_version: 0,
            observed: Observed::default(),
            cache: HashMap::new(),
            handle,
            client_conn_id: g.conn_id,
            drain_rx,
        };
        s.enable_tracking(0).await?;
        Ok(Some(s))
    }

    /// Turns on tidb-one session tracking for backend `i` and puts the
    /// connection in the session group of the client's connection ID, so that
    /// `CONNECTION_ID()` and `KILL` from any router see one session. A server
    /// without tracking (upstream `TiDB`) answers with an error and the session
    /// falls back to the SQL classifier; one without session groups (an older
    /// tidb-one) gets tracking alone. Connections opened later inherit both
    /// through the session states.
    async fn enable_tracking(&mut self, i: usize) -> io::Result<()> {
        if !self.router.options.session_track {
            return Ok(());
        }
        let with_group = query_packet(
            format!(
                "SET SESSION tidb_one_session_track = ON, tidb_one_session_group = {}",
                self.client_conn_id
            )
            .as_bytes(),
        );
        let b = &mut self.backends[i];
        b.conn.reset_seq();
        b.conn.send(&with_group).await?;
        let mut p = b.conn.read().await?;
        if wire::kind(&p) != PacketKind::Ok {
            b.conn.reset_seq();
            b.conn.send(ENABLE_TRACKING).await?;
            p = b.conn.read().await?;
        }
        b.tracking = wire::kind(&p) == PacketKind::Ok;
        if b.tracking {
            let s = wire::ok_status(&p).unwrap_or(b.status) & !status::TIDB_ONE_MASK;
            wire::set_terminator_status(&mut p, true, s);
            b.status = s;
        }
        Ok(())
    }

    fn deprecate_eof(&self) -> bool {
        self.caps & cap::DEPRECATE_EOF != 0
    }

    fn at_boundary(&self) -> bool {
        !self.sticky && !self.backends[self.cur].in_trans()
    }

    /// The durable session state changed on `cur`.
    fn bump_durable(&mut self) {
        self.durable_version += 1;
        self.backends[self.cur].synced = self.durable_version;
    }

    /// Serves commands until the client quits, the session is killed, or a
    /// connection fails.
    ///
    /// # Errors
    ///
    /// The error that ended the session.
    pub async fn run(mut self) -> io::Result<()> {
        let handle = Arc::clone(&self.handle);
        let result = loop {
            if self.router.any_draining()
                && let Err(e) = self.leave_draining().await
            {
                break Err(e);
            }
            // Wait for the next command without consuming it, so a drain
            // can interrupt the wait of an idle session.
            let ready = tokio::select! {
                r = self.client.wait_data() => r,
                () = handle.killed.notified() => break Ok(()),
                r = self.drain_rx.changed() => {
                    if r.is_err() {
                        break Ok(());
                    }
                    continue;
                }
            };
            match ready {
                Ok(true) => {}
                Ok(false) => break Ok(()),
                Err(e) => break Err(e),
            }
            self.client.reset_seq();
            let pkt = match self.client.read().await {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break Ok(()),
                Err(e) => break Err(e),
            };
            let Some(&command) = pkt.first() else {
                continue;
            };
            let r = match command {
                cmd::QUIT => break Ok(()),
                cmd::QUERY => self.on_query(pkt).await,
                cmd::STMT_EXECUTE => self.on_execute(pkt).await,
                cmd::STMT_PREPARE => self.on_prepare(pkt).await,
                cmd::STMT_CLOSE => self.on_close(&pkt).await,
                cmd::STMT_RESET => self.on_stmt_reset(pkt).await,
                cmd::STMT_SEND_LONG_DATA => self.on_long_data(pkt).await,
                cmd::STMT_FETCH => self.on_fetch(pkt).await,
                cmd::CHANGE_USER => self.on_change_user(pkt).await,
                cmd::PROCESS_KILL => self.on_process_kill(&pkt).await,
                _ => self.on_other(pkt, command).await,
            };
            if let Err(e) = r {
                break Err(e);
            }
        };
        let n = self.backends.len();
        for b in &mut self.backends {
            b.conn.reset_seq();
            let _ = b.conn.send(&[cmd::QUIT]).await;
        }
        self.router
            .counters
            .backend_conns
            .fetch_sub(i64::try_from(n).unwrap_or(i64::MAX), Ordering::Relaxed);
        result
    }

    async fn on_other(&mut self, pkt: Vec<u8>, command: u8) -> io::Result<()> {
        if command != cmd::PING && !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        if command == cmd::INIT_DB {
            self.db = Some(String::from_utf8_lossy(&pkt[1..]).to_lowercase());
        }
        if command == cmd::SET_OPTION {
            self.set_option = Some(pkt.clone());
            self.option_version += 1;
            self.backends[self.cur].option_synced = self.option_version;
        }
        self.forward(&pkt).await?;
        match command {
            cmd::FIELD_LIST => self.relay_until_eof().await?,
            _ => {
                self.relay_one().await?;
            }
        }
        match command {
            cmd::INIT_DB => self.bump_durable(),
            cmd::RESET_CONNECTION => {
                // The server dropped the session: variables, prepared
                // statements and LAST_INSERT_ID().
                self.reset_router_state();
                self.enable_tracking(self.cur).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Forgets router-owned state after the client reset or changed its session.
    fn reset_router_state(&mut self) {
        self.stmts.clear();
        for b in &mut self.backends {
            b.stmt_ids.clear();
            b.typed.clear();
        }
        self.lii = Some(0);
        self.backends[self.cur].lii = Some(0);
        self.blocked = false;
        self.bump_durable();
    }

    // ---- classification and routing -------------------------------------

    fn classify_cached(&mut self, sql: &[u8]) -> Arc<Entry> {
        if let Some(c) = self.cache.get(sql) {
            return Arc::clone(c);
        }
        let c = classify::classify(sql);
        let cands = if c.kind == Kind::Insert {
            classify::insert_candidates(sql)
        } else {
            Vec::new()
        };
        let entry = Arc::new((c, cands));
        if self.cache.len() >= CLASSIFY_CACHE_LIMIT {
            self.cache.clear();
        }
        self.cache.insert(sql.to_vec(), Arc::clone(&entry));
        entry
    }

    fn route(
        &self,
        c: &Classified,
        point_value: Option<i64>,
        candidates: &[(String, Value)],
        exec: Option<&[i64]>,
    ) -> (Option<String>, Reason) {
        let Some((db, table)) = &c.table else {
            return (None, Reason::Default);
        };
        let Some(db) = db.clone().or_else(|| self.db.clone()) else {
            return (None, Reason::Default);
        };
        let point = c
            .point
            .as_ref()
            .and_then(|p| point_value.map(|v| (p.column.as_str(), v)));
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

    /// Closes idle connections to draining backends and, at a transaction
    /// boundary, moves the session off a draining current backend.
    async fn leave_draining(&mut self) -> io::Result<()> {
        let mut i = 0;
        while i < self.backends.len() {
            if i != self.cur && self.router.is_draining(&self.backends[i].addr) {
                self.drop_backend(i).await;
            } else {
                i += 1;
            }
        }
        let cur_addr = self.backends[self.cur].addr.clone();
        if !self.router.is_draining(&cur_addr)
            || !self.at_boundary()
            || self.blocked
            || !self.prelude.is_empty()
        {
            return Ok(());
        }
        let Some(target) = self.router.pick_open() else {
            return Ok(());
        };
        self.switch_to(Some(target), false).await;
        if self.backends[self.cur].addr != cur_addr
            && let Some(old) = self.backends.iter().position(|b| b.addr == cur_addr)
        {
            self.drop_backend(old).await;
            self.router
                .counters
                .drain_moved
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Closes backend connection `i`, which is not the current one.
    async fn drop_backend(&mut self, i: usize) {
        debug_assert_ne!(i, self.cur);
        let mut b = self.backends.remove(i);
        if self.cur > i {
            self.cur -= 1;
        }
        self.verify_from = match self.verify_from {
            Some(v) if v == i => None,
            Some(v) if v > i => Some(v - 1),
            v => v,
        };
        b.conn.reset_seq();
        let _ = b.conn.send(&[cmd::QUIT]).await;
        self.router
            .counters
            .backend_conns
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// Moves the session to `addr` if it is not already there and may move.
    async fn switch_to(&mut self, addr: Option<String>, prev_dependent: bool) {
        let Some(addr) = addr else { return };
        if self.backends[self.cur].addr == addr {
            return;
        }
        let counters = &self.router.counters;
        if self.blocked {
            counters.switch_pinned.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if prev_dependent {
            counters
                .switch_prev_dependent
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let start = Instant::now();
        let from = self.cur;
        match self.sync_to(&addr).await {
            Ok((i, kind)) => {
                self.cur = i;
                let b = &self.backends[i];
                self.handle.set_current(&b.addr, b.conn_id);
                let counters = &self.router.counters;
                let (counter, trips) = match kind {
                    SwitchKind::Warm => (&counters.switch_warm, 0),
                    SwitchKind::Delta => (&counters.switch_delta, 0),
                    SwitchKind::Migrate => (&counters.switch_migrate, 2),
                    SwitchKind::Dial => (&counters.switch_dial, 4),
                };
                counter.fetch_add(1, Ordering::Relaxed);
                counters
                    .switch_round_trips
                    .fetch_add(trips, Ordering::Relaxed);
                counters.switch_seconds[kind as usize].observe(start.elapsed());
                if self.router.options.verify_session_states {
                    self.verify_from = Some(from);
                }
            }
            Err(e) => {
                self.prelude.clear();
                eprintln!(
                    "locality-router: switch to {addr} failed, staying on {}: {e}",
                    self.backends[self.cur].addr
                );
                self.router
                    .counters
                    .switch_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Brings the connection to `addr` in sync with the session, opening it if
    /// needed. Catch-up commands that need no round trip are queued in
    /// `prelude`. Returns the connection index and the kind of switch.
    async fn sync_to(&mut self, addr: &str) -> io::Result<(usize, SwitchKind)> {
        let existing = self.backends.iter().position(|b| b.addr == addr);
        let tracking = self.backends[self.cur].tracking;
        if let Some(i) = existing
            && self.backends[i].synced == self.durable_version
            && !self.backends[i].in_trans()
            && (self.lii.is_some() || !tracking)
        {
            let delta = self.catch_up(i);
            return Ok((
                i,
                if delta {
                    SwitchKind::Delta
                } else {
                    SwitchKind::Warm
                },
            ));
        }
        let (states, token) = self.show_session_states(self.cur).await?;
        let (states, states_lii) = prepare_states(&states)?;
        if tracking && self.lii.is_none() {
            // Only `cur` knew it; the session states carry it.
            self.lii = Some(states_lii);
            self.backends[self.cur].lii = Some(states_lii);
        }
        let (i, kind) = match existing {
            Some(i) => {
                if let Ok(true) = self.reset_and_apply(i, &states).await {
                    (i, SwitchKind::Migrate)
                } else {
                    // The reset was refused or the connection broke: its
                    // state is unknown; replace it with a new one.
                    self.backends[i].synced = UNSYNCED;
                    (
                        self.dial_and_apply(addr, &token, &states, Some(i)).await?,
                        SwitchKind::Dial,
                    )
                }
            }
            None => (
                self.dial_and_apply(addr, &token, &states, None).await?,
                SwitchKind::Dial,
            ),
        };
        let b = &mut self.backends[i];
        b.synced = self.durable_version;
        b.lii = Some(states_lii);
        b.tracking = tracking;
        b.stmt_ids.clear();
        b.typed.clear();
        self.catch_up(i);
        Ok((i, kind))
    }

    /// Queues the commands that bring backend `i` up to date with values the
    /// session states do not carry or that changed since its last sync.
    /// Returns whether anything was queued.
    fn catch_up(&mut self, i: usize) -> bool {
        let mut queued = false;
        let tracked = self.backends[self.cur].tracking && self.backends[i].tracking;
        if tracked
            && let Some(v) = self.lii
            && self.backends[i].lii != Some(v)
        {
            let sql = format!("DO LAST_INSERT_ID({v})");
            self.prelude.push(Internal {
                pkt: query_packet(sql.as_bytes()),
                expect: Expect::Ok,
                barrier: false,
            });
            self.backends[i].lii = Some(v);
            queued = true;
        }
        if let Some(opt) = &self.set_option
            && self.backends[i].option_synced < self.option_version
        {
            self.prelude.push(Internal {
                pkt: opt.clone(),
                expect: Expect::Ok,
                barrier: false,
            });
            self.backends[i].option_synced = self.option_version;
            queued = true;
        }
        queued
    }

    /// Re-synchronizes the open connection `i`: `COM_RESET_CONNECTION` and
    /// `SET SESSION_STATES` in one write. Returns false if the reset was
    /// refused (the connection must be replaced).
    async fn reset_and_apply(&mut self, i: usize, states: &str) -> io::Result<bool> {
        let b = &mut self.backends[i];
        b.conn.reset_seq();
        b.conn.write(&[cmd::RESET_CONNECTION]).await?;
        b.conn.reset_seq();
        b.conn.write(&set_states_packet(states)).await?;
        b.conn.flush().await?;
        let reset = b.conn.read().await?;
        let applied = b.conn.read().await?;
        if wire::kind(&reset) != PacketKind::Ok {
            return Ok(false);
        }
        if wire::kind(&applied) != PacketKind::Ok {
            return Err(other(format!(
                "SET SESSION_STATES on {}: {}",
                b.addr,
                err_text(&applied)
            )));
        }
        b.status = wire::ok_status(&applied).unwrap_or(status::AUTOCOMMIT) & !status::TIDB_ONE_MASK;
        Ok(true)
    }

    /// Opens a connection to `addr`, logs in with the session token and
    /// applies `states`. With `replace`, the new connection takes that slot.
    async fn dial_and_apply(
        &mut self,
        addr: &str,
        token: &[u8],
        states: &str,
        replace: Option<usize>,
    ) -> io::Result<usize> {
        let mut conn = dial(addr).await?;
        let greeting = conn.read().await?;
        let g = wire::Greeting::parse(&greeting).ok_or_else(|| other("bad greeting"))?;
        let caps = self.caps & g.capabilities;
        let db = self.db.as_ref().map(|d| d.as_bytes().to_vec());
        let resp = self
            .hs
            .encode(caps, "tidb_session_token", token, db.as_deref());
        conn.seq = 1;
        conn.send(&resp).await?;
        loop {
            let p = conn.read().await?;
            match p.first() {
                Some(0x00) => break,
                Some(0xfe) => {
                    // Auth switch: answer with the token again.
                    conn.send(token).await?;
                }
                _ => {
                    return Err(other(format!(
                        "session token rejected by {addr}: {}",
                        err_text(&p)
                    )));
                }
            }
        }
        conn.reset_seq();
        conn.send(&set_states_packet(states)).await?;
        let p = conn.read().await?;
        if wire::kind(&p) != PacketKind::Ok {
            return Err(other(format!(
                "SET SESSION_STATES on {addr}: {}",
                err_text(&p)
            )));
        }
        let st = wire::ok_status(&p).unwrap_or(status::AUTOCOMMIT) & !status::TIDB_ONE_MASK;
        self.handle.register(g.conn_id);
        let fresh = BackendConn::new(addr, conn, g.conn_id, st, self.router.conn_counter(addr));
        let counters = &self.router.counters;
        if let Some(i) = replace {
            let mut old = std::mem::replace(&mut self.backends[i], fresh);
            old.conn.reset_seq();
            let _ = old.conn.send(&[cmd::QUIT]).await;
            Ok(i)
        } else {
            counters.backend_conns.fetch_add(1, Ordering::Relaxed);
            self.backends.push(fresh);
            Ok(self.backends.len() - 1)
        }
    }

    /// Runs `SHOW SESSION_STATES` on backend `i`: the states JSON and a token.
    async fn show_session_states(&mut self, i: usize) -> io::Result<(String, Vec<u8>)> {
        let deprecate_eof = self.deprecate_eof();
        let b = &mut self.backends[i].conn;
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
                PacketKind::Err => {
                    return Err(other(format!("SHOW SESSION_STATES: {}", err_text(&p))));
                }
                _ => row = Some(p),
            }
        }
        let row = row.ok_or_else(|| other("SHOW SESSION_STATES returned no row"))?;
        let mut pos = 0;
        let states =
            wire::lenenc_bytes(&row, &mut pos).ok_or_else(|| other("bad session states"))?;
        let token = wire::lenenc_bytes(&row, &mut pos).ok_or_else(|| other("bad session token"))?;
        Ok((String::from_utf8_lossy(states).into_owned(), token.to_vec()))
    }

    // ---- statements -----------------------------------------------------

    async fn on_query(&mut self, pkt: Vec<u8>) -> io::Result<()> {
        let entry = self.classify_cached(&pkt[1..]);
        let (c, cands) = (&entry.0, &entry.1);
        if let Some(k) = c.kill {
            return self.on_kill(k).await;
        }
        let held = self.pending_begin.is_some();
        if self.at_boundary() || held {
            match c.kind {
                Kind::Begin => {
                    // Hold the BEGIN until the first statement names a table.
                    let autocommit = self.backends[self.cur].status & status::AUTOCOMMIT;
                    self.pending_begin = Some((pkt, c.simple_begin));
                    return self
                        .client
                        .send(&wire::ok_packet(autocommit | status::IN_TRANS))
                        .await;
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
            let (addr, _) = self.route(c, point, cands, None);
            if addr.is_some() {
                self.router
                    .counters
                    .txn_routed
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.switch_to(addr, c.prev_dependent).await;
        }
        if let Some(db) = &c.use_db {
            self.db = Some(db.clone());
        }
        if !self.send_with_prelude(&pkt).await? {
            return Ok(());
        }
        self.relay_statement(false, c).await
    }

    /// `KILL [TIDB] [CONNECTION | QUERY] id`: if `id` belongs to a session of
    /// this router, target the connection that runs that session now.
    async fn on_kill(&mut self, k: Kill) -> io::Result<()> {
        if !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        let target = kill::lookup(k.id);
        let id = match &target {
            Some(h) => {
                self.router
                    .counters
                    .kill_rewritten
                    .fetch_add(1, Ordering::Relaxed);
                u64::from(h.current().1)
            }
            None => k.id,
        };
        self.forward(&query_packet(k.sql(id).as_bytes())).await?;
        let ok = self.relay_one().await?;
        if ok
            && !k.query
            && let Some(h) = target
        {
            h.killed.notify_one();
        }
        Ok(())
    }

    async fn on_process_kill(&mut self, pkt: &[u8]) -> io::Result<()> {
        let id = pkt
            .get(1..5)
            .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        self.on_kill(Kill {
            query: false,
            tidb: false,
            id: u64::from(id),
        })
        .await
    }

    /// Sends a held `BEGIN` to the current backend on its own. Returns false if
    /// it failed and the error was already sent to the client as the reply to
    /// the current command.
    async fn flush_begin_or_reply(&mut self) -> io::Result<bool> {
        let Some((begin, _)) = self.pending_begin.take() else {
            return Ok(true);
        };
        self.router
            .counters
            .begin_waited
            .fetch_add(1, Ordering::Relaxed);
        self.prelude.push(Internal {
            pkt: begin,
            expect: Expect::Begin,
            barrier: true,
        });
        self.drain_prelude().await
    }

    /// Sends the queued catch-up commands, the held `BEGIN`, and then `pkt` to
    /// the current backend. Commands that cannot fail share one write with
    /// `pkt`; a `BEGIN` with options is answered before `pkt` is sent. Returns
    /// false if the client already got an error reply.
    async fn send_with_prelude(&mut self, pkt: &[u8]) -> io::Result<bool> {
        if let Some(from) = self.verify_from.take() {
            // Apply the catch-up first so that the states can be compared,
            // and compare before a held BEGIN opens a transaction.
            if !self.drain_prelude().await? {
                return Ok(false);
            }
            self.verify(from).await?;
        }
        if let Some((begin, simple)) = self.pending_begin.take() {
            let pipelined = simple && self.router.options.pipeline_begin;
            let counter = if pipelined {
                &self.router.counters.begin_pipelined
            } else {
                &self.router.counters.begin_waited
            };
            counter.fetch_add(1, Ordering::Relaxed);
            self.prelude.push(Internal {
                pkt: begin,
                expect: Expect::Begin,
                barrier: !pipelined,
            });
        }
        let mut unread = Vec::new();
        for item in std::mem::take(&mut self.prelude) {
            let b = &mut self.backends[self.cur].conn;
            b.reset_seq();
            b.write(&item.pkt).await?;
            unread.push(item.expect);
            if item.barrier {
                b.flush().await?;
                if !self.read_internal(&mut unread, false).await? {
                    return Ok(false);
                }
            }
        }
        let b = &mut self.backends[self.cur].conn;
        b.reset_seq();
        b.write(pkt).await?;
        b.flush().await?;
        self.read_internal(&mut unread, true).await
    }

    /// Sends every queued catch-up command and reads their responses.
    async fn drain_prelude(&mut self) -> io::Result<bool> {
        if self.prelude.is_empty() {
            return Ok(true);
        }
        let mut unread = Vec::new();
        let b = &mut self.backends[self.cur].conn;
        for item in std::mem::take(&mut self.prelude) {
            b.reset_seq();
            b.write(&item.pkt).await?;
            unread.push(item.expect);
        }
        b.flush().await?;
        self.read_internal(&mut unread, false).await
    }

    /// Reads the responses of internal commands. With `user_sent`, the
    /// client's own command follows them on the wire: if the held `BEGIN`
    /// failed, its error is the client's reply and the statement's response is
    /// discarded.
    async fn read_internal(
        &mut self,
        unread: &mut Vec<Expect>,
        user_sent: bool,
    ) -> io::Result<bool> {
        let deprecate_eof = self.deprecate_eof();
        for expect in std::mem::take(unread) {
            let cur = self.cur;
            match expect {
                Expect::Ok | Expect::Begin => {
                    let p = self.backends[cur].conn.read().await?;
                    match wire::kind(&p) {
                        PacketKind::Ok | PacketKind::Eof => {
                            let ok_form = wire::kind(&p) == PacketKind::Ok || deprecate_eof;
                            let s = if ok_form {
                                wire::ok_status(&p)
                            } else {
                                wire::eof_status(&p, false)
                            };
                            if let Some(s) = s {
                                self.backends[cur].status = s & !status::TIDB_ONE_MASK;
                            }
                        }
                        _ if expect == Expect::Begin => {
                            eprintln!(
                                "locality-router: held BEGIN failed on {}: {}",
                                self.backends[cur].addr,
                                err_text(&p)
                            );
                            self.client.send(&p).await?;
                            if user_sent {
                                self.relay_result(false, true).await?;
                            }
                            return Ok(false);
                        }
                        _ => {
                            eprintln!(
                                "locality-router: catch-up command failed on {}: {}",
                                self.backends[cur].addr,
                                err_text(&p)
                            );
                            self.backends[cur].lii = None;
                        }
                    }
                }
                Expect::Prepare(id) => {
                    if !self.read_prepare_response(id).await? {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    // ---- relaying ------------------------------------------------------

    async fn forward(&mut self, pkt: &[u8]) -> io::Result<()> {
        let b = &mut self.backends[self.cur].conn;
        b.reset_seq();
        b.send(pkt).await
    }

    /// Reads the server status of a status-bearing packet, records what
    /// tidb-one tracking reports (with `record`), and removes the tracking
    /// bits from the packet.
    fn take_status(&mut self, p: &mut [u8], ok_form: bool, record: bool) -> Option<u16> {
        let s = if ok_form {
            wire::ok_status(p)
        } else {
            wire::eof_status(p, false)
        }?;
        if !self.backends[self.cur].tracking {
            if record && ok_form {
                self.observed.header_lii = wire::ok_last_insert_id(p).unwrap_or(0);
            }
            return Some(s);
        }
        if record {
            let o = &mut self.observed;
            o.status_seen = true;
            o.changed |= s & status::SESSION_STATE_CHANGED != 0;
            o.blocked = s & status::TIDB_ONE_UNMIGRATABLE != 0;
            if s & status::TIDB_ONE_LAST_INSERT_ID != 0 {
                match wire::ok_last_insert_id(p).filter(|_| ok_form) {
                    Some(v) => o.lii = Some(v),
                    None => o.lii_unknown = true,
                }
            }
        }
        let stripped = s & !status::TIDB_ONE_MASK;
        if stripped != s {
            wire::set_terminator_status(p, ok_form, stripped);
        }
        Some(stripped)
    }

    /// Applies what the last statement reported to the session state.
    fn after_statement(&mut self, c: &Classified) {
        let o = std::mem::take(&mut self.observed);
        let cur = self.cur;
        if self.backends[cur].tracking {
            if o.changed {
                self.router
                    .counters
                    .state_changed
                    .fetch_add(1, Ordering::Relaxed);
            }
            // An error packet has no status; trust the classifier then.
            if o.changed || (o.err && c.dirty) {
                self.bump_durable();
            }
            if let Some(v) = o.lii {
                self.lii = Some(v);
                self.backends[cur].lii = Some(v);
            }
            if o.lii_unknown {
                self.lii = None;
                self.backends[cur].lii = None;
                self.bump_durable();
            }
            if o.status_seen {
                self.blocked = o.blocked;
            }
        } else if c.dirty || (c.kind == Kind::Insert && o.header_lii != 0) {
            // Without tracking, an auto-increment insert may change
            // LAST_INSERT_ID(); the session states carry it.
            self.bump_durable();
        }
    }

    async fn emit(&mut self, p: &[u8], discard: bool) -> io::Result<()> {
        if discard {
            Ok(())
        } else {
            self.client.write(p).await
        }
    }

    /// Relays one response packet (OK or ERR) of a non-statement command.
    /// Returns whether it was not an error.
    async fn relay_one(&mut self) -> io::Result<bool> {
        let deprecate_eof = self.deprecate_eof();
        let mut p = self.backends[self.cur].conn.read().await?;
        let k = wire::kind(&p);
        if matches!(k, PacketKind::Ok | PacketKind::Eof)
            && let Some(s) = self.take_status(&mut p, k == PacketKind::Ok || deprecate_eof, false)
        {
            self.backends[self.cur].status = s;
        }
        self.client.send(&p).await?;
        Ok(k != PacketKind::Err)
    }

    async fn relay_until_eof(&mut self) -> io::Result<()> {
        let deprecate_eof = self.deprecate_eof();
        loop {
            let mut p = self.backends[self.cur].conn.read().await?;
            match wire::kind(&p) {
                PacketKind::Eof => {
                    if let Some(s) = self.take_status(&mut p, deprecate_eof, false) {
                        self.backends[self.cur].status = s;
                    }
                    self.client.write(&p).await?;
                    break;
                }
                PacketKind::Err => {
                    self.client.write(&p).await?;
                    break;
                }
                _ => self.client.write(&p).await?,
            }
        }
        self.client.flush().await
    }

    /// Relays the response of a statement and applies what it reported.
    async fn relay_statement(&mut self, cursor: bool, c: &Classified) -> io::Result<()> {
        self.observed = Observed::default();
        self.relay_result(cursor, false).await?;
        self.after_statement(c);
        Ok(())
    }

    /// Relays a full command response (OK, ERR, result sets, LOAD DATA), or
    /// reads and drops it with `discard`. Returns whether it ended without an
    /// error.
    async fn relay_result(&mut self, cursor: bool, discard: bool) -> io::Result<bool> {
        let deprecate_eof = self.deprecate_eof();
        let mut ok = true;
        'results: loop {
            let mut p = self.backends[self.cur].conn.read().await?;
            match wire::kind(&p) {
                PacketKind::Ok | PacketKind::Eof => {
                    let ok_form = wire::kind(&p) == PacketKind::Ok || deprecate_eof;
                    let s = self
                        .take_status(&mut p, ok_form, true)
                        .unwrap_or(status::AUTOCOMMIT);
                    self.backends[self.cur].status = s;
                    self.emit(&p, discard).await?;
                    if s & status::MORE_RESULTS != 0 {
                        continue;
                    }
                    break;
                }
                PacketKind::Err => {
                    self.observed.err = true;
                    ok = false;
                    self.emit(&p, discard).await?;
                    break;
                }
                PacketKind::LocalInfile => {
                    self.client.write(&p).await?;
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
                    self.emit(&p, discard).await?;
                    let mut pos = 0;
                    let ncols = wire::lenenc_int(&p, &mut pos).unwrap_or(0);
                    for _ in 0..ncols {
                        let c = self.backends[self.cur].conn.read().await?;
                        self.emit(&c, discard).await?;
                    }
                    if !deprecate_eof || cursor {
                        let mut e = self.backends[self.cur].conn.read().await?;
                        let s = self.take_status(&mut e, deprecate_eof && !cursor, true);
                        self.emit(&e, discard).await?;
                        if let Some(s) = s {
                            self.backends[self.cur].status = s;
                            if cursor && s & status::CURSOR_EXISTS != 0 {
                                break 'results;
                            }
                        }
                    }
                    loop {
                        let mut r = self.backends[self.cur].conn.read().await?;
                        match wire::kind(&r) {
                            PacketKind::Eof => {
                                let s = self
                                    .take_status(&mut r, deprecate_eof, true)
                                    .unwrap_or(status::AUTOCOMMIT);
                                self.backends[self.cur].status = s;
                                self.emit(&r, discard).await?;
                                if s & status::MORE_RESULTS != 0 {
                                    continue 'results;
                                }
                                break 'results;
                            }
                            PacketKind::Err => {
                                self.observed.err = true;
                                ok = false;
                                self.emit(&r, discard).await?;
                                break 'results;
                            }
                            _ => self.emit(&r, discard).await?,
                        }
                    }
                }
            }
        }
        if !discard {
            self.client.flush().await?;
        }
        Ok(ok)
    }

    // ---- prepared statements ---------------------------------------------

    async fn on_prepare(&mut self, pkt: Vec<u8>) -> io::Result<()> {
        if !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        let entry = self.classify_cached(&pkt[1..]);
        self.forward(&pkt).await?;
        let mut first = self.backends[self.cur].conn.read().await?;
        if wire::kind(&first) != PacketKind::Ok || first.len() < 9 {
            return self.client.send(&first).await;
        }
        let backend_id = stmt_id(&first).unwrap_or(0);
        let ncols = usize::from(u16::from_le_bytes([first[5], first[6]]));
        let nparams = usize::from(u16::from_le_bytes([first[7], first[8]]));
        let client_id = self.next_stmt_id;
        self.next_stmt_id = self.next_stmt_id.wrapping_add(1).max(1);
        set_stmt_id(&mut first, client_id);
        self.client.write(&first).await?;
        self.relay_prepare_defs(nparams, ncols, false).await?;
        self.client.flush().await?;
        self.backends[self.cur]
            .stmt_ids
            .insert(client_id, backend_id);
        self.stmts.insert(
            client_id,
            Stmt {
                sql: pkt[1..].to_vec(),
                entry,
                num_params: nparams,
                types: None,
            },
        );
        Ok(())
    }

    /// Reads (and relays unless `discard`) the parameter and column
    /// definitions of a prepare response.
    async fn relay_prepare_defs(
        &mut self,
        nparams: usize,
        ncols: usize,
        discard: bool,
    ) -> io::Result<()> {
        let deprecate_eof = self.deprecate_eof();
        for n in [nparams, ncols] {
            for _ in 0..n {
                let p = self.backends[self.cur].conn.read().await?;
                self.emit(&p, discard).await?;
            }
            if n > 0 && !deprecate_eof {
                let mut p = self.backends[self.cur].conn.read().await?;
                self.take_status(&mut p, false, false);
                self.emit(&p, discard).await?;
            }
        }
        Ok(())
    }

    /// Reads the response of an on-demand `COM_STMT_PREPARE` for client
    /// statement `id`. On error, the error is sent to the client.
    async fn read_prepare_response(&mut self, id: u32) -> io::Result<bool> {
        let first = self.backends[self.cur].conn.read().await?;
        if wire::kind(&first) != PacketKind::Ok || first.len() < 9 {
            self.client.send(&first).await?;
            return Ok(false);
        }
        let backend_id = stmt_id(&first).unwrap_or(0);
        let ncols = usize::from(u16::from_le_bytes([first[5], first[6]]));
        let nparams = usize::from(u16::from_le_bytes([first[7], first[8]]));
        self.relay_prepare_defs(nparams, ncols, true).await?;
        let b = &mut self.backends[self.cur];
        b.stmt_ids.insert(id, backend_id);
        b.typed.remove(&id);
        self.router
            .counters
            .lazy_prepare
            .fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Makes sure client statement `id` is prepared on the current backend.
    /// Returns false if preparing failed and the client got the error.
    async fn ensure_prepared(&mut self, id: u32) -> io::Result<bool> {
        let Some(st) = self.stmts.get(&id) else {
            // Unknown statement: let the server report it.
            return Ok(true);
        };
        if self.backends[self.cur].stmt_ids.contains_key(&id) {
            return Ok(true);
        }
        let mut pkt = Vec::with_capacity(st.sql.len() + 1);
        pkt.push(cmd::STMT_PREPARE);
        pkt.extend_from_slice(&st.sql);
        self.prelude.push(Internal {
            pkt,
            expect: Expect::Prepare(id),
            barrier: true,
        });
        self.drain_prelude().await
    }

    /// Rewrites the client statement ID in `pkt` to the current backend's.
    fn map_stmt_id(&self, pkt: &mut [u8]) {
        if let Some(id) = stmt_id(pkt)
            && let Some(&backend_id) = self.backends[self.cur].stmt_ids.get(&id)
        {
            set_stmt_id(pkt, backend_id);
        }
    }

    async fn on_execute(&mut self, mut pkt: Vec<u8>) -> io::Result<()> {
        if pkt.len() < 10 {
            self.forward(&pkt).await?;
            self.relay_result(false, false).await?;
            return Ok(());
        }
        let id = stmt_id(&pkt).unwrap_or(0);
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
        let entry = self.stmts.get(&id).map(|st| Arc::clone(&st.entry));
        let held = self.pending_begin.is_some();
        if (self.at_boundary() || held)
            && let Some(e) = &entry
        {
            let c = &e.0;
            // Prepared BEGIN / COMMIT / ROLLBACK (sysbench prepares them):
            // same holding rules as for COM_QUERY.
            match c.kind {
                Kind::Begin => {
                    let autocommit = self.backends[self.cur].status & status::AUTOCOMMIT;
                    let sql = self
                        .stmts
                        .get(&id)
                        .map(|st| query_packet(&st.sql))
                        .unwrap_or_default();
                    self.pending_begin = Some((sql, c.simple_begin));
                    return self
                        .client
                        .send(&wire::ok_packet(autocommit | status::IN_TRANS))
                        .await;
                }
                Kind::Commit | Kind::Rollback if held => {
                    self.pending_begin = None;
                    let autocommit = self.backends[self.cur].status & status::AUTOCOMMIT;
                    return self.client.send(&wire::ok_packet(autocommit)).await;
                }
                _ => {}
            }
            let types = self.stmts.get(&id).and_then(|st| st.types.clone());
            let values = layout.and_then(|(at, n)| int_params(&pkt, at, n, types.as_deref()));
            let point = c.point.as_ref().and_then(|p| match p.value {
                Value::Literal(v) => Some(v),
                Value::Param(i) => values.as_ref().and_then(|v| v.get(i).copied()),
            });
            let (addr, _) = self.route(c, point, &e.1, values.as_deref());
            if addr.is_some() {
                self.router
                    .counters
                    .txn_routed
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.switch_to(addr, c.prev_dependent).await;
        }
        if !self.ensure_prepared(id).await? {
            return Ok(());
        }
        self.map_stmt_id(&mut pkt);
        // A connection that has not seen this statement's parameter types
        // needs them even when the client omitted them.
        if let Some((at, n)) = layout {
            let types = self.stmts.get(&id).and_then(|st| st.types.clone());
            let cur = &mut self.backends[self.cur];
            if pkt.get(at) == Some(&1) {
                cur.typed.insert(id);
            } else if !cur.typed.contains(&id)
                && let Some(types) = types
                && types.len() == 2 * n
            {
                pkt[at] = 1;
                pkt.splice((at + 1)..=at, types);
                cur.typed.insert(id);
            }
        }
        if !self.send_with_prelude(&pkt).await? {
            return Ok(());
        }
        match entry {
            Some(e) => self.relay_statement(cursor, &e.0).await,
            None => self.relay_result(cursor, false).await.map(|_| ()),
        }
    }

    async fn on_close(&mut self, pkt: &[u8]) -> io::Result<()> {
        let Some(id) = stmt_id(pkt) else {
            return Ok(());
        };
        self.stmts.remove(&id);
        // Close it on every connection that prepared it; no response.
        for b in &mut self.backends {
            if let Some(backend_id) = b.stmt_ids.remove(&id) {
                b.typed.remove(&id);
                let mut p = pkt.to_vec();
                set_stmt_id(&mut p, backend_id);
                b.conn.reset_seq();
                b.conn.send(&p).await?;
            }
        }
        Ok(())
    }

    async fn on_stmt_reset(&mut self, mut pkt: Vec<u8>) -> io::Result<()> {
        if !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        let id = stmt_id(&pkt).unwrap_or(0);
        if self.stmts.contains_key(&id) && !self.backends[self.cur].stmt_ids.contains_key(&id) {
            // Not prepared here yet: nothing to reset.
            let st = self.backends[self.cur].status;
            return self.client.send(&wire::ok_packet(st)).await;
        }
        self.map_stmt_id(&mut pkt);
        self.forward(&pkt).await?;
        self.relay_one().await.map(|_| ())
    }

    async fn on_long_data(&mut self, mut pkt: Vec<u8>) -> io::Result<()> {
        if !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        // Long data lives on one connection until the statement executes.
        self.sticky = true;
        let id = stmt_id(&pkt).unwrap_or(0);
        if !self.ensure_prepared(id).await? {
            return Ok(());
        }
        self.map_stmt_id(&mut pkt);
        self.forward(&pkt).await
    }

    async fn on_fetch(&mut self, mut pkt: Vec<u8>) -> io::Result<()> {
        self.map_stmt_id(&mut pkt);
        self.forward(&pkt).await?;
        self.relay_until_eof().await
    }

    async fn on_change_user(&mut self, pkt: Vec<u8>) -> io::Result<()> {
        if !self.flush_begin_or_reply().await? {
            return Ok(());
        }
        // Keep only the current connection; the user changes under it.
        let keep = self.backends.swap_remove(self.cur);
        let dropped = self.backends.len();
        for mut b in self.backends.drain(..) {
            b.conn.reset_seq();
            let _ = b.conn.send(&[cmd::QUIT]).await;
        }
        self.router.counters.backend_conns.fetch_sub(
            i64::try_from(dropped).unwrap_or(i64::MAX),
            Ordering::Relaxed,
        );
        self.backends.push(keep);
        self.cur = 0;
        self.reset_router_state();
        self.set_option = None;
        self.forward(&pkt).await?;
        loop {
            let p = self.backends[0].conn.read().await?;
            self.client.seq = self.backends[0].conn.seq.wrapping_sub(1);
            self.client.send(&p).await?;
            match p.first() {
                Some(0x00) => {
                    self.backends[0].status =
                        wire::ok_status(&p).unwrap_or(status::AUTOCOMMIT) & !status::TIDB_ONE_MASK;
                    return self.enable_tracking(0).await;
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

    // ---- verification ----------------------------------------------------

    /// Compares the session states of backend `from` and the current one
    /// (`--verify-session-states`, for tests).
    async fn verify(&mut self, from: usize) -> io::Result<()> {
        let a = self.show_session_states(from).await;
        let b = self.show_session_states(self.cur).await;
        let (a, b) = match (a, b) {
            (Ok((a, _)), Ok((b, _))) => (normalize_states(&a), normalize_states(&b)),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("locality-router: verify: {e}");
                return Ok(());
            }
        };
        let counters = &self.router.counters;
        if a == b {
            counters.verify_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.verify_mismatch.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "locality-router: session states differ after switch {} -> {}: {}",
                self.backends[from].addr,
                self.backends[self.cur].addr,
                states_diff(&a, &b)
            );
        }
        Ok(())
    }
}

fn err_text(p: &[u8]) -> String {
    if p.first() == Some(&0xff) && p.len() > 9 {
        String::from_utf8_lossy(&p[9..]).into_owned()
    } else {
        format!(
            "unexpected packet 0x{:02x}",
            p.first().copied().unwrap_or(0)
        )
    }
}

/// `SET SESSION_STATES '<states>'` as a `COM_QUERY` packet.
fn set_states_packet(states: &str) -> Vec<u8> {
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
    sql
}

/// Prepares session states from `SHOW SESSION_STATES` for another
/// connection: binary-protocol prepared statements are dropped (the router
/// prepares them on demand), text-protocol ones (`PREPARE name FROM ...`)
/// stay. Returns the states and the `LAST_INSERT_ID()` they carry.
fn prepare_states(states: &str) -> io::Result<(String, u64)> {
    let mut v: Json =
        serde_json::from_str(states).map_err(|e| other(format!("bad session states: {e}")))?;
    let lii = v.get("last-insert-id").and_then(Json::as_u64).unwrap_or(0);
    retain_text_prepared(&mut v);
    Ok((v.to_string(), lii))
}

fn retain_text_prepared(v: &mut Json) {
    let Some(obj) = v.as_object_mut() else { return };
    if let Some(Json::Object(ps)) = obj.get_mut("prepared-stmts") {
        ps.retain(|_, s| {
            s.get("name")
                .and_then(Json::as_str)
                .is_some_and(|n| !n.is_empty())
        });
        if ps.is_empty() {
            obj.remove("prepared-stmts");
        }
    }
}

/// Session states without what legitimately differs between two connections
/// of one session: statement-level results, binary prepared statements (they
/// are router-owned), and the prepared statement ID counter.
fn normalize_states(states: &str) -> Json {
    let mut v: Json = serde_json::from_str(states).unwrap_or(Json::Null);
    retain_text_prepared(&mut v);
    if let Some(obj) = v.as_object_mut() {
        for k in [
            "prepared-stmt-id",
            "txn-info",
            "query-info",
            "ddl-info",
            "found-rows",
            "affected-rows",
            "warnings",
            "in-plan-cache",
            "in-binding",
        ] {
            obj.remove(k);
        }
        // Only the transaction-related status bits are session state.
        if let Some(s) = obj.get("status").and_then(Json::as_u64) {
            let s = s & u64::from(status::IN_TRANS | status::AUTOCOMMIT);
            obj.insert("status".to_owned(), Json::from(s));
        }
    }
    v
}

/// Names the parts of two normalized states that differ.
fn states_diff(a: &Json, b: &Json) -> String {
    let empty = serde_json::Map::new();
    let (ao, bo) = (
        a.as_object().unwrap_or(&empty),
        b.as_object().unwrap_or(&empty),
    );
    let mut keys: Vec<&String> = ao.keys().chain(bo.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    for k in keys {
        let (x, y) = (ao.get(k), bo.get(k));
        if x == y {
            continue;
        }
        match (x.and_then(Json::as_object), y.and_then(Json::as_object)) {
            (Some(xm), Some(ym)) => {
                let mut sub: Vec<&String> = xm
                    .keys()
                    .chain(ym.keys())
                    .filter(|s| xm.get(*s) != ym.get(*s))
                    .collect();
                sub.sort();
                sub.dedup();
                out.push(format!("{k}{sub:?}"));
            }
            _ => out.push(format!("{k}: {x:?} vs {y:?}")),
        }
    }
    out.join(", ")
}

/// Decodes the integer parameters of a `COM_STMT_EXECUTE` (`None` for others).
/// Returns `None` if any parameter has a type it cannot skip.
fn int_params(
    pkt: &[u8],
    bound_at: usize,
    n: usize,
    cached_types: Option<&[u8]>,
) -> Option<Vec<i64>> {
    let bitmap = pkt.get(10..10 + n.div_ceil(8))?;
    let bound = *pkt.get(bound_at)?;
    let (types, mut pos) = if bound == 1 {
        (
            pkt.get(bound_at + 1..bound_at + 1 + 2 * n)?,
            bound_at + 1 + 2 * n,
        )
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
                (
                    Some(if unsigned {
                        i64::from(b)
                    } else {
                        i64::from(b.cast_signed())
                    }),
                    1,
                )
            }
            0x02 | 0x0d => {
                let b = pkt.get(pos..pos + 2)?;
                let raw = u16::from_le_bytes([b[0], b[1]]);
                (
                    Some(if unsigned {
                        i64::from(raw)
                    } else {
                        i64::from(raw.cast_signed())
                    }),
                    2,
                )
            }
            0x03 | 0x09 => {
                let b = pkt.get(pos..pos + 4)?;
                let raw = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                (
                    Some(if unsigned {
                        i64::from(raw)
                    } else {
                        i64::from(raw.cast_signed())
                    }),
                    4,
                )
            }
            0x08 => {
                let b = pkt.get(pos..pos + 8)?;
                let raw = u64::from_le_bytes(b.try_into().ok()?);
                (
                    i64::try_from(raw).ok().or(if unsigned {
                        None
                    } else {
                        Some(raw.cast_signed())
                    }),
                    8,
                )
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

    #[test]
    fn statement_ids() {
        let mut p = vec![0x17, 7, 0, 0, 0, 0];
        assert_eq!(stmt_id(&p), Some(7));
        set_stmt_id(&mut p, 0x0102_0304);
        assert_eq!(&p[1..5], &[4, 3, 2, 1]);
        assert_eq!(stmt_id(&[0x17, 1]), None);
    }

    #[test]
    fn prepared_states_keep_text_statements() {
        let states = r#"{"sys-vars":{"autocommit":"ON"},"prepared-stmts":{"1":{"text":"select ?"},"2":{"name":"s","text":"select 1"}},"prepared-stmt-id":2,"last-insert-id":42}"#;
        let (out, lii) = prepare_states(states).unwrap_or_default();
        assert_eq!(lii, 42);
        let v: Json = serde_json::from_str(&out).unwrap_or(Json::Null);
        assert!(v["prepared-stmts"].get("1").is_none());
        assert_eq!(v["prepared-stmts"]["2"]["name"], "s");
        assert_eq!(v["prepared-stmt-id"], 2);
        let (out, lii) =
            prepare_states(r#"{"prepared-stmts":{"1":{"text":"select ?"}}}"#).unwrap_or_default();
        assert_eq!(lii, 0);
        assert_eq!(out, "{}");
        assert!(prepare_states("not json").is_err());
    }

    #[test]
    fn normalized_states_ignore_statement_results() {
        let a = normalize_states(
            r#"{"sys-vars":{"x":"1"},"found-rows":3,"query-info":{"a":1},"status":3,"prepared-stmt-id":9}"#,
        );
        let b = normalize_states(r#"{"sys-vars":{"x":"1"},"status":16387}"#);
        assert_eq!(a, b);
        let c = normalize_states(r#"{"sys-vars":{"x":"2"},"last-insert-id":5}"#);
        assert_ne!(a, c);
        let d = states_diff(&a, &c);
        assert!(d.contains("sys-vars[\"x\"]"), "{d}");
        assert!(d.contains("last-insert-id"), "{d}");
    }
}
