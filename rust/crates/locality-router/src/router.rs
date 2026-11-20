// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Routing table: which tidb-one backend runs next to the Region leader of a
//! table or row.
//!
//! Sources, refreshed in the background:
//! * `TiDB` `/info/all`: SQL backends and their `tidb_one_store_id` label (the
//!   `TiKV` store embedded in the same process);
//! * `TiDB` `/schema/{db}/{table}`: table ID, integer-handle column, hash
//!   partitions;
//! * PD `/pd/api/v1/regions/key`: Regions and leaders of each physical table's
//!   key range.
//!
//! Lookups only read cached state; a miss schedules a fetch and the statement
//! falls back to the current backend.
//!
//! Backends can be drained: no new session or transaction goes to a draining
//! backend, and sessions leave it at their next transaction boundary (see
//! `Session::leave_draining`). A backend drains when an operator asks for it
//! (`POST /api/backends/drain` on the status port, used by `TiUP` before it
//! restarts a node), when its `/status` fails twice in a row (`TiDB` answers
//! 500 once it starts shutting down), or when it leaves `/info/all`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{Value as Json, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::keycodec;

/// Label that carries the ID of the `TiKV` store embedded in a tidb-one server.
pub const STORE_ID_LABEL: &str = "tidb_one_store_id";

const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const TABLE_META_TTL: Duration = Duration::from_secs(30);
/// Timeout of one `/status` probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// Consecutive failed probes after which a backend drains.
const PROBE_FAILURES: u32 = 2;

/// Why a backend is draining.
#[derive(Debug, Clone, Default)]
struct Drain {
    /// An operator asked for it (`POST /api/backends/drain`).
    api: bool,
    /// Its `/status` failed `PROBE_FAILURES` times in a row.
    unhealthy: bool,
    /// Consecutive failed probes.
    failures: u32,
    /// When the backend started draining.
    since: Option<Instant>,
}

impl Drain {
    fn active(&self) -> bool {
        self.api || self.unhealthy
    }
}

/// One SQL backend.
#[derive(Debug, Clone)]
pub struct Backend {
    /// `MySQL` protocol address.
    pub sql_addr: String,
    /// HTTP status address.
    pub status_addr: String,
    /// Embedded store, 0 if unknown.
    pub store_id: u64,
}

#[derive(Debug, Clone)]
struct Region {
    start: Vec<u8>,
    end: Vec<u8>, // empty = +inf
    leader_store: u64,
}

#[derive(Debug, Clone)]
struct Physical {
    id: i64,
    regions: Vec<Region>, // regions overlapping the whole table range, sorted
}

#[derive(Debug, Clone)]
struct TableRoute {
    handle_col: Option<String>,
    hash_partition_col: Option<String>,
    physicals: Vec<Physical>,
    /// Leader store when every Region of every physical table has the same
    /// leader (table / partition affinity), else 0.
    table_leader: u64,
    meta_at: Instant,
}

#[derive(Default)]
struct State {
    backends: Vec<Backend>,
    tables: HashMap<(String, String), TableRoute>,
}

/// Why a statement went to the backend it went to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Region of the row selected by its integer handle.
    Point,
    /// The single leader of an affinity table / partition.
    Table,
    /// No locality information; the current backend is kept.
    Default,
}

/// Prometheus-style counters.
#[derive(Default)]
pub struct Counters {
    /// Routes by point key.
    pub route_point: AtomicU64,
    /// Routes by table leader.
    pub route_table: AtomicU64,
    /// Statements without locality information.
    pub route_default: AtomicU64,
    /// Backend switches to a connection that was already in sync.
    pub switch_warm: AtomicU64,
    /// Switches to an open connection that only needed pipelined catch-up
    /// statements (`DO LAST_INSERT_ID(n)`), no extra round trip.
    pub switch_delta: AtomicU64,
    /// Switches that re-synchronized an open connection
    /// (`SHOW SESSION_STATES`, then `COM_RESET_CONNECTION` + `SET SESSION_STATES`).
    pub switch_migrate: AtomicU64,
    /// Switches that had to open and authenticate a new connection.
    pub switch_dial: AtomicU64,
    /// Failed switches (the session stayed on its backend).
    pub switch_failed: AtomicU64,
    /// Switches skipped because the session holds unmigratable state.
    pub switch_pinned: AtomicU64,
    /// Switches skipped because the statement reads the previous statement's
    /// results (`ROW_COUNT()`, `FOUND_ROWS()`, warnings).
    pub switch_prev_dependent: AtomicU64,
    /// Duration of switches by kind (see `SWITCH_KINDS`).
    pub switch_seconds: [Histogram; 4],
    /// Round trips added on the critical path by switches.
    pub switch_round_trips: AtomicU64,
    /// Held `BEGIN`s sent in the same write as the next statement.
    pub begin_pipelined: AtomicU64,
    /// Held `BEGIN`s sent with their own round trip.
    pub begin_waited: AtomicU64,
    /// Prepared statements prepared on demand on a backend.
    pub lazy_prepare: AtomicU64,
    /// Session-state changes reported by tidb-one session tracking.
    pub state_changed: AtomicU64,
    /// `KILL` statements rewritten to the connection that runs the session.
    pub kill_rewritten: AtomicU64,
    /// Session-state verifications that matched.
    pub verify_ok: AtomicU64,
    /// Session-state verifications that did not match.
    pub verify_mismatch: AtomicU64,
    /// Open backend connections.
    pub backend_conns: AtomicI64,
    /// Transactions whose first statement was routed.
    pub txn_routed: AtomicU64,
    /// Client connections accepted.
    pub connections: AtomicU64,
    /// Sessions moved off a draining backend.
    pub drain_moved: AtomicU64,
}

/// Switch kinds, index into `Counters::switch_seconds`.
pub const SWITCH_KINDS: [&str; 4] = ["warm", "delta", "migrate", "dial"];

/// A fixed-bucket latency histogram.
#[derive(Default)]
pub struct Histogram {
    buckets: [AtomicU64; 12],
    sum_us: AtomicU64,
    count: AtomicU64,
}

const BUCKETS_US: [u64; 12] = [
    25,
    50,
    100,
    200,
    400,
    800,
    1_600,
    3_200,
    6_400,
    12_800,
    51_200,
    u64::MAX,
];

impl Histogram {
    /// Records one observation.
    pub fn observe(&self, d: Duration) {
        let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        let i = BUCKETS_US
            .iter()
            .position(|&b| us <= b)
            .unwrap_or(BUCKETS_US.len() - 1);
        self.buckets[i].fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, label: &str) {
        let mut acc = 0;
        for (i, b) in BUCKETS_US.iter().enumerate() {
            acc += self.buckets[i].load(Ordering::Relaxed);
            let le = if *b == u64::MAX {
                "+Inf".to_owned()
            } else {
                format!("{}", Duration::from_micros(*b).as_secs_f64())
            };
            let _ = writeln!(out, "{name}_bucket{{{label},le=\"{le}\"}} {acc}");
        }
        let sum = Duration::from_micros(self.sum_us.load(Ordering::Relaxed)).as_secs_f64();
        let _ = writeln!(out, "{name}_sum{{{label}}} {sum}");
        let _ = writeln!(
            out,
            "{name}_count{{{label}}} {}",
            self.count.load(Ordering::Relaxed)
        );
    }
}

/// Session behavior switches, from the command line.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Enable tidb-one session tracking on backend connections.
    pub session_track: bool,
    /// Send a held option-less `BEGIN` in the same write as the next statement.
    pub pipeline_begin: bool,
    /// After every switch, compare `SHOW SESSION_STATES` of the old and the new
    /// connection (testing only; adds round trips).
    pub verify_session_states: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            session_track: true,
            pipeline_begin: true,
            verify_session_states: false,
        }
    }
}

/// Shared routing table.
pub struct Router {
    seeds: Vec<String>,
    pd: Vec<String>,
    state: RwLock<State>,
    wanted: RwLock<HashSet<(String, String)>>,
    rr: AtomicUsize,
    /// Drain state by SQL address.
    drains: Mutex<HashMap<String, Drain>>,
    /// Number of draining SQL addresses, for a lock-free check per command.
    draining: AtomicUsize,
    /// Bumped whenever the set of draining backends changes; sessions watch it.
    drain_epoch: watch::Sender<u64>,
    /// Open backend connections by SQL address.
    conns: Mutex<HashMap<String, Arc<AtomicI64>>>,
    /// Counters exported on the status port.
    pub counters: Counters,
    /// Session behavior.
    pub options: SessionOptions,
}

impl Router {
    /// Creates a router that discovers backends through the `TiDB` status
    /// addresses `seeds` and Regions through PD.
    #[must_use]
    pub fn new(seeds: Vec<String>, pd: Vec<String>) -> Arc<Self> {
        Self::with_options(seeds, pd, SessionOptions::default())
    }

    /// Like `new`, with explicit session options.
    #[must_use]
    pub fn with_options(seeds: Vec<String>, pd: Vec<String>, options: SessionOptions) -> Arc<Self> {
        Arc::new(Self {
            seeds,
            pd,
            state: RwLock::new(State::default()),
            wanted: RwLock::new(HashSet::new()),
            rr: AtomicUsize::new(0),
            drains: Mutex::new(HashMap::new()),
            draining: AtomicUsize::new(0),
            drain_epoch: watch::channel(0).0,
            conns: Mutex::new(HashMap::new()),
            counters: Counters::default(),
            options,
        })
    }

    /// Current backends.
    pub fn backends(&self) -> Vec<Backend> {
        self.state
            .read()
            .map(|s| s.backends.clone())
            .unwrap_or_default()
    }

    /// Picks the backend of a new connection (round robin over the backends
    /// that are not draining; any backend if all are).
    pub fn pick_default(&self) -> Option<String> {
        let mut backends = self.backends();
        if backends.is_empty() {
            return None;
        }
        if self.any_draining() {
            let open: Vec<Backend> = backends
                .iter()
                .filter(|b| !self.is_draining(&b.sql_addr))
                .cloned()
                .collect();
            if !open.is_empty() {
                backends = open;
            }
        }
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(backends[i].sql_addr.clone())
    }

    /// Like `pick_default`, but never a draining backend.
    pub fn pick_open(&self) -> Option<String> {
        self.pick_default().filter(|a| !self.is_draining(a))
    }

    /// Whether any backend is draining (one atomic load).
    pub fn any_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire) > 0
    }

    /// Whether sessions must leave the backend at `sql_addr`: it is draining,
    /// or it is no longer in `/info/all`.
    pub fn is_draining(&self, sql_addr: &str) -> bool {
        if self.any_draining()
            && self
                .drains
                .lock()
                .is_ok_and(|d| d.get(sql_addr).is_some_and(Drain::active))
        {
            return true;
        }
        self.state.read().is_ok_and(|s| {
            !s.backends.is_empty() && !s.backends.iter().any(|b| b.sql_addr == sql_addr)
        })
    }

    /// Receives a new value whenever the set of draining backends changes.
    pub fn subscribe_drain(&self) -> watch::Receiver<u64> {
        self.drain_epoch.subscribe()
    }

    fn update_drain(&self, sql_addr: &str, f: impl FnOnce(&mut Drain)) {
        let Ok(mut drains) = self.drains.lock() else {
            return;
        };
        let d = drains.entry(sql_addr.to_owned()).or_default();
        let was = d.active();
        f(d);
        let now = d.active();
        if now && !was {
            d.since = Some(Instant::now());
        } else if !now {
            d.since = None;
        }
        if !now && d.failures == 0 {
            drains.remove(sql_addr);
        }
        let n = drains.values().filter(|d| d.active()).count();
        drop(drains);
        self.draining.store(n, Ordering::Release);
        if now != was {
            eprintln!(
                "locality-router: backend {sql_addr} {}",
                if now { "draining" } else { "open" }
            );
            self.drain_epoch.send_modify(|e| *e += 1);
        }
    }

    /// Starts draining `sql_addr` on an operator's request.
    pub fn drain(&self, sql_addr: &str) {
        self.update_drain(sql_addr, |d| d.api = true);
    }

    /// Ends an operator's drain of `sql_addr`. A backend whose probe fails
    /// keeps draining until it is healthy again.
    pub fn resume(&self, sql_addr: &str) {
        self.update_drain(sql_addr, |d| d.api = false);
    }

    /// Counter of open connections to `sql_addr`, shared by the sessions.
    pub fn conn_counter(&self, sql_addr: &str) -> Arc<AtomicI64> {
        self.conns.lock().map_or_else(
            |_| Arc::new(AtomicI64::new(0)),
            |mut c| Arc::clone(c.entry(sql_addr.to_owned()).or_default()),
        )
    }

    fn conn_count(&self, sql_addr: &str) -> i64 {
        self.conns.lock().map_or(0, |c| {
            c.get(sql_addr).map_or(0, |n| n.load(Ordering::Relaxed))
        })
    }

    /// Backends with their drain state and open connections, for
    /// `GET /api/backends`. Draining addresses that left `/info/all` but
    /// still have connections are included.
    pub fn backends_json(&self) -> Json {
        let backends = self.backends();
        let drains = self.drains.lock().map(|d| d.clone()).unwrap_or_default();
        let mut addrs: Vec<String> = backends.iter().map(|b| b.sql_addr.clone()).collect();
        for a in drains.keys() {
            if !addrs.contains(a) {
                addrs.push(a.clone());
            }
        }
        if let Ok(c) = self.conns.lock() {
            for (a, n) in c.iter() {
                if n.load(Ordering::Relaxed) > 0 && !addrs.contains(a) {
                    addrs.push(a.clone());
                }
            }
        }
        addrs.sort();
        let list: Vec<Json> = addrs
            .iter()
            .map(|a| {
                let b = backends.iter().find(|b| &b.sql_addr == a);
                let d = drains.get(a).cloned().unwrap_or_default();
                json!({
                    "addr": a,
                    "status_addr": b.map(|b| b.status_addr.clone()),
                    "store_id": b.map_or(0, |b| b.store_id),
                    "registered": b.is_some(),
                    "draining": self.is_draining(a),
                    "drain_requested": d.api,
                    "healthy": !d.unhealthy,
                    "draining_seconds": d.since.map(|t| t.elapsed().as_secs_f64()),
                    "connections": self.conn_count(a),
                })
            })
            .collect();
        Json::Array(list)
    }

    /// Probes `/status` of every backend once and updates their health.
    async fn probe_backends(&self) {
        let mut probes = tokio::task::JoinSet::new();
        for b in self.backends() {
            probes.spawn(async move {
                let ok = matches!(
                    timeout(PROBE_TIMEOUT, http_get(&b.status_addr, "/status")).await,
                    Ok(Ok(_))
                );
                (b.sql_addr, ok)
            });
        }
        while let Some(Ok((addr, ok))) = probes.join_next().await {
            self.update_drain(&addr, |d| {
                if ok {
                    d.failures = 0;
                    d.unhealthy = false;
                } else {
                    d.failures += 1;
                    if d.failures >= PROBE_FAILURES {
                        d.unhealthy = true;
                    }
                }
            });
        }
    }

    /// Finds the backend next to the leader of the row `handle` of `db.table`,
    /// or of the whole table when it has a single leader.
    pub fn locate(
        &self,
        db: &str,
        table: &str,
        point: Option<(&str, i64)>,
    ) -> (Option<String>, Reason) {
        let key = (db.to_owned(), table.to_owned());
        let Ok(state) = self.state.read() else {
            return (None, Reason::Default);
        };
        let Some(route) = state.tables.get(&key) else {
            drop(state);
            if let Ok(mut w) = self.wanted.write() {
                w.insert(key);
            }
            self.counters.route_default.fetch_add(1, Ordering::Relaxed);
            return (None, Reason::Default);
        };
        let mut store = 0;
        let mut reason = Reason::Default;
        if let Some((col, handle)) = point
            && route.handle_col.as_deref() == Some(col)
        {
            let physical = if route.physicals.len() > 1 {
                if route.hash_partition_col.as_deref() == Some(col) {
                    let n = i64::try_from(route.physicals.len()).unwrap_or(i64::MAX);
                    route
                        .physicals
                        .get(usize::try_from((handle % n).abs()).unwrap_or(0))
                } else {
                    None
                }
            } else {
                route.physicals.first()
            };
            if let Some(p) = physical {
                let k = keycodec::encode_bytes(&keycodec::record_key(p.id, handle));
                if let Some(r) = p
                    .regions
                    .iter()
                    .find(|r| r.start <= k && (r.end.is_empty() || k < r.end))
                {
                    store = r.leader_store;
                    reason = Reason::Point;
                }
            }
        }
        if store == 0 && route.table_leader != 0 {
            store = route.table_leader;
            reason = Reason::Table;
        }
        let addr = (store != 0)
            .then(|| {
                state
                    .backends
                    .iter()
                    .find(|b| b.store_id == store)
                    .map(|b| b.sql_addr.clone())
            })
            .flatten();
        drop(state);
        // A draining backend gets no new transactions; the leader is about to
        // move anyway (TiUP evicts leaders before it drains).
        let addr = addr.filter(|a| !self.is_draining(a));
        let counter = match (addr.is_some(), reason) {
            (true, Reason::Point) => &self.counters.route_point,
            (true, Reason::Table) => &self.counters.route_table,
            _ => &self.counters.route_default,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if addr.is_none() {
            reason = Reason::Default;
        }
        (addr, reason)
    }

    /// Refreshes backends and the Regions of every known table forever.
    pub async fn refresh_loop(self: Arc<Self>, every: Duration) {
        loop {
            if let Err(e) = self.refresh_backends().await {
                eprintln!("locality-router: refresh backends: {e}");
            }
            self.probe_backends().await;
            let mut keys: Vec<(String, String)> = self
                .state
                .read()
                .map(|s| s.tables.keys().cloned().collect())
                .unwrap_or_default();
            if let Ok(mut w) = self.wanted.write() {
                keys.extend(w.drain());
            }
            keys.sort();
            keys.dedup();
            for (db, table) in keys {
                if let Err(e) = self.refresh_table(&db, &table).await {
                    eprintln!("locality-router: refresh {db}.{table}: {e}");
                }
            }
            tokio::time::sleep(every).await;
        }
    }

    async fn status_get(&self, path: &str) -> io::Result<Json> {
        let mut last = io::Error::other("no TiDB status address");
        let mut addrs: Vec<String> = self.backends().into_iter().map(|b| b.status_addr).collect();
        addrs.extend(self.seeds.iter().cloned());
        for a in addrs {
            match http_get_json(&a, path).await {
                Ok(v) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn pd_get(&self, path: &str) -> io::Result<Json> {
        let mut last = io::Error::other("no PD address");
        for a in &self.pd {
            match http_get_json(a, path).await {
                Ok(v) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn refresh_backends(&self) -> io::Result<()> {
        let info = self.status_get("/info/all").await?;
        let mut backends = Vec::new();
        if let Some(all) = info.get("all_servers_info").and_then(Json::as_object) {
            for s in all.values() {
                let ip = s.get("ip").and_then(Json::as_str).unwrap_or("127.0.0.1");
                let port = s
                    .get("listening_port")
                    .and_then(Json::as_u64)
                    .unwrap_or(4000);
                let status = s.get("status_port").and_then(Json::as_u64).unwrap_or(10080);
                let store_id = s
                    .get("labels")
                    .and_then(|l| l.get(STORE_ID_LABEL))
                    .and_then(Json::as_str)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                backends.push(Backend {
                    sql_addr: format!("{ip}:{port}"),
                    status_addr: format!("{ip}:{status}"),
                    store_id,
                });
            }
        }
        backends.sort_by(|a, b| a.sql_addr.cmp(&b.sql_addr));
        if backends.is_empty() {
            return Err(io::Error::other("/info/all returned no servers"));
        }
        if let Ok(mut s) = self.state.write() {
            s.backends = backends;
        }
        Ok(())
    }

    async fn refresh_table(&self, db: &str, table: &str) -> io::Result<()> {
        let key = (db.to_owned(), table.to_owned());
        let cached = self
            .state
            .read()
            .ok()
            .and_then(|s| s.tables.get(&key).cloned());
        let (handle_col, hash_col, ids, meta_at) = match cached {
            Some(r) if r.meta_at.elapsed() < TABLE_META_TTL => (
                r.handle_col,
                r.hash_partition_col,
                r.physicals.iter().map(|p| p.id).collect::<Vec<_>>(),
                r.meta_at,
            ),
            _ => {
                let meta = self.status_get(&format!("/schema/{db}/{table}")).await?;
                let (h, p, ids) = parse_table_meta(&meta)?;
                (h, p, ids, Instant::now())
            }
        };
        let mut physicals = Vec::with_capacity(ids.len());
        for id in ids {
            let start = keycodec::url_escape(&keycodec::encode_bytes(&keycodec::table_prefix(id)));
            let end = keycodec::url_escape(&keycodec::encode_bytes(&keycodec::table_end(id)));
            let v = self
                .pd_get(&format!(
                    "/pd/api/v1/regions/key?key={start}&end_key={end}&limit=4096"
                ))
                .await?;
            physicals.push(Physical {
                id,
                regions: parse_regions(&v),
            });
        }
        let mut leaders = physicals
            .iter()
            .flat_map(|p| p.regions.iter().map(|r| r.leader_store));
        let first = leaders.next().unwrap_or(0);
        let table_leader = if first != 0 && leaders.all(|l| l == first) {
            first
        } else {
            0
        };
        let route = TableRoute {
            handle_col,
            hash_partition_col: hash_col,
            physicals,
            table_leader,
            meta_at,
        };
        if let Ok(mut s) = self.state.write() {
            s.tables.insert(key, route);
        }
        Ok(())
    }

    /// Renders the counters in Prometheus text format.
    pub fn render_metrics(&self) -> String {
        let c = &self.counters;
        let mut s = String::new();
        let mut put = |name: &str, label: &str, v: &AtomicU64| {
            let _ = writeln!(
                s,
                "tiproxy_locality_{name}{label} {}",
                v.load(Ordering::Relaxed)
            );
        };
        put("route_total", "{reason=\"point\"}", &c.route_point);
        put("route_total", "{reason=\"table\"}", &c.route_table);
        put("route_total", "{reason=\"default\"}", &c.route_default);
        put("switch_total", "{kind=\"warm\"}", &c.switch_warm);
        put("switch_total", "{kind=\"delta\"}", &c.switch_delta);
        put("switch_total", "{kind=\"migrate\"}", &c.switch_migrate);
        put("switch_total", "{kind=\"dial\"}", &c.switch_dial);
        put("switch_total", "{kind=\"failed\"}", &c.switch_failed);
        put(
            "switch_skipped_total",
            "{reason=\"unmigratable\"}",
            &c.switch_pinned,
        );
        put(
            "switch_skipped_total",
            "{reason=\"prev_dependent\"}",
            &c.switch_prev_dependent,
        );
        put("switch_round_trips_total", "", &c.switch_round_trips);
        put("begin_total", "{mode=\"pipelined\"}", &c.begin_pipelined);
        put("begin_total", "{mode=\"waited\"}", &c.begin_waited);
        put("lazy_prepare_total", "", &c.lazy_prepare);
        put("state_changed_total", "", &c.state_changed);
        put("kill_rewritten_total", "", &c.kill_rewritten);
        put("verify_total", "{result=\"ok\"}", &c.verify_ok);
        put("verify_total", "{result=\"mismatch\"}", &c.verify_mismatch);
        put("txn_routed_total", "", &c.txn_routed);
        put("connections_total", "", &c.connections);
        put("drain_moved_total", "", &c.drain_moved);
        let _ = writeln!(
            s,
            "tiproxy_locality_backend_conns {}",
            c.backend_conns.load(Ordering::Relaxed)
        );
        for (i, kind) in SWITCH_KINDS.iter().enumerate() {
            c.switch_seconds[i].render(
                &mut s,
                "tiproxy_locality_switch_seconds",
                &format!("kind=\"{kind}\""),
            );
        }
        if let Ok(st) = self.state.read() {
            for b in &st.backends {
                let _ = writeln!(
                    s,
                    "tiproxy_locality_backend{{addr=\"{}\",store_id=\"{}\"}} 1",
                    b.sql_addr, b.store_id
                );
            }
        }
        if let Ok(c) = self.conns.lock() {
            for (a, n) in c.iter() {
                let _ = writeln!(
                    s,
                    "tiproxy_locality_backend_connections{{addr=\"{a}\"}} {}",
                    n.load(Ordering::Relaxed)
                );
            }
        }
        if let Ok(d) = self.drains.lock() {
            for (a, d) in d.iter().filter(|(_, d)| d.active()) {
                let _ = writeln!(
                    s,
                    "tiproxy_locality_backend_draining{{addr=\"{a}\",requested=\"{}\"}} 1",
                    d.api
                );
            }
        }
        if let Ok(st) = self.state.read() {
            for ((db, t), r) in &st.tables {
                let _ = writeln!(
                    s,
                    "tiproxy_locality_table_leader{{db=\"{db}\",table=\"{t}\"}} {}",
                    r.table_leader
                );
            }
        }
        s
    }
}

type TableMeta = (Option<String>, Option<String>, Vec<i64>);

fn parse_table_meta(meta: &Json) -> io::Result<TableMeta> {
    let id = meta
        .get("id")
        .and_then(Json::as_i64)
        .ok_or_else(|| io::Error::other("table id missing"))?;
    let mut handle = None;
    if meta.get("pk_is_handle").and_then(Json::as_bool) == Some(true)
        && let Some(cols) = meta.get("cols").and_then(Json::as_array)
    {
        for c in cols {
            let flag = c
                .get("type")
                .and_then(|t| t.get("Flag"))
                .and_then(Json::as_u64)
                .unwrap_or(0);
            if flag & 2 != 0 {
                handle = c
                    .get("name")
                    .and_then(|n| n.get("L"))
                    .and_then(Json::as_str)
                    .map(str::to_owned);
            }
        }
    }
    let mut ids = vec![id];
    let mut hash_col = None;
    if let Some(p) = meta.get("partition").filter(|p| !p.is_null()) {
        let defs: Vec<i64> = p
            .get("definitions")
            .and_then(Json::as_array)
            .map(|d| {
                d.iter()
                    .filter_map(|x| x.get("id").and_then(Json::as_i64))
                    .collect()
            })
            .unwrap_or_default();
        if !defs.is_empty() {
            ids = defs;
        }
        // model.PartitionTypeHash == 2; the expression is a bare column.
        if p.get("type").and_then(Json::as_u64) == Some(2) {
            hash_col = p
                .get("expr")
                .and_then(Json::as_str)
                .map(|e| e.trim_matches('`').to_lowercase())
                .filter(|e| e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        }
    }
    Ok((handle, hash_col, ids))
}

fn parse_regions(v: &Json) -> Vec<Region> {
    let mut out = Vec::new();
    if let Some(regions) = v.get("regions").and_then(Json::as_array) {
        for r in regions {
            let start = r
                .get("start_key")
                .and_then(Json::as_str)
                .and_then(keycodec::from_hex)
                .unwrap_or_default();
            let end = r
                .get("end_key")
                .and_then(Json::as_str)
                .and_then(keycodec::from_hex)
                .unwrap_or_default();
            let leader = r
                .get("leader")
                .and_then(|l| l.get("store_id"))
                .and_then(Json::as_u64)
                .unwrap_or(0);
            out.push(Region {
                start,
                end,
                leader_store: leader,
            });
        }
    }
    out.sort_by(|a, b| a.start.cmp(&b.start));
    out
}

/// Minimal HTTP/1.1 GET returning a JSON body (handles chunked encoding).
async fn http_get_json(addr: &str, path: &str) -> io::Result<Json> {
    let body = timeout(HTTP_TIMEOUT, http_get(addr, path))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("GET {addr}{path} timed out"),
            )
        })??;
    serde_json::from_slice(&body).map_err(|e| io::Error::other(format!("GET {addr}{path}: {e}")))
}

async fn http_get(addr: &str, path: &str) -> io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await?;
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("bad HTTP response"))?;
    let head = String::from_utf8_lossy(&buf[..split]).to_lowercase();
    let body = &buf[split + 4..];
    let code = head.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(io::Error::other(format!("GET {addr}{path}: HTTP {code}")));
    }
    if head.contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut rest = body;
        loop {
            let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
                break;
            };
            let size_txt = String::from_utf8_lossy(&rest[..eol]);
            let size = usize::from_str_radix(size_txt.split(';').next().unwrap_or("0").trim(), 16)
                .unwrap_or(0);
            rest = &rest[eol + 2..];
            if size == 0 || rest.len() < size {
                break;
            }
            out.extend_from_slice(&rest[..size]);
            rest = rest.get(size + 2..).unwrap_or(&[]);
        }
        Ok(out)
    } else {
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_meta_parsing() {
        let meta: Json = serde_json::from_str(
            r#"{"id":112,"pk_is_handle":true,"cols":[{"name":{"O":"id","L":"id"},"type":{"Tp":3,"Flag":4099}},{"name":{"O":"k","L":"k"},"type":{"Tp":3,"Flag":1}}],"partition":null}"#,
        )
        .unwrap_or_default();
        let (h, p, ids) = parse_table_meta(&meta).unwrap_or_default();
        assert_eq!(h.as_deref(), Some("id"));
        assert_eq!(p, None);
        assert_eq!(ids, vec![112]);
    }

    #[test]
    fn locate_by_point_and_table() {
        let r = Router::new(vec![], vec![]);
        let split = keycodec::encode_bytes(&keycodec::record_key(10, 1000));
        if let Ok(mut s) = r.state.write() {
            s.backends = vec![
                Backend {
                    sql_addr: "a:1".into(),
                    status_addr: String::new(),
                    store_id: 1,
                },
                Backend {
                    sql_addr: "b:1".into(),
                    status_addr: String::new(),
                    store_id: 2,
                },
            ];
            s.tables.insert(
                ("test".into(), "t".into()),
                TableRoute {
                    handle_col: Some("id".into()),
                    hash_partition_col: None,
                    physicals: vec![Physical {
                        id: 10,
                        regions: vec![
                            Region {
                                start: vec![],
                                end: split.clone(),
                                leader_store: 1,
                            },
                            Region {
                                start: split,
                                end: vec![],
                                leader_store: 2,
                            },
                        ],
                    }],
                    table_leader: 0,
                    meta_at: Instant::now(),
                },
            );
        }
        assert_eq!(
            r.locate("test", "t", Some(("id", 5))),
            (Some("a:1".into()), Reason::Point)
        );
        assert_eq!(
            r.locate("test", "t", Some(("id", 5000))),
            (Some("b:1".into()), Reason::Point)
        );
        assert_eq!(r.locate("test", "t", None), (None, Reason::Default));
        assert_eq!(r.locate("test", "missing", None), (None, Reason::Default));

        // A draining backend gets no transactions; its rows fall back to the
        // current backend.
        r.drain("b:1");
        assert_eq!(
            r.locate("test", "t", Some(("id", 5000))),
            (None, Reason::Default)
        );
        r.resume("b:1");
        assert_eq!(
            r.locate("test", "t", Some(("id", 5000))),
            (Some("b:1".into()), Reason::Point)
        );
    }

    fn two_backends() -> Arc<Router> {
        let r = Router::new(vec![], vec![]);
        if let Ok(mut s) = r.state.write() {
            s.backends = ["a:1", "b:1"]
                .iter()
                .map(|a| Backend {
                    sql_addr: (*a).into(),
                    status_addr: String::new(),
                    store_id: 0,
                })
                .collect();
        }
        r
    }

    #[test]
    fn drain_and_resume() {
        let r = two_backends();
        let mut rx = r.subscribe_drain();
        assert!(!r.any_draining());
        r.drain("a:1");
        assert!(rx.has_changed().unwrap_or(false));
        rx.mark_unchanged();
        assert!(r.any_draining() && r.is_draining("a:1") && !r.is_draining("b:1"));
        for _ in 0..4 {
            assert_eq!(r.pick_open().as_deref(), Some("b:1"));
        }
        // Draining again changes nothing.
        r.drain("a:1");
        assert!(!rx.has_changed().unwrap_or(true));
        // With every backend draining, new sessions still get one, but no
        // session moves to a draining backend.
        r.drain("b:1");
        assert!(r.pick_default().is_some());
        assert_eq!(r.pick_open(), None);
        r.resume("a:1");
        r.resume("b:1");
        assert!(!r.any_draining() && !r.is_draining("a:1"));
        assert!(rx.has_changed().unwrap_or(false));
        // An address that left /info/all counts as draining.
        assert!(r.is_draining("gone:1"));
    }

    #[test]
    fn failed_probes_drain() {
        let r = two_backends();
        let fail = |d: &mut Drain| {
            d.failures += 1;
            if d.failures >= PROBE_FAILURES {
                d.unhealthy = true;
            }
        };
        r.update_drain("a:1", fail);
        assert!(!r.is_draining("a:1"), "one failed probe is not enough");
        r.update_drain("a:1", fail);
        assert!(r.is_draining("a:1"));
        // An operator's resume does not open an unhealthy backend.
        r.resume("a:1");
        assert!(r.is_draining("a:1"));
        r.update_drain("a:1", |d| {
            d.failures = 0;
            d.unhealthy = false;
        });
        assert!(!r.is_draining("a:1"));
    }

    #[test]
    fn backends_json_counts_connections() {
        let r = two_backends();
        let c = r.conn_counter("a:1");
        c.fetch_add(3, Ordering::Relaxed);
        r.drain("a:1");
        let j = r.backends_json();
        let a = &j[0];
        assert_eq!(a["addr"], "a:1");
        assert_eq!(a["connections"], 3);
        assert_eq!(a["draining"], true);
        assert_eq!(a["drain_requested"], true);
        assert_eq!(j[1]["connections"], 0);
    }
}
