// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Routing table: which tidb-one backend runs next to the Region leader of a
//! table or row.
//!
//! Sources, refreshed in the background:
//! * TiDB `/info/all`: SQL backends and their `tidb_one_store_id` label (the
//!   TiKV store embedded in the same process);
//! * TiDB `/schema/{db}/{table}`: table ID, integer-handle column, hash
//!   partitions;
//! * PD `/pd/api/v1/regions/key`: Regions and leaders of each physical table's
//!   key range.
//!
//! Lookups only read cached state; a miss schedules a fetch and the statement
//! falls back to the current backend.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde_json::Value as Json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::keycodec;

/// Label that carries the ID of the TiKV store embedded in a tidb-one server.
pub const STORE_ID_LABEL: &str = "tidb_one_store_id";

const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const TABLE_META_TTL: Duration = Duration::from_secs(30);

/// One SQL backend.
#[derive(Debug, Clone)]
pub struct Backend {
    /// MySQL protocol address.
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
    /// Switches that had to migrate the session to a new connection.
    pub switch_migrate: AtomicU64,
    /// Failed switches (the session stayed on its backend).
    pub switch_failed: AtomicU64,
    /// Transactions whose first statement was routed.
    pub txn_routed: AtomicU64,
    /// Client connections accepted.
    pub connections: AtomicU64,
}

/// Shared routing table.
pub struct Router {
    seeds: Vec<String>,
    pd: Vec<String>,
    state: RwLock<State>,
    wanted: RwLock<HashSet<(String, String)>>,
    rr: AtomicUsize,
    /// Counters exported on the status port.
    pub counters: Counters,
}

impl Router {
    /// Creates a router that discovers backends through the TiDB status
    /// addresses `seeds` and Regions through PD.
    pub fn new(seeds: Vec<String>, pd: Vec<String>) -> Arc<Self> {
        Arc::new(Self {
            seeds,
            pd,
            state: RwLock::new(State::default()),
            wanted: RwLock::new(HashSet::new()),
            rr: AtomicUsize::new(0),
            counters: Counters::default(),
        })
    }

    /// Current backends.
    pub fn backends(&self) -> Vec<Backend> {
        self.state.read().map(|s| s.backends.clone()).unwrap_or_default()
    }

    /// Picks the backend of a new connection (round robin).
    pub fn pick_default(&self) -> Option<String> {
        let backends = self.backends();
        if backends.is_empty() {
            return None;
        }
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(backends[i].sql_addr.clone())
    }

    /// Finds the backend next to the leader of the row `handle` of `db.table`,
    /// or of the whole table when it has a single leader.
    pub fn locate(&self, db: &str, table: &str, point: Option<(&str, i64)>) -> (Option<String>, Reason) {
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
                    let n = route.physicals.len() as i64;
                    route.physicals.get(usize::try_from((handle % n).abs()).unwrap_or(0))
                } else {
                    None
                }
            } else {
                route.physicals.first()
            };
            if let Some(p) = physical {
                let k = keycodec::encode_bytes(&keycodec::record_key(p.id, handle));
                if let Some(r) = p.regions.iter().find(|r| r.start <= k && (r.end.is_empty() || k < r.end)) {
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
            .then(|| state.backends.iter().find(|b| b.store_id == store).map(|b| b.sql_addr.clone()))
            .flatten();
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
                let port = s.get("listening_port").and_then(Json::as_u64).unwrap_or(4000);
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
        let cached = self.state.read().ok().and_then(|s| s.tables.get(&key).cloned());
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
                .pd_get(&format!("/pd/api/v1/regions/key?key={start}&end_key={end}&limit=4096"))
                .await?;
            physicals.push(Physical { id, regions: parse_regions(&v) });
        }
        let mut leaders = physicals.iter().flat_map(|p| p.regions.iter().map(|r| r.leader_store));
        let first = leaders.next().unwrap_or(0);
        let table_leader = if first != 0 && leaders.all(|l| l == first) { first } else { 0 };
        let route = TableRoute { handle_col, hash_partition_col: hash_col, physicals, table_leader, meta_at };
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
            s.push_str(&format!("tiproxy_locality_{name}{label} {}\n", v.load(Ordering::Relaxed)));
        };
        put("route_total", "{reason=\"point\"}", &c.route_point);
        put("route_total", "{reason=\"table\"}", &c.route_table);
        put("route_total", "{reason=\"default\"}", &c.route_default);
        put("switch_total", "{kind=\"warm\"}", &c.switch_warm);
        put("switch_total", "{kind=\"migrate\"}", &c.switch_migrate);
        put("switch_total", "{kind=\"failed\"}", &c.switch_failed);
        put("txn_routed_total", "", &c.txn_routed);
        put("connections_total", "", &c.connections);
        if let Ok(st) = self.state.read() {
            for b in &st.backends {
                s.push_str(&format!(
                    "tiproxy_locality_backend{{addr=\"{}\",store_id=\"{}\"}} 1\n",
                    b.sql_addr, b.store_id
                ));
            }
            for ((db, t), r) in &st.tables {
                s.push_str(&format!(
                    "tiproxy_locality_table_leader{{db=\"{db}\",table=\"{t}\"}} {}\n",
                    r.table_leader
                ));
            }
        }
        s
    }
}

type TableMeta = (Option<String>, Option<String>, Vec<i64>);

fn parse_table_meta(meta: &Json) -> io::Result<TableMeta> {
    let id = meta.get("id").and_then(Json::as_i64).ok_or_else(|| io::Error::other("table id missing"))?;
    let mut handle = None;
    if meta.get("pk_is_handle").and_then(Json::as_bool) == Some(true)
        && let Some(cols) = meta.get("cols").and_then(Json::as_array)
    {
        for c in cols {
            let flag = c.get("type").and_then(|t| t.get("Flag")).and_then(Json::as_u64).unwrap_or(0);
            if flag & 2 != 0 {
                handle = c.get("name").and_then(|n| n.get("L")).and_then(Json::as_str).map(str::to_owned);
            }
        }
    }
    let mut ids = vec![id];
    let mut hash_col = None;
    if let Some(p) = meta.get("partition").filter(|p| !p.is_null()) {
        let defs: Vec<i64> = p
            .get("definitions")
            .and_then(Json::as_array)
            .map(|d| d.iter().filter_map(|x| x.get("id").and_then(Json::as_i64)).collect())
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
            let start = r.get("start_key").and_then(Json::as_str).and_then(keycodec::from_hex).unwrap_or_default();
            let end = r.get("end_key").and_then(Json::as_str).and_then(keycodec::from_hex).unwrap_or_default();
            let leader = r.get("leader").and_then(|l| l.get("store_id")).and_then(Json::as_u64).unwrap_or(0);
            out.push(Region { start, end, leader_store: leader });
        }
    }
    out.sort_by(|a, b| a.start.cmp(&b.start));
    out
}

/// Minimal HTTP/1.1 GET returning a JSON body (handles chunked encoding).
async fn http_get_json(addr: &str, path: &str) -> io::Result<Json> {
    let body = timeout(HTTP_TIMEOUT, http_get(addr, path))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("GET {addr}{path} timed out")))??;
    serde_json::from_slice(&body).map_err(|e| io::Error::other(format!("GET {addr}{path}: {e}")))
}

async fn http_get(addr: &str, path: &str) -> io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
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
            let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else { break };
            let size_txt = String::from_utf8_lossy(&rest[..eol]);
            let size = usize::from_str_radix(size_txt.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
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
                Backend { sql_addr: "a:1".into(), status_addr: String::new(), store_id: 1 },
                Backend { sql_addr: "b:1".into(), status_addr: String::new(), store_id: 2 },
            ];
            s.tables.insert(
                ("test".into(), "t".into()),
                TableRoute {
                    handle_col: Some("id".into()),
                    hash_partition_col: None,
                    physicals: vec![Physical {
                        id: 10,
                        regions: vec![
                            Region { start: vec![], end: split.clone(), leader_store: 1 },
                            Region { start: split, end: vec![], leader_store: 2 },
                        ],
                    }],
                    table_leader: 0,
                    meta_at: Instant::now(),
                },
            );
        }
        assert_eq!(r.locate("test", "t", Some(("id", 5))), (Some("a:1".into()), Reason::Point));
        assert_eq!(r.locate("test", "t", Some(("id", 5000))), (Some("b:1".into()), Reason::Point));
        assert_eq!(r.locate("test", "t", None), (None, Reason::Default));
        assert_eq!(r.locate("test", "missing", None), (None, Reason::Default));
    }
}
