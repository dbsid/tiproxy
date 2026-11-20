// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Transaction-level locality routing for tidb-one.
//!
//! In tidb-one every SQL backend is a `TiDB` process that embeds a `TiKV` store.
//! A transaction whose keys are led by that store runs entirely in process
//! (local KV calls, and 1PC when the keys share one Region, as with table
//! affinity). This dataplane mode sends each transaction to the backend that
//! embeds the Region leader of the first table its first statement touches:
//!
//! 1. point `SELECT`/`UPDATE`/`DELETE`/`INSERT` on the integer primary key:
//!    the leader of the row's Region;
//! 2. otherwise, a table or hash partition whose Regions share one leader
//!    (table / partition affinity): that leader;
//! 3. otherwise the session stays where it is; new sessions are balanced
//!    round robin.
//!
//! Run it with `tiproxy-rs locality-router --listen ADDR --status ADDR
//! --tidb-status HOST:PORT[,..] --pd HOST:PORT[,..]`.

pub mod classify;
pub mod keycodec;
pub mod kill;
pub mod router;
pub mod session;
pub mod wire;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub use router::{Router, SessionOptions};

/// Command-line options of the locality router.
#[derive(Debug, Clone)]
pub struct Options {
    /// `MySQL` listen address.
    pub listen: String,
    /// HTTP status/metrics listen address.
    pub status: Option<String>,
    /// `TiDB` status addresses used to discover backends.
    pub tidb_status: Vec<String>,
    /// PD client addresses.
    pub pd: Vec<String>,
    /// Routing table refresh interval.
    pub refresh: Duration,
    /// Session behavior.
    pub session: SessionOptions,
}

/// Parses `--flag value` pairs.
///
/// # Errors
///
/// An unknown flag, a missing or invalid value, or missing required flags.
pub fn parse_options<I: Iterator<Item = String>>(mut args: I) -> Result<Options, String> {
    let mut o = Options {
        listen: "0.0.0.0:6000".to_owned(),
        status: None,
        tidb_status: Vec::new(),
        pd: Vec::new(),
        refresh: Duration::from_secs(1),
        session: SessionOptions::default(),
    };
    let list = |v: String| {
        v.split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => o.listen = value()?,
            "--status" => o.status = Some(value()?),
            "--tidb-status" => o.tidb_status = list(value()?),
            "--pd" => o.pd = list(value()?),
            "--refresh-ms" => {
                let ms: u64 = value()?.parse().map_err(|e| format!("--refresh-ms: {e}"))?;
                o.refresh = Duration::from_millis(ms.max(100));
            }
            "--no-session-track" => o.session.session_track = false,
            "--no-pipeline-begin" => o.session.pipeline_begin = false,
            "--verify-session-states" => o.session.verify_session_states = true,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    if o.tidb_status.is_empty() || o.pd.is_empty() {
        return Err("--tidb-status and --pd are required".to_owned());
    }
    Ok(o)
}

/// Runs the router until the process exits.
///
/// # Errors
///
/// Failing to bind the listen or status address, or to accept connections.
pub async fn run(o: Options) -> io::Result<()> {
    let router = Router::with_options(o.tidb_status.clone(), o.pd.clone(), o.session.clone());
    tokio::spawn(Arc::clone(&router).refresh_loop(o.refresh));
    if let Some(addr) = &o.status {
        let listener = TcpListener::bind(addr).await?;
        tokio::spawn(serve_status(listener, Arc::clone(&router)));
    }
    // Wait for the first backend list before accepting clients.
    for _ in 0..300 {
        if !router.backends().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let listener = TcpListener::bind(&o.listen).await?;
    eprintln!(
        "locality-router: listening on {}, backends {:?}",
        o.listen,
        router.backends()
    );
    loop {
        let (client, peer) = listener.accept().await?;
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            let Some(backend) = router.pick_default() else {
                eprintln!("locality-router: no backend for {peer}");
                return;
            };
            match session::Session::handshake(Arc::clone(&router), client, backend).await {
                Ok(Some(s)) => {
                    if let Err(e) = s.run().await
                        && e.kind() != io::ErrorKind::UnexpectedEof
                        && e.kind() != io::ErrorKind::ConnectionReset
                    {
                        eprintln!("locality-router: session {peer}: {e}");
                    }
                }
                Ok(None) => {}
                Err(e) => eprintln!("locality-router: handshake {peer}: {e}"),
            }
        });
    }
}

async fn serve_status(listener: TcpListener, router: Arc<Router>) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            continue;
        };
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let (code, ctype, body) = status_response(&router, &req);
            let resp = format!(
                "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });
    }
}

const TEXT: &str = "text/plain; version=0.0.4";
const JSON: &str = "application/json";

/// Answers one request on the status port.
///
/// * `GET /metrics`: Prometheus metrics.
/// * `GET /api/backends`: backends with drain state and open connections.
/// * `POST /api/backends/drain?addr=HOST:PORT`: stop sending new sessions and
///   transactions to the `TiDB` SQL address and move sessions off it.
/// * `POST /api/backends/resume?addr=HOST:PORT`: undo a drain.
///
/// The port has no authentication, like the `TiDB` status port; bind it to a
/// management network.
fn status_response(router: &Router, req: &str) -> (&'static str, &'static str, String) {
    let line = req.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let addr = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("addr="))
        .map(|a| a.replace("%3A", ":").replace("%3a", ":"))
        .filter(|a| !a.is_empty());
    match (method, path) {
        ("GET", "/metrics") => ("200 OK", TEXT, router.render_metrics()),
        ("GET", "/api/backends") => ("200 OK", JSON, router.backends_json().to_string()),
        ("POST" | "PUT", "/api/backends/drain" | "/api/backends/resume") => {
            let Some(addr) = addr else {
                return (
                    "400 Bad Request",
                    TEXT,
                    "missing addr=HOST:PORT\n".to_owned(),
                );
            };
            if path.ends_with("drain") {
                router.drain(&addr);
            } else {
                router.resume(&addr);
            }
            ("200 OK", JSON, router.backends_json().to_string())
        }
        (_, "/api/backends/drain" | "/api/backends/resume") => {
            ("405 Method Not Allowed", TEXT, "use POST\n".to_owned())
        }
        _ => ("200 OK", TEXT, "ok\n".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_api() {
        let r = Router::new(vec![], vec![]);
        let (code, _, body) = status_response(
            &r,
            "POST /api/backends/drain?addr=10.0.0.1%3A4000 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(code, "200 OK");
        assert!(body.contains("\"addr\":\"10.0.0.1:4000\""), "{body}");
        assert!(r.is_draining("10.0.0.1:4000"));
        let (code, _, _) = status_response(&r, "GET /api/backends/drain?addr=x:1 HTTP/1.1\r\n");
        assert_eq!(code, "405 Method Not Allowed");
        let (code, _, _) = status_response(&r, "POST /api/backends/drain HTTP/1.1\r\n");
        assert_eq!(code, "400 Bad Request");
        status_response(
            &r,
            "POST /api/backends/resume?addr=10.0.0.1:4000 HTTP/1.1\r\n",
        );
        assert!(!r.any_draining());
        let (_, ctype, _) = status_response(&r, "GET /metrics HTTP/1.1\r\n");
        assert_eq!(ctype, TEXT);
    }
}
