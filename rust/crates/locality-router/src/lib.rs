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
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.starts_with("GET /metrics") {
                router.render_metrics()
            } else {
                "ok\n".to_owned()
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });
    }
}
