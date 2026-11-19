// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Connection IDs and `KILL`.
//!
//! A routed session runs its statements on one of several backend
//! connections, and each has its own `TiDB` connection ID. The client only knows
//! the ID of the connection it authenticated on (from the greeting), and
//! `CONNECTION_ID()` returns the ID of whichever connection runs the query.
//! The registry maps every backend connection ID of every live session in
//! this router to the session, so `KILL [QUERY] id` with any of them can be
//! rewritten to the connection that runs the session right now. `TiDB`'s global
//! kill then delivers it to the right server.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use tokio::sync::Notify;

/// The kill-relevant view of one routed session.
#[derive(Default)]
pub struct SessionHandle {
    /// Backend connection that currently runs the session: (address, ID).
    current: Mutex<(String, u32)>,
    /// Signalled when the session is killed with `KILL CONNECTION`.
    pub killed: Notify,
    ids: Mutex<Vec<u32>>,
}

static REGISTRY: LazyLock<Mutex<HashMap<u32, Weak<SessionHandle>>>> =
    LazyLock::new(Default::default);

impl SessionHandle {
    /// Creates a handle whose current connection is `(addr, id)` and
    /// registers `id`.
    #[must_use]
    pub fn new(addr: &str, id: u32) -> Arc<Self> {
        let h = Arc::new(Self::default());
        h.set_current(addr, id);
        h.register(id);
        h
    }

    /// Registers another backend connection ID of this session.
    pub fn register(self: &Arc<Self>, id: u32) {
        if id == 0 {
            return;
        }
        if let Ok(mut ids) = self.ids.lock()
            && !ids.contains(&id)
        {
            ids.push(id);
        }
        if let Ok(mut r) = REGISTRY.lock() {
            r.insert(id, Arc::downgrade(self));
        }
    }

    /// Records the connection that runs the session now.
    pub fn set_current(&self, addr: &str, id: u32) {
        if let Ok(mut c) = self.current.lock() {
            *c = (addr.to_owned(), id);
        }
    }

    /// The connection that runs the session now.
    pub fn current(&self) -> (String, u32) {
        self.current.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        let ids = self.ids.get_mut().map(std::mem::take).unwrap_or_default();
        if let Ok(mut r) = REGISTRY.lock() {
            for id in ids {
                // Only remove entries that still point to a dead handle; the ID
                // may have been reused by a newer session.
                if r.get(&id).is_some_and(|w| w.strong_count() == 0) {
                    r.remove(&id);
                }
            }
        }
    }
}

/// Finds the live session that owns backend connection `id`.
pub fn lookup(id: u64) -> Option<Arc<SessionHandle>> {
    let id = u32::try_from(id).ok()?;
    REGISTRY.lock().ok()?.get(&id)?.upgrade()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_follows_session_lifetime() {
        let h = SessionHandle::new("a:1", 1001);
        h.register(2002);
        h.set_current("b:1", 2002);
        let found = lookup(1001).map(|s| s.current());
        assert_eq!(found, Some(("b:1".to_owned(), 2002)));
        assert!(lookup(2002).is_some());
        drop(found);
        drop(h);
        assert!(lookup(1001).is_none());
        assert!(lookup(2002).is_none());
        assert!(lookup(u64::MAX).is_none());
    }
}
