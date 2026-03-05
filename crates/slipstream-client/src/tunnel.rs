//! Per-route tunnel isolation.
//!
//! Each `(resolver, domain)` pair gets its own independent QUIC connection
//! ("tunnel"), ensuring that a failure on one route does not affect others.
//!
//! The runtime creates one tunnel per configured route and manages them
//! through the [`TunnelPool`].  Health checking is per-tunnel, and the
//! pool selects the best healthy tunnel when dispatching new TCP streams.

use crate::dns::resolver::ResolverState;
use crate::streams::{ClientState, Command};
use slipstream_ffi::picoquic::picoquic_cnx_t;
use tokio::sync::mpsc;

// ── TunnelRoute ─────────────────────────────────────────────────────

/// A single tunnel bound to a specific `(resolver, domain)` route.
///
/// Each tunnel owns:
/// - A QUIC connection (`cnx`) to its resolver.
/// - A `state_ptr` to its [`ClientState`] (lifetime managed externally).
/// - A command channel for stream I/O events.
/// - A [`ResolverState`] tracking path/poll state.
pub(crate) struct TunnelRoute {
    /// Unique tunnel ID (index in the pool).
    pub(crate) id: usize,
    /// Index of the resolver in the original config list.
    pub(crate) resolver_idx: usize,
    /// Index of the domain in the config domain list.
    pub(crate) domain_idx: usize,
    /// The domain string used for DNS encoding on this tunnel.
    pub(crate) domain: String,
    /// QUIC connection handle for this tunnel.
    pub(crate) cnx: *mut picoquic_cnx_t,
    /// Raw pointer to the per-tunnel ClientState.
    /// Lifetime is managed by the `_tunnel_states` Vec in the runtime.
    pub(crate) state_ptr: *mut ClientState,
    /// Per-tunnel command channel receiver (stream I/O events).
    pub(crate) command_rx: mpsc::UnboundedReceiver<Command>,
    /// Per-tunnel resolver state (path, pending polls, etc.).
    pub(crate) resolver: ResolverState,
    /// Rolling DNS query ID for this tunnel.
    pub(crate) dns_id: u16,
    /// Whether this tunnel is currently healthy (set by health checker).
    pub(crate) healthy: bool,
    /// Timestamp of last successful network activity (picoquic µs).
    pub(crate) last_activity_at: u64,
}

// Safety: The raw pointers (`cnx`, `state_ptr`) are managed exclusively
// by the single-threaded tokio runtime.
unsafe impl Send for TunnelRoute {}

impl TunnelRoute {
    /// Human-readable label for logging.
    pub(crate) fn label(&self) -> String {
        format!(
            "tunnel[{}] resolver={} domain={}",
            self.id, self.resolver.addr, self.domain
        )
    }

    /// Whether this tunnel's QUIC connection is ready for streams.
    pub(crate) fn is_ready(&self) -> bool {
        unsafe { (*self.state_ptr).is_ready() }
    }

    /// Whether this tunnel's QUIC connection is closing.
    pub(crate) fn is_closing(&self) -> bool {
        unsafe { (*self.state_ptr).is_closing() }
    }

    /// Number of active streams on this tunnel.
    pub(crate) fn streams_len(&self) -> usize {
        unsafe { (*self.state_ptr).streams_len() }
    }
}

// ── TunnelPool ──────────────────────────────────────────────────────

/// Manages a pool of [`TunnelRoute`] instances.
///
/// Provides tunnel selection for new TCP connections and lookup helpers
/// for mapping QUIC connections or resolver addresses back to tunnels.
pub(crate) struct TunnelPool {
    pub(crate) tunnels: Vec<TunnelRoute>,
    /// Round-robin cursor for weighted tunnel selection.
    rr_cursor: usize,
}

impl TunnelPool {
    pub(crate) fn new() -> Self {
        Self {
            tunnels: Vec::new(),
            rr_cursor: 0,
        }
    }

    /// Select the best healthy tunnel for a new TCP stream.
    ///
    /// Preference order:
    /// 1. Ready + healthy tunnels (round-robin, prefer fewest streams).
    /// 2. Any ready tunnel (even if unhealthy).
    /// 3. `None` if no tunnel is ready.
    pub(crate) fn select_tunnel(&mut self) -> Option<usize> {
        let n = self.tunnels.len();
        if n == 0 {
            return None;
        }

        // Round-robin across healthy + ready tunnels.
        let mut best: Option<(usize, usize)> = None; // (index, stream_count)
        for offset in 0..n {
            let i = (self.rr_cursor + offset) % n;
            let t = &self.tunnels[i];
            if t.is_ready() && t.healthy {
                let count = t.streams_len();
                if best.is_none() || count < best.unwrap().1 {
                    best = Some((i, count));
                }
            }
        }
        if let Some((idx, _)) = best {
            self.rr_cursor = (idx + 1) % n;
            return Some(idx);
        }

        // Fall back to any ready tunnel.
        for offset in 0..n {
            let i = (self.rr_cursor + offset) % n;
            if self.tunnels[i].is_ready() {
                self.rr_cursor = (i + 1) % n;
                return Some(i);
            }
        }

        None
    }

    /// Find the tunnel that owns a specific QUIC connection.
    pub(crate) fn find_by_cnx(&self, cnx: *mut picoquic_cnx_t) -> Option<usize> {
        self.tunnels.iter().position(|t| t.cnx == cnx)
    }

    /// Find tunnel indices for a given resolver address.
    pub(crate) fn find_by_resolver_addr(
        &self,
        addr: std::net::SocketAddr,
    ) -> Vec<usize> {
        let addr = slipstream_core::normalize_dual_stack_addr(addr);
        self.tunnels
            .iter()
            .enumerate()
            .filter(|(_, t)| t.resolver.addr == addr)
            .map(|(i, _)| i)
            .collect()
    }

    /// Whether any tunnel is in the closing state.
    pub(crate) fn any_closing(&self) -> bool {
        self.tunnels.iter().any(|t| t.is_closing())
    }

    /// Whether any tunnel is ready.
    pub(crate) fn any_ready(&self) -> bool {
        self.tunnels.iter().any(|t| t.is_ready())
    }

    /// Total number of active streams across all tunnels.
    pub(crate) fn total_streams(&self) -> usize {
        self.tunnels.iter().map(|t| t.streams_len()).sum()
    }

    /// Whether all tunnels are unhealthy (triggers full reconnect).
    pub(crate) fn all_unhealthy(&self) -> bool {
        !self.tunnels.is_empty() && self.tunnels.iter().all(|t| !t.healthy)
    }

    /// Summary string for logging.
    pub(crate) fn summary(&self) -> String {
        let total = self.tunnels.len();
        let healthy = self.tunnels.iter().filter(|t| t.healthy).count();
        let ready = self.tunnels.iter().filter(|t| t.is_ready()).count();
        format!("tunnels={total} healthy={healthy} ready={ready}")
    }
}
