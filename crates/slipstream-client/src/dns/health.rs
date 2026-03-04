//! Periodic health checker for active resolvers.
//!
//! Runs as a background tokio task.  Every `HEALTH_CHECK_INTERVAL` it
//! probes every resolver currently known to the runtime by sending a
//! real tunnel-encoded DNS query (reusing the scanner's probe logic).
//!
//! Results are sent back to the runtime via a channel so the balancer
//! can suspend / unsuspend resolvers without blocking the hot path.

use super::scanner::{probe_candidate, ProbeResult};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ── Constants ───────────────────────────────────────────────────────

/// How often we health-check all active resolvers.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// A resolver must fail this many consecutive health checks before
/// we tell the balancer to suspend it.
const CONSECUTIVE_FAIL_THRESHOLD: u32 = 2;

/// Maximum number of resolvers we health-check in a single round.
/// Prevents the checker from consuming too many resources if the
/// scanner has discovered thousands of resolvers.
const MAX_CHECK_PER_ROUND: usize = 64;

// ── Public types ────────────────────────────────────────────────────

/// A health-check result sent from the checker to the runtime.
#[derive(Debug, Clone)]
pub(crate) struct HealthUpdate {
    /// Index of the resolver in the runtime's resolver list.
    pub(crate) resolver_idx: usize,
    /// Socket address (for logging / verification).
    pub(crate) addr: SocketAddr,
    /// `true` = resolver is working, `false` = failed.
    pub(crate) healthy: bool,
    /// Measured round-trip time (only meaningful when `healthy`).
    pub(crate) latency: Duration,
}

/// Snapshot of a resolver to probe — sent from the runtime to the
/// health checker so it always has an up-to-date list.
#[derive(Debug, Clone)]
pub(crate) struct ResolverSnapshot {
    pub(crate) idx: usize,
    pub(crate) addr: SocketAddr,
}

// ── Background task ─────────────────────────────────────────────────

/// Run the health checker loop.
///
/// * `resolver_rx` — receives the current resolver list from the runtime
///   at the start of each round.
/// * `result_tx` — sends health results back to the runtime.
/// * `domains` — tunnel domains used for probe queries.
pub(crate) async fn run_health_checker(
    mut resolver_rx: mpsc::UnboundedReceiver<Vec<ResolverSnapshot>>,
    result_tx: mpsc::UnboundedSender<HealthUpdate>,
    domains: Vec<String>,
) {
    info!(
        "[health] checker started: interval={}s, fail_threshold={}",
        HEALTH_CHECK_INTERVAL.as_secs(),
        CONSECUTIVE_FAIL_THRESHOLD,
    );

    // Per-resolver consecutive failure counter (keyed by resolver index).
    // Reset whenever we get a fresh resolver list.
    let mut fail_counts: Vec<u32> = Vec::new();
    let mut resolvers: Vec<ResolverSnapshot> = Vec::new();

    loop {
        // Drain all pending resolver list updates — keep only the latest.
        let mut got_update = false;
        while let Ok(snapshot) = resolver_rx.try_recv() {
            resolvers = snapshot;
            got_update = true;
        }
        if got_update {
            // Resize fail counters to match new resolver list.
            fail_counts.resize(resolvers.len(), 0);
        }

        if resolvers.is_empty() {
            // No resolvers yet — wait a bit and check again.
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        let check_count = resolvers.len().min(MAX_CHECK_PER_ROUND);
        debug!(
            "[health] checking {}/{} resolvers",
            check_count,
            resolvers.len()
        );

        for i in 0..check_count {
            let r = &resolvers[i];
            let domain = &domains[i % domains.len()];
            let id = ((r.idx as u32 * 7 + i as u32) % 65536) as u16;

            let (result, latency) = probe_candidate(r.addr, domain, id).await;
            let is_healthy = result >= ProbeResult::TunnelReachable;

            if is_healthy {
                if fail_counts.get(i).copied().unwrap_or(0) > 0 {
                    info!(
                        "[health] resolver {} ({}) recovered ({}ms)",
                        r.idx,
                        r.addr,
                        latency.as_millis()
                    );
                }
                if let Some(c) = fail_counts.get_mut(i) {
                    *c = 0;
                }
                let _ = result_tx.send(HealthUpdate {
                    resolver_idx: r.idx,
                    addr: r.addr,
                    healthy: true,
                    latency,
                });
            } else {
                let count = fail_counts.get_mut(i).map(|c| {
                    *c = c.saturating_add(1);
                    *c
                }).unwrap_or(1);

                if count >= CONSECUTIVE_FAIL_THRESHOLD {
                    warn!(
                        "[health] resolver {} ({}) failed {} consecutive checks — suspending",
                        r.idx, r.addr, count
                    );
                    let _ = result_tx.send(HealthUpdate {
                        resolver_idx: r.idx,
                        addr: r.addr,
                        healthy: false,
                        latency: Duration::ZERO,
                    });
                } else {
                    debug!(
                        "[health] resolver {} ({}) failed check ({}/{})",
                        r.idx, r.addr, count, CONSECUTIVE_FAIL_THRESHOLD
                    );
                }
            }
        }

        tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;
    }
}
