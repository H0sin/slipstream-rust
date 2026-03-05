//! Per-tunnel health checker.
//!
//! Runs as a background tokio task.  Every `HEALTH_CHECK_INTERVAL` it
//! probes every tunnel currently known to the runtime by sending a
//! real tunnel-encoded DNS query.
//!
//! Each tunnel `(resolver, domain)` is probed independently — a domain
//! failure through one resolver does not affect other tunnels.
//!
//! Results are sent back to the runtime via a channel so the pool can
//! mark tunnels healthy/unhealthy without blocking the hot path.

use slipstream_dns::{build_qname, decode_response, encode_query, QueryParams, CLASS_IN, RR_TXT};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ── Probe constants ─────────────────────────────────────────────────

/// Timeout for a single DNS health-check probe round-trip.
const PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);

// ── Probe types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProbeResult {
    /// No response at all (timeout / error).
    NoResponse,
    /// Got a DNS response but wrong RCODE (NXDOMAIN, SERVFAIL, etc.).
    WrongRcode,
    /// Got RCODE=NOERROR — tunnel server answered.
    TunnelReachable,
    /// Got RCODE=NOERROR **and** TXT response contains data.
    TunnelResponded,
}

/// Build a tunnel-realistic DNS TXT probe.
fn build_tunnel_probe(domain: &str, id: u16) -> Result<Vec<u8>, String> {
    let probe_marker: [u8; 8] = [
        0x53, 0x4C, 0x50, 0x52, // "SLPR" magic
        (id >> 8) as u8,
        (id & 0xFF) as u8,
        0x00,
        0x01,
    ];
    let qname = build_qname(&probe_marker, domain).map_err(|e| e.to_string())?;
    let params = QueryParams {
        id,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    };
    encode_query(&params).map_err(|e| e.to_string())
}

/// Probe a single resolver+domain with a tunnel-encoded DNS query.
async fn probe_candidate(
    addr: SocketAddr,
    domain: &str,
    id: u16,
) -> (ProbeResult, Duration) {
    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let sock = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!("[health] probe: failed to bind socket: {e}");
            return (ProbeResult::NoResponse, Duration::ZERO);
        }
    };

    let query = match build_tunnel_probe(domain, id) {
        Ok(q) => q,
        Err(e) => {
            debug!("[health] probe: failed to build probe: {e}");
            return (ProbeResult::NoResponse, Duration::ZERO);
        }
    };

    let start = Instant::now();
    if let Err(e) = sock.send_to(&query, addr).await {
        debug!("[health] probe: send_to {addr} failed: {e}");
        return (ProbeResult::NoResponse, Duration::ZERO);
    }

    let mut buf = [0u8; 2048];
    match tokio::time::timeout(PROBE_TIMEOUT, sock.recv_from(&mut buf)).await {
        Ok(Ok((size, _))) if size >= 12 => {
            let latency = start.elapsed();
            let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
            let flags = u16::from_be_bytes([buf[2], buf[3]]);
            let is_response = flags & 0x8000 != 0;
            let rcode = (flags & 0x000F) as u8;

            if !is_response || resp_id != id {
                return (ProbeResult::NoResponse, latency);
            }
            if rcode != 0 {
                return (ProbeResult::WrongRcode, latency);
            }
            if let Some(payload) = decode_response(&buf[..size]) {
                debug!("[health] probe: {addr} NOERROR +{}B for {domain}", payload.len());
                (ProbeResult::TunnelResponded, latency)
            } else {
                debug!("[health] probe: {addr} NOERROR (empty) for {domain}");
                (ProbeResult::TunnelReachable, latency)
            }
        }
        Ok(Ok((size, _))) => {
            debug!("[health] probe: {addr} too-small response ({size}B)");
            (ProbeResult::NoResponse, start.elapsed())
        }
        Ok(Err(e)) => {
            debug!("[health] probe: recv from {addr} failed: {e}");
            (ProbeResult::NoResponse, Duration::ZERO)
        }
        Err(_) => (ProbeResult::NoResponse, Duration::ZERO),
    }
}

// ── Constants ───────────────────────────────────────────────────────

/// How often we health-check all active tunnels.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// A tunnel must fail this many consecutive health checks before
/// we tell the pool to mark it unhealthy.
const CONSECUTIVE_FAIL_THRESHOLD: u32 = 2;

/// Maximum number of tunnels we health-check in a single round.
const MAX_CHECK_PER_ROUND: usize = 128;

// ── Public types ────────────────────────────────────────────────────

/// A health-check result sent from the checker to the runtime.
#[derive(Debug, Clone)]
pub(crate) struct HealthUpdate {
    /// Tunnel ID in the runtime's TunnelPool.
    pub(crate) tunnel_id: usize,
    /// Socket address of the resolver (for logging / verification).
    #[allow(dead_code)]
    pub(crate) addr: SocketAddr,
    /// `true` = tunnel is working, `false` = failed.
    pub(crate) healthy: bool,
    /// Measured round-trip time (only meaningful when `healthy`).
    #[allow(dead_code)]
    pub(crate) latency: Duration,
}

/// Snapshot of a tunnel to probe — sent from the runtime to the
/// health checker so it always has an up-to-date list.
#[derive(Debug, Clone)]
pub(crate) struct TunnelSnapshot {
    /// Tunnel ID in the pool.
    pub(crate) tunnel_id: usize,
    /// Resolver address for this tunnel.
    pub(crate) addr: SocketAddr,
    /// Domain to use for the probe query.
    pub(crate) domain: String,
}

/// Legacy alias kept for backward compatibility during transition.
#[allow(dead_code)]
pub(crate) type ResolverSnapshot = TunnelSnapshot;

// ── Background task ─────────────────────────────────────────────────

/// Run the per-tunnel health checker loop.
///
/// * `tunnel_rx` — receives the current tunnel list from the runtime.
/// * `result_tx` — sends health results back to the runtime.
/// * `_domains` — kept for signature compat; domain is now per-tunnel.
pub(crate) async fn run_health_checker(
    mut tunnel_rx: mpsc::UnboundedReceiver<Vec<TunnelSnapshot>>,
    result_tx: mpsc::UnboundedSender<HealthUpdate>,
    _domains: Vec<String>,
) {
    info!(
        "[health] per-tunnel checker started: interval={}s, fail_threshold={}",
        HEALTH_CHECK_INTERVAL.as_secs(),
        CONSECUTIVE_FAIL_THRESHOLD,
    );

    let mut fail_counts: Vec<u32> = Vec::new();
    let mut tunnels: Vec<TunnelSnapshot> = Vec::new();

    loop {
        // Drain all pending tunnel list updates — keep only the latest.
        let mut got_update = false;
        while let Ok(snapshot) = tunnel_rx.try_recv() {
            tunnels = snapshot;
            got_update = true;
        }
        if got_update {
            fail_counts.resize(tunnels.len(), 0);
        }

        if tunnels.is_empty() {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        let check_count = tunnels.len().min(MAX_CHECK_PER_ROUND);
        debug!(
            "[health] checking {}/{} tunnels",
            check_count,
            tunnels.len()
        );

        for i in 0..check_count {
            let t = &tunnels[i];
            let id = ((t.tunnel_id as u32 * 7 + i as u32) % 65536) as u16;

            // Probe this tunnel with its own resolver + domain.
            let (result, latency) = probe_candidate(t.addr, &t.domain, id).await;
            let is_healthy = result >= ProbeResult::TunnelReachable;

            if is_healthy {
                if fail_counts.get(i).copied().unwrap_or(0) > 0 {
                    info!(
                        "[health] tunnel {} ({} via {}) recovered ({}ms)",
                        t.tunnel_id,
                        t.domain,
                        t.addr,
                        latency.as_millis()
                    );
                }
                if let Some(c) = fail_counts.get_mut(i) {
                    *c = 0;
                }
                let _ = result_tx.send(HealthUpdate {
                    tunnel_id: t.tunnel_id,
                    addr: t.addr,
                    healthy: true,
                    latency,
                });
            } else {
                let count = fail_counts
                    .get_mut(i)
                    .map(|c| {
                        *c = c.saturating_add(1);
                        *c
                    })
                    .unwrap_or(1);

                if count >= CONSECUTIVE_FAIL_THRESHOLD {
                    warn!(
                        "[health] tunnel {} ({} via {}) failed {} checks — suspending",
                        t.tunnel_id, t.domain, t.addr, count
                    );
                    let _ = result_tx.send(HealthUpdate {
                        tunnel_id: t.tunnel_id,
                        addr: t.addr,
                        healthy: false,
                        latency: Duration::ZERO,
                    });
                } else {
                    debug!(
                        "[health] tunnel {} ({} via {}) failed check ({}/{})",
                        t.tunnel_id, t.domain, t.addr, count, CONSECUTIVE_FAIL_THRESHOLD
                    );
                }
            }
        }

        tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;
    }
}
