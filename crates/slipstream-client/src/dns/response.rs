use crate::error::ClientError;
use crate::tunnel::TunnelRoute;
use slipstream_dns::decode_response;
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_current_time, picoquic_incoming_packet_ex, picoquic_quic_t,
    PICOQUIC_PACKET_LOOP_RECV_MAX,
};
use slipstream_ffi::{socket_addr_to_storage, ResolverMode};
use std::net::SocketAddr;
use tracing::warn;

use super::balancer::DomainBalancer;
use super::resolver::ResolverState;
use slipstream_core::normalize_dual_stack_addr;

const MAX_POLL_BURST: usize = PICOQUIC_PACKET_LOOP_RECV_MAX;

#[allow(dead_code)]
pub(crate) struct DnsResponseContext<'a> {
    pub(crate) quic: *mut picoquic_quic_t,
    pub(crate) local_addr_storage: &'a libc::sockaddr_storage,
    pub(crate) resolvers: &'a mut [ResolverState],
    pub(crate) balancer: &'a mut DomainBalancer,
}

#[allow(dead_code)]
pub(crate) fn handle_dns_response(
    buf: &[u8],
    peer: SocketAddr,
    ctx: &mut DnsResponseContext<'_>,
) -> Result<(), ClientError> {
    let peer = normalize_dual_stack_addr(peer);
    let response_id = dns_response_id(buf);
    if let Some(payload) = decode_response(buf) {
        let resolver_index = ctx
            .resolvers
            .iter()
            .position(|resolver| resolver.addr == peer);
        let mut peer_storage = socket_addr_to_storage(peer);
        let mut local_storage = if let Some(index) = resolver_index {
            ctx.resolvers[index]
                .local_addr_storage
                .as_ref()
                .map(|storage| unsafe { std::ptr::read(storage) })
                .unwrap_or_else(|| unsafe { std::ptr::read(ctx.local_addr_storage) })
        } else {
            unsafe { std::ptr::read(ctx.local_addr_storage) }
        };
        let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
        let mut first_path: libc::c_int = -1;
        let current_time = unsafe { picoquic_current_time() };
        let ret = unsafe {
            picoquic_incoming_packet_ex(
                ctx.quic,
                payload.as_ptr() as *mut u8,
                payload.len(),
                &mut peer_storage as *mut _ as *mut libc::sockaddr,
                &mut local_storage as *mut _ as *mut libc::sockaddr,
                0,
                0,
                &mut first_cnx,
                &mut first_path,
                current_time,
            )
        };
        if ret < 0 {
            warn!("Failed processing inbound QUIC packet (ret={ret}); skipping");
            return Ok(());
        }
        let resolved_idx = resolver_index.or_else(|| {
            ctx.resolvers
                .iter()
                .position(|r| r.added && r.path_id == first_path)
        });
        let resolver = if let Some(resolver) = find_resolver_by_path_id(ctx.resolvers, first_path) {
            Some(resolver)
        } else {
            find_resolver_by_addr(ctx.resolvers, peer)
        };
        if let Some(resolver) = resolver {
            if first_path >= 0 && resolver.path_id != first_path {
                resolver.path_id = first_path;
                resolver.added = true;
            }
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if let Some(response_id) = response_id {
                if resolver.mode == ResolverMode::Authoritative {
                    resolver.inflight_poll_ids.remove(&response_id);
                }
            }
            if resolver.mode == ResolverMode::Recursive {
                resolver.pending_polls =
                    resolver.pending_polls.saturating_add(1).min(MAX_POLL_BURST);
            }
        }
        // Record health: successful response for all domains of this resolver.
        // The DNS layer doesn't know which domain was used in the query, so we
        // credit the resolver broadly — the balancer weights will still steer
        // toward low-latency domains via other signals.
        if let Some(ri) = resolved_idx {
            let num_domains = ctx.balancer.num_domains();
            for d in 0..num_domains {
                ctx.balancer.record_success(ri, d, None, payload.len());
            }
        }
    } else if let Some(response_id) = response_id {
        let resolver_index = ctx
            .resolvers
            .iter()
            .position(|resolver| resolver.addr == peer);
        if let Some(resolver) = find_resolver_by_addr(ctx.resolvers, peer) {
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if resolver.mode == ResolverMode::Authoritative {
                resolver.inflight_poll_ids.remove(&response_id);
            }
        }
        // Empty response (no payload) — record failure for balancer health.
        if let Some(ri) = resolver_index {
            let num_domains = ctx.balancer.num_domains();
            for d in 0..num_domains {
                ctx.balancer.record_failure(ri, d);
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn find_resolver_by_path_id(
    resolvers: &mut [ResolverState],
    path_id: libc::c_int,
) -> Option<&mut ResolverState> {
    if path_id < 0 {
        return None;
    }
    resolvers
        .iter_mut()
        .find(|resolver| resolver.added && resolver.path_id == path_id)
}

#[allow(dead_code)]
fn find_resolver_by_addr(
    resolvers: &mut [ResolverState],
    peer: SocketAddr,
) -> Option<&mut ResolverState> {
    let peer = normalize_dual_stack_addr(peer);
    resolvers.iter_mut().find(|resolver| resolver.addr == peer)
}

fn dns_response_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    Some(id)
}

// ── Per-tunnel response handler ─────────────────────────────────────

/// Context for handling DNS responses in the per-tunnel architecture.
pub(crate) struct TunneledResponseContext<'a> {
    pub(crate) quic: *mut picoquic_quic_t,
    pub(crate) local_addr_storage: &'a libc::sockaddr_storage,
    pub(crate) balancer: &'a mut DomainBalancer,
}

/// Handle a DNS response and route it to the correct tunnel.
///
/// The shared QUIC context demultiplexes via connection IDs.  We then
/// map `first_cnx` back to a tunnel for per-tunnel health accounting.
///
/// Returns the tunnel index that handled the packet (if any).
pub(crate) fn handle_dns_response_tunneled(
    buf: &[u8],
    peer: SocketAddr,
    ctx: &mut TunneledResponseContext<'_>,
    tunnels: &mut [TunnelRoute],
) -> Result<Option<usize>, ClientError> {
    let peer = normalize_dual_stack_addr(peer);
    let response_id = dns_response_id(buf);

    if let Some(payload) = decode_response(buf) {
        // Find the first tunnel whose resolver matches the peer address.
        let tunnel_idx_by_addr = tunnels
            .iter()
            .position(|t| t.resolver.addr == peer);

        let mut peer_storage = socket_addr_to_storage(peer);
        let mut local_storage = if let Some(idx) = tunnel_idx_by_addr {
            tunnels[idx]
                .resolver
                .local_addr_storage
                .as_ref()
                .map(|s| unsafe { std::ptr::read(s) })
                .unwrap_or_else(|| unsafe { std::ptr::read(ctx.local_addr_storage) })
        } else {
            unsafe { std::ptr::read(ctx.local_addr_storage) }
        };

        let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
        let mut first_path: libc::c_int = -1;
        let current_time = unsafe { picoquic_current_time() };
        let ret = unsafe {
            picoquic_incoming_packet_ex(
                ctx.quic,
                payload.as_ptr() as *mut u8,
                payload.len(),
                &mut peer_storage as *mut _ as *mut libc::sockaddr,
                &mut local_storage as *mut _ as *mut libc::sockaddr,
                0,
                0,
                &mut first_cnx,
                &mut first_path,
                current_time,
            )
        };
        if ret < 0 {
            warn!("Failed processing inbound QUIC packet (ret={ret}); skipping");
            return Ok(None);
        }

        // Map first_cnx → tunnel for precise accounting.
        let resolved_tunnel = if !first_cnx.is_null() {
            tunnels.iter().position(|t| t.cnx == first_cnx)
        } else {
            tunnel_idx_by_addr
        };

        // Update the tunnel's resolver state.
        if let Some(ti) = resolved_tunnel {
            let resolver = &mut tunnels[ti].resolver;
            if first_path >= 0 && resolver.path_id != first_path {
                resolver.path_id = first_path;
                resolver.added = true;
            }
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if let Some(rid) = response_id {
                if resolver.mode == ResolverMode::Authoritative {
                    resolver.inflight_poll_ids.remove(&rid);
                }
            }
            if resolver.mode == ResolverMode::Recursive {
                resolver.pending_polls = resolver
                    .pending_polls
                    .saturating_add(1)
                    .min(MAX_POLL_BURST);
            }

            // Record health for this specific route only.
            let ri = tunnels[ti].resolver_idx;
            let di = tunnels[ti].domain_idx;
            ctx.balancer.record_success(ri, di, None, payload.len());
        }

        Ok(resolved_tunnel)
    } else if let Some(response_id) = response_id {
        // Empty response — find tunnel and update stats.
        let tunnel_idx_by_addr = tunnels
            .iter()
            .position(|t| t.resolver.addr == peer);

        if let Some(ti) = tunnel_idx_by_addr {
            let resolver = &mut tunnels[ti].resolver;
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if resolver.mode == ResolverMode::Authoritative {
                resolver.inflight_poll_ids.remove(&response_id);
            }
            // Only count as failure if the QUIC handshake is already done.
            // During handshake, empty responses are normal and should not
            // penalise the route health.
            if tunnels[ti].is_ready() {
                let ri = tunnels[ti].resolver_idx;
                let di = tunnels[ti].domain_idx;
                ctx.balancer.record_failure(ri, di);
            }
        }

        Ok(tunnel_idx_by_addr)
    } else {
        Ok(None)
    }
}

