use crate::dns::{
    refresh_resolver_path, reset_resolver_path, resolver_mode_to_c,
    sockaddr_storage_to_socket_addr, DomainBalancer, ResolverState,
};
use crate::error::ClientError;
use crate::streams::{ClientState, PathEvent};
use slipstream_core::normalize_dual_stack_addr;
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_get_default_path_quality, picoquic_get_path_addr,
    picoquic_get_path_quality, slipstream_get_path_id_from_unique, slipstream_set_path_ack_delay,
    slipstream_set_path_mode, PICOQUIC_PACKET_LOOP_SEND_MAX,
};
use slipstream_ffi::ResolverMode;
use std::net::SocketAddr;
use tracing::info;

const AUTHORITATIVE_LOOP_MULTIPLIER: usize = 4;

pub(crate) fn apply_path_mode(
    cnx: *mut picoquic_cnx_t,
    resolver: &mut ResolverState,
) -> Result<(), ClientError> {
    if !refresh_resolver_path(cnx, resolver) {
        return Ok(());
    }
    unsafe {
        slipstream_set_path_mode(cnx, resolver.path_id, resolver_mode_to_c(resolver.mode));
        let disable_ack_delay = matches!(resolver.mode, ResolverMode::Authoritative) as libc::c_int;
        slipstream_set_path_ack_delay(cnx, resolver.path_id, disable_ack_delay);
    }
    Ok(())
}

pub(crate) fn fetch_path_quality(
    cnx: *mut picoquic_cnx_t,
    resolver: &ResolverState,
) -> slipstream_ffi::picoquic::picoquic_path_quality_t {
    let mut quality = slipstream_ffi::picoquic::picoquic_path_quality_t::default();
    let mut ret = -1;
    if let Some(unique_path_id) = resolver.unique_path_id {
        ret = unsafe { picoquic_get_path_quality(cnx, unique_path_id, &mut quality as *mut _) };
    }
    if ret != 0 {
        unsafe {
            picoquic_get_default_path_quality(cnx, &mut quality as *mut _);
        }
    }
    quality
}

pub(crate) fn drain_path_events(
    cnx: *mut picoquic_cnx_t,
    resolvers: &mut [ResolverState],
    state_ptr: *mut ClientState,
    balancer: &mut DomainBalancer,
) {
    if state_ptr.is_null() {
        return;
    }
    let events = unsafe { (*state_ptr).take_path_events() };
    if events.is_empty() {
        return;
    }
    for event in events {
        match event {
            PathEvent::Available(unique_path_id) => {
                if let Some(addr) = path_peer_addr(cnx, unique_path_id) {
                    if let Some((idx, resolver)) = find_resolver_by_addr_with_index(resolvers, addr) {
                        let path_id =
                            unsafe { slipstream_get_path_id_from_unique(cnx, unique_path_id) };
                        if path_id >= 0 {
                            resolver.unique_path_id = Some(unique_path_id);
                            resolver.path_id = path_id;
                            resolver.added = true;
                            // Path came back — unsuspend in balancer.
                            balancer.unsuspend_resolver(idx);
                        } else {
                            resolver.unique_path_id = None;
                        }
                    }
                }
            }
            PathEvent::Deleted(unique_path_id) => {
                if let Some((idx, resolver)) = find_resolver_by_unique_id_with_index(resolvers, unique_path_id) {
                    reset_resolver_path(resolver);
                    // Path lost — suspend all routes for this resolver.
                    info!(
                        "Path deleted for resolver {} (idx={}) — suspending in balancer",
                        resolver.addr, idx
                    );
                    balancer.suspend_resolver(idx);
                }
            }
        }
    }
}

fn path_peer_addr(cnx: *mut picoquic_cnx_t, unique_path_id: u64) -> Option<SocketAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let ret = unsafe { picoquic_get_path_addr(cnx, unique_path_id, 2, &mut storage) };
    if ret != 0 {
        return None;
    }
    sockaddr_storage_to_socket_addr(&storage).ok()
}

#[allow(dead_code)]
pub(crate) fn loop_burst_total(resolvers: &[ResolverState], base: usize) -> usize {
    resolvers.iter().fold(0usize, |acc, resolver| {
        acc.saturating_add(base.saturating_mul(path_loop_multiplier(resolver.mode)))
    })
}

pub(crate) fn path_poll_burst_max(resolver: &ResolverState) -> usize {
    PICOQUIC_PACKET_LOOP_SEND_MAX.saturating_mul(path_loop_multiplier(resolver.mode))
}

fn path_loop_multiplier(mode: ResolverMode) -> usize {
    match mode {
        ResolverMode::Authoritative => AUTHORITATIVE_LOOP_MULTIPLIER,
        ResolverMode::Recursive => 1,
    }
}

#[allow(dead_code)]
pub(crate) fn find_resolver_by_addr_mut(
    resolvers: &mut [ResolverState],
    addr: SocketAddr,
) -> Option<&mut ResolverState> {
    let addr = normalize_dual_stack_addr(addr);
    resolvers.iter_mut().find(|resolver| resolver.addr == addr)
}

fn find_resolver_by_addr_with_index(
    resolvers: &mut [ResolverState],
    addr: SocketAddr,
) -> Option<(usize, &mut ResolverState)> {
    let addr = normalize_dual_stack_addr(addr);
    resolvers
        .iter_mut()
        .enumerate()
        .find(|(_, resolver)| resolver.addr == addr)
}

#[allow(dead_code)]
fn find_resolver_by_unique_id_mut(
    resolvers: &mut [ResolverState],
    unique_path_id: u64,
) -> Option<&mut ResolverState> {
    resolvers
        .iter_mut()
        .find(|resolver| resolver.unique_path_id == Some(unique_path_id))
}

fn find_resolver_by_unique_id_with_index(
    resolvers: &mut [ResolverState],
    unique_path_id: u64,
) -> Option<(usize, &mut ResolverState)> {
    resolvers
        .iter_mut()
        .enumerate()
        .find(|(_, resolver)| resolver.unique_path_id == Some(unique_path_id))
}
