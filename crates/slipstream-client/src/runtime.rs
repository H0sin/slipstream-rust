mod path;
pub(crate) mod setup;

use self::path::{
    apply_path_mode, drain_path_events, fetch_path_quality,
    path_poll_burst_max,
};
use self::setup::{bind_tcp_listener, bind_udp_socket, compute_mtu, map_io};
use crate::dns::{
    expire_inflight_polls, handle_dns_response_tunneled, maybe_report_debug,
    refresh_resolver_path, resolve_resolvers, resolver_mode_to_c,
    send_poll_queries, sockaddr_storage_to_socket_addr,
    DomainBalancer, DiscoveredResolver, HealthUpdate, ScannerConfig,
    TunnelSnapshot, TunneledResponseContext,
    run_resolver_scanner,
};
use crate::error::ClientError;
use crate::pacing::{cwnd_target_polls, inflight_packet_estimate};
use crate::pinning::configure_pinned_certificate;
use crate::streams::{
    acceptor::ClientAcceptor, client_callback, drain_commands, drain_stream_data, handle_command,
    ClientState, Command,
};
use crate::tunnel::{TunnelPool, TunnelRoute};
use slipstream_core::{net::is_transient_udp_error, normalize_dual_stack_addr};
use slipstream_dns::{build_qname, encode_query, QueryParams, CLASS_IN, RR_TXT};
use slipstream_ffi::{
    configure_quic_with_custom,
    picoquic::{
        picoquic_close, picoquic_cnx_t, picoquic_connection_id_t, picoquic_create,
        picoquic_create_client_cnx, picoquic_current_time, picoquic_disable_keep_alive,
        picoquic_enable_keep_alive, picoquic_enable_path_callbacks,
        picoquic_enable_path_callbacks_default, picoquic_get_next_wake_delay,
        picoquic_prepare_next_packet_ex, picoquic_set_callback, slipstream_has_ready_stream,
        slipstream_is_flow_blocked, slipstream_mixed_cc_algorithm, slipstream_set_cc_override,
        slipstream_set_default_path_mode, PICOQUIC_CONNECTION_ID_MAX_SIZE,
        PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX, PICOQUIC_PACKET_LOOP_SEND_MAX,
    },
    socket_addr_to_storage, take_crypto_errors, ClientConfig, QuicGuard, ResolverMode,
};
use std::ffi::CString;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

// Protocol defaults; see docs/config.md for details.
const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const SLIPSTREAM_SNI: &str = "test.example.com";
const DNS_WAKE_DELAY_MAX_US: i64 = 10_000_000;
const DNS_POLL_SLICE_US: u64 = 20_000;
const RECONNECT_SLEEP_MIN_MS: u64 = 250;
const RECONNECT_SLEEP_MAX_MS: u64 = 5_000;
const FLOW_BLOCKED_LOG_INTERVAL_US: u64 = 1_000_000;
const WATCHDOG_TIMEOUT_US: u64 = 20_000_000;
/// Idle recursive tunnels send a keepalive poll every this many µs.
const KEEPALIVE_POLL_INTERVAL_US: u64 = 10_000_000;
const HEARTBEAT_INTERVAL_US: u64 = 60_000_000;
/// If flow_blocked stays true for this long with active streams, mark unhealthy.
const FLOW_BLOCKED_KILL_US: u64 = 10_000_000;
/// Throughput stall: if streams exist but no bytes move for this long, mark unhealthy.
const THROUGHPUT_STALL_US: u64 = 15_000_000;
/// Hard upper bound on the send loop to prevent CPU spinning when the pool
/// grows large (many discovered resolvers × domains).
const PACKET_LOOP_SEND_CAP: usize = 200;

fn is_ipv6_unspecified(host: &str) -> bool {
    host.parse::<Ipv6Addr>()
        .map(|addr| addr.is_unspecified())
        .unwrap_or(false)
}

#[allow(dead_code)]
fn drain_disconnected_commands(command_rx: &mut mpsc::UnboundedReceiver<Command>) -> usize {
    let mut dropped = 0usize;
    while let Ok(command) = command_rx.try_recv() {
        dropped += 1;
        if let Command::NewStream { stream, .. } = command {
            drop(stream);
        }
    }
    dropped
}

pub async fn run_client(config: &ClientConfig<'_>) -> Result<i32, ClientError> {
    if config.domains.is_empty() {
        return Err(ClientError::new("At least one domain is required"));
    }
    // Use the longest domain for the conservative MTU estimate so that
    // QUIC never produces a packet too big for *any* configured domain.
    let max_domain_len = config.domains.iter().map(|d| d.len()).max().unwrap_or(0);
    let mtu = compute_mtu(max_domain_len)?;
    let udp = bind_udp_socket().await?;

    // Accept channel: the TCP acceptor pushes new connections here.
    // Per-tunnel command channels are created inside the reconnect loop.
    let (accept_tx, mut accept_rx) = mpsc::unbounded_channel::<Command>();
    // Shared data notify — wakes the main loop when any tunnel has data.
    let data_notify = Arc::new(Notify::new());
    let acceptor = ClientAcceptor::new();
    let debug_streams = config.debug_streams;
    let tcp_host = config.tcp_listen_host;
    let tcp_port = config.tcp_listen_port;
    let mut bound_host = tcp_host.to_string();
    let listener = match bind_tcp_listener(tcp_host, tcp_port).await {
        Ok(listener) => listener,
        Err(err) => {
            if is_ipv6_unspecified(tcp_host) {
                warn!(
                    "Failed to bind TCP listener on {}:{} ({}); falling back to 0.0.0.0",
                    tcp_host, tcp_port, err
                );
                match bind_tcp_listener("0.0.0.0", tcp_port).await {
                    Ok(listener) => {
                        bound_host = "0.0.0.0".to_string();
                        listener
                    }
                    Err(fallback_err) => {
                        return Err(ClientError::new(format!(
                            "Failed to bind TCP listener on {}:{} ({}) or 0.0.0.0:{} ({})",
                            tcp_host, tcp_port, err, tcp_port, fallback_err
                        )));
                    }
                }
            } else {
                return Err(err);
            }
        }
    };
    // Acceptor pushes new TCP connections to accept_tx (not per-tunnel).
    acceptor.spawn(listener, accept_tx.clone());
    info!("Listening on TCP port {} (host {})", tcp_port, bound_host);

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ClientError::new("ALPN contains an unexpected null byte"))?;
    let sni = CString::new(SLIPSTREAM_SNI)
        .map_err(|_| ClientError::new("SNI contains an unexpected null byte"))?;
    let cc_override = match config.congestion_control {
        Some(value) => Some(CString::new(value).map_err(|_| {
            ClientError::new("Congestion control contains an unexpected null byte")
        })?),
        None => None,
    };

    let mut reconnect_delay = Duration::from_millis(RECONNECT_SLEEP_MIN_MS);

    // Spawn background per-tunnel health checker.
    let (health_snapshot_tx, health_snapshot_rx) = mpsc::unbounded_channel::<Vec<TunnelSnapshot>>();
    let (health_result_tx, mut health_result_rx) = mpsc::unbounded_channel::<HealthUpdate>();
    {
        let domains = config.domains.to_vec();
        tokio::spawn(async move {
            crate::dns::health::run_health_checker(health_snapshot_rx, health_result_tx, domains).await;
        });
    }

    // Validate resolvers once before the reconnect loop.
    let initial_resolvers = resolve_resolvers(config.resolvers, mtu, config.debug_poll)?;
    if initial_resolvers.is_empty() {
        return Err(ClientError::new("At least one resolver is required"));
    }
    let mut balancer = DomainBalancer::new(config.domains, initial_resolvers.len());
    drop(initial_resolvers);
    info!("Domain balancer created: {}", balancer.summary());

    // Spawn background resolver scanner.
    // Uses the specified scan file if provided and exists, otherwise falls back
    // to built-in default ranges embedded in the binary.
    let (scanner_tx, mut scanner_rx) = mpsc::unbounded_channel::<DiscoveredResolver>();
    {
        let ranges_file = config
            .scan_file
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        let cache_path = config
            .scan_cache
            .map(|s| std::path::PathBuf::from(s))
            .unwrap_or_else(|| std::path::PathBuf::from("scan-cache.json"));
        let scan_config = ScannerConfig {
            ranges_file,
            cache_file: cache_path,
            domains: config.domains.to_vec(),
            interval: Duration::from_secs(config.scan_interval_secs),
            max_discovered: config.scan_max_resolvers,
            mode: ResolverMode::Recursive,
            batch_size: config.scan_batch_size,
        };
        let tx = scanner_tx.clone();
        tokio::spawn(async move {
            run_resolver_scanner(scan_config, tx).await;
        });
    }

    // Track dynamically discovered resolvers (persists across reconnects).
    let mut discovered_resolvers: Vec<(SocketAddr, ResolverMode)> = Vec::new();

    let mut reconnect_count: u64 = 0;

    loop {
        let base_resolvers = resolve_resolvers(config.resolvers, mtu, config.debug_poll)?;
        if base_resolvers.is_empty() {
            return Err(ClientError::new("At least one resolver is required"));
        }

        balancer.resize_resolvers(base_resolvers.len() + discovered_resolvers.len());
        if reconnect_count > 0 {
            info!(
                "Reconnect #{}: balancer state preserved — {}",
                reconnect_count,
                balancer.summary(),
            );
        }
        reconnect_count += 1;

        // ── Tunnel state storage ────────────────────────────────
        // Declared BEFORE _quic_guard so it is dropped AFTER picoquic_delete.
        // Rust drops in reverse declaration order; if states were freed first,
        // picoquic_delete would fire close callbacks on dangling pointers → SEGV.
        let mut _tunnel_states: Vec<Box<ClientState>> = Vec::new();

        let mut local_addr_storage = socket_addr_to_storage(udp.local_addr().map_err(map_io)?);

        let current_time = unsafe { picoquic_current_time() };
        // Shared QUIC context — one context, one connection per tunnel.
        let quic = unsafe {
            picoquic_create(
                8,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                alpn.as_ptr(),
                Some(client_callback),
                std::ptr::null_mut(), // default ctx; overridden per-connection
                None,
                std::ptr::null_mut(),
                std::ptr::null(),
                current_time,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if quic.is_null() {
            let crypto_errors = take_crypto_errors();
            if crypto_errors.is_empty() {
                return Err(ClientError::new("Could not create QUIC context"));
            }
            return Err(ClientError::new(format!(
                "Could not create QUIC context (TLS errors: {})",
                crypto_errors.join("; ")
            )));
        }
        let _quic_guard = QuicGuard::new(quic);
        let mixed_cc = unsafe { slipstream_mixed_cc_algorithm };
        if mixed_cc.is_null() {
            return Err(ClientError::new("Could not load mixed congestion control"));
        }
        unsafe {
            configure_quic_with_custom(quic, mixed_cc, mtu);
            picoquic_enable_path_callbacks_default(quic, 1);
            let override_ptr = cc_override
                .as_ref()
                .map(|value| value.as_ptr())
                .unwrap_or(std::ptr::null());
            slipstream_set_cc_override(override_ptr);
        }
        if let Some(cert) = config.cert {
            configure_pinned_certificate(quic, cert).map_err(ClientError::new)?;
        }

        if config.gso {
            warn!("GSO is not implemented in the Rust client loop yet.");
        }

        // ── Create one tunnel per (resolver, domain) pair ───────────
        let mut pool = TunnelPool::new();

        for (ri, base_res) in base_resolvers.iter().enumerate() {
            for (di, domain) in config.domains.iter().enumerate() {
                let tunnel_id = pool.tunnels.len();
                let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Command>();
                let mut tunnel_state = Box::new(ClientState::new(
                    cmd_tx,
                    data_notify.clone(),
                    debug_streams,
                    acceptor.clone(),
                ));
                let tunnel_state_ptr: *mut ClientState = &mut *tunnel_state;

                unsafe {
                    slipstream_set_default_path_mode(resolver_mode_to_c(base_res.mode));
                }

                let mut server_storage = base_res.storage;
                let cnx = unsafe {
                    picoquic_create_client_cnx(
                        quic,
                        &mut server_storage as *mut _ as *mut libc::sockaddr,
                        current_time,
                        0,
                        sni.as_ptr(),
                        alpn.as_ptr(),
                        Some(client_callback),
                        tunnel_state_ptr as *mut _,
                    )
                };
                if cnx.is_null() {
                    warn!(
                        "Could not create QUIC connection for tunnel[{}] (resolver={} domain={}); skipping",
                        tunnel_id, base_res.addr, domain
                    );
                    continue;
                }

                // Per-tunnel resolver state.
                let mut resolver = crate::dns::resolver::ResolverState {
                    addr: base_res.addr,
                    storage: base_res.storage,
                    local_addr_storage: None,
                    mode: base_res.mode,
                    added: true,
                    path_id: 0,
                    unique_path_id: Some(0),
                    probe_attempts: 0,
                    next_probe_at: 0,
                    pending_polls: 0,
                    inflight_poll_ids: std::collections::HashMap::new(),
                    pacing_budget: match base_res.mode {
                        ResolverMode::Authoritative => {
                            Some(crate::pacing::PacingPollBudget::new(mtu))
                        }
                        ResolverMode::Recursive => None,
                    },
                    last_pacing_snapshot: None,
                    debug: crate::dns::debug::DebugMetrics::new(config.debug_poll),
                };

                apply_path_mode(cnx, &mut resolver)?;

                unsafe {
                    picoquic_set_callback(cnx, Some(client_callback), tunnel_state_ptr as *mut _);
                    picoquic_enable_path_callbacks(cnx, 1);
                    if config.keep_alive_interval > 0 {
                        picoquic_enable_keep_alive(cnx, config.keep_alive_interval as u64 * 1000);
                    } else {
                        picoquic_disable_keep_alive(cnx);
                    }
                }

                pool.tunnels.push(TunnelRoute {
                    id: tunnel_id,
                    resolver_idx: ri,
                    domain_idx: di,
                    domain: domain.clone(),
                    cnx,
                    state_ptr: tunnel_state_ptr,
                    command_rx: cmd_rx,
                    resolver,
                    dns_id: 1,
                    healthy: true,
                    last_activity_at: current_time,
                    flow_blocked_since: 0,
                    stall_rx_snapshot: 0,
                    stall_tx_snapshot: 0,
                    stall_check_at: current_time,
                });
                _tunnel_states.push(tunnel_state);
            }
        }

        // ── Create tunnels for previously discovered resolvers ──────
        for (disc_i, (disc_addr, disc_mode)) in discovered_resolvers.iter().enumerate() {
            let ri = base_resolvers.len() + disc_i;
            let disc_storage = socket_addr_to_storage(*disc_addr);
            for (di, domain) in config.domains.iter().enumerate() {
                let tunnel_id = pool.tunnels.len();
                let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Command>();
                let mut tunnel_state = Box::new(ClientState::new(
                    cmd_tx,
                    data_notify.clone(),
                    debug_streams,
                    acceptor.clone(),
                ));
                let tunnel_state_ptr: *mut ClientState = &mut *tunnel_state;

                unsafe {
                    slipstream_set_default_path_mode(resolver_mode_to_c(*disc_mode));
                }

                let mut server_storage = disc_storage;
                let cnx = unsafe {
                    picoquic_create_client_cnx(
                        quic,
                        &mut server_storage as *mut _ as *mut libc::sockaddr,
                        current_time,
                        0,
                        sni.as_ptr(),
                        alpn.as_ptr(),
                        Some(client_callback),
                        tunnel_state_ptr as *mut _,
                    )
                };
                if cnx.is_null() {
                    warn!(
                        "Could not create QUIC connection for discovered tunnel[{}] (resolver={} domain={}); skipping",
                        tunnel_id, disc_addr, domain
                    );
                    continue;
                }

                let mut resolver = crate::dns::resolver::ResolverState {
                    addr: *disc_addr,
                    storage: disc_storage,
                    local_addr_storage: None,
                    mode: *disc_mode,
                    added: true,
                    path_id: 0,
                    unique_path_id: Some(0),
                    probe_attempts: 0,
                    next_probe_at: 0,
                    pending_polls: 0,
                    inflight_poll_ids: std::collections::HashMap::new(),
                    pacing_budget: match disc_mode {
                        ResolverMode::Authoritative => {
                            Some(crate::pacing::PacingPollBudget::new(mtu))
                        }
                        ResolverMode::Recursive => None,
                    },
                    last_pacing_snapshot: None,
                    debug: crate::dns::debug::DebugMetrics::new(config.debug_poll),
                };

                apply_path_mode(cnx, &mut resolver)?;

                unsafe {
                    picoquic_set_callback(cnx, Some(client_callback), tunnel_state_ptr as *mut _);
                    picoquic_enable_path_callbacks(cnx, 1);
                    if config.keep_alive_interval > 0 {
                        picoquic_enable_keep_alive(cnx, config.keep_alive_interval as u64 * 1000);
                    } else {
                        picoquic_disable_keep_alive(cnx);
                    }
                }

                pool.tunnels.push(TunnelRoute {
                    id: tunnel_id,
                    resolver_idx: ri,
                    domain_idx: di,
                    domain: domain.clone(),
                    cnx,
                    state_ptr: tunnel_state_ptr,
                    command_rx: cmd_rx,
                    resolver,
                    dns_id: 1,
                    healthy: true,
                    last_activity_at: current_time,
                    flow_blocked_since: 0,
                    stall_rx_snapshot: 0,
                    stall_tx_snapshot: 0,
                    stall_check_at: current_time,
                });
                _tunnel_states.push(tunnel_state);
            }
        }
        if !discovered_resolvers.is_empty() {
            info!(
                "Recreated {} discovered resolver tunnels on reconnect",
                discovered_resolvers.len() * config.domains.len(),
            );
        }

        if pool.tunnels.is_empty() {
            return Err(ClientError::new(
                "Could not create any QUIC tunnels; check resolver/domain configuration",
            ));
        }
        info!(
            "Created {} per-route tunnels: {}",
            pool.tunnels.len(),
            pool.summary()
        );

        let mut recv_buf = vec![0u8; 4096];
        let mut send_buf = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];
        // Use per-tunnel burst limits; aggregate across all tunnels.
        let mut packet_loop_send_max =
            (pool.tunnels.len() * PICOQUIC_PACKET_LOOP_SEND_MAX * 2).min(PACKET_LOOP_SEND_CAP);
        let mut packet_loop_recv_max = pool.tunnels.len() * PICOQUIC_PACKET_LOOP_RECV_MAX * 2;
        let mut zero_send_loops = 0u64;
        let mut zero_send_with_streams = 0u64;
        let mut last_flow_block_log_at = 0u64;
        let _last_activity_at = unsafe { picoquic_current_time() };
        let mut last_heartbeat_at = unsafe { picoquic_current_time() };
        let mut last_health_snapshot_at = std::time::Instant::now();
        const HEALTH_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(30);

        'inner: loop {
            let current_time = unsafe { picoquic_current_time() };

            // ── Dispatch new TCP connections to the best tunnel ──────
            while let Ok(cmd) = accept_rx.try_recv() {
                if let Command::NewStream { stream, reservation } = cmd {
                    if let Some(idx) = pool.select_tunnel() {
                        let t = &mut pool.tunnels[idx];
                        info!(
                            "Dispatching TCP connection to {}: ready={} streams={}",
                            t.label(), t.is_ready(), t.streams_len(),
                        );
                        handle_command(
                            t.cnx,
                            t.state_ptr,
                            Command::NewStream { stream, reservation },
                        );
                    } else {
                        warn!(
                            "No healthy tunnel available; dropping TCP connection ({})",
                            pool.summary(),
                        );
                        drop(stream);
                    }
                }
            }

            // ── Per-tunnel: drain stream I/O commands ────────────────
            for tunnel in pool.tunnels.iter_mut() {
                if tunnel.is_closing() {
                    continue;
                }
                drain_commands(tunnel.cnx, tunnel.state_ptr, &mut tunnel.command_rx);
                drain_stream_data(tunnel.cnx, tunnel.state_ptr);
            }

            // Mark closing tunnels as unhealthy so the pool skips them.
            // Only force a full reconnect if ALL tunnels are closing/dead
            // (handled by the all_unhealthy check later).
            for tunnel in pool.tunnels.iter_mut() {
                if tunnel.is_closing() && tunnel.healthy {
                    warn!("{}: connection closed — marking unhealthy", tunnel.label());
                    tunnel.healthy = false;
                    balancer.suspend_resolver(tunnel.resolver_idx);
                }
            }

            // ── Per-tunnel readiness updates ─────────────────────────
            for tunnel in pool.tunnels.iter_mut() {
                if tunnel.is_ready() {
                    unsafe { (*tunnel.state_ptr).update_acceptor_limit(tunnel.cnx) };
                    if reconnect_delay != Duration::from_millis(RECONNECT_SLEEP_MIN_MS) {
                        reconnect_delay = Duration::from_millis(RECONNECT_SLEEP_MIN_MS);
                    }
                }
            }

            // Per-tunnel path events.
            for tunnel in pool.tunnels.iter_mut() {
                drain_path_events(
                    tunnel.cnx,
                    std::slice::from_mut(&mut tunnel.resolver),
                    tunnel.state_ptr,
                    &mut balancer,
                    Some(tunnel.resolver_idx),
                );
            }

            // ── Periodically push per-tunnel snapshot to health checker
            if last_health_snapshot_at.elapsed() >= HEALTH_SNAPSHOT_INTERVAL {
                let snapshot: Vec<TunnelSnapshot> = pool
                    .tunnels
                    .iter()
                    .map(|t| TunnelSnapshot {
                        tunnel_id: t.id,
                        addr: t.resolver.addr,
                        domain: t.domain.clone(),
                    })
                    .collect();
                let _ = health_snapshot_tx.send(snapshot);
                last_health_snapshot_at = std::time::Instant::now();
            }

            // ── Drain per-tunnel health-check results ────────────────
            while let Ok(update) = health_result_rx.try_recv() {
                if let Some(tunnel) = pool.tunnels.get_mut(update.tunnel_id) {
                    let was_healthy = tunnel.healthy;
                    if !update.healthy {
                        // Don't kill an active tunnel just because a probe timed out.
                        // If data flowed recently (within 2× health-check interval),
                        // the QUIC path is obviously alive.
                        let now_us = unsafe { picoquic_current_time() };
                        let idle_us = now_us.saturating_sub(tunnel.last_activity_at);
                        let grace_us = 15_000_000; // 15 s
                        if idle_us < grace_us {
                            debug!(
                                "{}: health probe failed but tunnel active {}s ago — ignoring",
                                tunnel.label(),
                                idle_us / 1_000_000,
                            );
                            continue;
                        }
                    }
                    tunnel.healthy = update.healthy;
                    if update.healthy && !was_healthy {
                        info!("{}: recovered", tunnel.label());
                        balancer.unsuspend_resolver(tunnel.resolver_idx);
                    } else if !update.healthy && was_healthy {
                        warn!("{}: marked unhealthy", tunnel.label());
                        balancer.suspend_resolver(tunnel.resolver_idx);
                    }
                }
            }

            // ── Drain resolver scanner discoveries ───────────────────
            while let Ok(discovered) = scanner_rx.try_recv() {
                let addr = discovered.addr;

                // Skip if already in pool (config or previously discovered).
                if pool.tunnels.iter().any(|t| t.resolver.addr == addr) {
                    debug!("[scanner] {} already in pool; skipping", addr);
                    continue;
                }
                // Skip if it matches a config resolver.
                if base_resolvers.iter().any(|r| r.addr == addr) {
                    debug!("[scanner] {} is a config resolver; skipping", addr);
                    continue;
                }
                // Respect the max-discovered limit.
                if discovered_resolvers.len() >= config.scan_max_resolvers {
                    debug!("[scanner] max discovered reached; ignoring {}", addr);
                    continue;
                }

                info!(
                    "[scanner] adding discovered resolver {} to pool (latency={}ms)",
                    addr,
                    discovered.latency.as_millis(),
                );
                discovered_resolvers.push((addr, discovered.mode));

                let new_ri = balancer.add_resolver();
                let disc_storage = socket_addr_to_storage(addr);

                for (di, domain) in config.domains.iter().enumerate() {
                    let tunnel_id = pool.tunnels.len();
                    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Command>();
                    let mut tunnel_state = Box::new(ClientState::new(
                        cmd_tx,
                        data_notify.clone(),
                        debug_streams,
                        acceptor.clone(),
                    ));
                    let tunnel_state_ptr: *mut ClientState = &mut *tunnel_state;

                    unsafe {
                        slipstream_set_default_path_mode(resolver_mode_to_c(discovered.mode));
                    }

                    let mut server_storage = disc_storage;
                    let cnx = unsafe {
                        picoquic_create_client_cnx(
                            quic,
                            &mut server_storage as *mut _ as *mut libc::sockaddr,
                            current_time,
                            0,
                            sni.as_ptr(),
                            alpn.as_ptr(),
                            Some(client_callback),
                            tunnel_state_ptr as *mut _,
                        )
                    };
                    if cnx.is_null() {
                        warn!(
                            "[scanner] failed to create QUIC tunnel for {} domain={}; skipping",
                            addr, domain,
                        );
                        // Keep state alive so the QUIC context can clean up safely.
                        _tunnel_states.push(tunnel_state);
                        continue;
                    }

                    let mut resolver = crate::dns::resolver::ResolverState {
                        addr,
                        storage: disc_storage,
                        local_addr_storage: None,
                        mode: discovered.mode,
                        added: true,
                        path_id: 0,
                        unique_path_id: Some(0),
                        probe_attempts: 0,
                        next_probe_at: 0,
                        pending_polls: 0,
                        inflight_poll_ids: std::collections::HashMap::new(),
                        pacing_budget: match discovered.mode {
                            ResolverMode::Authoritative => {
                                Some(crate::pacing::PacingPollBudget::new(mtu))
                            }
                            ResolverMode::Recursive => None,
                        },
                        last_pacing_snapshot: None,
                        debug: crate::dns::debug::DebugMetrics::new(config.debug_poll),
                    };

                    if let Err(e) = apply_path_mode(cnx, &mut resolver) {
                        warn!(
                            "[scanner] apply_path_mode failed for {} domain={}: {}; skipping",
                            addr, domain, e,
                        );
                        _tunnel_states.push(tunnel_state);
                        continue;
                    }

                    unsafe {
                        picoquic_set_callback(cnx, Some(client_callback), tunnel_state_ptr as *mut _);
                        picoquic_enable_path_callbacks(cnx, 1);
                        if config.keep_alive_interval > 0 {
                            picoquic_enable_keep_alive(
                                cnx,
                                config.keep_alive_interval as u64 * 1000,
                            );
                        } else {
                            picoquic_disable_keep_alive(cnx);
                        }
                    }

                    pool.tunnels.push(TunnelRoute {
                        id: tunnel_id,
                        resolver_idx: new_ri,
                        domain_idx: di,
                        domain: domain.clone(),
                        cnx,
                        state_ptr: tunnel_state_ptr,
                        command_rx: cmd_rx,
                        resolver,
                        dns_id: 1,
                        healthy: true,
                        last_activity_at: current_time,
                        flow_blocked_since: 0,
                        stall_rx_snapshot: 0,
                        stall_tx_snapshot: 0,
                        stall_check_at: current_time,
                    });
                    _tunnel_states.push(tunnel_state);
                }

                // Update burst limits for the expanded pool.
                packet_loop_send_max =
                    (pool.tunnels.len() * PICOQUIC_PACKET_LOOP_SEND_MAX * 2).min(PACKET_LOOP_SEND_CAP);
                packet_loop_recv_max = pool.tunnels.len() * PICOQUIC_PACKET_LOOP_RECV_MAX * 2;

                info!(
                    "[scanner] resolver {} added as resolver_idx={}, pool: {}",
                    addr,
                    new_ri,
                    pool.summary(),
                );
            }

            // ── Per-tunnel: expire inflight polls ────────────────────
            for tunnel in pool.tunnels.iter_mut() {
                if tunnel.resolver.mode == ResolverMode::Authoritative {
                    expire_inflight_polls(&mut tunnel.resolver.inflight_poll_ids, current_time);
                }
            }

            // ── Sleep timeout calculation ────────────────────────────
            let delay_us =
                unsafe { picoquic_get_next_wake_delay(quic, current_time, DNS_WAKE_DELAY_MAX_US) };
            let delay_us = if delay_us < 0 { 0 } else { delay_us as u64 };
            let mut has_work = pool.total_streams() > 0;
            for tunnel in pool.tunnels.iter_mut() {
                if !refresh_resolver_path(tunnel.cnx, &mut tunnel.resolver) {
                    continue;
                }
                let pending_for_sleep = match tunnel.resolver.mode {
                    ResolverMode::Authoritative => {
                        let quality = fetch_path_quality(tunnel.cnx, &tunnel.resolver);
                        let snapshot = tunnel
                            .resolver
                            .pacing_budget
                            .as_mut()
                            .map(|budget| budget.target_inflight(&quality, delay_us.max(1)));
                        tunnel.resolver.last_pacing_snapshot = snapshot;
                        let target = snapshot
                            .map(|s| s.target_inflight)
                            .unwrap_or_else(|| cwnd_target_polls(quality.cwin, mtu));
                        let inflight_packets =
                            inflight_packet_estimate(quality.bytes_in_transit, mtu);
                        target.saturating_sub(inflight_packets)
                    }
                    ResolverMode::Recursive => tunnel.resolver.pending_polls,
                };
                if pending_for_sleep > 0 {
                    has_work = true;
                }
                if tunnel.resolver.mode == ResolverMode::Authoritative
                    && !tunnel.resolver.inflight_poll_ids.is_empty()
                {
                    has_work = true;
                }
            }
            let timeout_us = if has_work {
                delay_us.clamp(1, DNS_POLL_SLICE_US)
            } else {
                delay_us.max(1)
            };
            let timeout = Duration::from_micros(timeout_us);

            // ── Async select: recv / accept / data / timeout ─────────
            tokio::select! {
                cmd = accept_rx.recv() => {
                    if let Some(Command::NewStream { stream, reservation }) = cmd {
                        if let Some(idx) = pool.select_tunnel() {
                            let t = &mut pool.tunnels[idx];
                            info!(
                                "Dispatching TCP connection (select) to {}: ready={} streams={}",
                                t.label(), t.is_ready(), t.streams_len(),
                            );
                            handle_command(t.cnx, t.state_ptr, Command::NewStream { stream, reservation });
                        } else {
                            warn!("No healthy tunnel; dropping TCP connection ({})", pool.summary());
                        }
                    }
                }
                _ = data_notify.notified() => {}
                recv = udp.recv_from(&mut recv_buf) => {
                    match recv {
                        Ok((size, peer)) => {
                            let mut response_ctx = TunneledResponseContext {
                                quic,
                                local_addr_storage: &local_addr_storage,
                                balancer: &mut balancer,
                            };
                            match handle_dns_response_tunneled(
                                &recv_buf[..size],
                                peer,
                                &mut response_ctx,
                                &mut pool.tunnels,
                            ) {
                                Ok(Some(ti)) => {
                                    pool.tunnels[ti].last_activity_at = unsafe { picoquic_current_time() };
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    warn!("DNS response error: {e}; skipping packet");
                                }
                            }
                            for _ in 1..packet_loop_recv_max {
                                match udp.try_recv_from(&mut recv_buf) {
                                    Ok((size, peer)) => {
                                        match handle_dns_response_tunneled(
                                            &recv_buf[..size],
                                            peer,
                                            &mut response_ctx,
                                            &mut pool.tunnels,
                                        ) {
                                            Ok(Some(ti)) => {
                                                pool.tunnels[ti].last_activity_at = unsafe { picoquic_current_time() };
                                            }
                                            Ok(None) => {}
                                            Err(e) => {
                                                warn!("DNS response error (burst): {e}; stopping burst");
                                                break;
                                            }
                                        }
                                    }
                                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                                    Err(err) => {
                                        if is_transient_udp_error(&err) {
                                            break;
                                        }
                                        warn!("Non-transient UDP recv error: {err}; will reconnect");
                                        break 'inner;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if !is_transient_udp_error(&err) {
                                warn!("Non-transient UDP recv_from error: {err}; will reconnect");
                                break 'inner;
                            }
                        }
                    }
                }
                _ = sleep(timeout) => {}
            }

            // ── Post-select: drain all tunnels ───────────────────────
            for tunnel in pool.tunnels.iter_mut() {
                if tunnel.is_closing() {
                    continue;
                }
                drain_commands(tunnel.cnx, tunnel.state_ptr, &mut tunnel.command_rx);
                drain_stream_data(tunnel.cnx, tunnel.state_ptr);
                drain_path_events(
                    tunnel.cnx,
                    std::slice::from_mut(&mut tunnel.resolver),
                    tunnel.state_ptr,
                    &mut balancer,
                    Some(tunnel.resolver_idx),
                );
            }

            // ── Send phase: prepare packets from shared QUIC context ─
            // picoquic_prepare_next_packet_ex returns which cnx it
            // prepared for — we map that to a tunnel for DNS encoding.
            'send: for _ in 0..packet_loop_send_max {
                let current_time = unsafe { picoquic_current_time() };
                let mut send_length: libc::size_t = 0;
                let mut addr_to: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut addr_from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut if_index: libc::c_int = 0;
                let mut log_cid = picoquic_connection_id_t {
                    id: [0; PICOQUIC_CONNECTION_ID_MAX_SIZE],
                    id_len: 0,
                };
                let mut last_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();

                let ret = unsafe {
                    picoquic_prepare_next_packet_ex(
                        quic,
                        current_time,
                        send_buf.as_mut_ptr(),
                        send_buf.len(),
                        &mut send_length,
                        &mut addr_to,
                        &mut addr_from,
                        &mut if_index,
                        &mut log_cid,
                        &mut last_cnx,
                        std::ptr::null_mut(),
                    )
                };
                if ret < 0 {
                    warn!("Failed preparing outbound QUIC packet (ret={ret}); will reconnect");
                    break 'inner;
                }
                if send_length == 0 {
                    zero_send_loops = zero_send_loops.saturating_add(1);
                    let total_streams = pool.total_streams();
                    if total_streams > 0 {
                        zero_send_with_streams = zero_send_with_streams.saturating_add(1);
                        // Nudge pending_polls on blocked recursive tunnels.
                        for tunnel in pool.tunnels.iter_mut() {
                            let flow_blocked =
                                unsafe { slipstream_is_flow_blocked(tunnel.cnx) } != 0;
                            if flow_blocked
                                && tunnel.resolver.mode == ResolverMode::Recursive
                                && tunnel.resolver.added
                            {
                                tunnel.resolver.pending_polls =
                                    tunnel.resolver.pending_polls.max(1);
                            }
                        }
                    }
                    break;
                }

                if addr_to.ss_family == 0 {
                    break;
                }

                // Map last_cnx → tunnel to determine which domain to use.
                let tunnel_idx = pool.find_by_cnx(last_cnx);
                let (selected_domain, dns_id_for_pkt) = if let Some(ti) = tunnel_idx {
                    let tunnel = &mut pool.tunnels[ti];
                    tunnel.resolver.local_addr_storage =
                        Some(unsafe { std::ptr::read(&addr_from) });
                    tunnel.resolver.debug.send_packets =
                        tunnel.resolver.debug.send_packets.saturating_add(1);
                    tunnel.resolver.debug.send_bytes = tunnel
                        .resolver
                        .debug
                        .send_bytes
                        .saturating_add(send_length as u64);
                    let domain = tunnel.domain.clone();
                    let id = tunnel.dns_id;
                    tunnel.dns_id = id.wrapping_add(1);
                    (domain, id)
                } else {
                    // Fallback: first domain (should not happen in normal operation).
                    let domain = config.domains.first().cloned().unwrap_or_else(|| "unknown.com".to_string());
                    (domain, 0)
                };

                let qname = match build_qname(&send_buf[..send_length], &selected_domain) {
                    Ok(q) => q,
                    Err(err) => {
                        warn!("Failed to build DNS query name: {err}; skipping packet");
                        tokio::task::yield_now().await;
                        continue 'send;
                    }
                };
                let params = QueryParams {
                    id: dns_id_for_pkt,
                    qname: &qname,
                    qtype: RR_TXT,
                    qclass: CLASS_IN,
                    rd: true,
                    cd: false,
                    qdcount: 1,
                    is_query: true,
                };
                let packet = match encode_query(&params) {
                    Ok(p) => p,
                    Err(err) => {
                        warn!("Failed to encode DNS query: {err}; skipping packet");
                        tokio::task::yield_now().await;
                        continue 'send;
                    }
                };

                let dest = match sockaddr_storage_to_socket_addr(&addr_to) {
                    Ok(d) => normalize_dual_stack_addr(d),
                    Err(err) => {
                        warn!("Failed to parse dest address: {err}; skipping packet");
                        tokio::task::yield_now().await;
                        continue 'send;
                    }
                };
                local_addr_storage = addr_from;
                if let Err(err) = udp.send_to(&packet, dest).await {
                    if !is_transient_udp_error(&err) {
                        warn!("Non-transient UDP send error: {err}; will reconnect");
                        break 'inner;
                    }
                }
            }

            // ── Per-tunnel flow-blocked detection + auto-recovery ─────
            for tunnel in pool.tunnels.iter_mut() {
                if !tunnel.healthy || tunnel.is_closing() {
                    continue;
                }
                let has_ready_stream =
                    unsafe { slipstream_has_ready_stream(tunnel.cnx) != 0 };
                let flow_blocked =
                    unsafe { slipstream_is_flow_blocked(tunnel.cnx) != 0 };
                let streams_len = tunnel.streams_len();
                let now = unsafe { picoquic_current_time() };

                if streams_len > 0 && has_ready_stream && flow_blocked {
                    // Track when flow_blocked first started.
                    if tunnel.flow_blocked_since == 0 {
                        tunnel.flow_blocked_since = now;
                    }
                    let blocked_dur = now.saturating_sub(tunnel.flow_blocked_since);

                    if now.saturating_sub(last_flow_block_log_at) >= FLOW_BLOCKED_LOG_INTERVAL_US {
                        error!(
                            "{}: flow blocked for {}s, streams={}",
                            tunnel.label(),
                            blocked_dur / 1_000_000,
                            streams_len,
                        );
                        last_flow_block_log_at = now;
                    }

                    // If stuck for too long, mark unhealthy so we reconnect.
                    if blocked_dur >= FLOW_BLOCKED_KILL_US {
                        warn!(
                            "{}: flow blocked for {}s — marking unhealthy for reconnect",
                            tunnel.label(),
                            blocked_dur / 1_000_000,
                        );
                        tunnel.healthy = false;
                        balancer.suspend_resolver(tunnel.resolver_idx);
                    }
                } else {
                    // Clear the tracker when flow is unblocked.
                    tunnel.flow_blocked_since = 0;
                }
            }

            // ── Per-tunnel poll queries ──────────────────────────────
            for tunnel_idx in 0..pool.tunnels.len() {
                let tunnel = &mut pool.tunnels[tunnel_idx];
                // Skip dead tunnels — don't waste DNS queries.
                if tunnel.is_closing() || !tunnel.healthy {
                    continue;
                }
                if !refresh_resolver_path(tunnel.cnx, &mut tunnel.resolver) {
                    continue;
                }
                let has_ready_stream =
                    unsafe { slipstream_has_ready_stream(tunnel.cnx) != 0 };
                let flow_blocked =
                    unsafe { slipstream_is_flow_blocked(tunnel.cnx) != 0 };

                match tunnel.resolver.mode {
                    ResolverMode::Authoritative => {
                        let quality = fetch_path_quality(tunnel.cnx, &tunnel.resolver);
                        let snapshot = tunnel.resolver.last_pacing_snapshot;
                        let pacing_target = snapshot
                            .map(|s| s.target_inflight)
                            .unwrap_or_else(|| cwnd_target_polls(quality.cwin, mtu));
                        let inflight_packets =
                            inflight_packet_estimate(quality.bytes_in_transit, mtu);
                        let mut poll_deficit = pacing_target.saturating_sub(inflight_packets);
                        if has_ready_stream && !flow_blocked {
                            poll_deficit = 0;
                        }
                        if poll_deficit > 0 {
                            let burst_max = path_poll_burst_max(&tunnel.resolver);
                            let mut to_send = poll_deficit.min(burst_max);
                            if let Err(e) = send_poll_queries(
                                tunnel.cnx,
                                &udp,
                                &mut balancer,
                                tunnel.resolver_idx,
                                Some(tunnel.domain_idx),
                                &mut local_addr_storage,
                                &mut tunnel.dns_id,
                                &mut tunnel.resolver,
                                &mut to_send,
                                &mut send_buf,
                            )
                            .await
                            {
                                warn!("{}: poll query failed: {e}; marking unhealthy", tunnel.label());
                                pool.tunnels[tunnel_idx].healthy = false;
                            }
                        }
                    }
                    ResolverMode::Recursive => {
                        tunnel.resolver.last_pacing_snapshot = None;
                        // Keepalive: idle recursive tunnels need at least 1
                        // poll periodically so the QUIC connection stays warm
                        // and the watchdog doesn't kill them.
                        if tunnel.resolver.pending_polls == 0 && tunnel.is_ready() {
                            let now_ka = unsafe { picoquic_current_time() };
                            let idle_us = now_ka.saturating_sub(tunnel.last_activity_at);
                            if idle_us >= KEEPALIVE_POLL_INTERVAL_US {
                                tunnel.resolver.pending_polls = 1;
                            }
                        }
                        if tunnel.resolver.pending_polls > 0 {
                            let burst_max = path_poll_burst_max(&tunnel.resolver);
                            let to_send_count = tunnel.resolver.pending_polls.min(burst_max);
                            let mut to_send = to_send_count;
                            if let Err(e) = send_poll_queries(
                                tunnel.cnx,
                                &udp,
                                &mut balancer,
                                tunnel.resolver_idx,
                                Some(tunnel.domain_idx),
                                &mut local_addr_storage,
                                &mut tunnel.dns_id,
                                &mut tunnel.resolver,
                                &mut to_send,
                                &mut send_buf,
                            )
                            .await
                            {
                                warn!("{}: poll query failed: {e}; marking unhealthy", tunnel.label());
                                pool.tunnels[tunnel_idx].healthy = false;
                            } else {
                                let sent = to_send_count.saturating_sub(to_send);
                                tunnel.resolver.pending_polls = tunnel
                                    .resolver
                                    .pending_polls
                                    .saturating_sub(sent);
                            }
                        }
                    }
                }
            }

            // ── Per-tunnel debug reporting ───────────────────────────
            let report_time = unsafe { picoquic_current_time() };
            for tunnel in pool.tunnels.iter_mut() {
                let (enqueued_bytes, last_enqueue_at) =
                    unsafe { (*tunnel.state_ptr).debug_snapshot() };
                let streams_len = tunnel.streams_len();
                tunnel.resolver.debug.enqueued_bytes = enqueued_bytes;
                tunnel.resolver.debug.last_enqueue_at = last_enqueue_at;
                tunnel.resolver.debug.zero_send_loops = zero_send_loops;
                tunnel.resolver.debug.zero_send_with_streams = zero_send_with_streams;
                if !refresh_resolver_path(tunnel.cnx, &mut tunnel.resolver) {
                    continue;
                }
                let inflight_polls = tunnel.resolver.inflight_poll_ids.len();
                let pending_for_debug = match tunnel.resolver.mode {
                    ResolverMode::Authoritative => {
                        let quality = fetch_path_quality(tunnel.cnx, &tunnel.resolver);
                        let inflight_packets =
                            inflight_packet_estimate(quality.bytes_in_transit, mtu);
                        tunnel
                            .resolver
                            .last_pacing_snapshot
                            .map(|s| s.target_inflight.saturating_sub(inflight_packets))
                            .unwrap_or(0)
                    }
                    ResolverMode::Recursive => tunnel.resolver.pending_polls,
                };
                let snap = tunnel.resolver.last_pacing_snapshot;
                maybe_report_debug(
                    &mut tunnel.resolver,
                    report_time,
                    streams_len,
                    pending_for_debug,
                    inflight_polls,
                    snap,
                );
            }

            // ── Periodic heartbeat (diagnostics) ─────────────────────
            let now_wd = unsafe { picoquic_current_time() };
            if now_wd.saturating_sub(last_heartbeat_at) >= HEARTBEAT_INTERVAL_US {
                last_heartbeat_at = now_wd;
                let healthy_count = pool.tunnels.iter().filter(|t| t.healthy).count();
                let ready_count = pool.tunnels.iter().filter(|t| t.is_ready()).count();
                let total_streams = pool.total_streams();
                info!(
                    "heartbeat: tunnels={} healthy={} ready={} streams={}",
                    pool.tunnels.len(), healthy_count, ready_count, total_streams,
                );
            }

            // ── Per-tunnel watchdog ──────────────────────────────────
            for tunnel in pool.tunnels.iter_mut() {
                // Only warn once — skip tunnels already marked unhealthy.
                if tunnel.healthy
                    && now_wd.saturating_sub(tunnel.last_activity_at) >= WATCHDOG_TIMEOUT_US
                {
                    warn!(
                        "{}: no activity for {}s; marking unhealthy",
                        tunnel.label(),
                        WATCHDOG_TIMEOUT_US / 1_000_000,
                    );
                    tunnel.healthy = false;
                    balancer.suspend_resolver(tunnel.resolver_idx);
                }
            }

            // ── Per-tunnel throughput stall detection ─────────────────
            // If a tunnel has active streams but no bytes are moving
            // (send_bytes + dns_responses unchanged), it's stalled.
            for tunnel in pool.tunnels.iter_mut() {
                if !tunnel.healthy || tunnel.is_closing() {
                    continue;
                }
                let streams_len = tunnel.streams_len();
                if streams_len == 0 {
                    // No streams → reset snapshot, nothing to stall on.
                    tunnel.stall_rx_snapshot = tunnel.resolver.debug.dns_responses;
                    tunnel.stall_tx_snapshot = tunnel.resolver.debug.send_bytes;
                    tunnel.stall_check_at = now_wd;
                    continue;
                }
                let cur_rx = tunnel.resolver.debug.dns_responses;
                let cur_tx = tunnel.resolver.debug.send_bytes;
                if cur_rx != tunnel.stall_rx_snapshot || cur_tx != tunnel.stall_tx_snapshot {
                    // Progress — update snapshot.
                    tunnel.stall_rx_snapshot = cur_rx;
                    tunnel.stall_tx_snapshot = cur_tx;
                    tunnel.stall_check_at = now_wd;
                } else {
                    // No progress — check how long.
                    let stall_dur = now_wd.saturating_sub(tunnel.stall_check_at);
                    if stall_dur >= THROUGHPUT_STALL_US {
                        warn!(
                            "{}: throughput stall for {}s with {} streams — marking unhealthy",
                            tunnel.label(),
                            stall_dur / 1_000_000,
                            streams_len,
                        );
                        tunnel.healthy = false;
                        balancer.suspend_resolver(tunnel.resolver_idx);
                    }
                }
            }

            if pool.all_unhealthy() {
                warn!("All tunnels unhealthy; forcing reconnect");
                break 'inner;
            }
        }

        // ── Cleanup: close all tunnel connections ────────────────────
        for tunnel in pool.tunnels.iter_mut() {
            unsafe {
                // Only close tunnels that are not already disconnected;
                // calling picoquic_close on a disconnected cnx is UB.
                if !(*tunnel.state_ptr).is_closing() {
                    picoquic_close(tunnel.cnx, 0);
                }
                (*tunnel.state_ptr).reset_for_reconnect();
            }
        }
        // Drain stale commands from the shared accept channel.
        let mut dropped = 0usize;
        while let Ok(_cmd) = accept_rx.try_recv() {
            dropped += 1;
        }
        // Also drain per-tunnel command channels.
        for tunnel in pool.tunnels.iter_mut() {
            while let Ok(_cmd) = tunnel.command_rx.try_recv() {
                dropped += 1;
            }
        }
        if dropped > 0 {
            warn!("Dropped {} queued commands while reconnecting", dropped);
        }
        warn!(
            "Connection closed; reconnecting in {}ms ({})",
            reconnect_delay.as_millis(),
            pool.summary(),
        );
        let jitter_us = unsafe { picoquic_current_time() };
        let base_ms = reconnect_delay.as_millis() as u64;
        let jitter_ms = jitter_us % (base_ms / 2 + 1);
        let jittered_delay = reconnect_delay + Duration::from_millis(jitter_ms);
        let mut remaining_sleep = jittered_delay;
        while remaining_sleep > Duration::ZERO {
            let chunk = remaining_sleep.min(Duration::from_millis(100));
            sleep(chunk).await;
            remaining_sleep -= chunk;
            while let Ok(_) = accept_rx.try_recv() {}
        }
        reconnect_delay = (reconnect_delay * 2).min(Duration::from_millis(RECONNECT_SLEEP_MAX_MS));
    }
}
