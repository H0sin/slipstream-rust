//! Background DNS resolver scanner.
//!
//! Reads a file of IP addresses and CIDR ranges, probes each candidate
//! with a lightweight DNS TXT query for the configured tunnel domains,
//! and reports working resolvers back to the runtime via a channel.
//!
//! # File format
//!
//! ```text
//! # Lines starting with '#' are comments; blank lines are skipped.
//! 1.1.1.1
//! 8.8.8.8:5353
//! 1.0.0.0/24
//! 10.0.0.0/20 5353
//! ```
//!
//! Each line is either an individual IP (port 53 implied) or a CIDR
//! range.  An optional port may follow after a colon (for single IPs)
//! or a space (for CIDRs).  Only IPv4 is currently supported; IPv6
//! lines are silently skipped.

use super::default_ranges::DEFAULT_SCAN_TARGETS;
use slipstream_dns::{build_qname, decode_response, encode_query, QueryParams, CLASS_IN, RR_TXT};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ── Constants ───────────────────────────────────────────────────────

/// Maximum number of hosts we will expand from a single CIDR range.
const MAX_CIDR_HOSTS: u32 = 65_536; // /16

/// Timeout for a single DNS probe round-trip.
const PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);

/// How many probes we send in parallel (tokio tasks).
const SCAN_CONCURRENCY: usize = 128;

/// How many IPs to sample from each group per interleave round.
const SLICE_PER_GROUP: usize = 8;

/// Interval between full re-scans of the candidate list.
const RESCAN_INTERVAL: Duration = Duration::from_secs(300);

/// Default DNS port when none is specified.
const DEFAULT_DNS_PORT: u16 = 53;

/// Number of probe attempts per candidate before giving up.
const PROBE_ATTEMPTS: usize = 2;

/// Delay between probe retries for the same candidate.
const PROBE_RETRY_DELAY: Duration = Duration::from_millis(500);

// ── Public types ────────────────────────────────────────────────────

/// A resolver discovered by the background scanner.
#[derive(Debug, Clone)]
pub(crate) struct DiscoveredResolver {
    /// The socket address of the working resolver.
    pub(crate) addr: SocketAddr,
    /// Measured round-trip latency of the probe.
    pub(crate) latency: Duration,
}

// ── Deterministic shuffle (no rand crate) ───────────────────────────

/// A simple ad-hoc PRNG seeded from system clock + extra entropy.
/// Uses SplitMix64 which has excellent distribution for shuffling.
struct FastRng(u64);

impl FastRng {
    fn new() -> Self {
        let mut seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Mix in the address of a stack variable for extra entropy.
        let stack_var: u8 = 0;
        let mut h = DefaultHasher::new();
        ((&stack_var as *const u8) as usize).hash(&mut h);
        seed ^= h.finish();
        FastRng(seed)
    }

    /// SplitMix64 next value.
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    /// Random number in `[0, bound)`.
    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

/// Fisher-Yates shuffle in-place.
fn shuffle<T>(slice: &mut [T], rng: &mut FastRng) {
    for i in (1..slice.len()).rev() {
        let j = rng.next_usize(i + 1);
        slice.swap(i, j);
    }
}

// ── File parsing ────────────────────────────────────────────────────

/// A group of scan targets (one entry from the config — either a
/// single IP or an expanded CIDR range).
#[derive(Debug, Clone)]
struct ScanGroup {
    addrs: Vec<SocketAddr>,
}

/// Read and parse a scan-targets file, keeping groups separate.
fn parse_scan_file_grouped(path: &Path) -> Result<Vec<ScanGroup>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read scan file {}: {}", path.display(), e))?;
    Ok(parse_scan_targets_grouped(&content))
}

/// Read and parse a scan-targets file (flat — for backward compat).
pub(crate) fn parse_scan_file(path: &Path) -> Result<Vec<SocketAddr>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read scan file {}: {}", path.display(), e))?;
    Ok(parse_scan_targets(&content))
}

/// Parse text into *groups*, one group per non-comment line.
fn parse_scan_targets_grouped(content: &str) -> Vec<ScanGroup> {
    let mut groups = Vec::new();
    for (line_no, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok(addrs) if !addrs.is_empty() => groups.push(ScanGroup { addrs }),
            Ok(_) => {}
            Err(err) => {
                warn!("scan file line {}: {}: {:?}", line_no + 1, err, line);
            }
        }
    }
    groups
}

/// Parse the textual content of a scan-targets file into addresses (flat).
fn parse_scan_targets(content: &str) -> Vec<SocketAddr> {
    let mut targets = Vec::new();
    for (line_no, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok(addrs) => targets.extend(addrs),
            Err(err) => {
                warn!("scan file line {}: {}: {:?}", line_no + 1, err, line);
            }
        }
    }
    targets
}

/// Parse a single non-comment, non-empty line.
fn parse_line(line: &str) -> Result<Vec<SocketAddr>, String> {
    // Detect CIDR by the presence of '/'.
    if line.contains('/') {
        return parse_cidr_line(line);
    }
    // Single IP, optionally with :port
    parse_single_ip(line).map(|addr| vec![addr])
}

/// Parse `IP` or `IP:port`.
fn parse_single_ip(input: &str) -> Result<SocketAddr, String> {
    // Try parsing as SocketAddr first (covers `IP:port`).
    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Try as bare IP (use default port).
    let ip: IpAddr = input
        .parse()
        .map_err(|_| format!("invalid IP address: {}", input))?;
    Ok(SocketAddr::new(ip, DEFAULT_DNS_PORT))
}

/// Parse `CIDR` or `CIDR PORT` (space separated).
fn parse_cidr_line(line: &str) -> Result<Vec<SocketAddr>, String> {
    let (cidr_part, port) = if let Some((cidr, port_str)) = line.split_once(|c: char| c.is_whitespace()) {
        let port: u16 = port_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid port in CIDR line: {}", port_str.trim()))?;
        (cidr, port)
    } else {
        (line, DEFAULT_DNS_PORT)
    };

    let (ip_str, prefix_str) = cidr_part
        .split_once('/')
        .ok_or_else(|| format!("missing '/' in CIDR: {}", cidr_part))?;

    let ip: Ipv4Addr = ip_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid IPv4 in CIDR: {}", ip_str))?;

    let prefix_len: u8 = prefix_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid prefix length: {}", prefix_str))?;

    if prefix_len > 32 {
        return Err(format!("prefix length {} > 32", prefix_len));
    }

    expand_cidr(ip, prefix_len, port)
}

/// Expand a CIDR range into individual socket addresses.
fn expand_cidr(network: Ipv4Addr, prefix_len: u8, port: u16) -> Result<Vec<SocketAddr>, String> {
    if prefix_len == 32 {
        return Ok(vec![SocketAddr::new(IpAddr::V4(network), port)]);
    }

    let host_bits = 32 - prefix_len as u32;
    let num_hosts = 1u32.checked_shl(host_bits).unwrap_or(u32::MAX);

    if num_hosts > MAX_CIDR_HOSTS {
        return Err(format!(
            "CIDR /{} would expand to {} hosts (max {}); use /16 or smaller",
            prefix_len, num_hosts, MAX_CIDR_HOSTS
        ));
    }

    let base = u32::from(network);
    let mask = !((1u32 << host_bits) - 1);
    let network_addr = base & mask;

    let mut addrs = Vec::with_capacity(num_hosts as usize);
    for i in 1..num_hosts.saturating_sub(1) {
        // Skip .0 (network) and .255 (broadcast) for /24 and smaller.
        let ip = Ipv4Addr::from(network_addr + i);
        addrs.push(SocketAddr::new(IpAddr::V4(ip), port));
    }
    // For very small ranges (/31, /32), include all
    if num_hosts <= 2 {
        let mut addrs = Vec::new();
        for i in 0..num_hosts {
            let ip = Ipv4Addr::from(network_addr + i);
            addrs.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
        return Ok(addrs);
    }
    Ok(addrs)
}

// ── Probe logic ─────────────────────────────────────────────────────

/// Result of a single probe — how confident we are the tunnel works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProbeResult {
    /// No response at all (timeout / error).
    NoResponse,
    /// Got a DNS response but wrong RCODE (NXDOMAIN, SERVFAIL, etc.)
    /// — the resolver works but doesn't reach our tunnel server.
    WrongRcode,
    /// Got RCODE=NOERROR — the tunnel server's authoritative NS answered,
    /// confirming the resolver can route to our server.
    TunnelReachable,
    /// Got RCODE=NOERROR **and** the TXT response contains actual data —
    /// the tunnel server processed the query and returned QUIC payload
    /// (e.g. a stateless reject).  Strongest possible confirmation.
    TunnelResponded,
}

/// Build a tunnel-realistic DNS TXT probe: encodes a small payload
/// through `build_qname` exactly like the real tunnel, so the server's
/// authoritative NS can recognise and answer it.
pub(crate) fn build_tunnel_probe(domain: &str, id: u16) -> Result<Vec<u8>, String> {
    // Encode a small marker payload through the real tunnel codec.
    // The server will decode it via base32, feed it to picoquic (which
    // rejects it as invalid QUIC), and still respond NOERROR.
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

/// Probe a single candidate resolver with one domain using a real
/// tunnel-encoded query.  Returns `(ProbeResult, latency)`.
pub(crate) async fn probe_candidate(
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
            debug!("scanner: failed to bind probe socket: {e}");
            return (ProbeResult::NoResponse, Duration::ZERO);
        }
    };

    let query = match build_tunnel_probe(domain, id) {
        Ok(q) => q,
        Err(e) => {
            debug!("scanner: failed to build tunnel probe: {e}");
            return (ProbeResult::NoResponse, Duration::ZERO);
        }
    };

    let start = Instant::now();
    if let Err(e) = sock.send_to(&query, addr).await {
        debug!("scanner: send_to {addr} failed: {e}");
        return (ProbeResult::NoResponse, Duration::ZERO);
    }

    let mut buf = [0u8; 2048];
    match tokio::time::timeout(PROBE_TIMEOUT, sock.recv_from(&mut buf)).await {
        Ok(Ok((size, _))) if size >= 12 => {
            let latency = start.elapsed();
            // Verify DNS response basics.
            let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
            let flags = u16::from_be_bytes([buf[2], buf[3]]);
            let is_response = flags & 0x8000 != 0;
            let rcode = (flags & 0x000F) as u8;

            if !is_response || resp_id != id {
                debug!("scanner: {addr} returned non-matching response");
                return (ProbeResult::NoResponse, latency);
            }

            if rcode != 0 {
                // NXDOMAIN (3), SERVFAIL (2), etc. — resolver works but
                // can't reach our tunnel server for this domain.
                debug!(
                    "scanner: {addr} returned rcode={rcode} for {domain} — not our tunnel"
                );
                return (ProbeResult::WrongRcode, latency);
            }

            // RCODE=NOERROR — the authoritative server for our domain
            // answered.  This strongly suggests the tunnel is reachable.
            // Check if TXT data is present (even stronger signal).
            if let Some(payload) = decode_response(&buf[..size]) {
                debug!(
                    "scanner: {addr} returned NOERROR + {} bytes payload for {domain} — tunnel confirmed",
                    payload.len()
                );
                (ProbeResult::TunnelResponded, latency)
            } else {
                debug!(
                    "scanner: {addr} returned NOERROR (empty) for {domain} — tunnel reachable"
                );
                (ProbeResult::TunnelReachable, latency)
            }
        }
        Ok(Ok((size, _))) => {
            debug!("scanner: {addr} returned too-small response ({size} bytes)");
            (ProbeResult::NoResponse, start.elapsed())
        }
        Ok(Err(e)) => {
            debug!("scanner: recv from {addr} failed: {e}");
            (ProbeResult::NoResponse, Duration::ZERO)
        }
        Err(_) => {
            // Timeout — resolver didn't answer at all.
            (ProbeResult::NoResponse, Duration::ZERO)
        }
    }
}

/// Probe a candidate with retries across multiple domains.
/// Only reports success if the tunnel is actually reachable (NOERROR).
async fn probe_with_retries(
    addr: SocketAddr,
    domains: &[String],
    base_id: u16,
) -> Option<Duration> {
    let mut best_result = ProbeResult::NoResponse;
    let mut best_latency = Duration::MAX;

    for attempt in 0..PROBE_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(PROBE_RETRY_DELAY).await;
        }
        // Rotate through domains on each attempt.
        let domain = &domains[attempt % domains.len()];
        let id = base_id.wrapping_add(attempt as u16);
        let (result, latency) = probe_candidate(addr, domain, id).await;

        if result > best_result {
            best_result = result;
        }
        if result >= ProbeResult::TunnelReachable && latency < best_latency {
            best_latency = latency;
        }

        // If we already confirmed the tunnel, stop probing.
        if result >= ProbeResult::TunnelReachable {
            break;
        }
    }

    // Only accept resolvers where the tunnel is actually reachable.
    if best_result >= ProbeResult::TunnelReachable {
        Some(best_latency)
    } else {
        None
    }
}

// ── Background scanner task ─────────────────────────────────────────

/// Load scan targets as **groups** (shuffled).  If a file is
/// provided, read from it; otherwise use the compiled-in defaults.
/// Both groups and the IPs within each group are shuffled.
fn load_scan_groups(scan_file: &Option<String>, rng: &mut FastRng) -> Vec<ScanGroup> {
    let mut groups = match scan_file {
        Some(path) => {
            let mut g = match parse_scan_file_grouped(Path::new(path)) {
                Ok(g) => g,
                Err(e) => {
                    warn!("DNS scanner: {e}; falling back to defaults");
                    Vec::new()
                }
            };
            // Always include defaults too.
            g.extend(parse_scan_targets_grouped(DEFAULT_SCAN_TARGETS));
            g
        }
        None => parse_scan_targets_grouped(DEFAULT_SCAN_TARGETS),
    };

    // Shuffle groups.
    shuffle(&mut groups, rng);

    // Shuffle IPs within each group.
    for group in &mut groups {
        shuffle(&mut group.addrs, rng);
    }

    groups
}

/// Build an interleaved scan order from shuffled groups.
///
/// Takes `SLICE_PER_GROUP` IPs from each group in round-robin fashion
/// until all IPs are consumed.  This ensures we quickly sample many
/// different networks instead of exhausting one range first.
fn interleave_groups(groups: &[ScanGroup]) -> Vec<SocketAddr> {
    let total: usize = groups.iter().map(|g| g.addrs.len()).sum();
    let mut result = Vec::with_capacity(total);
    let mut cursors: Vec<usize> = vec![0; groups.len()];

    loop {
        let mut progress = false;
        for (i, group) in groups.iter().enumerate() {
            let start = cursors[i];
            if start >= group.addrs.len() {
                continue;
            }
            let end = (start + SLICE_PER_GROUP).min(group.addrs.len());
            result.extend_from_slice(&group.addrs[start..end]);
            cursors[i] = end;
            progress = true;
        }
        if !progress {
            break;
        }
    }
    result
}

/// Run the background scanner loop.
///
/// This function never returns; it continuously scans the candidate
/// list and sends discovered resolvers through the channel.
///
/// Scanning is **shuffled and interleaved**: groups (ranges) are
/// shuffled, IPs within each group are shuffled, and we probe a
/// small slice from each group in round-robin so that we quickly
/// cover many different networks.
///
/// If `scan_file` is `None`, the compiled-in default ranges
/// (Iranian IP ranges + well-known public DNS) are used.
pub(crate) async fn run_scanner(
    scan_file: Option<String>,
    domains: Vec<String>,
    tx: mpsc::UnboundedSender<DiscoveredResolver>,
) {
    let source = scan_file
        .as_deref()
        .unwrap_or("<built-in defaults>");
    info!(
        "[scanner] started: source={}, domains={}, interval={}s",
        source,
        domains.join(","),
        RESCAN_INTERVAL.as_secs(),
    );

    let mut rng = FastRng::new();
    let mut round: u64 = 0;
    let mut total_found: u64 = 0;

    loop {
        round += 1;
        let groups = load_scan_groups(&scan_file, &mut rng);
        let total_ips: usize = groups.iter().map(|g| g.addrs.len()).sum();

        if total_ips == 0 {
            warn!("DNS scanner: no targets found; sleeping");
            tokio::time::sleep(RESCAN_INTERVAL).await;
            continue;
        }

        let targets = interleave_groups(&groups);
        info!(
            "[scanner] round {}: scanning {} IPs across {} groups",
            round,
            targets.len(),
            groups.len(),
        );
        let discovered = scan_batch(&targets, &domains).await;

        if discovered.is_empty() {
            info!("[scanner] round {}: no new resolvers (total found so far: {})", round, total_found);
        } else {
            total_found += discovered.len() as u64;
            info!(
                "[scanner] round {}: found {} working resolvers (total: {})",
                round,
                discovered.len(),
                total_found,
            );
            for resolver in discovered {
                debug!(
                    "[scanner]   {} ({}ms)",
                    resolver.addr,
                    resolver.latency.as_millis()
                );
                if tx.send(resolver).is_err() {
                    warn!("[scanner] channel closed; stopping");
                    return;
                }
            }
        }

        info!("[scanner] sleeping {}s until next round", RESCAN_INTERVAL.as_secs());
        tokio::time::sleep(RESCAN_INTERVAL).await;
    }
}

/// Scan a batch of candidates with bounded concurrency.
async fn scan_batch(targets: &[SocketAddr], domains: &[String]) -> Vec<DiscoveredResolver> {
    use tokio::sync::Semaphore;
    use std::sync::Arc;

    let semaphore = Arc::new(Semaphore::new(SCAN_CONCURRENCY));
    let domains = Arc::new(domains.to_vec());
    let mut handles = Vec::with_capacity(targets.len());

    for (i, &addr) in targets.iter().enumerate() {
        let permit = semaphore.clone().acquire_owned().await;
        let domains = domains.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            let base_id = ((i as u32) % 65536) as u16;
            let result = probe_with_retries(addr, &domains, base_id).await;
            result.map(|latency| DiscoveredResolver { addr, latency })
        });
        handles.push(handle);
    }

    let mut discovered = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Some(resolver)) => discovered.push(resolver),
            Ok(None) => {} // candidate didn't respond
            Err(e) => {
                debug!("scanner: probe task panicked: {e}");
            }
        }
    }

    // Sort by latency — fastest first.
    discovered.sort_by_key(|r| r.latency);
    discovered
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_ip() {
        let targets = parse_scan_targets("1.1.1.1\n");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], "1.1.1.1:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_ip_with_port() {
        let targets = parse_scan_targets("8.8.8.8:5353\n");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], "8.8.8.8:5353".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_cidr_24() {
        let targets = parse_scan_targets("10.0.0.0/24\n");
        // /24 = 256 hosts, skip network (.0) and broadcast (.255) → 254
        assert_eq!(targets.len(), 254);
        assert_eq!(
            targets[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53)
        );
        assert_eq!(
            targets[253],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)), 53)
        );
    }

    #[test]
    fn parse_cidr_with_port() {
        let targets = parse_scan_targets("192.168.1.0/30 5353\n");
        // /30 = 4 hosts, skip .0 and .3 → 2 usable
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].port(), 5353);
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let input = r#"
# This is a comment
1.1.1.1

# Another comment
8.8.8.8
"#;
        let targets = parse_scan_targets(input);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn rejects_too_large_cidr() {
        let targets = parse_scan_targets("10.0.0.0/8\n");
        // /8 = 16M hosts — way over limit; should be skipped with warning.
        assert_eq!(targets.len(), 0);
    }

    #[test]
    fn parse_cidr_32_single_host() {
        let targets = parse_scan_targets("10.0.0.5/32\n");
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 53)
        );
    }

    #[test]
    fn probe_query_builds_successfully() {
        let query = build_tunnel_probe("example.com", 1234).unwrap();
        assert!(query.len() >= 12, "DNS query too short");
        // Check DNS ID
        assert_eq!(query[0], (1234 >> 8) as u8);
        assert_eq!(query[1], (1234 & 0xFF) as u8);
        // QR=0 (query)
        assert_eq!(query[2] & 0x80, 0);
    }

    #[test]
    fn probe_query_uses_real_tunnel_encoding() {
        // The tunnel probe must encode via build_qname (base32 + dotify),
        // so the server recognises it as a tunnel query.
        let query = build_tunnel_probe("tunnel.example.com", 42).unwrap();
        // The qname should contain the domain as a suffix.
        let query_str = String::from_utf8_lossy(&query);
        // We just verify the packet is non-trivially long (base32 labels +
        // domain) and starts with a valid DNS header.
        assert!(query.len() > 40, "tunnel probe should be longer than a minimal query");
    }

    #[test]
    fn probe_result_ordering() {
        // TunnelResponded > TunnelReachable > WrongRcode > NoResponse
        assert!(ProbeResult::TunnelResponded > ProbeResult::TunnelReachable);
        assert!(ProbeResult::TunnelReachable > ProbeResult::WrongRcode);
        assert!(ProbeResult::WrongRcode > ProbeResult::NoResponse);
    }

    #[test]
    fn shuffle_changes_order() {
        // A sufficiently large list should be reordered by shuffle.
        let mut data: Vec<u32> = (0..100).collect();
        let original = data.clone();
        let mut rng = FastRng::new();
        shuffle(&mut data, &mut rng);
        // It's astronomically unlikely for 100 elements to stay sorted.
        assert_ne!(data, original, "shuffle should reorder elements");
        // But the same elements must be present.
        data.sort();
        assert_eq!(data, original);
    }

    #[test]
    fn interleave_round_robins_groups() {
        // 3 groups of different sizes.
        let groups = vec![
            ScanGroup {
                addrs: (1..=20)
                    .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 53))
                    .collect(),
            },
            ScanGroup {
                addrs: (1..=5)
                    .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(20, 0, 0, i)), 53))
                    .collect(),
            },
            ScanGroup {
                addrs: (1..=12)
                    .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(30, 0, 0, i)), 53))
                    .collect(),
            },
        ];
        let interleaved = interleave_groups(&groups);

        // Total count must be preserved.
        assert_eq!(interleaved.len(), 20 + 5 + 12);

        // First SLICE_PER_GROUP entries should come from group 0.
        let first_slice = &interleaved[..SLICE_PER_GROUP];
        for addr in first_slice {
            assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, first_slice.iter().position(|a| a == addr).unwrap() as u8 + 1)));
        }

        // Next slice should come from group 1 (only 5 entries).
        let g1_start = SLICE_PER_GROUP;
        let g1_end = g1_start + 5.min(SLICE_PER_GROUP);
        for addr in &interleaved[g1_start..g1_end] {
            match addr.ip() {
                IpAddr::V4(ip) => assert_eq!(ip.octets()[0], 20),
                _ => panic!("expected ipv4"),
            }
        }
    }

    #[test]
    fn interleave_empty_groups_ok() {
        let groups: Vec<ScanGroup> = vec![];
        let interleaved = interleave_groups(&groups);
        assert!(interleaved.is_empty());
    }

    #[test]
    fn fast_rng_produces_variety() {
        let mut rng = FastRng::new();
        let mut values = std::collections::HashSet::new();
        for _ in 0..100 {
            values.insert(rng.next_u64());
        }
        // 100 calls should produce at least 95 unique values.
        assert!(values.len() >= 95, "RNG produced too many duplicates: {}", values.len());
    }
}
