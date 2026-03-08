//! Background resolver scanner / discoverer.
//!
//! Reads IP ranges from a file, shuffles and probes them in batches,
//! persists working resolvers to a JSON cache file, and reports them
//! to the runtime for dynamic tunnel creation.
//!
//! # Range file format
//!
//! One entry per line.  Supported formats:
//! - CIDR:          `178.22.122.0/24`
//! - Dash range:    `10.202.10.1-10.202.10.255`
//! - Single IP:     `8.8.4.4`
//! - With port:     `178.22.122.0/24:5353`  (default port is 53)
//!
//! Lines starting with `#` or empty lines are ignored.
//!
//! # Cache file (`scan-cache`)
//!
//! A JSON array of discovered resolvers, each with `addr`, `latency_ms`,
//! `discovered_at`, and `fail_count`.  Resolvers that accumulate
//! `MAX_CACHE_FAILURES` consecutive failures are evicted.

use super::health::{probe_candidate, ProbeResult};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{thread_rng, SeedableRng};
use serde::{Deserialize, Serialize};
use slipstream_ffi::ResolverMode;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Delay between consecutive probes within a batch.
const INTER_PROBE_DELAY: Duration = Duration::from_millis(100);

/// Cache entries with this many consecutive re-validation failures
/// are evicted from the cache file.
const MAX_CACHE_FAILURES: u32 = 10;

/// How often (in scan rounds) we re-validate cached resolvers.
const REVALIDATE_EVERY_N_ROUNDS: u32 = 3;

// ── IP range parsing ────────────────────────────────────────────────

/// A parsed IP range with an optional port override.
#[derive(Debug, Clone)]
pub(crate) struct IpRange {
    start: u32, // IPv4 as u32 (network order)
    end: u32,   // inclusive
    port: u16,
}

impl IpRange {
    fn count(&self) -> u64 {
        (self.end as u64) - (self.start as u64) + 1
    }

    /// Pick `n` random IPs from this range (shuffled).
    fn sample(&self, n: usize) -> Vec<SocketAddr> {
        let total = self.count();
        let mut rng = thread_rng();

        if total <= n as u64 {
            // Range is small enough — return all, shuffled.
            let mut addrs: Vec<SocketAddr> = (self.start..=self.end)
                .map(|ip| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), self.port))
                .collect();
            addrs.shuffle(&mut rng);
            return addrs;
        }

        // Reservoir-sample `n` indices, then convert.
        let mut indices: Vec<u32> = Vec::with_capacity(n);
        // Simple approach: collect all into a vec and shuffle-take.
        // For ranges up to ~16M this is fine; larger ranges use random offset.
        if total <= 1_000_000 {
            let mut all: Vec<u32> = (self.start..=self.end).collect();
            all.shuffle(&mut rng);
            all.truncate(n);
            indices = all;
        } else {
            // For very large ranges, pick random offsets.
            let mut seen = HashSet::with_capacity(n);
            while indices.len() < n {
                let offset = rand::random::<u32>() % (total as u32);
                let ip = self.start.wrapping_add(offset);
                if seen.insert(ip) {
                    indices.push(ip);
                }
            }
        }

        indices
            .into_iter()
            .map(|ip| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), self.port))
            .collect()
    }
}

/// Parse a single line from the range file.
///
/// Accepted formats:
/// - `1.2.3.0/24`          → CIDR, port 53
/// - `1.2.3.0/24:5353`     → CIDR, port 5353
/// - `1.2.3.1-1.2.3.255`   → dash range, port 53
/// - `1.2.3.1-1.2.3.255:5353` → dash range, port 5353
/// - `1.2.3.4`             → single IP, port 53
/// - `1.2.3.4:5353`        → single IP, port 5353
fn parse_range_line(line: &str) -> Result<IpRange, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Err("empty or comment".into());
    }

    // Split off trailing `:PORT` — but only if after the main spec.
    // Careful: CIDR has `/`, dash ranges have `-`.
    let (spec, port) = split_port_suffix(trimmed);

    // CIDR?
    if let Some(slash_pos) = spec.find('/') {
        let ip_str = &spec[..slash_pos];
        let prefix_str = &spec[slash_pos + 1..];
        let base: Ipv4Addr = ip_str
            .parse()
            .map_err(|e| format!("bad CIDR IP '{}': {}", ip_str, e))?;
        let prefix: u32 = prefix_str
            .parse()
            .map_err(|e| format!("bad CIDR prefix '{}': {}", prefix_str, e))?;
        if prefix > 32 {
            return Err(format!("CIDR prefix {} out of range", prefix));
        }
        let base_u32 = u32::from(base);
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let start = base_u32 & mask;
        let end = start | !mask;
        return Ok(IpRange { start, end, port });
    }

    // Dash range?
    if let Some(dash_pos) = spec.find('-') {
        let start_str = &spec[..dash_pos];
        let end_str = &spec[dash_pos + 1..];
        let start_ip: Ipv4Addr = start_str
            .parse()
            .map_err(|e| format!("bad range start '{}': {}", start_str, e))?;
        let end_ip: Ipv4Addr = end_str
            .parse()
            .map_err(|e| format!("bad range end '{}': {}", end_str, e))?;
        let start = u32::from(start_ip);
        let end = u32::from(end_ip);
        if end < start {
            return Err(format!("range end {} < start {}", end_str, start_str));
        }
        return Ok(IpRange { start, end, port });
    }

    // Single IP.
    let ip: Ipv4Addr = spec
        .parse()
        .map_err(|e| format!("bad IP '{}': {}", spec, e))?;
    let v = u32::from(ip);
    Ok(IpRange {
        start: v,
        end: v,
        port,
    })
}

/// Split off a trailing `:PORT` from the spec string.
/// Returns (spec_without_port, port).
fn split_port_suffix(input: &str) -> (&str, u16) {
    // Find the last `:` that is after any `/` or `-` (so it's a port, not part of IP).
    if let Some(colon_pos) = input.rfind(':') {
        let after_colon = &input[colon_pos + 1..];
        // Make sure it's a valid port number.
        if let Ok(port) = after_colon.parse::<u16>() {
            // Make sure the colon is after any range delimiter.
            let spec = &input[..colon_pos];
            if !spec.is_empty() {
                return (spec, port);
            }
        }
    }
    (input, 53)
}

/// Load and parse all ranges from a file.
pub(crate) fn load_ranges_from_file(path: &Path) -> Result<Vec<IpRange>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read range file '{}': {}", path.display(), e))?;

    let mut ranges = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        match parse_range_line(line) {
            Ok(r) => ranges.push(r),
            Err(e) if e == "empty or comment" => continue,
            Err(e) => {
                warn!(
                    "[scanner] {}:{}: skipping bad line '{}': {}",
                    path.display(),
                    line_no + 1,
                    line.trim(),
                    e,
                );
            }
        }
    }
    Ok(ranges)
}

// ── JSON cache ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CachedResolver {
    pub(crate) addr: String, // "IP:PORT"
    pub(crate) latency_ms: u64,
    pub(crate) discovered_at: String, // ISO-8601ish timestamp
    pub(crate) fail_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct ScanCache {
    pub(crate) resolvers: Vec<CachedResolver>,
}

impl ScanCache {
    pub(crate) fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(data) => match serde_json::from_str::<ScanCache>(&data) {
                Ok(cache) => {
                    info!(
                        "[scanner] loaded {} cached resolvers from {}",
                        cache.resolvers.len(),
                        path.display(),
                    );
                    cache
                }
                Err(e) => {
                    warn!(
                        "[scanner] failed to parse cache {}: {}; starting fresh",
                        path.display(),
                        e,
                    );
                    ScanCache::default()
                }
            },
            Err(_) => {
                debug!("[scanner] no cache file at {}; starting fresh", path.display());
                ScanCache::default()
            }
        }
    }

    pub(crate) fn save(&self, path: &Path) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    warn!("[scanner] failed to write cache {}: {}", path.display(), e);
                }
            }
            Err(e) => {
                warn!("[scanner] failed to serialize cache: {}", e);
            }
        }
    }

    fn contains(&self, addr: &SocketAddr) -> bool {
        let key = addr.to_string();
        self.resolvers.iter().any(|r| r.addr == key)
    }

    fn add(&mut self, addr: SocketAddr, latency: Duration) {
        let key = addr.to_string();
        if self.resolvers.iter().any(|r| r.addr == key) {
            return;
        }
        self.resolvers.push(CachedResolver {
            addr: key,
            latency_ms: latency.as_millis() as u64,
            discovered_at: chrono_now(),
            fail_count: 0,
        });
    }

    fn mark_success(&mut self, addr: &SocketAddr) {
        let key = addr.to_string();
        if let Some(entry) = self.resolvers.iter_mut().find(|r| r.addr == key) {
            entry.fail_count = 0;
        }
    }

    fn mark_failure(&mut self, addr: &SocketAddr) {
        let key = addr.to_string();
        if let Some(entry) = self.resolvers.iter_mut().find(|r| r.addr == key) {
            entry.fail_count = entry.fail_count.saturating_add(1);
        }
    }

    /// Remove entries that have exceeded the failure threshold.
    fn evict_stale(&mut self) -> Vec<String> {
        let mut evicted = Vec::new();
        self.resolvers.retain(|r| {
            if r.fail_count >= MAX_CACHE_FAILURES {
                evicted.push(r.addr.clone());
                false
            } else {
                true
            }
        });
        evicted
    }

    /// Get all cached addresses as SocketAddr.
    fn addrs(&self) -> Vec<SocketAddr> {
        self.resolvers
            .iter()
            .filter_map(|r| r.addr.parse().ok())
            .collect()
    }
}

/// Simple timestamp without pulling in the `chrono` crate.
fn chrono_now() -> String {
    // Use seconds since UNIX epoch as a simple timestamp.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

// ── Public types ────────────────────────────────────────────────────

/// A resolver discovered by the scanner — sent to the runtime.
#[derive(Debug, Clone)]
pub(crate) struct DiscoveredResolver {
    /// Socket address of the discovered resolver.
    pub(crate) addr: SocketAddr,
    /// Resolver mode (defaults to Recursive for scanned resolvers).
    pub(crate) mode: ResolverMode,
    /// Measured probe round-trip time.
    pub(crate) latency: Duration,
}

/// Configuration for the resolver scanner background task.
#[derive(Debug, Clone)]
pub(crate) struct ScannerConfig {
    /// Path to the IP ranges file.
    pub(crate) ranges_file: PathBuf,
    /// Path to the JSON cache file for persistence.
    pub(crate) cache_file: PathBuf,
    /// Domain(s) to use for probe queries.
    pub(crate) domains: Vec<String>,
    /// How often to run a full scan round.
    pub(crate) interval: Duration,
    /// Maximum number of resolvers to discover and report.
    pub(crate) max_discovered: usize,
    /// Resolver mode to assign to discovered resolvers.
    pub(crate) mode: ResolverMode,
    /// IPs per batch per round.
    pub(crate) batch_size: usize,
}

// ── Background task ─────────────────────────────────────────────────

/// Run the resolver scanner loop.
///
/// 1. Load cached resolvers from JSON → report them immediately.
/// 2. Load IP ranges from file.
/// 3. Each round: pick a random range, shuffle-sample `batch_size` IPs,
///    probe them, report discoveries, save cache.
/// 4. Every N rounds: re-validate cached resolvers; evict failures.
pub(crate) async fn run_resolver_scanner(
    config: ScannerConfig,
    result_tx: mpsc::UnboundedSender<DiscoveredResolver>,
) {
    if config.domains.is_empty() {
        debug!("[scanner] no domains configured; exiting");
        return;
    }

    // ── Phase 1: load cache and report existing resolvers ────────
    let mut cache = ScanCache::load(&config.cache_file);
    let cached_addrs = cache.addrs();
    let mut reported: HashSet<SocketAddr> = HashSet::new();

    if !cached_addrs.is_empty() {
        info!(
            "[scanner] reporting {} cached resolvers from previous runs",
            cached_addrs.len(),
        );
        for addr in &cached_addrs {
            if reported.len() >= config.max_discovered {
                break;
            }
            reported.insert(*addr);
            let _ = result_tx.send(DiscoveredResolver {
                addr: *addr,
                mode: config.mode,
                latency: Duration::from_millis(
                    cache
                        .resolvers
                        .iter()
                        .find(|r| r.addr == addr.to_string())
                        .map(|r| r.latency_ms)
                        .unwrap_or(0),
                ),
            });
        }
    }

    // ── Phase 2: load ranges ────────────────────────────────────
    let ranges = match load_ranges_from_file(&config.ranges_file) {
        Ok(r) if r.is_empty() => {
            warn!(
                "[scanner] range file {} is empty or has no valid ranges; scanner will only re-validate cache",
                config.ranges_file.display(),
            );
            Vec::new()
        }
        Ok(r) => {
            let total_ips: u64 = r.iter().map(|rg| rg.count()).sum();
            info!(
                "[scanner] loaded {} ranges ({} total IPs) from {}",
                r.len(),
                total_ips,
                config.ranges_file.display(),
            );
            r
        }
        Err(e) => {
            warn!(
                "[scanner] failed to load ranges: {}; scanner will only re-validate cache",
                e,
            );
            Vec::new()
        }
    };

    let mut round: u32 = 0;
    let mut rng = StdRng::from_entropy();

    loop {
        round = round.wrapping_add(1);

        // ── Re-validate cached resolvers periodically ───────────
        if round % REVALIDATE_EVERY_N_ROUNDS == 0 && !cache.resolvers.is_empty() {
            info!(
                "[scanner] re-validating {} cached resolvers",
                cache.resolvers.len(),
            );
            let addrs = cache.addrs();
            for addr in &addrs {
                let probe_id = hash_probe_id(*addr);
                let (result, _latency) =
                    probe_candidate(*addr, &config.domains[0], probe_id).await;
                if result >= ProbeResult::TunnelReachable {
                    cache.mark_success(addr);
                    debug!("[scanner] cache re-validate: {} OK", addr);
                } else {
                    cache.mark_failure(addr);
                    let entry = cache
                        .resolvers
                        .iter()
                        .find(|r| r.addr == addr.to_string());
                    let fails = entry.map(|e| e.fail_count).unwrap_or(0);
                    warn!(
                        "[scanner] cache re-validate: {} FAILED ({}/{})",
                        addr, fails, MAX_CACHE_FAILURES,
                    );
                }
                tokio::time::sleep(INTER_PROBE_DELAY).await;
            }
            let evicted = cache.evict_stale();
            for addr_str in &evicted {
                warn!("[scanner] evicted {} from cache (>{} failures)", addr_str, MAX_CACHE_FAILURES);
                if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                    reported.remove(&addr);
                }
            }
            cache.save(&config.cache_file);
        }

        // ── Scan a random batch from a random range ─────────────
        if !ranges.is_empty() && reported.len() < config.max_discovered {
            // Pick a random range.
            let range = ranges.choose(&mut rng).unwrap();
            let batch = range.sample(config.batch_size);

            info!(
                "[scanner] round {}: scanning {} IPs from range {}-{} (discovered={})",
                round,
                batch.len(),
                Ipv4Addr::from(range.start),
                Ipv4Addr::from(range.end),
                reported.len(),
            );

            let mut found_this_round = 0usize;

            for candidate in &batch {
                if reported.contains(candidate) || cache.contains(candidate) {
                    continue;
                }
                if reported.len() >= config.max_discovered {
                    debug!("[scanner] max discovered reached; stopping batch");
                    break;
                }

                let probe_id = hash_probe_id(*candidate);
                let (result, latency) =
                    probe_candidate(*candidate, &config.domains[0], probe_id).await;

                if result >= ProbeResult::TunnelReachable {
                    info!(
                        "[scanner] discovered: {} (latency={}ms, {:?})",
                        candidate,
                        latency.as_millis(),
                        result,
                    );
                    reported.insert(*candidate);
                    found_this_round += 1;

                    // Persist to cache.
                    cache.add(*candidate, latency);
                    cache.save(&config.cache_file);

                    // Notify runtime.
                    if result_tx
                        .send(DiscoveredResolver {
                            addr: *candidate,
                            mode: config.mode,
                            latency,
                        })
                        .is_err()
                    {
                        warn!("[scanner] runtime channel closed; stopping scanner");
                        return;
                    }
                } else {
                    debug!("[scanner] {} unreachable: {:?}", candidate, result);
                }

                tokio::time::sleep(INTER_PROBE_DELAY).await;
            }

            if found_this_round > 0 {
                info!(
                    "[scanner] round {} complete: {} new, {} total discovered",
                    round,
                    found_this_round,
                    reported.len(),
                );
            } else {
                debug!(
                    "[scanner] round {} complete: no new (total={})",
                    round,
                    reported.len(),
                );
            }
        }

        tokio::time::sleep(config.interval).await;
    }
}

/// Simple hash to generate varied probe IDs per candidate address.
fn hash_probe_id(addr: SocketAddr) -> u16 {
    let port = addr.port() as u32;
    let ip_part = match addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            u32::from_be_bytes([o[12], o[13], o[14], o[15]])
        }
    };
    ((ip_part.wrapping_mul(2654435761) ^ port) & 0xFFFF) as u16
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr() {
        let r = parse_range_line("10.0.0.0/24").unwrap();
        assert_eq!(r.start, u32::from(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(r.end, u32::from(Ipv4Addr::new(10, 0, 0, 255)));
        assert_eq!(r.port, 53);
        assert_eq!(r.count(), 256);
    }

    #[test]
    fn parse_cidr_with_port() {
        let r = parse_range_line("10.0.0.0/24:5353").unwrap();
        assert_eq!(r.port, 5353);
        assert_eq!(r.count(), 256);
    }

    #[test]
    fn parse_dash_range() {
        let r = parse_range_line("192.168.1.1-192.168.1.10").unwrap();
        assert_eq!(r.start, u32::from(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(r.end, u32::from(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(r.count(), 10);
    }

    #[test]
    fn parse_single_ip() {
        let r = parse_range_line("8.8.8.8").unwrap();
        assert_eq!(r.start, r.end);
        assert_eq!(r.port, 53);
    }

    #[test]
    fn parse_single_ip_with_port() {
        let r = parse_range_line("8.8.8.8:5353").unwrap();
        assert_eq!(r.start, r.end);
        assert_eq!(r.port, 5353);
    }

    #[test]
    fn parse_comment_and_empty() {
        assert!(parse_range_line("# comment").is_err());
        assert!(parse_range_line("   ").is_err());
        assert!(parse_range_line("").is_err());
    }

    #[test]
    fn sample_returns_correct_count() {
        let r = IpRange {
            start: u32::from(Ipv4Addr::new(10, 0, 0, 0)),
            end: u32::from(Ipv4Addr::new(10, 0, 0, 255)),
            port: 53,
        };
        let sample = r.sample(10);
        assert_eq!(sample.len(), 10);
        // All unique.
        let unique: HashSet<_> = sample.iter().collect();
        assert_eq!(unique.len(), 10);
    }

    #[test]
    fn sample_small_range() {
        let r = IpRange {
            start: u32::from(Ipv4Addr::new(1, 2, 3, 4)),
            end: u32::from(Ipv4Addr::new(1, 2, 3, 6)),
            port: 53,
        };
        // Range has 3 IPs, ask for 10 → get 3.
        let sample = r.sample(10);
        assert_eq!(sample.len(), 3);
    }

    #[test]
    fn cache_round_trip() {
        let mut cache = ScanCache::default();
        let addr: SocketAddr = "1.2.3.4:53".parse().unwrap();
        cache.add(addr, Duration::from_millis(42));
        assert!(cache.contains(&addr));
        assert_eq!(cache.resolvers.len(), 1);
        assert_eq!(cache.resolvers[0].latency_ms, 42);

        // Mark failures up to threshold.
        for _ in 0..MAX_CACHE_FAILURES {
            cache.mark_failure(&addr);
        }
        let evicted = cache.evict_stale();
        assert_eq!(evicted.len(), 1);
        assert!(cache.resolvers.is_empty());
    }
}
