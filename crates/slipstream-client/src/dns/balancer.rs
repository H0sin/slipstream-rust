//! Smart multi-domain load balancer with health tracking and failover.
//!
//! Routes traffic across multiple domains and resolvers to maximise
//! aggregate bandwidth and automatically sidestep paths that become
//! unhealthy (timeouts, errors, high latency).
//!
//! # Design
//!
//! A **route** is the combination `(resolver_index, domain_index)`.
//! Each route has independent health state so that a single broken
//! domain or resolver does not drag down the others.
//!
//! Selection is weighted round‑robin: healthy routes are chosen in turn
//! while the balancer transparently skips unhealthy ones.  After a
//! cool‑down period unhealthy routes are *probed* — if the probe
//! succeeds the route returns to service.

use std::time::{Duration, Instant};

/// How many consecutive failures before we mark a route unhealthy.
const FAILURE_THRESHOLD: u32 = 3;
/// Minimum time a route stays in cooldown before we probe it again.
const COOLDOWN_DURATION: Duration = Duration::from_secs(10);
/// Maximum cooldown with exponential back-off.
const MAX_COOLDOWN: Duration = Duration::from_secs(120);
/// Exponential‑moving‑average factor for latency tracking.
const LATENCY_ALPHA: f64 = 0.3;

// ── Route health state ──────────────────────────────────────────────

/// Per‑route health metrics.
#[derive(Debug)]
struct RouteHealth {
    /// Resolver index into the resolver list.
    resolver_idx: usize,
    /// Domain index into the domain list.
    domain_idx: usize,
    /// Rolling success count (reset on failure).
    consecutive_successes: u32,
    /// Rolling failure count (reset on success).
    consecutive_failures: u32,
    /// Lifetime successes.
    total_successes: u64,
    /// Lifetime failures.
    total_failures: u64,
    /// Bytes successfully transferred through this route.
    total_bytes: u64,
    /// Exponential moving average of RTT (microseconds).
    avg_latency_us: f64,
    /// Whether the route is considered healthy.
    healthy: bool,
    /// When the route was marked unhealthy.
    unhealthy_since: Option<Instant>,
    /// Next time we are allowed to probe this route.
    next_probe_at: Option<Instant>,
    /// Cooldown exponent for exponential back-off.
    cooldown_exponent: u32,
}

impl RouteHealth {
    fn new(resolver_idx: usize, domain_idx: usize) -> Self {
        Self {
            resolver_idx,
            domain_idx,
            consecutive_successes: 0,
            consecutive_failures: 0,
            total_successes: 0,
            total_failures: 0,
            total_bytes: 0,
            avg_latency_us: 0.0,
            healthy: true,
            unhealthy_since: None,
            next_probe_at: None,
            cooldown_exponent: 0,
        }
    }

    /// Effective weight used for selection (higher is better).
    fn weight(&self) -> f64 {
        if !self.healthy {
            return 0.0;
        }
        // Base weight; slightly prefer routes with more observed successes.
        let success_bonus = (self.consecutive_successes as f64).min(20.0) / 20.0;
        // Penalise high-latency routes (latency in ms; divide a baseline
        // of 200ms by the observed latency to get a scaling factor).
        let latency_factor = if self.avg_latency_us > 0.0 {
            (200_000.0 / self.avg_latency_us).clamp(0.2, 2.0)
        } else {
            1.0
        };
        (1.0 + success_bonus) * latency_factor
    }

    fn record_success(&mut self, latency_us: Option<u64>, bytes: usize) {
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        self.consecutive_failures = 0;
        self.total_successes = self.total_successes.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(bytes as u64);
        if let Some(latency) = latency_us {
            if self.avg_latency_us == 0.0 {
                self.avg_latency_us = latency as f64;
            } else {
                self.avg_latency_us = LATENCY_ALPHA * (latency as f64)
                    + (1.0 - LATENCY_ALPHA) * self.avg_latency_us;
            }
        }
        if !self.healthy {
            self.healthy = true;
            self.unhealthy_since = None;
            self.next_probe_at = None;
            self.cooldown_exponent = 0;
            tracing::info!(
                "route (resolver={}, domain={}) recovered",
                self.resolver_idx,
                self.domain_idx
            );
        }
    }

    fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.consecutive_successes = 0;
        self.total_failures = self.total_failures.saturating_add(1);
        if self.healthy && self.consecutive_failures >= FAILURE_THRESHOLD {
            self.healthy = false;
            let now = Instant::now();
            self.unhealthy_since = Some(now);
            let cooldown = compute_cooldown(self.cooldown_exponent);
            self.next_probe_at = Some(now + cooldown);
            self.cooldown_exponent = self.cooldown_exponent.saturating_add(1);
            tracing::warn!(
                "route (resolver={}, domain={}) marked unhealthy after {} failures, cooldown {}s",
                self.resolver_idx,
                self.domain_idx,
                self.consecutive_failures,
                cooldown.as_secs(),
            );
        }
    }

    /// Returns `true` if the route is unhealthy but the cooldown has
    /// elapsed and it should be probed.
    fn should_probe(&self, now: Instant) -> bool {
        if self.healthy {
            return false;
        }
        match self.next_probe_at {
            Some(at) => now >= at,
            None => true,
        }
    }

    /// Advance the cooldown for a failed probe.
    #[allow(dead_code)]
    fn advance_cooldown(&mut self) {
        let now = Instant::now();
        let cooldown = compute_cooldown(self.cooldown_exponent);
        self.next_probe_at = Some(now + cooldown);
        self.cooldown_exponent = self.cooldown_exponent.saturating_add(1);
    }
}

fn compute_cooldown(exponent: u32) -> Duration {
    let secs = COOLDOWN_DURATION.as_secs().saturating_mul(1u64 << exponent.min(6));
    Duration::from_secs(secs).min(MAX_COOLDOWN)
}

// ── DomainBalancer ──────────────────────────────────────────────────

/// Smart load balancer that distributes packets across (resolver, domain)
/// routes with health tracking and automatic failover.
pub(crate) struct DomainBalancer {
    /// All known routes.
    routes: Vec<RouteHealth>,
    /// Domain list (owned copies for labelling).
    domains: Vec<String>,
    /// Number of resolvers.
    num_resolvers: usize,
    /// Round-robin cursor.
    rr_cursor: usize,
}

impl DomainBalancer {
    /// Create a balancer for the given resolver × domain matrix.
    pub(crate) fn new(domains: &[String], num_resolvers: usize) -> Self {
        let mut routes = Vec::with_capacity(num_resolvers * domains.len());
        for r in 0..num_resolvers {
            for (d, _) in domains.iter().enumerate() {
                routes.push(RouteHealth::new(r, d));
            }
        }
        Self {
            routes,
            domains: domains.to_vec(),
            num_resolvers,
            rr_cursor: 0,
        }
    }

    /// Total number of domains.
    #[allow(dead_code)]
    pub(crate) fn num_domains(&self) -> usize {
        self.domains.len()
    }

    /// Current number of resolvers.
    #[allow(dead_code)]
    pub(crate) fn num_resolvers(&self) -> usize {
        self.num_resolvers
    }

    /// Dynamically add a new resolver to the balancer.
    ///
    /// Creates fresh `RouteHealth` entries for every domain paired with
    /// the new resolver.  Returns the index assigned to it.
    pub(crate) fn add_resolver(&mut self) -> usize {
        let new_idx = self.num_resolvers;
        for d in 0..self.domains.len() {
            self.routes.push(RouteHealth::new(new_idx, d));
        }
        self.num_resolvers += 1;
        tracing::info!(
            "balancer: added resolver idx={}, total routes={}",
            new_idx,
            self.routes.len()
        );
        new_idx
    }

    /// Ensure the balancer has routes for exactly `count` resolvers.
    ///
    /// Existing routes (and their health state) are preserved.  If
    /// `count` is greater than `num_resolvers`, fresh routes are added.
    /// If `count` is smaller, excess routes are trimmed.
    pub(crate) fn resize_resolvers(&mut self, count: usize) {
        if count == self.num_resolvers {
            return;
        }
        if count > self.num_resolvers {
            while self.num_resolvers < count {
                self.add_resolver();
            }
        } else {
            // Trim routes belonging to removed resolvers.
            self.routes.retain(|r| r.resolver_idx < count);
            self.num_resolvers = count;
        }
        // Keep cursor in bounds.
        if self.rr_cursor >= self.routes.len() {
            self.rr_cursor = 0;
        }
    }

    /// Returns the domain string for a given index.
    pub(crate) fn domain(&self, idx: usize) -> &str {
        &self.domains[idx]
    }

    /// Returns all domain strings.
    #[allow(dead_code)]
    pub(crate) fn domains(&self) -> &[String] {
        &self.domains
    }

    /// The minimum MTU across all domains (conservative for QUIC).
    /// Uses the same formula as the client runtime: (240 - domain_len) / 1.6
    #[allow(dead_code)]
    pub(crate) fn min_mtu(&self) -> u32 {
        self.domains
            .iter()
            .map(|d| {
                let domain_len = d.len();
                if domain_len >= 240 {
                    return 1;
                }
                let mtu = ((240.0 - domain_len as f64) / 1.6) as u32;
                if mtu == 0 { 1 } else { mtu }
            })
            .min()
            .unwrap_or(1)
    }

    // ── Selection ───────────────────────────────────────────────

    /// Pick the best domain index for a given resolver.
    /// Returns `None` only if every route for this resolver is unhealthy
    /// and not yet probeable.
    pub(crate) fn select_domain_for_resolver(&mut self, resolver_idx: usize) -> Option<usize> {
        let now = Instant::now();
        let num_domains = self.domains.len();
        if num_domains == 0 {
            return None;
        }
        if num_domains == 1 {
            // Fast path: single domain always used.
            return Some(0);
        }

        // Collect weights for domains of this resolver.
        let base = resolver_idx * num_domains;
        let mut best_weight = 0.0f64;
        let mut best_idx: Option<usize> = None;

        // Try weighted round-robin: start from cursor, wrap around.
        for offset in 0..num_domains {
            let d = (self.rr_cursor + offset) % num_domains;
            let route = &self.routes[base + d];
            if route.healthy {
                let w = route.weight();
                if w > best_weight || best_idx.is_none() {
                    best_weight = w;
                    best_idx = Some(d);
                }
            }
        }

        if let Some(idx) = best_idx {
            // Advance cursor for round-robin spread.
            self.rr_cursor = (idx + 1) % num_domains;
            return Some(idx);
        }

        // All unhealthy: try to find one that is ready to probe.
        for d in 0..num_domains {
            let route = &self.routes[base + d];
            if route.should_probe(now) {
                return Some(d);
            }
        }

        // Absolute fallback: use first domain anyway (don't block traffic).
        Some(0)
    }

    /// Select a (resolver_index, domain_index) pair from all routes,
    /// useful when the caller wants to spread across resolvers too.
    #[allow(dead_code)]
    pub(crate) fn select_route(&mut self) -> (usize, usize) {
        let now = Instant::now();
        let total = self.routes.len();
        if total == 0 {
            return (0, 0);
        }

        let mut best_weight = 0.0f64;
        let mut best_route: Option<(usize, usize)> = None;

        // Weighted round-robin across all routes.
        for offset in 0..total {
            let idx = (self.rr_cursor + offset) % total;
            let route = &self.routes[idx];
            if route.healthy {
                let w = route.weight();
                if w > best_weight || best_route.is_none() {
                    best_weight = w;
                    best_route = Some((route.resolver_idx, route.domain_idx));
                }
            }
        }

        if let Some((r, d)) = best_route {
            let base = r * self.domains.len() + d;
            self.rr_cursor = (base + 1) % total;
            return (r, d);
        }

        // All unhealthy — try probing.
        for idx in 0..total {
            let route = &self.routes[idx];
            if route.should_probe(now) {
                return (route.resolver_idx, route.domain_idx);
            }
        }

        (0, 0)
    }

    // ── Feedback ────────────────────────────────────────────────

    /// Record a successful response for a (resolver, domain) route.
    pub(crate) fn record_success(
        &mut self,
        resolver_idx: usize,
        domain_idx: usize,
        latency_us: Option<u64>,
        bytes: usize,
    ) {
        if let Some(route) = self.route_mut(resolver_idx, domain_idx) {
            route.record_success(latency_us, bytes);
        }
    }

    /// Record a failure (timeout, error) for a (resolver, domain) route.
    #[allow(dead_code)]
    pub(crate) fn record_failure(&mut self, resolver_idx: usize, domain_idx: usize) {
        if let Some(route) = self.route_mut(resolver_idx, domain_idx) {
            route.record_failure();
        }
    }

    /// Record a failed probe for an unhealthy route (extends cooldown).
    #[allow(dead_code)]
    pub(crate) fn record_probe_failure(&mut self, resolver_idx: usize, domain_idx: usize) {
        if let Some(route) = self.route_mut(resolver_idx, domain_idx) {
            route.advance_cooldown();
        }
    }

    /// Check whether a specific resolver has any healthy route at all.
    #[allow(dead_code)]
    pub(crate) fn resolver_has_healthy_route(&self, resolver_idx: usize) -> bool {
        let num_domains = self.domains.len();
        let base = resolver_idx * num_domains;
        (0..num_domains).any(|d| {
            self.routes
                .get(base + d)
                .map(|r| r.healthy)
                .unwrap_or(false)
        })
    }

    /// Suspend a single (resolver, domain) route.
    pub(crate) fn suspend_route(&mut self, resolver_idx: usize, domain_idx: usize) {
        if let Some(route) = self.route_mut(resolver_idx, domain_idx) {
            if route.healthy {
                for _ in 0..FAILURE_THRESHOLD + 1 {
                    route.record_failure();
                }
                tracing::warn!(
                    "[health] route ({}, {}) suspended",
                    resolver_idx,
                    domain_idx,
                );
            }
        }
    }

    /// Unsuspend / recover a single (resolver, domain) route.
    pub(crate) fn unsuspend_route(&mut self, resolver_idx: usize, domain_idx: usize) {
        if let Some(route) = self.route_mut(resolver_idx, domain_idx) {
            if !route.healthy {
                route.record_success(None, 0);
                tracing::info!(
                    "[health] route ({}, {}) recovered",
                    resolver_idx,
                    domain_idx,
                );
            }
        }
    }

    /// Suspend all routes for a resolver (transport-level failure, e.g.
    /// QUIC path lost).  Only used when the entire network path is gone.
    pub(crate) fn suspend_resolver(&mut self, resolver_idx: usize) {
        let num_domains = self.domains.len();
        let base = resolver_idx * num_domains;
        let mut any_changed = false;
        for d in 0..num_domains {
            if let Some(route) = self.routes.get_mut(base + d) {
                if route.healthy {
                    for _ in 0..FAILURE_THRESHOLD + 1 {
                        route.record_failure();
                    }
                    any_changed = true;
                }
            }
        }
        if any_changed {
            tracing::warn!(
                "[health] resolver {} suspended — all {} routes marked unhealthy",
                resolver_idx,
                num_domains,
            );
        }
    }

    /// Unsuspend / recover all routes for a resolver (transport-level
    /// recovery, e.g. QUIC path restored).
    pub(crate) fn unsuspend_resolver(&mut self, resolver_idx: usize) {
        let num_domains = self.domains.len();
        let base = resolver_idx * num_domains;
        let mut any_changed = false;
        for d in 0..num_domains {
            if let Some(route) = self.routes.get_mut(base + d) {
                if !route.healthy {
                    route.record_success(None, 0);
                    any_changed = true;
                }
            }
        }
        if any_changed {
            tracing::info!(
                "[health] resolver {} recovered — routes restored to healthy",
                resolver_idx,
            );
        }
    }

    /// Returns the number of healthy routes overall.
    pub(crate) fn healthy_route_count(&self) -> usize {
        self.routes.iter().filter(|r| r.healthy).count()
    }

    /// Summary string for debug logging.
    pub(crate) fn summary(&self) -> String {
        let healthy = self.healthy_route_count();
        let total = self.routes.len();
        format!(
            "routes={}/{} healthy, domains={} resolvers={}",
            healthy, total, self.domains.len(), self.num_resolvers
        )
    }

    // ── Internals ───────────────────────────────────────────────

    fn route_mut(
        &mut self,
        resolver_idx: usize,
        domain_idx: usize,
    ) -> Option<&mut RouteHealth> {
        let num_domains = self.domains.len();
        let idx = resolver_idx * num_domains + domain_idx;
        self.routes.get_mut(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn single_domain_always_selected() {
        let mut b = DomainBalancer::new(&domains(&["example.com"]), 1);
        assert_eq!(b.select_domain_for_resolver(0), Some(0));
        assert_eq!(b.select_domain_for_resolver(0), Some(0));
    }

    #[test]
    fn round_robin_across_domains() {
        let mut b = DomainBalancer::new(&domains(&["a.com", "b.com", "c.com"]), 1);
        let mut seen = [0usize; 3];
        for _ in 0..30 {
            let d = b.select_domain_for_resolver(0).unwrap();
            seen[d] += 1;
            b.record_success(0, d, Some(1000), 100);
        }
        // Each domain should be used roughly equally.
        for count in &seen {
            assert!(*count >= 5, "uneven distribution: {:?}", seen);
        }
    }

    #[test]
    fn unhealthy_route_skipped() {
        let mut b = DomainBalancer::new(&domains(&["good.com", "bad.com"]), 1);
        // Make bad.com unhealthy.
        for _ in 0..5 {
            b.record_failure(0, 1);
        }
        // Should only select good.com now.
        for _ in 0..10 {
            assert_eq!(b.select_domain_for_resolver(0), Some(0));
        }
    }

    #[test]
    fn recovery_after_cooldown() {
        let mut b = DomainBalancer::new(&domains(&["a.com", "b.com"]), 1);
        for _ in 0..5 {
            b.record_failure(0, 1);
        }
        assert!(!b.routes[1].healthy);
        // Simulate a successful probe.
        b.record_success(0, 1, Some(1000), 100);
        assert!(b.routes[1].healthy);
    }

    #[test]
    fn select_route_spreads_across_resolvers() {
        let mut b = DomainBalancer::new(&domains(&["a.com", "b.com"]), 2);
        let mut resolver_counts = [0usize; 2];
        for _ in 0..20 {
            let (r, d) = b.select_route();
            resolver_counts[r] += 1;
            b.record_success(r, d, Some(1000), 100);
        }
        assert!(resolver_counts[0] >= 3, "resolver 0 underused");
        assert!(resolver_counts[1] >= 3, "resolver 1 underused");
    }

    #[test]
    fn healthy_route_count_accurate() {
        let mut b = DomainBalancer::new(&domains(&["a.com", "b.com"]), 2);
        assert_eq!(b.healthy_route_count(), 4);
        for _ in 0..5 {
            b.record_failure(0, 1);
        }
        assert_eq!(b.healthy_route_count(), 3);
    }
}
