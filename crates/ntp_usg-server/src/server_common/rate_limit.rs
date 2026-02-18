use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::protocol;

/// Configuration for per-client rate limiting.
///
/// Rate limiting is per client IP address (not per port, per RFC 9109).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum requests allowed per window from a single client IP.
    pub max_requests_per_window: u32,
    /// Duration of the rate limit window.
    pub window_duration: Duration,
    /// Minimum interval between successive requests from the same client.
    pub min_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_requests_per_window: 20,
            window_duration: Duration::from_secs(60),
            min_interval: Duration::from_secs(2),
        }
    }
}

/// Result of a rate limit check.
pub(crate) enum RateLimitResult {
    /// Request is within limits.
    Allow,
    /// Request exceeds rate limit — send KoD RATE.
    RateExceeded,
}

/// Per-client state for rate limiting and interleaved mode tracking.
pub struct ClientState {
    // Rate limiting.
    /// Timestamp of last valid request from this client.
    last_request_time: Instant,
    /// Number of requests in the current rate limit window.
    request_count: u32,
    /// Start of the current rate limit window.
    window_start: Instant,

    // Interleaved mode (RFC 9769).
    /// Last receive timestamp (T2) we recorded for this client.
    pub(crate) last_t2: protocol::TimestampFormat,
    /// Last transmit timestamp (T3) we sent to this client.
    pub(crate) last_t3: protocol::TimestampFormat,
    /// Client's last transmit timestamp from their request.
    pub(crate) last_client_xmt: protocol::TimestampFormat,
}

impl ClientState {
    /// Create a new client state entry initialized to the given time.
    pub fn new(now: Instant) -> Self {
        ClientState {
            last_request_time: now,
            request_count: 0,
            window_start: now,
            last_t2: protocol::TimestampFormat::default(),
            last_t3: protocol::TimestampFormat::default(),
            last_client_xmt: protocol::TimestampFormat::default(),
        }
    }
}

/// Bounded client state table keyed by IP address (not port, per RFC 9109).
pub struct ClientTable {
    entries: HashMap<IpAddr, ClientState>,
    max_entries: usize,
    /// How long until a stale entry can be evicted.
    stale_threshold: Duration,
}

impl ClientTable {
    /// Create a new client table with the given maximum number of entries.
    pub fn new(max_entries: usize) -> Self {
        ClientTable {
            entries: HashMap::new(),
            max_entries,
            stale_threshold: Duration::from_secs(24 * 3600),
        }
    }

    /// Get or create a client state entry, evicting stale entries if needed.
    pub(crate) fn get_or_insert(&mut self, ip: IpAddr, now: Instant) -> &mut ClientState {
        // Evict stale entries if table is full.
        if !self.entries.contains_key(&ip) && self.entries.len() >= self.max_entries {
            self.evict_stale(now);
        }

        self.entries
            .entry(ip)
            .or_insert_with(|| ClientState::new(now))
    }

    /// Get an existing client state entry (for interleaved mode lookup).
    pub(crate) fn get(&self, ip: &IpAddr) -> Option<&ClientState> {
        self.entries.get(ip)
    }

    /// Return the number of tracked clients.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Remove entries older than the stale threshold.
    fn evict_stale(&mut self, now: Instant) {
        let threshold = self.stale_threshold;
        self.entries
            .retain(|_, state| now.duration_since(state.last_request_time) < threshold);

        // If still full after evicting stale entries, evict the oldest.
        if self.entries.len() >= self.max_entries
            && let Some(oldest_ip) = self
                .entries
                .iter()
                .min_by_key(|(_, state)| state.last_request_time)
                .map(|(ip, _)| *ip)
        {
            self.entries.remove(&oldest_ip);
        }
    }
}

/// Check the rate limit for a client.
pub(crate) fn check_rate_limit(
    client: &mut ClientState,
    now: Instant,
    config: &RateLimitConfig,
) -> RateLimitResult {
    // Check minimum interval.
    if now.duration_since(client.last_request_time) < config.min_interval {
        return RateLimitResult::RateExceeded;
    }

    // Reset window if expired.
    if now.duration_since(client.window_start) > config.window_duration {
        client.window_start = now;
        client.request_count = 0;
    }

    client.request_count += 1;
    if client.request_count > config.max_requests_per_window {
        return RateLimitResult::RateExceeded;
    }

    client.last_request_time = now;
    RateLimitResult::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allows_first_request() {
        let now = Instant::now();
        let mut client = ClientState::new(now - Duration::from_secs(10)); // Old enough
        let config = RateLimitConfig::default();
        assert!(matches!(
            check_rate_limit(&mut client, now, &config),
            RateLimitResult::Allow
        ));
    }

    #[test]
    fn test_rate_limit_min_interval() {
        let now = Instant::now();
        let mut client = ClientState::new(now);
        client.last_request_time = now; // Just now
        let config = RateLimitConfig {
            min_interval: Duration::from_secs(2),
            ..Default::default()
        };
        // Request 1 second later — too soon.
        let result = check_rate_limit(&mut client, now + Duration::from_secs(1), &config);
        assert!(matches!(result, RateLimitResult::RateExceeded));
    }

    #[test]
    fn test_rate_limit_window_exceeded() {
        let now = Instant::now();
        let mut client = ClientState::new(now - Duration::from_secs(10));
        let config = RateLimitConfig {
            max_requests_per_window: 2,
            window_duration: Duration::from_secs(60),
            min_interval: Duration::from_millis(1),
        };
        // Send 3 requests spaced apart (passes min_interval but exceeds window).
        let t1 = now;
        let t2 = now + Duration::from_millis(100);
        let t3 = now + Duration::from_millis(200);

        assert!(matches!(
            check_rate_limit(&mut client, t1, &config),
            RateLimitResult::Allow
        ));
        assert!(matches!(
            check_rate_limit(&mut client, t2, &config),
            RateLimitResult::Allow
        ));
        assert!(matches!(
            check_rate_limit(&mut client, t3, &config),
            RateLimitResult::RateExceeded
        ));
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let now = Instant::now();
        let mut client = ClientState::new(now - Duration::from_secs(10));
        let config = RateLimitConfig {
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(1),
            min_interval: Duration::from_millis(1),
        };

        let t1 = now;
        let t2 = now + Duration::from_millis(100);
        let t3 = now + Duration::from_secs(2); // After window reset

        assert!(matches!(
            check_rate_limit(&mut client, t1, &config),
            RateLimitResult::Allow
        ));
        assert!(matches!(
            check_rate_limit(&mut client, t2, &config),
            RateLimitResult::RateExceeded
        ));
        // After window resets.
        assert!(matches!(
            check_rate_limit(&mut client, t3, &config),
            RateLimitResult::Allow
        ));
    }

    #[test]
    fn test_client_table_get_or_insert() {
        let mut table = ClientTable::new(100);
        let now = Instant::now();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let _client = table.get_or_insert(ip, now);
        assert!(table.get(&ip).is_some());
    }

    #[test]
    fn test_client_table_eviction() {
        let mut table = ClientTable::new(2);
        let now = Instant::now();
        let ip1: IpAddr = "1.0.0.1".parse().unwrap();
        let ip2: IpAddr = "1.0.0.2".parse().unwrap();
        let ip3: IpAddr = "1.0.0.3".parse().unwrap();

        table.get_or_insert(ip1, now);
        table.get_or_insert(ip2, now + Duration::from_secs(1));
        // Table is full (2 entries). Adding ip3 should evict the oldest.
        table.get_or_insert(ip3, now + Duration::from_secs(2));

        assert_eq!(table.entries.len(), 2);
        // ip1 should have been evicted (oldest last_request_time).
        assert!(table.get(&ip1).is_none());
        assert!(table.get(&ip3).is_some());
    }
}
