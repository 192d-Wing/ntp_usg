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
    /// Request exceeds the rate limit — send KoD RATE.
    ///
    /// Returned for at most one over-limit request per rate-limit window per
    /// client, so a flood of spoofed requests cannot turn the server into a
    /// reflector toward the spoofed address (RFC 8633 §5.7).
    RateExceeded,
    /// Request exceeds the rate limit and a KoD was already sent recently —
    /// drop silently.
    Drop,
}

/// Per-client state for rate limiting and interleaved mode tracking.
pub struct ClientState {
    // Rate limiting.
    /// Timestamp of the last *accepted* request from this client. `None`
    /// until the first request is accepted, so first contact is never
    /// rejected by the minimum-interval check.
    last_request_time: Option<Instant>,
    /// Timestamp of the last time this client touched the table (accepted or
    /// not). Used for stale-entry eviction.
    last_seen: Instant,
    /// When the last KoD RATE was sent to this client, if any.
    last_kod_time: Option<Instant>,
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
            last_request_time: None,
            last_seen: now,
            last_kod_time: None,
            request_count: 0,
            window_start: now,
            last_t2: protocol::TimestampFormat::default(),
            last_t3: protocol::TimestampFormat::default(),
            last_client_xmt: protocol::TimestampFormat::default(),
        }
    }
}

/// Number of entries sampled when the table is full and no stale entry was
/// found; the least recently seen of the sample is evicted. Keeps eviction
/// O(1) instead of a full-table scan per new client.
const EVICTION_SAMPLE: usize = 8;

/// Bounded client state table keyed by IP address (not port, per RFC 9109).
pub struct ClientTable {
    entries: HashMap<IpAddr, ClientState>,
    max_entries: usize,
    /// How long until a stale entry can be evicted.
    stale_threshold: Duration,
    /// Minimum interval between full stale sweeps.
    sweep_interval: Duration,
    /// When the last full stale sweep ran.
    last_sweep: Option<Instant>,
}

impl ClientTable {
    /// Create a new client table with the given maximum number of entries.
    pub fn new(max_entries: usize) -> Self {
        ClientTable {
            entries: HashMap::new(),
            max_entries,
            stale_threshold: Duration::from_secs(24 * 3600),
            sweep_interval: Duration::from_secs(60),
            last_sweep: None,
        }
    }

    /// Get or create a client state entry, evicting an entry if the table is
    /// full.
    pub(crate) fn get_or_insert(&mut self, ip: IpAddr, now: Instant) -> &mut ClientState {
        if !self.entries.contains_key(&ip) && self.entries.len() >= self.max_entries {
            self.make_room(now);
        }

        let state = self
            .entries
            .entry(ip)
            .or_insert_with(|| ClientState::new(now));
        state.last_seen = now;
        state
    }

    /// Get an existing client state entry (for interleaved mode lookup).
    pub(crate) fn get(&self, ip: &IpAddr) -> Option<&ClientState> {
        self.entries.get(ip)
    }

    /// Return the number of tracked clients.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Free at least one slot in a full table.
    ///
    /// A full stale sweep is O(n), so it runs at most once per
    /// `sweep_interval`. Between sweeps a small sample of entries is examined
    /// and the least recently seen one is evicted, which is O(1) per packet
    /// and cannot be driven into a CPU-exhaustion state by a flood of spoofed
    /// source addresses.
    fn make_room(&mut self, now: Instant) {
        if self.max_entries == 0 {
            return;
        }

        let sweep_due = self
            .last_sweep
            .is_none_or(|t| now.duration_since(t) >= self.sweep_interval);
        if sweep_due {
            self.last_sweep = Some(now);
            let threshold = self.stale_threshold;
            self.entries
                .retain(|_, state| now.duration_since(state.last_seen) < threshold);
            if self.entries.len() < self.max_entries {
                return;
            }
        }

        // HashMap iteration order is arbitrary, so the first few entries act as
        // a cheap pseudo-random sample.
        if let Some(victim) = self
            .entries
            .iter()
            .take(EVICTION_SAMPLE)
            .min_by_key(|(_, state)| state.last_seen)
            .map(|(ip, _)| *ip)
        {
            self.entries.remove(&victim);
        }
    }
}

/// Check the rate limit for a client.
pub(crate) fn check_rate_limit(
    client: &mut ClientState,
    now: Instant,
    config: &RateLimitConfig,
) -> RateLimitResult {
    // Reset window if expired.
    if now.duration_since(client.window_start) > config.window_duration {
        client.window_start = now;
        client.request_count = 0;
    }

    // Check minimum interval since the last accepted request. A brand-new
    // client has no previous request and must be allowed through.
    let too_soon = client
        .last_request_time
        .is_some_and(|last| now.duration_since(last) < config.min_interval);

    // Saturate rather than wrap: a sustained flood must never overflow the
    // counter back to zero (which would briefly re-allow the client) and must
    // not panic in debug builds.
    client.request_count = client.request_count.saturating_add(1);
    let over_window = client.request_count > config.max_requests_per_window;

    if too_soon || over_window {
        return rate_exceeded(client, now, config);
    }

    client.last_request_time = Some(now);
    RateLimitResult::Allow
}

/// Decide whether an over-limit request gets a KoD RATE or is dropped.
///
/// At most one KoD per `window_duration` is sent to a given client. KoD
/// replies are the same size as the request, so they do not amplify, but
/// answering every over-limit packet still reflects the full attack rate at a
/// spoofed victim. The real client only needs to see one KoD to back off.
fn rate_exceeded(
    client: &mut ClientState,
    now: Instant,
    config: &RateLimitConfig,
) -> RateLimitResult {
    let kod_recent = client
        .last_kod_time
        .is_some_and(|t| now.duration_since(t) < config.window_duration);
    if kod_recent {
        RateLimitResult::Drop
    } else {
        client.last_kod_time = Some(now);
        RateLimitResult::RateExceeded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(r: RateLimitResult) -> bool {
        matches!(r, RateLimitResult::Allow)
    }

    #[test]
    fn test_rate_limit_allows_first_request() {
        // Regression: a brand-new client must not be KoD'd on first contact
        // under the default (2 s min_interval) config.
        let now = Instant::now();
        let mut client = ClientState::new(now);
        let config = RateLimitConfig::default();
        assert!(allowed(check_rate_limit(&mut client, now, &config)));
    }

    #[test]
    fn test_rate_limit_allows_first_request_via_table() {
        let mut table = ClientTable::new(10);
        let now = Instant::now();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let client = table.get_or_insert(ip, now);
        assert!(allowed(check_rate_limit(
            client,
            now,
            &RateLimitConfig::default()
        )));
    }

    #[test]
    fn test_rate_limit_min_interval() {
        let now = Instant::now();
        let mut client = ClientState::new(now);
        let config = RateLimitConfig {
            min_interval: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(allowed(check_rate_limit(&mut client, now, &config)));
        // Request 1 second later — too soon.
        let result = check_rate_limit(&mut client, now + Duration::from_secs(1), &config);
        assert!(matches!(result, RateLimitResult::RateExceeded));
        // 2 seconds after the accepted request — fine again.
        let result = check_rate_limit(&mut client, now + Duration::from_secs(2), &config);
        assert!(allowed(result));
    }

    #[test]
    fn test_rate_limit_window_exceeded() {
        let now = Instant::now();
        let mut client = ClientState::new(now);
        let config = RateLimitConfig {
            max_requests_per_window: 2,
            window_duration: Duration::from_secs(60),
            min_interval: Duration::from_millis(1),
        };
        // Send 3 requests spaced apart (passes min_interval but exceeds window).
        let t1 = now;
        let t2 = now + Duration::from_millis(100);
        let t3 = now + Duration::from_millis(200);

        assert!(allowed(check_rate_limit(&mut client, t1, &config)));
        assert!(allowed(check_rate_limit(&mut client, t2, &config)));
        assert!(matches!(
            check_rate_limit(&mut client, t3, &config),
            RateLimitResult::RateExceeded
        ));
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let now = Instant::now();
        let mut client = ClientState::new(now);
        let config = RateLimitConfig {
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(1),
            min_interval: Duration::from_millis(1),
        };

        let t1 = now;
        let t2 = now + Duration::from_millis(100);
        let t3 = now + Duration::from_secs(2); // After window reset

        assert!(allowed(check_rate_limit(&mut client, t1, &config)));
        assert!(matches!(
            check_rate_limit(&mut client, t2, &config),
            RateLimitResult::RateExceeded
        ));
        // After window resets.
        assert!(allowed(check_rate_limit(&mut client, t3, &config)));
    }

    #[test]
    fn test_kod_sent_once_per_window_then_dropped() {
        let now = Instant::now();
        let mut client = ClientState::new(now);
        let config = RateLimitConfig {
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(60),
            min_interval: Duration::ZERO,
        };
        assert!(allowed(check_rate_limit(&mut client, now, &config)));

        // A flood of over-limit packets: exactly one KoD, the rest dropped.
        let mut kods = 0;
        let mut drops = 0;
        for i in 1..=1000u64 {
            match check_rate_limit(&mut client, now + Duration::from_millis(i), &config) {
                RateLimitResult::RateExceeded => kods += 1,
                RateLimitResult::Drop => drops += 1,
                RateLimitResult::Allow => panic!("over-limit request allowed"),
            }
        }
        assert_eq!(kods, 1);
        assert_eq!(drops, 999);

        // After the window a new KoD may be sent.
        let later = now + Duration::from_secs(61);
        assert!(allowed(check_rate_limit(&mut client, later, &config)));
        assert!(matches!(
            check_rate_limit(&mut client, later + Duration::from_millis(1), &config),
            RateLimitResult::RateExceeded
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
    fn test_client_table_eviction_keeps_bound() {
        let mut table = ClientTable::new(2);
        let now = Instant::now();
        let ip1: IpAddr = "1.0.0.1".parse().unwrap();
        let ip2: IpAddr = "1.0.0.2".parse().unwrap();
        let ip3: IpAddr = "1.0.0.3".parse().unwrap();

        table.get_or_insert(ip1, now);
        table.get_or_insert(ip2, now + Duration::from_secs(1));
        // Table is full (2 entries). Adding ip3 must evict one of the others.
        table.get_or_insert(ip3, now + Duration::from_secs(2));

        assert_eq!(table.len(), 2);
        assert!(table.get(&ip3).is_some());
        // With a sample size >= table size the eviction is exact: the least
        // recently seen entry (ip1) goes.
        assert!(table.get(&ip1).is_none());
        assert!(table.get(&ip2).is_some());
    }

    #[test]
    fn test_client_table_evicts_stale_first() {
        let mut table = ClientTable::new(3);
        let now = Instant::now();
        let stale: IpAddr = "1.0.0.1".parse().unwrap();
        let fresh_a: IpAddr = "1.0.0.2".parse().unwrap();
        let fresh_b: IpAddr = "1.0.0.3".parse().unwrap();
        let newcomer: IpAddr = "1.0.0.4".parse().unwrap();

        table.get_or_insert(stale, now);
        let later = now + Duration::from_secs(25 * 3600);
        table.get_or_insert(fresh_a, later);
        table.get_or_insert(fresh_b, later);
        table.get_or_insert(newcomer, later + Duration::from_secs(1));

        assert!(table.get(&stale).is_none());
        assert!(table.get(&fresh_a).is_some());
        assert!(table.get(&fresh_b).is_some());
        assert!(table.get(&newcomer).is_some());
    }

    #[test]
    fn test_client_table_flood_stays_bounded() {
        // Many distinct sources must never grow the table past its bound and
        // must not require a full scan per insert (this test would be very
        // slow at 1.1 ms/packet).
        let max = 1_000;
        let mut table = ClientTable::new(max);
        let now = Instant::now();
        for i in 0..50_000u32 {
            let ip = IpAddr::from(i.to_be_bytes());
            table.get_or_insert(ip, now + Duration::from_micros(i as u64));
            assert!(table.len() <= max);
        }
        assert_eq!(table.len(), max);
    }
}
