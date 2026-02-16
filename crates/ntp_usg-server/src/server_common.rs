// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared types and logic for the NTP server, used by both the
//! tokio-based [`crate::server`] and smol-based [`crate::smol_server`] modules.
//!
//! Provides request validation, response building, rate limiting, access control,
//! and interleaved mode tracking per RFC 5905, RFC 8633, and RFC 9769.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use log::debug;

use crate::protocol::{self, ConstPackedSizeBytes, ReadBytes, WriteBytes};
use crate::unix_time;

// ============================================================================
// Server system state
// ============================================================================

/// Server-wide system variables (RFC 5905 Section 11).
///
/// These values are populated from the server's reference clock or upstream
/// source and are included in every response packet. They can be updated at
/// runtime (e.g., when the server synchronizes to a new upstream source) by
/// obtaining a write lock on the `Arc<RwLock<ServerSystemState>>`.
#[derive(Clone, Debug)]
pub struct ServerSystemState {
    /// Leap indicator warning of impending leap second.
    pub leap_indicator: protocol::LeapIndicator,
    /// Stratum level of this server.
    pub stratum: protocol::Stratum,
    /// Precision of the server's clock, in log2 seconds (e.g., -20 ≈ 1μs).
    pub precision: i8,
    /// Total round-trip delay to the primary reference source.
    pub root_delay: protocol::ShortFormat,
    /// Total dispersion to the primary reference source.
    pub root_dispersion: protocol::ShortFormat,
    /// Reference clock identifier (e.g., GPS, LOCL, or upstream server IP).
    pub reference_id: protocol::ReferenceIdentifier,
    /// Time when the system clock was last set or corrected.
    pub reference_timestamp: protocol::TimestampFormat,
}

impl Default for ServerSystemState {
    fn default() -> Self {
        ServerSystemState {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            stratum: protocol::Stratum::PRIMARY,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::PrimarySource(
                protocol::PrimarySource::Locl,
            ),
            reference_timestamp: unix_time::Instant::now().into(),
        }
    }
}

// ============================================================================
// Request validation
// ============================================================================

/// Validate an incoming NTP client request packet.
///
/// Performs the server-side checks required by RFC 5905 Section 8:
/// - Minimum packet size (48 bytes)
/// - Mode is Client (3)
/// - Version is recognized (V3 or V4)
/// - Transmit timestamp is non-zero
///
/// Returns the parsed packet on success.
pub(crate) fn validate_client_request(
    recv_buf: &[u8],
    recv_len: usize,
) -> io::Result<protocol::Packet> {
    if recv_len < protocol::Packet::PACKED_SIZE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTP request too short",
        ));
    }

    let request: protocol::Packet =
        (&recv_buf[..protocol::Packet::PACKED_SIZE_BYTES]).read_bytes()?;

    if request.mode != protocol::Mode::Client {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected request mode: expected Client, got {:?}",
                request.mode
            ),
        ));
    }

    if !request.version.is_known() || request.version < protocol::Version::V3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported NTP version",
        ));
    }

    if request.transmit_timestamp.seconds == 0 && request.transmit_timestamp.fraction == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client transmit timestamp is zero",
        ));
    }

    Ok(request)
}

// ============================================================================
// Response building
// ============================================================================

/// Build an NTP server response packet for a client request.
///
/// Per RFC 5905 Section 8:
/// - `origin_timestamp` is set to the client's `transmit_timestamp` (anti-replay)
/// - `receive_timestamp` is T2 (when the request arrived)
/// - `transmit_timestamp` is left as default (caller patches T3 just before sending)
/// - `version` echoes the client's version
/// - `mode` is `Server`
pub(crate) fn build_server_response(
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    t2: protocol::TimestampFormat,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: server_state.leap_indicator,
        version: request.version,
        mode: protocol::Mode::Server,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_timestamp: server_state.reference_timestamp,
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: t2,
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Build a Kiss-o'-Death (KoD) response packet.
///
/// Per RFC 5905 Section 7.4, KoD packets have stratum 0 and the reference
/// identifier set to the kiss code.
pub(crate) fn build_kod_response(
    request: &protocol::Packet,
    kod: protocol::KissOfDeath,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: protocol::LeapIndicator::Unknown,
        version: request.version,
        mode: protocol::Mode::Server,
        stratum: protocol::Stratum::UNSPECIFIED,
        poll: request.poll,
        precision: 0,
        root_delay: protocol::ShortFormat::default(),
        root_dispersion: protocol::ShortFormat::default(),
        reference_id: protocol::ReferenceIdentifier::KissOfDeath(kod),
        reference_timestamp: protocol::TimestampFormat::default(),
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Serialize a response packet to bytes and patch T3 (transmit timestamp)
/// as late as possible for maximum accuracy.
///
/// Returns the serialized buffer ready to send.
pub(crate) fn serialize_response_with_t3(
    response: &protocol::Packet,
) -> io::Result<[u8; protocol::Packet::PACKED_SIZE_BYTES]> {
    let mut buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];

    // Serialize the packet with a placeholder T3.
    (&mut buf[..]).write_bytes(*response)?;

    // Patch T3 at offset 40..48 with the current time.
    let t3: protocol::TimestampFormat = unix_time::Instant::now().into();
    let t3_bytes_sec = t3.seconds.to_be_bytes();
    let t3_bytes_frac = t3.fraction.to_be_bytes();
    buf[40..44].copy_from_slice(&t3_bytes_sec);
    buf[44..48].copy_from_slice(&t3_bytes_frac);

    Ok(buf)
}

// ============================================================================
// IP network matching
// ============================================================================

/// An IP network (address + prefix length) for access control matching.
///
/// Supports both IPv4 and IPv6 addresses. Prefix lengths are bounded to
/// the address type's maximum (32 for IPv4, 128 for IPv6).
#[derive(Clone, Debug)]
pub struct IpNet {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    /// Create a new IP network.
    ///
    /// The prefix length is clamped to the maximum for the address type
    /// (32 for IPv4, 128 for IPv6).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        IpNet {
            addr,
            prefix_len: prefix_len.min(max),
        }
    }

    /// Check whether the given IP address falls within this network.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX.checked_shl(32 - self.prefix_len as u32).unwrap_or(0);
                (u32::from(*net) & mask) == (u32::from(*addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX
                    .checked_shl(128 - self.prefix_len as u32)
                    .unwrap_or(0);
                (u128::from(*net) & mask) == (u128::from(*addr) & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

// ============================================================================
// Access control
// ============================================================================

/// Result of an access control check.
pub(crate) enum AccessResult {
    /// Request is allowed.
    Allow,
    /// Client is explicitly denied — send KoD DENY.
    Deny,
    /// Client is restricted (not on allow list) — send KoD RSTR.
    Restrict,
}

/// IP-based access control lists for the NTP server.
///
/// If a deny list is configured, any matching client receives a KoD DENY.
/// If an allow list is configured, non-matching clients receive a KoD RSTR.
/// If neither list is configured, all clients are allowed.
#[derive(Clone, Debug, Default)]
pub struct AccessControl {
    allow_list: Option<Vec<IpNet>>,
    deny_list: Option<Vec<IpNet>>,
}

impl AccessControl {
    /// Create an access control with optional allow and deny lists.
    pub fn new(allow_list: Option<Vec<IpNet>>, deny_list: Option<Vec<IpNet>>) -> Self {
        AccessControl {
            allow_list,
            deny_list,
        }
    }

    /// Check whether the given client IP is allowed.
    pub(crate) fn check(&self, client_ip: &IpAddr) -> AccessResult {
        // Deny list checked first.
        if let Some(deny) = &self.deny_list
            && deny.iter().any(|net| net.contains(client_ip)) {
                return AccessResult::Deny;
            }
        // If allow list exists, client must match.
        if let Some(allow) = &self.allow_list
            && !allow.iter().any(|net| net.contains(client_ip)) {
                return AccessResult::Restrict;
            }
        AccessResult::Allow
    }
}

// ============================================================================
// Rate limiting
// ============================================================================

/// Configuration for per-client rate limiting.
///
/// Rate limiting is per client IP address (not per port, per RFC 9109).
#[derive(Clone, Debug)]
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

// ============================================================================
// Per-client state
// ============================================================================

/// Per-client state for rate limiting and interleaved mode tracking.
pub(crate) struct ClientState {
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
    fn new(now: Instant) -> Self {
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
pub(crate) struct ClientTable {
    entries: HashMap<IpAddr, ClientState>,
    max_entries: usize,
    /// How long until a stale entry can be evicted.
    stale_threshold: Duration,
}

impl ClientTable {
    pub(crate) fn new(max_entries: usize) -> Self {
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

// ============================================================================
// Interleaved mode (RFC 9769)
// ============================================================================

/// Attempt to build an interleaved-mode response for the client.
///
/// Returns `Some(packet)` if the client's origin timestamp matches our
/// previous transmit timestamp (indicating interleaved mode), or `None`
/// for basic mode.
pub(crate) fn build_interleaved_response(
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    client_state: &ClientState,
    t2: protocol::TimestampFormat,
) -> Option<protocol::Packet> {
    // A zero last_t3 means we have no previous exchange to interleave with.
    if client_state.last_t3.seconds == 0 && client_state.last_t3.fraction == 0 {
        return None;
    }

    // Check if client's origin timestamp matches our previous T3.
    if request.origin_timestamp != client_state.last_t3 {
        return None;
    }

    debug!(
        "interleaved mode detected for client (origin matches prev T3: {:?})",
        client_state.last_t3
    );

    Some(protocol::Packet {
        leap_indicator: server_state.leap_indicator,
        version: request.version,
        mode: protocol::Mode::Server,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_timestamp: server_state.reference_timestamp,
        // Interleaved: origin = client's previous xmt.
        origin_timestamp: client_state.last_client_xmt,
        // Interleaved: T2 from the previous exchange.
        receive_timestamp: client_state.last_t2,
        // T3 will be patched later.
        transmit_timestamp: t2, // Use current T2 as a placeholder; real T3 patched in serialize
    })
}

/// Update per-client state after a successful exchange.
pub(crate) fn update_client_state(
    client: &mut ClientState,
    t2: protocol::TimestampFormat,
    t3: protocol::TimestampFormat,
    client_xmt: protocol::TimestampFormat,
) {
    client.last_t2 = t2;
    client.last_t3 = t3;
    client.last_client_xmt = client_xmt;
}

// ============================================================================
// Request handling pipeline
// ============================================================================

/// The complete result of handling a client request.
pub(crate) enum HandleResult {
    /// Send this response buffer to the client.
    Response([u8; protocol::Packet::PACKED_SIZE_BYTES]),
    /// Drop the packet (invalid request, silently ignored).
    Drop,
}

/// Handle a single incoming NTP request (pure logic, no I/O).
///
/// This is the main request processing pipeline called by both the tokio
/// and smol server loops.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_request(
    recv_buf: &[u8],
    recv_len: usize,
    src_ip: IpAddr,
    server_state: &ServerSystemState,
    access_control: &AccessControl,
    rate_limit_config: Option<&RateLimitConfig>,
    client_table: &mut ClientTable,
    enable_interleaved: bool,
) -> HandleResult {
    // 1. Validate the request.
    let request = match validate_client_request(recv_buf, recv_len) {
        Ok(req) => req,
        Err(e) => {
            debug!("dropping invalid request from {}: {}", src_ip, e);
            return HandleResult::Drop;
        }
    };

    // 2. Access control.
    match access_control.check(&src_ip) {
        AccessResult::Allow => {}
        AccessResult::Deny => {
            let kod = build_kod_response(&request, protocol::KissOfDeath::Deny);
            match serialize_response_with_t3(&kod) {
                Ok(buf) => return HandleResult::Response(buf),
                Err(_) => return HandleResult::Drop,
            }
        }
        AccessResult::Restrict => {
            let kod = build_kod_response(&request, protocol::KissOfDeath::Rstr);
            match serialize_response_with_t3(&kod) {
                Ok(buf) => return HandleResult::Response(buf),
                Err(_) => return HandleResult::Drop,
            }
        }
    }

    let now = Instant::now();

    // 3. Rate limiting.
    if let Some(config) = rate_limit_config {
        let client = client_table.get_or_insert(src_ip, now);
        match check_rate_limit(client, now, config) {
            RateLimitResult::Allow => {}
            RateLimitResult::RateExceeded => {
                let kod = build_kod_response(&request, protocol::KissOfDeath::Rate);
                match serialize_response_with_t3(&kod) {
                    Ok(buf) => return HandleResult::Response(buf),
                    Err(_) => return HandleResult::Drop,
                }
            }
        }
    }

    // 4. Record T2 (receive timestamp).
    let t2: protocol::TimestampFormat = unix_time::Instant::now().into();

    // 5. Check for interleaved mode.
    let response = if enable_interleaved {
        if let Some(client_state) = client_table.get(&src_ip) {
            build_interleaved_response(&request, server_state, client_state, t2)
        } else {
            None
        }
    } else {
        None
    };

    // 6. Build response (basic or interleaved).
    let response = response.unwrap_or_else(|| build_server_response(&request, server_state, t2));

    // 7. Serialize with T3.
    let buf = match serialize_response_with_t3(&response) {
        Ok(buf) => buf,
        Err(e) => {
            debug!("failed to serialize response for {}: {}", src_ip, e);
            return HandleResult::Drop;
        }
    };

    // 8. Extract the actual T3 we just wrote for client state update.
    let t3_seconds = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
    let t3_fraction = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);
    let t3 = protocol::TimestampFormat {
        seconds: t3_seconds,
        fraction: t3_fraction,
    };

    // 9. Update per-client state.
    let client = client_table.get_or_insert(src_ip, now);
    update_client_state(client, t2, t3, request.transmit_timestamp);

    HandleResult::Response(buf)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_request_packet(version: protocol::Version) -> protocol::Packet {
        protocol::Packet {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            version,
            mode: protocol::Mode::Client,
            stratum: protocol::Stratum::UNSPECIFIED,
            poll: 6,
            precision: 0,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::PrimarySource(
                protocol::PrimarySource::Null,
            ),
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: protocol::TimestampFormat::default(),
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 12345,
            },
        }
    }

    fn serialize_packet(pkt: &protocol::Packet) -> [u8; 48] {
        let mut buf = [0u8; 48];
        (&mut buf[..]).write_bytes(*pkt).unwrap();
        buf
    }

    fn test_server_state() -> ServerSystemState {
        ServerSystemState {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            stratum: protocol::Stratum(2),
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat {
                seconds: 3_913_000_000,
                fraction: 0,
            },
        }
    }

    // ── validate_client_request ──────────────────────────────────

    #[test]
    fn test_validate_accepts_v4_client() {
        let pkt = make_client_request_packet(protocol::Version::V4);
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.mode, protocol::Mode::Client);
        assert_eq!(parsed.version, protocol::Version::V4);
    }

    #[test]
    fn test_validate_accepts_v3_client() {
        let pkt = make_client_request_packet(protocol::Version::V3);
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_short_packet() {
        let buf = [0u8; 48];
        let result = validate_client_request(&buf, 47);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_validate_rejects_server_mode() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.mode = protocol::Mode::Server;
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unexpected request mode")
        );
    }

    #[test]
    fn test_validate_rejects_v2() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.version = protocol::Version::V2;
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported NTP version")
        );
    }

    #[test]
    fn test_validate_rejects_zero_transmit() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.transmit_timestamp = protocol::TimestampFormat {
            seconds: 0,
            fraction: 0,
        };
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("transmit timestamp is zero")
        );
    }

    // ── build_server_response ─────────────────────────────────────

    #[test]
    fn test_response_copies_client_xmt_to_origin() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.origin_timestamp, request.transmit_timestamp);
    }

    #[test]
    fn test_response_mode_is_server() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat::default();
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.mode, protocol::Mode::Server);
    }

    #[test]
    fn test_response_echoes_version() {
        let request = make_client_request_packet(protocol::Version::V3);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat::default();
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.version, protocol::Version::V3);
    }

    #[test]
    fn test_response_sets_t2() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 999,
        };
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.receive_timestamp, t2);
    }

    #[test]
    fn test_response_uses_server_state() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat::default();
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.stratum, state.stratum);
        assert_eq!(response.precision, state.precision);
        assert_eq!(response.leap_indicator, state.leap_indicator);
        assert_eq!(response.reference_id, state.reference_id);
    }

    // ── build_kod_response ────────────────────────────────────────

    #[test]
    fn test_kod_deny() {
        let request = make_client_request_packet(protocol::Version::V4);
        let kod = build_kod_response(&request, protocol::KissOfDeath::Deny);
        assert_eq!(kod.stratum, protocol::Stratum::UNSPECIFIED);
        assert_eq!(kod.mode, protocol::Mode::Server);
        assert_eq!(
            kod.reference_id,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Deny)
        );
        assert_eq!(kod.origin_timestamp, request.transmit_timestamp);
        assert_eq!(kod.leap_indicator, protocol::LeapIndicator::Unknown);
    }

    #[test]
    fn test_kod_rate() {
        let request = make_client_request_packet(protocol::Version::V4);
        let kod = build_kod_response(&request, protocol::KissOfDeath::Rate);
        assert_eq!(
            kod.reference_id,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Rate)
        );
    }

    #[test]
    fn test_kod_rstr() {
        let request = make_client_request_packet(protocol::Version::V4);
        let kod = build_kod_response(&request, protocol::KissOfDeath::Rstr);
        assert_eq!(
            kod.reference_id,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Rstr)
        );
    }

    // ── serialize_response_with_t3 ────────────────────────────────

    #[test]
    fn test_serialize_patches_t3() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = build_server_response(&request, &state, t2);
        let buf = serialize_response_with_t3(&response).unwrap();

        // Parse it back.
        let parsed: protocol::Packet = (&buf[..48]).read_bytes().unwrap();
        // T3 should be non-zero (patched to current time).
        assert!(
            parsed.transmit_timestamp.seconds != 0 || parsed.transmit_timestamp.fraction != 0
        );
    }

    // ── IpNet ─────────────────────────────────────────────────────

    #[test]
    fn test_ipnet_contains_exact() {
        let net = IpNet::new("192.168.1.1".parse().unwrap(), 32);
        assert!(net.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!net.contains(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_contains_subnet() {
        let net = IpNet::new("192.168.1.0".parse().unwrap(), 24);
        assert!(net.contains(&"192.168.1.0".parse().unwrap()));
        assert!(net.contains(&"192.168.1.255".parse().unwrap()));
        assert!(!net.contains(&"192.168.2.0".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_contains_slash_zero() {
        let net = IpNet::new("0.0.0.0".parse().unwrap(), 0);
        assert!(net.contains(&"1.2.3.4".parse().unwrap()));
        assert!(net.contains(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_v4_v6_mismatch() {
        let net = IpNet::new("192.168.1.0".parse().unwrap(), 24);
        assert!(!net.contains(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_ipv6() {
        let net = IpNet::new("2001:db8::".parse().unwrap(), 32);
        assert!(net.contains(&"2001:db8::1".parse().unwrap()));
        assert!(net.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!net.contains(&"2001:db9::1".parse().unwrap()));
    }

    // ── AccessControl ─────────────────────────────────────────────

    #[test]
    fn test_access_no_lists() {
        let ac = AccessControl::new(None, None);
        assert!(matches!(
            ac.check(&"1.2.3.4".parse().unwrap()),
            AccessResult::Allow
        ));
    }

    #[test]
    fn test_access_deny_list() {
        let deny = vec![IpNet::new("10.0.0.0".parse().unwrap(), 8)];
        let ac = AccessControl::new(None, Some(deny));
        assert!(matches!(
            ac.check(&"10.1.2.3".parse().unwrap()),
            AccessResult::Deny
        ));
        assert!(matches!(
            ac.check(&"192.168.1.1".parse().unwrap()),
            AccessResult::Allow
        ));
    }

    #[test]
    fn test_access_allow_list() {
        let allow = vec![IpNet::new("192.168.0.0".parse().unwrap(), 16)];
        let ac = AccessControl::new(Some(allow), None);
        assert!(matches!(
            ac.check(&"192.168.1.1".parse().unwrap()),
            AccessResult::Allow
        ));
        assert!(matches!(
            ac.check(&"10.0.0.1".parse().unwrap()),
            AccessResult::Restrict
        ));
    }

    #[test]
    fn test_access_deny_overrides_allow() {
        let allow = vec![IpNet::new("10.0.0.0".parse().unwrap(), 8)];
        let deny = vec![IpNet::new("10.0.0.1".parse().unwrap(), 32)];
        let ac = AccessControl::new(Some(allow), Some(deny));
        // 10.0.0.1 is in both — deny wins.
        assert!(matches!(
            ac.check(&"10.0.0.1".parse().unwrap()),
            AccessResult::Deny
        ));
        // 10.0.0.2 is in allow but not deny — allowed.
        assert!(matches!(
            ac.check(&"10.0.0.2".parse().unwrap()),
            AccessResult::Allow
        ));
    }

    // ── Rate limiting ─────────────────────────────────────────────

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

    // ── Interleaved mode ──────────────────────────────────────────

    #[test]
    fn test_interleaved_not_detected_first_exchange() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let client = ClientState::new(Instant::now());
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        // No previous state → basic mode.
        let result = build_interleaved_response(&request, &state, &client, t2);
        assert!(result.is_none());
    }

    #[test]
    fn test_interleaved_detected() {
        let state = test_server_state();
        let prev_t3 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 500,
        };
        let prev_t2 = protocol::TimestampFormat {
            seconds: 3_913_055_999,
            fraction: 999,
        };
        let prev_client_xmt = protocol::TimestampFormat {
            seconds: 3_913_055_998,
            fraction: 0,
        };

        let mut client = ClientState::new(Instant::now());
        client.last_t3 = prev_t3;
        client.last_t2 = prev_t2;
        client.last_client_xmt = prev_client_xmt;

        // Client sends origin = our previous T3 → interleaved.
        let mut request = make_client_request_packet(protocol::Version::V4);
        request.origin_timestamp = prev_t3;

        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_010,
            fraction: 0,
        };
        let result = build_interleaved_response(&request, &state, &client, t2);
        assert!(result.is_some());
        let pkt = result.unwrap();
        assert_eq!(pkt.origin_timestamp, prev_client_xmt);
        assert_eq!(pkt.receive_timestamp, prev_t2);
    }

    #[test]
    fn test_interleaved_not_detected_mismatch() {
        let state = test_server_state();
        let mut client = ClientState::new(Instant::now());
        client.last_t3 = protocol::TimestampFormat {
            seconds: 100,
            fraction: 0,
        };

        let mut request = make_client_request_packet(protocol::Version::V4);
        request.origin_timestamp = protocol::TimestampFormat {
            seconds: 999,
            fraction: 0,
        }; // Doesn't match

        let t2 = protocol::TimestampFormat::default();
        let result = build_interleaved_response(&request, &state, &client, t2);
        assert!(result.is_none());
    }

    // ── ClientTable ───────────────────────────────────────────────

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

    // ── handle_request pipeline ───────────────────────────────────

    #[test]
    fn test_handle_valid_request() {
        let request = make_client_request_packet(protocol::Version::V4);
        let buf = serialize_packet(&request);
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );
        assert!(matches!(result, HandleResult::Response(_)));

        if let HandleResult::Response(resp_buf) = result {
            let response: protocol::Packet = (&resp_buf[..48]).read_bytes().unwrap();
            assert_eq!(response.mode, protocol::Mode::Server);
            assert_eq!(response.origin_timestamp, request.transmit_timestamp);
            assert_eq!(response.stratum, state.stratum);
        }
    }

    #[test]
    fn test_handle_denied_ip() {
        let request = make_client_request_packet(protocol::Version::V4);
        let buf = serialize_packet(&request);
        let state = test_server_state();
        let ac = AccessControl::new(
            None,
            Some(vec![IpNet::new("127.0.0.0".parse().unwrap(), 8)]),
        );
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );
        if let HandleResult::Response(resp_buf) = result {
            let response: protocol::Packet = (&resp_buf[..48]).read_bytes().unwrap();
            assert_eq!(response.stratum, protocol::Stratum::UNSPECIFIED);
            assert_eq!(
                response.reference_id,
                protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Deny)
            );
        } else {
            panic!("expected Response, got Drop");
        }
    }

    #[test]
    fn test_handle_drops_invalid_packet() {
        let buf = [0u8; 48]; // All zeros → zero xmt timestamp
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );
        assert!(matches!(result, HandleResult::Drop));
    }
}
