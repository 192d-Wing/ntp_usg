//! Core NTP request types and blocking networking functions.
//!
//! This module contains the types (`NtpResult`, `KissOfDeathError`), packet
//! construction, response validation, and blocking I/O used by the synchronous
//! `request()` API.  The async modules (`async_ntp`, `smol_ntp`) and continuous
//! clients reuse the packet-building and validation helpers defined here.

use log::debug;

use crate::protocol::{self, ConstPackedSizeBytes, ReadBytes, WriteBytes};
use crate::unix_time;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::ops::Deref;
use std::time::Duration;

/// Select the appropriate bind address based on the target address family.
///
/// Returns `"0.0.0.0:0"` for IPv4 targets and `"[::]:0"` for IPv6 targets.
pub(crate) fn bind_addr_for(target: &SocketAddr) -> &'static str {
    match target {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    }
}

/// Error returned when the server responds with a Kiss-o'-Death (KoD) packet.
///
/// Per RFC 5905 Section 7.4, recipients of kiss codes MUST inspect them and take
/// the described actions. This error is returned as the inner error of an
/// [`io::Error`] with kind [`io::ErrorKind::ConnectionRefused`], and can be
/// extracted via [`io::Error::get_ref`] and `downcast_ref`.
///
/// # Caller Responsibilities
///
/// - **DENY / RSTR**: The caller MUST stop sending packets to this server.
/// - **RATE**: The caller MUST reduce its polling interval before retrying.
///
/// # Examples
///
/// ```no_run
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// match ntp_client::request("time.nist.gov:123") {
///     Ok(result) => println!("Offset: {:.6}s", result.offset_seconds),
///     Err(e) => {
///         if let Some(kod) = e.get_ref().and_then(|inner| inner.downcast_ref::<ntp_client::KissOfDeathError>()) {
///             eprintln!("Kiss-o'-Death: {:?}", kod.code);
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct KissOfDeathError {
    /// The specific kiss code received from the server.
    pub code: protocol::KissOfDeath,
}

impl std::fmt::Display for KissOfDeathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            protocol::KissOfDeath::Deny => {
                write!(
                    f,
                    "server sent Kiss-o'-Death DENY: access denied, stop querying this server"
                )
            }
            protocol::KissOfDeath::Rstr => {
                write!(
                    f,
                    "server sent Kiss-o'-Death RSTR: access restricted, stop querying this server"
                )
            }
            protocol::KissOfDeath::Rate => {
                write!(f, "server sent Kiss-o'-Death RATE: reduce polling interval")
            }
        }
    }
}

impl std::error::Error for KissOfDeathError {}

/// The result of an NTP request, containing the server's response packet
/// along with computed timing information.
///
/// This struct implements `Deref<Target = protocol::Packet>`, so all packet
/// fields can be accessed directly (e.g., `result.transmit_timestamp`).
#[derive(Clone, Copy, Debug)]
pub struct NtpResult {
    /// The parsed NTP response packet from the server.
    pub packet: protocol::Packet,
    /// The destination timestamp (T4): local time when the response was received.
    ///
    /// Expressed as an NTP `TimestampFormat` for consistency with the packet timestamps.
    pub destination_timestamp: protocol::TimestampFormat,
    /// Clock offset: the estimated difference between the local clock and the server clock.
    ///
    /// Computed as `((T2 - T1) + (T3 - T4)) / 2` per RFC 5905 Section 8, where:
    /// - T1 = origin timestamp (client transmit time)
    /// - T2 = receive timestamp (server receive time)
    /// - T3 = transmit timestamp (server transmit time)
    /// - T4 = destination timestamp (client receive time)
    ///
    /// A positive value means the local clock is behind the server.
    /// A negative value means the local clock is ahead of the server.
    pub offset_seconds: f64,
    /// Round-trip delay between the client and server.
    ///
    /// Computed as `(T4 - T1) - (T3 - T2)` per RFC 5905 Section 8.
    pub delay_seconds: f64,
}

impl Deref for NtpResult {
    type Target = protocol::Packet;
    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

/// Convert a Unix `Instant` to seconds as f64 (relative to Unix epoch).
fn instant_to_f64(instant: &unix_time::Instant) -> f64 {
    instant.secs() as f64 + (instant.subsec_nanos() as f64 / 1e9)
}

/// Compute clock offset and round-trip delay from the four NTP timestamps
/// using era-aware `Instant` values.
pub(crate) fn compute_offset_delay(
    t1: &unix_time::Instant,
    t2: &unix_time::Instant,
    t3: &unix_time::Instant,
    t4: &unix_time::Instant,
) -> (f64, f64) {
    let t1 = instant_to_f64(t1);
    let t2 = instant_to_f64(t2);
    let t3 = instant_to_f64(t3);
    let t4 = instant_to_f64(t4);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = (t4 - t1) - (t3 - t2);
    (offset, delay)
}

/// Build an NTP client request packet and serialize it.
///
/// Returns the serialized buffer and the origin timestamp (T1).
pub(crate) fn build_request_packet() -> io::Result<(
    [u8; protocol::Packet::PACKED_SIZE_BYTES],
    protocol::TimestampFormat,
)> {
    let packet = protocol::Packet {
        leap_indicator: protocol::LeapIndicator::default(),
        version: protocol::Version::V4,
        mode: protocol::Mode::Client,
        stratum: protocol::Stratum::UNSPECIFIED,
        poll: 0,
        precision: 0,
        root_delay: protocol::ShortFormat::default(),
        root_dispersion: protocol::ShortFormat::default(),
        reference_id: protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Null),
        reference_timestamp: protocol::TimestampFormat::default(),
        origin_timestamp: protocol::TimestampFormat::default(),
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: unix_time::Instant::now().into(),
    };
    let t1 = packet.transmit_timestamp;
    let mut send_buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut send_buf[..]).write_bytes(packet)?;
    Ok((send_buf, t1))
}

/// Parse and validate an NTP server response, performing all checks except
/// origin timestamp verification.
///
/// Records T4 (destination timestamp) immediately, then validates source IP,
/// packet size, mode, Kiss-o'-Death codes, transmit timestamp, and
/// unsynchronized clock status.
///
/// Returns the parsed packet and the destination timestamp (T4). This is used
/// by both the one-shot [`validate_response`] and the continuous client (which
/// does its own origin timestamp handling for interleaved mode support).
pub(crate) fn parse_and_validate_response(
    recv_buf: &[u8],
    recv_len: usize,
    src_addr: SocketAddr,
    resolved_addrs: &[SocketAddr],
) -> io::Result<(protocol::Packet, protocol::TimestampFormat)> {
    // Record T4 (destination timestamp) immediately.
    let t4_instant = unix_time::Instant::now();
    let t4: protocol::TimestampFormat = t4_instant.into();

    // Verify the response came from one of the resolved addresses (IP only, port may differ).
    if !resolved_addrs.iter().any(|a| a.ip() == src_addr.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response from unexpected source address",
        ));
    }

    // Verify minimum packet size.
    if recv_len < protocol::Packet::PACKED_SIZE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTP response too short",
        ));
    }

    // Parse the first 48 bytes as an NTP packet (ignoring extension fields/MAC).
    let response: protocol::Packet =
        (&recv_buf[..protocol::Packet::PACKED_SIZE_BYTES]).read_bytes()?;

    // Validate response mode (RFC 5905 Section 8).
    #[cfg(not(feature = "symmetric"))]
    let valid_mode = response.mode == protocol::Mode::Server;
    #[cfg(feature = "symmetric")]
    let valid_mode = response.mode == protocol::Mode::Server
        || response.mode == protocol::Mode::SymmetricPassive;

    if !valid_mode {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected response mode (expected Server)",
        ));
    }

    // Enforce Kiss-o'-Death codes (RFC 5905 Section 7.4).
    if let protocol::ReferenceIdentifier::KissOfDeath(kod) = response.reference_id {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            KissOfDeathError { code: kod },
        ));
    }

    // Validate that the server's transmit timestamp is non-zero.
    if response.transmit_timestamp.seconds == 0 && response.transmit_timestamp.fraction == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server transmit timestamp is zero",
        ));
    }

    // Reject unsynchronized servers (LI=Unknown with non-zero stratum).
    if response.leap_indicator == protocol::LeapIndicator::Unknown
        && response.stratum != protocol::Stratum::UNSPECIFIED
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server reports unsynchronized clock",
        ));
    }

    Ok((response, t4))
}

/// Validate and parse an NTP server response (one-shot API).
///
/// Delegates to [`parse_and_validate_response`] for common checks, then
/// verifies the origin timestamp (anti-replay) and computes clock offset
/// and round-trip delay.
pub(crate) fn validate_response(
    recv_buf: &[u8],
    recv_len: usize,
    src_addr: SocketAddr,
    resolved_addrs: &[SocketAddr],
    t1: &protocol::TimestampFormat,
) -> io::Result<NtpResult> {
    let (response, t4) = parse_and_validate_response(recv_buf, recv_len, src_addr, resolved_addrs)?;

    // Validate origin timestamp matches what we sent (anti-replay, RFC 5905 Section 8).
    if response.origin_timestamp != *t1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "origin timestamp mismatch: response does not match our request",
        ));
    }

    // Convert all four timestamps to Instant for era-aware offset/delay computation.
    let t4_instant = unix_time::Instant::from(t4);
    let t1_instant = unix_time::timestamp_to_instant(*t1, &t4_instant);
    let t2_instant = unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
    let t3_instant = unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);

    let (offset_seconds, delay_seconds) =
        compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);

    Ok(NtpResult {
        packet: response,
        destination_timestamp: t4,
        offset_seconds,
        delay_seconds,
    })
}

/// Send a blocking request to an NTP server with a hardcoded 5 second timeout.
///
/// This is a convenience wrapper around [`request_with_timeout`] with a 5 second timeout.
///
/// # Arguments
///
/// * `addr` - Any valid socket address (e.g., `"time.nist.gov:123"` or `"192.168.1.1:123"`)
///
/// # Returns
///
/// Returns an [`NtpResult`] containing the server's response packet and computed timing
/// information, or an error if the server cannot be reached or the response is invalid.
///
/// # Examples
///
/// ```no_run
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// // Request time from NTP server
/// let result = ntp_client::request("time.nist.gov:123")?;
///
/// // Access packet fields directly via Deref
/// println!("Server time: {:?}", result.transmit_timestamp);
/// println!("Stratum: {:?}", result.stratum);
///
/// // Access computed timing information
/// println!("Offset: {:.6} seconds", result.offset_seconds);
/// println!("Delay: {:.6} seconds", result.delay_seconds);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns `io::Error` if:
/// - Cannot bind to local UDP socket
/// - Network timeout (5 seconds for read/write)
/// - Invalid NTP packet response
/// - DNS resolution fails
/// - Response fails validation (wrong mode, origin timestamp mismatch, etc.)
/// - Server sent a Kiss-o'-Death packet (see [`KissOfDeathError`])
pub fn request<A: ToSocketAddrs>(addr: A) -> io::Result<NtpResult> {
    request_with_timeout(addr, Duration::from_secs(5))
}

/// Send a blocking request to an NTP server with a configurable timeout.
///
/// Constructs an NTPv4 client-mode packet, sends it to the specified server, and validates
/// the response per RFC 5905. Returns the parsed response along with computed clock offset
/// and round-trip delay.
///
/// # Arguments
///
/// * `addr` - Any valid socket address (e.g., `"time.nist.gov:123"` or `"192.168.1.1:123"`)
/// * `timeout` - Maximum duration to wait for both sending and receiving the NTP packet
///
/// # Returns
///
/// Returns an [`NtpResult`] containing the server's response packet and computed timing
/// information, or an error if the server cannot be reached or the response is invalid.
///
/// # Examples
///
/// ```no_run
/// # use std::error::Error;
/// # use std::time::Duration;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// // Request time with a 10 second timeout
/// let result = ntp_client::request_with_timeout("time.nist.gov:123", Duration::from_secs(10))?;
/// println!("Offset: {:.6} seconds", result.offset_seconds);
/// println!("Delay: {:.6} seconds", result.delay_seconds);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns `io::Error` if:
/// - Cannot bind to local UDP socket
/// - Network timeout (specified duration exceeded)
/// - Invalid NTP packet response
/// - DNS resolution fails
/// - Response source address does not match the target server
/// - Response origin timestamp does not match our request (anti-replay)
/// - Server responds with unexpected mode or zero transmit timestamp
/// - Server reports unsynchronized clock (LI=Unknown with non-zero stratum)
/// - Server sent a Kiss-o'-Death packet (see [`KissOfDeathError`])
pub fn request_with_timeout<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<NtpResult> {
    // Resolve the target address eagerly so we can verify the response source.
    let resolved_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    if resolved_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address resolved to no socket addresses",
        ));
    }
    let target_addr = resolved_addrs[0];

    // Build the request packet (shared with async path).
    let (send_buf, t1) = build_request_packet()?;

    // Create the socket from which we will send the packet.
    let sock = UdpSocket::bind(bind_addr_for(&target_addr))?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    // Send the data.
    let sz = sock.send_to(&send_buf, target_addr)?;
    debug!("{:?}", sock.local_addr());
    debug!("sent: {}", sz);

    // Receive the response into a larger buffer to accommodate extension fields.
    let mut recv_buf = [0u8; 1024];
    let (recv_len, src_addr) = sock.recv_from(&mut recv_buf[..])?;
    debug!("recv: {} bytes from {:?}", recv_len, src_addr);

    // Validate and parse the response (shared with async path).
    validate_response(&recv_buf, recv_len, src_addr, &resolved_addrs, &t1)
}

#[cfg(test)]
#[test]
fn test_request_nist() {
    match request_with_timeout("time.nist.gov:123", Duration::from_secs(10)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            eprintln!("skipping test_request_nist: NTP port unreachable ({e})");
        }
        Err(e) => panic!("unexpected error from time.nist.gov: {e}"),
    }
}

#[cfg(test)]
#[test]
fn test_request_nist_alt() {
    match request_with_timeout("time-a-g.nist.gov:123", Duration::from_secs(10)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            eprintln!("skipping test_request_nist_alt: NTP port unreachable ({e})");
        }
        Err(e) => panic!("unexpected error from time-a-g.nist.gov: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compute_offset_delay ──────────────────────────────────────

    #[test]
    fn test_offset_delay_symmetric() {
        // T1=0, T2=0.5, T3=0.5, T4=1.0
        // offset = ((0.5-0)+(0.5-1))/2 = (0.5+(-0.5))/2 = 0
        // delay = (1-0)-(0.5-0.5) = 1.0
        let t1 = unix_time::Instant::new(0, 0);
        let t2 = unix_time::Instant::new(0, 500_000_000);
        let t3 = unix_time::Instant::new(0, 500_000_000);
        let t4 = unix_time::Instant::new(1, 0);
        let (offset, delay) = compute_offset_delay(&t1, &t2, &t3, &t4);
        assert!(offset.abs() < 1e-9, "expected ~0 offset, got {offset}");
        assert!(
            (delay - 1.0).abs() < 1e-9,
            "expected 1.0 delay, got {delay}"
        );
    }

    #[test]
    fn test_offset_delay_local_behind() {
        // Client behind by 1s: T1=0, T2=1.5, T3=1.5, T4=1.0
        // offset = ((1.5-0)+(1.5-1))/2 = (1.5+0.5)/2 = 1.0
        // delay = (1-0)-(1.5-1.5) = 1.0
        let t1 = unix_time::Instant::new(0, 0);
        let t2 = unix_time::Instant::new(1, 500_000_000);
        let t3 = unix_time::Instant::new(1, 500_000_000);
        let t4 = unix_time::Instant::new(1, 0);
        let (offset, delay) = compute_offset_delay(&t1, &t2, &t3, &t4);
        assert!(
            (offset - 1.0).abs() < 1e-9,
            "expected 1.0 offset, got {offset}"
        );
        assert!(
            (delay - 1.0).abs() < 1e-9,
            "expected 1.0 delay, got {delay}"
        );
    }

    #[test]
    fn test_offset_delay_local_ahead() {
        // Client ahead by 1s: T1=10, T2=9.25, T3=9.75, T4=11
        // offset = ((9.25-10)+(9.75-11))/2 = (-0.75+(-1.25))/2 = -1.0
        // delay = (11-10)-(9.75-9.25) = 1.0 - 0.5 = 0.5
        let t1 = unix_time::Instant::new(10, 0);
        let t2 = unix_time::Instant::new(9, 250_000_000);
        let t3 = unix_time::Instant::new(9, 750_000_000);
        let t4 = unix_time::Instant::new(11, 0);
        let (offset, delay) = compute_offset_delay(&t1, &t2, &t3, &t4);
        assert!(
            (offset - (-1.0)).abs() < 1e-9,
            "expected -1.0 offset, got {offset}"
        );
        assert!(
            (delay - 0.5).abs() < 1e-9,
            "expected 0.5 delay, got {delay}"
        );
    }

    #[test]
    fn test_offset_delay_zero_processing_time() {
        // Server processes instantly, RTT=0.1s: T1=0, T2=0.05, T3=0.05, T4=0.1
        // offset = ((0.05-0)+(0.05-0.1))/2 = (0.05+(-0.05))/2 = 0
        // delay = (0.1-0)-(0.05-0.05) = 0.1
        let t1 = unix_time::Instant::new(0, 0);
        let t2 = unix_time::Instant::new(0, 50_000_000);
        let t3 = unix_time::Instant::new(0, 50_000_000);
        let t4 = unix_time::Instant::new(0, 100_000_000);
        let (offset, delay) = compute_offset_delay(&t1, &t2, &t3, &t4);
        assert!(offset.abs() < 1e-9, "expected ~0 offset, got {offset}");
        assert!(
            (delay - 0.1).abs() < 1e-9,
            "expected 0.1 delay, got {delay}"
        );
    }

    // ── build_request_packet ──────────────────────────────────────

    #[test]
    fn test_build_request_packet_structure() {
        let (buf, t1) = build_request_packet().unwrap();

        // Deserialize and verify fields.
        let pkt: protocol::Packet = (&buf[..protocol::Packet::PACKED_SIZE_BYTES])
            .read_bytes()
            .unwrap();
        assert_eq!(pkt.version, protocol::Version::V4);
        assert_eq!(pkt.mode, protocol::Mode::Client);
        assert_eq!(pkt.stratum, protocol::Stratum::UNSPECIFIED);
        assert_eq!(pkt.transmit_timestamp, t1);
        // T1 should be non-zero (set to current time).
        assert!(t1.seconds != 0 || t1.fraction != 0);
    }

    #[test]
    fn test_build_request_packet_size() {
        let (buf, _) = build_request_packet().unwrap();
        assert_eq!(buf.len(), protocol::Packet::PACKED_SIZE_BYTES);
        assert_eq!(buf.len(), 48);
    }

    // ── parse_and_validate_response ───────────────────────────────

    /// Helper: build a valid 48-byte server response buffer.
    fn make_server_response(
        mode: protocol::Mode,
        li: protocol::LeapIndicator,
        stratum: protocol::Stratum,
        ref_id: protocol::ReferenceIdentifier,
        transmit_secs: u32,
    ) -> [u8; 48] {
        let pkt = protocol::Packet {
            leap_indicator: li,
            version: protocol::Version::V4,
            mode,
            stratum,
            poll: 6,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: ref_id,
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: protocol::TimestampFormat {
                seconds: 100,
                fraction: 0,
            },
            receive_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 0,
            },
            transmit_timestamp: protocol::TimestampFormat {
                seconds: transmit_secs,
                fraction: 1,
            },
        };
        let mut buf = [0u8; 48];
        (&mut buf[..]).write_bytes(pkt).unwrap();
        buf
    }

    fn valid_server_buf() -> [u8; 48] {
        make_server_response(
            protocol::Mode::Server,
            protocol::LeapIndicator::NoWarning,
            protocol::Stratum(2),
            protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            3_913_056_001,
        )
    }

    fn src_addr() -> SocketAddr {
        "127.0.0.1:123".parse().unwrap()
    }

    #[test]
    fn test_validate_accepts_valid_response() {
        let buf = valid_server_buf();
        let addrs = vec![src_addr()];
        let result = parse_and_validate_response(&buf, 48, src_addr(), &addrs);
        assert!(result.is_ok());
        let (pkt, _t4) = result.unwrap();
        assert_eq!(pkt.mode, protocol::Mode::Server);
    }

    #[test]
    fn test_validate_rejects_wrong_source_ip() {
        let buf = valid_server_buf();
        let addrs = vec!["10.0.0.1:123".parse().unwrap()];
        let result = parse_and_validate_response(&buf, 48, src_addr(), &addrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unexpected source")
        );
    }

    #[test]
    fn test_validate_rejects_short_packet() {
        let buf = valid_server_buf();
        let addrs = vec![src_addr()];
        let result = parse_and_validate_response(&buf, 47, src_addr(), &addrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_validate_rejects_client_mode() {
        let buf = make_server_response(
            protocol::Mode::Client,
            protocol::LeapIndicator::NoWarning,
            protocol::Stratum(2),
            protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            3_913_056_001,
        );
        let addrs = vec![src_addr()];
        let result = parse_and_validate_response(&buf, 48, src_addr(), &addrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unexpected response mode")
        );
    }

    #[test]
    fn test_validate_rejects_kiss_of_death() {
        let buf = make_server_response(
            protocol::Mode::Server,
            protocol::LeapIndicator::NoWarning,
            protocol::Stratum::UNSPECIFIED,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Deny),
            3_913_056_001,
        );
        let addrs = vec![src_addr()];
        let result = parse_and_validate_response(&buf, 48, src_addr(), &addrs);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        let kod = err
            .get_ref()
            .unwrap()
            .downcast_ref::<KissOfDeathError>()
            .unwrap();
        assert!(matches!(kod.code, protocol::KissOfDeath::Deny));
    }

    #[test]
    fn test_validate_rejects_zero_transmit() {
        // Build a packet with fully zero transmit timestamp.
        let pkt = protocol::Packet {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            version: protocol::Version::V4,
            mode: protocol::Mode::Server,
            stratum: protocol::Stratum(2),
            poll: 6,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: protocol::TimestampFormat::default(),
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 0,
                fraction: 0,
            },
        };
        let mut raw = [0u8; 48];
        (&mut raw[..]).write_bytes(pkt).unwrap();
        let addrs = vec![src_addr()];
        let result = parse_and_validate_response(&raw, 48, src_addr(), &addrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("transmit timestamp is zero")
        );
    }

    #[test]
    fn test_validate_rejects_unsynchronized() {
        let buf = make_server_response(
            protocol::Mode::Server,
            protocol::LeapIndicator::Unknown,
            protocol::Stratum(2), // non-zero stratum + LI=Unknown = unsynchronized
            protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            3_913_056_001,
        );
        let addrs = vec![src_addr()];
        let result = parse_and_validate_response(&buf, 48, src_addr(), &addrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsynchronized"));
    }

    #[test]
    fn test_validate_allows_li_unknown_stratum_zero() {
        // LI=Unknown with stratum 0 (UNSPECIFIED) is OK — it's a KoD or reference clock.
        // But stratum 0 with a non-KoD ref_id should pass the LI check.
        let buf = make_server_response(
            protocol::Mode::Server,
            protocol::LeapIndicator::Unknown,
            protocol::Stratum::UNSPECIFIED,
            protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Gps),
            3_913_056_001,
        );
        let addrs = vec![src_addr()];
        let result = parse_and_validate_response(&buf, 48, src_addr(), &addrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_accepts_different_port() {
        // Source port doesn't need to match — only IP.
        let buf = valid_server_buf();
        let addrs = vec!["127.0.0.1:456".parse().unwrap()];
        let result = parse_and_validate_response(&buf, 48, src_addr(), &addrs);
        assert!(result.is_ok());
    }

    // ── KissOfDeathError display ──────────────────────────────────

    #[test]
    fn test_kod_display_deny() {
        let kod = KissOfDeathError {
            code: protocol::KissOfDeath::Deny,
        };
        assert!(kod.to_string().contains("DENY"));
    }

    #[test]
    fn test_kod_display_rstr() {
        let kod = KissOfDeathError {
            code: protocol::KissOfDeath::Rstr,
        };
        assert!(kod.to_string().contains("RSTR"));
    }

    #[test]
    fn test_kod_display_rate() {
        let kod = KissOfDeathError {
            code: protocol::KissOfDeath::Rate,
        };
        assert!(kod.to_string().contains("RATE"));
    }
}
