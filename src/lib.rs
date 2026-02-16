/*!
# Example
Shows how to use the ntp library to fetch the current time according
to the requested ntp server.

```rust,no_run
extern crate chrono;
extern crate ntp;

use chrono::TimeZone;

fn main() {
    let address = "0.pool.ntp.org:123";
    let result = ntp::request(address).unwrap();
    let unix_time = ntp::unix_time::Instant::from(result.transmit_timestamp);
    let local_time = chrono::Local.timestamp_opt(unix_time.secs(), unix_time.subsec_nanos() as _).unwrap();
    println!("{}", local_time);
    println!("Offset: {:.6} seconds", result.offset_seconds);
}
```
*/

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Custom error types for buffer-based NTP packet parsing and serialization.
pub mod error;
/// NTP extension field parsing and NTS extension types.
///
/// Provides types for parsing and serializing NTP extension fields (RFC 7822)
/// and NTS-specific extension field types (RFC 8915).
pub mod extension;
pub mod protocol;
/// Unix time conversion utilities for NTP timestamps.
///
/// Provides the `Instant` type for converting between NTP timestamps
/// (seconds since 1900-01-01) and Unix timestamps (seconds since 1970-01-01).
pub mod unix_time;

/// Clock sample filtering for the continuous NTP client.
///
/// Implements a simplified version of the RFC 5905 Section 10 clock filter
/// algorithm.
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
pub mod filter;

/// Continuous NTP client with adaptive poll interval management and interleaved mode.
///
/// Enable with the `tokio` feature flag:
///
/// ```toml
/// [dependencies]
/// ntp_usg = { version = "0.9", features = ["tokio"] }
/// ```
#[cfg(feature = "tokio")]
pub mod client;

/// Network Time Security (NTS) client (RFC 8915).
///
/// Provides authenticated NTP using TLS 1.3 key establishment and AEAD
/// per-packet authentication. Enable with the `nts` feature flag:
///
/// ```toml
/// [dependencies]
/// ntp_usg = { version = "0.9", features = ["nts"] }
/// ```
#[cfg(feature = "nts")]
pub mod nts;

/// System clock adjustment utilities for applying NTP corrections.
///
/// Provides platform-specific functions for slewing (gradual) and stepping
/// (immediate) the system clock. Requires elevated privileges (root/admin).
///
/// Enable with the `clock` feature flag:
///
/// ```toml
/// [dependencies]
/// ntp_usg = { version = "1.1", features = ["clock"] }
/// ```
#[cfg(feature = "clock")]
pub mod clock;

/// Async NTP client functions using the Tokio runtime.
///
/// Enable with the `tokio` feature flag:
///
/// ```toml
/// [dependencies]
/// ntp_usg = { version = "0.9", features = ["tokio"] }
/// ```
///
/// See [`async_ntp::request`] and [`async_ntp::request_with_timeout`] for details.
#[cfg(feature = "tokio")]
pub mod async_ntp;

/// Async NTP client functions using the smol runtime.
///
/// Enable with the `smol-runtime` feature flag:
///
/// ```toml
/// [dependencies]
/// ntp_usg = { version = "1.2", features = ["smol-runtime"] }
/// ```
///
/// See [`smol_ntp::request`] and [`smol_ntp::request_with_timeout`] for details.
#[cfg(feature = "smol-runtime")]
pub mod smol_ntp;

/// Continuous NTP client using the smol runtime.
///
/// Enable with the `smol-runtime` feature flag:
///
/// ```toml
/// [dependencies]
/// ntp_usg = { version = "1.2", features = ["smol-runtime"] }
/// ```
#[cfg(feature = "smol-runtime")]
pub mod smol_client;

/// Network Time Security (NTS) client using the smol runtime (RFC 8915).
///
/// Provides the same NTS functionality as [`nts`] but using smol
/// and futures-rustls instead of tokio and tokio-rustls.
///
/// Enable with the `nts-smol` feature flag:
///
/// ```toml
/// [dependencies]
/// ntp_usg = { version = "1.2", features = ["nts-smol"] }
/// ```
#[cfg(feature = "nts-smol")]
pub mod smol_nts;

// ============================================================================
// Everything below requires std (networking, blocking I/O, etc.)
// ============================================================================

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use protocol::{ConstPackedSizeBytes, ReadBytes, WriteBytes};
#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
#[cfg(feature = "std")]
use std::ops::Deref;
#[cfg(feature = "std")]
use std::time::Duration;

/// Select the appropriate bind address based on the target address family.
///
/// Returns `"0.0.0.0:0"` for IPv4 targets and `"[::]:0"` for IPv6 targets.
#[cfg(feature = "std")]
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
/// match ntp::request("pool.ntp.org:123") {
///     Ok(result) => println!("Offset: {:.6}s", result.offset_seconds),
///     Err(e) => {
///         if let Some(kod) = e.get_ref().and_then(|inner| inner.downcast_ref::<ntp::KissOfDeathError>()) {
///             eprintln!("Kiss-o'-Death: {:?}", kod.code);
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug)]
pub struct KissOfDeathError {
    /// The specific kiss code received from the server.
    pub code: protocol::KissOfDeath,
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl std::error::Error for KissOfDeathError {}

/// The result of an NTP request, containing the server's response packet
/// along with computed timing information.
///
/// This struct implements `Deref<Target = protocol::Packet>`, so all packet
/// fields can be accessed directly (e.g., `result.transmit_timestamp`).
#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl Deref for NtpResult {
    type Target = protocol::Packet;
    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

/// Convert a Unix `Instant` to seconds as f64 (relative to Unix epoch).
#[cfg(feature = "std")]
fn instant_to_f64(instant: &unix_time::Instant) -> f64 {
    instant.secs() as f64 + (instant.subsec_nanos() as f64 / 1e9)
}

/// Compute clock offset and round-trip delay from the four NTP timestamps
/// using era-aware `Instant` values.
#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
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

    // Validate server mode (RFC 5905 Section 8).
    if response.mode != protocol::Mode::Server {
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
#[cfg(feature = "std")]
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
/// * `addr` - Any valid socket address (e.g., `"pool.ntp.org:123"` or `"192.168.1.1:123"`)
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
/// // Request time from NTP pool
/// let result = ntp::request("pool.ntp.org:123")?;
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
#[cfg(feature = "std")]
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
/// * `addr` - Any valid socket address (e.g., `"pool.ntp.org:123"` or `"192.168.1.1:123"`)
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
/// let result = ntp::request_with_timeout("pool.ntp.org:123", Duration::from_secs(10))?;
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
#[cfg(feature = "std")]
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

#[cfg(all(test, feature = "std"))]
#[test]
fn test_request_ntp_org() {
    let res = request("0.pool.ntp.org:123");
    let _ = res.expect("Failed to get a ntp packet from ntp.org");
}

#[cfg(all(test, feature = "std"))]
#[test]
fn test_request_google() {
    let res = request("time.google.com:123");
    let _ = res.expect("Failed to get a ntp packet from time.google.com");
}
