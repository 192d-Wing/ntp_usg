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

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use log::debug;
use protocol::{ConstPackedSizeBytes, ReadBytes, WriteBytes};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::ops::Deref;
use std::time::Duration;

pub mod protocol;
/// Unix time conversion utilities for NTP timestamps.
///
/// Provides the `Instant` type for converting between NTP timestamps
/// (seconds since 1900-01-01) and Unix timestamps (seconds since 1970-01-01).
pub mod unix_time;

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

/// Convert an NTP TimestampFormat to seconds as f64.
fn timestamp_to_f64(ts: &protocol::TimestampFormat) -> f64 {
    ts.seconds as f64 + (ts.fraction as f64 / (u32::MAX as f64 + 1.0))
}

/// Compute clock offset and round-trip delay from the four NTP timestamps.
fn compute_offset_delay(
    t1: &protocol::TimestampFormat,
    t2: &protocol::TimestampFormat,
    t3: &protocol::TimestampFormat,
    t4: &protocol::TimestampFormat,
) -> (f64, f64) {
    let t1 = timestamp_to_f64(t1);
    let t2 = timestamp_to_f64(t2);
    let t3 = timestamp_to_f64(t3);
    let t4 = timestamp_to_f64(t4);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = (t4 - t1) - (t3 - t2);
    (offset, delay)
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
pub fn request_with_timeout<A: ToSocketAddrs>(
    addr: A,
    timeout: Duration,
) -> io::Result<NtpResult> {
    // Resolve the target address eagerly so we can verify the response source.
    let resolved_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    if resolved_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address resolved to no socket addresses",
        ));
    }
    let target_addr = resolved_addrs[0];

    // Create a packet for requesting from an NTP server as a client.
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

    // Record T1 (our transmit timestamp) for later validation and offset computation.
    let t1 = packet.transmit_timestamp;

    // Write the packet to a send buffer.
    let mut send_buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut send_buf[..]).write_bytes(packet)?;

    // Create the socket from which we will send the packet.
    let sock = UdpSocket::bind("0.0.0.0:0")?;
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

    // Record T4 (destination timestamp) immediately after receiving.
    let t4: protocol::TimestampFormat = unix_time::Instant::now().into();

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

    // Validate that the server's transmit timestamp is non-zero.
    if response.transmit_timestamp.seconds == 0 && response.transmit_timestamp.fraction == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server transmit timestamp is zero",
        ));
    }

    // Validate origin timestamp matches what we sent (anti-replay, RFC 5905 Section 8).
    if response.origin_timestamp != t1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "origin timestamp mismatch: response does not match our request",
        ));
    }

    // Reject unsynchronized servers (LI=Unknown with non-zero stratum).
    // Stratum 0 with LI=Unknown is a valid KoD packet and is allowed through.
    if response.leap_indicator == protocol::LeapIndicator::Unknown
        && response.stratum != protocol::Stratum::UNSPECIFIED
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server reports unsynchronized clock",
        ));
    }

    // Compute clock offset and round-trip delay (RFC 5905 Section 8).
    let (offset_seconds, delay_seconds) = compute_offset_delay(
        &t1,
        &response.receive_timestamp,
        &response.transmit_timestamp,
        &t4,
    );

    Ok(NtpResult {
        packet: response,
        destination_timestamp: t4,
        offset_seconds,
        delay_seconds,
    })
}

#[test]
fn test_request_ntp_org() {
    let res = request("0.pool.ntp.org:123");
    let _ = res.expect("Failed to get a ntp packet from ntp.org");
}

#[test]
fn test_request_google() {
    let res = request("time.google.com:123");
    let _ = res.expect("Failed to get a ntp packet from time.google.com");
}
