// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Simple Network Time Protocol (SNTP) client per RFC 4330.
//!
//! SNTP is a simplified subset of NTP designed for clients that do not require
//! the complexity of full NTP. This module provides an SNTP-compliant client
//! API that wraps the underlying NTP implementation.
//!
//! # SNTP vs NTP
//!
//! SNTP clients:
//! - Send a single request and process a single response
//! - Do not implement the full NTP selection, clustering, or discipline algorithms
//! - Are suitable for simple time synchronization use cases
//! - Can operate in "unicast client mode" (sending requests to a server)
//!
//! This implementation is fully compliant with RFC 4330 and implements all
//! required SNTP client behaviors including:
//! - Proper packet format (compatible with NTPv4)
//! - Kiss-o'-Death handling (DENY, RSTR, RATE)
//! - Sanity checking (leap indicator, stratum, transmit timestamp)
//! - Clock offset and round-trip delay computation
//!
//! # Examples
//!
//! ## Basic SNTP request
//!
//! ```ignore
//! use ntp_client::sntp;
//!
//! let result = sntp::request("time.nist.gov:123")?;
//! println!("Clock offset: {:.6} seconds", result.offset_seconds);
//! println!("Round-trip delay: {:.6} seconds", result.delay_seconds);
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! ## SNTP with custom timeout
//!
//! ```ignore
//! use std::time::Duration;
//! use ntp_client::sntp;
//!
//! let result = sntp::request_with_timeout(
//!     "pool.ntp.org:123",
//!     Duration::from_secs(10)
//! )?;
//! println!("Offset: {:.6}s", result.offset_seconds);
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! ## Async SNTP with Tokio
//!
//! Requires the `tokio` feature flag:
//!
//! ```toml
//! [dependencies]
//! ntp_usg-client = { version = "3.0", features = ["tokio"] }
//! ```
//!
//! ```ignore
//! use ntp_client::sntp;
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let result = sntp::async_request("time.cloudflare.com:123").await?;
//!     println!("Offset: {:.6}s", result.offset_seconds);
//!     Ok(())
//! }
//! ```
//!
//! ## Async SNTP with smol
//!
//! Requires the `smol-runtime` feature flag:
//!
//! ```toml
//! [dependencies]
//! ntp_usg-client = { version = "3.0", features = ["smol-runtime"] }
//! ```
//!
//! ```ignore
//! use ntp_client::sntp;
//!
//! fn main() -> std::io::Result<()> {
//!     smol::block_on(async {
//!         let result = sntp::smol_request("time.nist.gov:123").await?;
//!         println!("Offset: {:.6}s", result.offset_seconds);
//!         Ok(())
//!     })
//! }
//! ```
//!
//! # RFC 4330 Compliance
//!
//! This implementation is fully compliant with RFC 4330 Section 5 (SNTP Client
//! Operations):
//!
//! - ✅ Unicast mode client operation
//! - ✅ Sanity checks on received packets
//! - ✅ Kiss-o'-Death (KoD) packet handling
//! - ✅ Origin timestamp matching (replay protection)
//! - ✅ Leap indicator validation
//! - ✅ Transmit timestamp validation (non-zero check)
//! - ✅ Proper clock offset and delay computation
//!
//! # Security Considerations
//!
//! Per RFC 4330 Section 8, SNTP clients should:
//! - Handle Kiss-o'-Death packets appropriately (see [`crate::KissOfDeathError`])
//! - Validate origin timestamps to prevent replay attacks
//! - Use multiple servers for redundancy (call this API multiple times)
//!
//! For authenticated time synchronization, use NTS (Network Time Security)
//! instead via the `nts` feature flag and [`crate::nts`] module.

use std::io;
use std::net::ToSocketAddrs;
use std::time::Duration;

pub use crate::NtpResult;

/// Send a synchronous SNTP request with a 5-second timeout.
///
/// This is the simplest SNTP client function. It sends a single NTP packet
/// to the specified server and returns the clock offset and delay.
///
/// Per RFC 4330, this implements a basic SNTP unicast client.
///
/// # Arguments
///
/// * `addr` - Server address (hostname or IP with port, e.g. `"time.nist.gov:123"`)
///
/// # Returns
///
/// Returns an [`NtpResult`] containing:
/// - `offset_seconds` — Clock offset (positive means local clock is behind)
/// - `delay_seconds` — Round-trip delay
/// - `packet` — Full NTP response packet
///
/// # Errors
///
/// - `io::ErrorKind::TimedOut` — Server did not respond within timeout
/// - `io::ErrorKind::InvalidData` — Invalid response from server
/// - `io::ErrorKind::ConnectionRefused` — Server sent Kiss-o'-Death packet
///
/// # Examples
///
/// ```no_run
/// use ntp_client::sntp;
///
/// let result = sntp::request("pool.ntp.org:123")?;
/// println!("Offset: {:.6} seconds", result.offset_seconds);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn request<A: ToSocketAddrs>(addr: A) -> io::Result<NtpResult> {
    crate::request(addr)
}

/// Send a synchronous SNTP request with a configurable timeout.
///
/// Same as [`request`] but allows specifying a custom timeout duration.
///
/// # Arguments
///
/// * `addr` - Server address
/// * `timeout` - Maximum wait time for response
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use ntp_client::sntp;
///
/// let result = sntp::request_with_timeout(
///     "time.nist.gov:123",
///     Duration::from_secs(10)
/// )?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn request_with_timeout<A: ToSocketAddrs>(
    addr: A,
    timeout: Duration,
) -> io::Result<NtpResult> {
    crate::request_with_timeout(addr, timeout)
}

/// Send an asynchronous SNTP request using Tokio with a 5-second timeout.
///
/// This is the async equivalent of [`request`] for use with the Tokio runtime.
///
/// Requires the `tokio` feature flag.
///
/// # Examples
///
/// ```no_run
/// use ntp_client::sntp;
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     let result = sntp::async_request("time.cloudflare.com:123").await?;
///     println!("Offset: {:.6}s", result.offset_seconds);
///     Ok(())
/// }
/// ```
#[cfg(feature = "tokio")]
pub async fn async_request<A: tokio::net::ToSocketAddrs>(addr: A) -> io::Result<NtpResult> {
    crate::async_ntp::request(addr).await
}

/// Send an asynchronous SNTP request using Tokio with a configurable timeout.
///
/// Same as [`async_request`] but allows specifying a custom timeout duration.
///
/// Requires the `tokio` feature flag.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use ntp_client::sntp;
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     let result = sntp::async_request_with_timeout(
///         "time.nist.gov:123",
///         Duration::from_secs(10)
///     ).await?;
///     Ok(())
/// }
/// ```
#[cfg(feature = "tokio")]
pub async fn async_request_with_timeout<A: tokio::net::ToSocketAddrs>(
    addr: A,
    timeout: Duration,
) -> io::Result<NtpResult> {
    crate::async_ntp::request_with_timeout(addr, timeout).await
}

/// Send an asynchronous SNTP request using smol with a 5-second timeout.
///
/// This is the async equivalent of [`request`] for use with the smol runtime.
///
/// Requires the `smol-runtime` feature flag.
///
/// # Examples
///
/// ```no_run
/// use ntp_client::sntp;
///
/// fn main() -> std::io::Result<()> {
///     smol::block_on(async {
///         let result = sntp::smol_request("time.nist.gov:123").await?;
///         println!("Offset: {:.6}s", result.offset_seconds);
///         Ok(())
///     })
/// }
/// ```
#[cfg(feature = "smol-runtime")]
pub async fn smol_request(addr: &str) -> io::Result<NtpResult> {
    crate::smol_ntp::request(addr).await
}

/// Send an asynchronous SNTP request using smol with a configurable timeout.
///
/// Same as [`smol_request`] but allows specifying a custom timeout duration.
///
/// Requires the `smol-runtime` feature flag.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use ntp_client::sntp;
///
/// fn main() -> std::io::Result<()> {
///     smol::block_on(async {
///         let result = sntp::smol_request_with_timeout(
///             "pool.ntp.org:123",
///             Duration::from_secs(10)
///         ).await?;
///         Ok(())
///     })
/// }
/// ```
#[cfg(feature = "smol-runtime")]
pub async fn smol_request_with_timeout(
    addr: &str,
    timeout: Duration,
) -> io::Result<NtpResult> {
    crate::smol_ntp::request_with_timeout(addr, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sntp_request_nist() {
        // Basic smoke test - may fail in CI if NTP port is blocked
        match request_with_timeout("time.nist.gov:123", Duration::from_secs(10)) {
            Ok(result) => {
                // Offset should be reasonable (within 24 hours)
                assert!(
                    result.offset_seconds.abs() < 86400.0,
                    "offset {} seems unreasonable",
                    result.offset_seconds
                );
                // Delay should be positive and reasonable (within 10 seconds)
                assert!(
                    result.delay_seconds > 0.0 && result.delay_seconds < 10.0,
                    "delay {} seems unreasonable",
                    result.delay_seconds
                );
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                eprintln!("Skipping SNTP test: timeout (NTP port may be blocked)");
            }
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_sntp_module_accessible() {
        // Compilation test: ensure SNTP module and types are accessible
        // This is a no-op test that verifies the API compiles correctly
        let _ = std::mem::size_of::<NtpResult>();
    }
}
