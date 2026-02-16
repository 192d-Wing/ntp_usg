// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Async NTP client using the smol runtime.
//!
//! This module provides async versions of the synchronous [`request`](crate::request) and
//! [`request_with_timeout`](crate::request_with_timeout) functions, using
//! [`smol::net::UdpSocket`] for non-blocking I/O.
//!
//! # Runtime Requirements
//!
//! These functions must be called from within a smol runtime context
//! (e.g., inside `smol::block_on` or a `smol::spawn`ed task).
//!
//! # Differences from [`crate::async_ntp`]
//!
//! The `addr` parameter is `&str` rather than Tokio's generic `ToSocketAddrs`,
//! because smol uses `smol::net::resolve()` which takes a string slice.
//!
//! # Examples
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! let result = ntp::smol_ntp::request("time.nist.gov:123").await?;
//! println!("Offset: {:.6} seconds", result.offset_seconds);
//! # Ok(())
//! # }
//! ```

use log::debug;
use smol::net::UdpSocket;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::{NtpResult, build_request_packet, validate_response};

/// Send an async request to an NTP server with a hardcoded 5 second timeout.
///
/// This is a convenience wrapper around [`request_with_timeout`] with a 5 second timeout.
///
/// # Arguments
///
/// * `addr` - Any valid socket address (e.g., `"time.nist.gov:123"` or `"192.168.1.1:123"`)
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> std::io::Result<()> {
/// let result = ntp::smol_ntp::request("time.nist.gov:123").await?;
/// println!("Offset: {:.6} seconds", result.offset_seconds);
/// # Ok(())
/// # }
/// ```
pub async fn request(addr: &str) -> io::Result<NtpResult> {
    request_with_timeout(addr, Duration::from_secs(5)).await
}

/// Send an async request to an NTP server with a configurable timeout.
///
/// Constructs an NTPv4 client-mode packet, sends it to the specified server, and validates
/// the response per RFC 5905. Uses [`futures_lite::future::or`] with [`smol::Timer`] for
/// async-friendly timeouts.
///
/// # Arguments
///
/// * `addr` - Any valid socket address (e.g., `"time.nist.gov:123"` or `"192.168.1.1:123"`)
/// * `timeout` - Maximum duration for the entire request (DNS + send + receive)
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> std::io::Result<()> {
/// use std::time::Duration;
/// let result = ntp::smol_ntp::request_with_timeout(
///     "time.nist.gov:123",
///     Duration::from_secs(10),
/// ).await?;
/// println!("Offset: {:.6} seconds", result.offset_seconds);
/// # Ok(())
/// # }
/// ```
pub async fn request_with_timeout(addr: &str, timeout: Duration) -> io::Result<NtpResult> {
    futures_lite::future::or(request_inner(addr), async {
        smol::Timer::after(timeout).await;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "NTP request timed out",
        ))
    })
    .await
}

/// Inner async implementation without timeout wrapping.
async fn request_inner(addr: &str) -> io::Result<NtpResult> {
    // Async DNS resolution via smol.
    let resolved_addrs: Vec<SocketAddr> = smol::net::resolve(addr).await?;
    if resolved_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address resolved to no socket addresses",
        ));
    }
    let target_addr = resolved_addrs[0];

    // Build packet (pure computation, shared with sync path).
    let (send_buf, t1) = build_request_packet()?;

    // Create async UDP socket with address family matching the target.
    let sock = UdpSocket::bind(crate::bind_addr_for(&target_addr)).await?;

    // Send the request.
    let sz = sock.send_to(&send_buf, target_addr).await?;
    debug!("{:?}", sock.local_addr());
    debug!("sent: {}", sz);

    // Receive the response.
    let mut recv_buf = [0u8; 1024];
    let (recv_len, src_addr) = sock.recv_from(&mut recv_buf[..]).await?;
    debug!("recv: {} bytes from {:?}", recv_len, src_addr);

    // Validate and parse (pure computation, shared with sync path).
    validate_response(&recv_buf, recv_len, src_addr, &resolved_addrs, &t1)
}
