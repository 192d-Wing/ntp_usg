// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Roughtime client for authenticated coarse time.
//!
//! Roughtime (draft-ietf-ntp-roughtime-15) provides cryptographically verified
//! time with ~1 second accuracy using Ed25519 signatures and SHA-512 Merkle trees.
//!
//! # Sync API
//!
//! ```no_run
//! use ntp_client::roughtime;
//!
//! let pk = roughtime::decode_public_key("0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=").unwrap();
//! let result = roughtime::request("roughtime.cloudflare.com:2003", &pk).unwrap();
//! println!("Time: {} seconds since epoch (±{}s)",
//!     result.midpoint_seconds(), result.radius_seconds());
//! ```
//!
//! # Async API (tokio)
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! use ntp_client::roughtime;
//!
//! let pk = roughtime::decode_public_key("0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=").unwrap();
//! let result = roughtime::async_request("roughtime.cloudflare.com:2003", &pk).await?;
//! println!("Time: {} seconds since epoch", result.midpoint_seconds());
//! # Ok(())
//! # }
//! ```

use log::debug;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub use ntp_proto::roughtime::{
    RoughtimeResult, build_chained_request, build_request, build_request_with_nonce,
    verify_response,
};

use crate::request::{bind_addr_for, prefer_addresses};

/// Default timeout for Roughtime requests (5 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum response buffer size (Roughtime responses are larger than NTP).
const RECV_BUF_SIZE: usize = 4096;

/// Decode a base64-encoded Ed25519 public key (32 bytes).
///
/// # Examples
///
/// ```
/// let pk = ntp_client::roughtime::decode_public_key(
///     "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
/// ).unwrap();
/// assert_eq!(pk.len(), 32);
/// ```
pub fn decode_public_key(base64_key: &str) -> io::Result<[u8; 32]> {
    // Simple base64 decoder (no external dependency needed for 32 bytes).
    let bytes = base64_decode(base64_key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid base64 public key: {e}"),
        )
    })?;
    if bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("public key must be 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    Ok(pk)
}

/// Send a blocking Roughtime request with a 5 second timeout.
///
/// # Arguments
///
/// * `addr` - Server address (e.g., `"roughtime.cloudflare.com:2003"`)
/// * `public_key` - Server's Ed25519 long-term public key (32 bytes)
///
/// # Examples
///
/// ```no_run
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let pk = ntp_client::roughtime::decode_public_key(
///     "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
/// )?;
/// let result = ntp_client::roughtime::request("roughtime.cloudflare.com:2003", &pk)?;
/// println!("Time: {} seconds since epoch (±{}s)",
///     result.midpoint_seconds(), result.radius_seconds());
/// # Ok(())
/// # }
/// ```
pub fn request<A: ToSocketAddrs>(addr: A, public_key: &[u8; 32]) -> io::Result<RoughtimeResult> {
    request_with_timeout(addr, public_key, DEFAULT_TIMEOUT)
}

/// Send a blocking Roughtime request with a configurable timeout.
pub fn request_with_timeout<A: ToSocketAddrs>(
    addr: A,
    public_key: &[u8; 32],
    timeout: Duration,
) -> io::Result<RoughtimeResult> {
    let resolved_addrs: Vec<SocketAddr> = prefer_addresses(addr.to_socket_addrs()?.collect());
    if resolved_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address resolved to no socket addresses",
        ));
    }
    let target_addr = resolved_addrs[0];

    let (request_bytes, nonce) = build_request();

    let sock = UdpSocket::bind(bind_addr_for(&target_addr))?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    let sz = sock.send_to(&request_bytes, target_addr)?;
    debug!("roughtime: sent {} bytes to {:?}", sz, target_addr);

    let mut recv_buf = [0u8; RECV_BUF_SIZE];
    let (recv_len, src_addr) = sock.recv_from(&mut recv_buf)?;
    debug!("roughtime: recv {} bytes from {:?}", recv_len, src_addr);

    verify_response(&recv_buf[..recv_len], &nonce, public_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Send an async Roughtime request with a 5 second timeout (tokio).
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> std::io::Result<()> {
/// let pk = ntp_client::roughtime::decode_public_key(
///     "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
/// )?;
/// let result = ntp_client::roughtime::async_request("roughtime.cloudflare.com:2003", &pk).await?;
/// println!("Time: {} seconds since epoch", result.midpoint_seconds());
/// # Ok(())
/// # }
/// ```
pub async fn async_request<A: tokio::net::ToSocketAddrs>(
    addr: A,
    public_key: &[u8; 32],
) -> io::Result<RoughtimeResult> {
    async_request_with_timeout(addr, public_key, DEFAULT_TIMEOUT).await
}

/// Send an async Roughtime request with a configurable timeout (tokio).
pub async fn async_request_with_timeout<A: tokio::net::ToSocketAddrs>(
    addr: A,
    public_key: &[u8; 32],
    timeout: Duration,
) -> io::Result<RoughtimeResult> {
    tokio::time::timeout(timeout, async_request_inner(addr, public_key))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Roughtime request timed out"))?
}

async fn async_request_inner<A: tokio::net::ToSocketAddrs>(
    addr: A,
    public_key: &[u8; 32],
) -> io::Result<RoughtimeResult> {
    let resolved_addrs: Vec<SocketAddr> =
        prefer_addresses(tokio::net::lookup_host(addr).await?.collect());
    if resolved_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "address resolved to no socket addresses",
        ));
    }
    let target_addr = resolved_addrs[0];

    let (request_bytes, nonce) = build_request();

    let sock = tokio::net::UdpSocket::bind(bind_addr_for(&target_addr)).await?;

    let sz = sock.send_to(&request_bytes, target_addr).await?;
    debug!("roughtime: sent {} bytes to {:?}", sz, target_addr);

    let mut recv_buf = [0u8; RECV_BUF_SIZE];
    let (recv_len, src_addr) = sock.recv_from(&mut recv_buf).await?;
    debug!("roughtime: recv {} bytes from {:?}", recv_len, src_addr);

    verify_response(&recv_buf[..recv_len], &nonce, public_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ── Minimal base64 decoder ──────────────────────────────────────────

fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for ch in input.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'\n' | b'\r' | b' ' => continue,
            _ => return Err("invalid base64 character"),
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_public_key_cloudflare() {
        let pk = decode_public_key("0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=").unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(pk[0], 0xD0);
        assert_eq!(pk[1], 0x60);
    }

    #[test]
    fn test_decode_public_key_wrong_length() {
        let result = decode_public_key("AQID"); // 3 bytes
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_decode_public_key_invalid_base64() {
        let result = decode_public_key("not!valid@base64");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode_simple() {
        assert_eq!(base64_decode("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(base64_decode("").unwrap(), vec![]);
    }

    #[test]
    fn test_base64_decode_with_padding() {
        // "YQ==" decodes to "a"
        assert_eq!(base64_decode("YQ==").unwrap(), vec![b'a']);
    }
}
