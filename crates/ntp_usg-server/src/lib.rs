// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP server library with tokio/smol runtime support and NTS-KE.
//!
//! This crate provides NTPv4 server implementations using either the tokio
//! or smol async runtimes, with optional NTS (Network Time Security) support.

#![warn(missing_docs)]

// Re-export protocol types from ntp_proto for convenience.
pub use ntp_proto::{error, extension, protocol, unix_time};

/// Shared NTS logic re-exported from `ntp_proto`.
#[cfg(any(feature = "nts", feature = "nts-smol"))]
pub(crate) use ntp_proto::nts_common;

/// TLS configuration for NTS-KE server (crypto provider selection).
#[cfg(any(feature = "nts", feature = "nts-smol"))]
pub(crate) mod tls_config;

/// Default listen address based on the `ipv4` feature flag.
///
/// Without `ipv4`: binds to `[::]` (IPv6 dual-stack, accepts both IPv4 and IPv6).
/// With `ipv4`: binds to `0.0.0.0` (IPv4 only).
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
pub(crate) fn default_listen_addr(port: u16) -> String {
    #[cfg(not(feature = "ipv4"))]
    {
        format!("[::]:{port}")
    }
    #[cfg(feature = "ipv4")]
    {
        format!("0.0.0.0:{port}")
    }
}

/// Socket options for `IPV6_V6ONLY` and DSCP/Traffic Class control.
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
mod socket_opts;

/// Shared types and logic for the NTP server.
///
/// Provides request validation, response building, rate limiting, access control,
/// and interleaved mode tracking per RFC 5905, RFC 8633, and RFC 9769.
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
pub mod server_common;

/// NTP server using the Tokio runtime.
///
/// Provides a configurable NTPv4 server that responds to client requests.
#[cfg(feature = "tokio")]
pub mod server;

/// NTP server using the smol runtime.
///
/// Provides the same server functionality as [`server`] but using the smol
/// async runtime.
#[cfg(feature = "smol-runtime")]
pub mod smol_server;

/// Shared NTS server logic (cookie generation, master key management, NTS request processing).
#[cfg(any(feature = "nts", feature = "nts-smol"))]
pub mod nts_server_common;

/// NTS-KE server using the Tokio runtime (RFC 8915).
///
/// Provides a TLS 1.3 listener for NTS Key Establishment, distributing cookies
/// and negotiating AEAD algorithms with NTS clients.
#[cfg(feature = "nts")]
pub mod nts_ke_server;

/// NTS-KE server using the smol runtime (RFC 8915).
///
/// Provides the same NTS-KE server functionality as [`nts_ke_server`] but
/// using the smol async runtime and futures-rustls.
#[cfg(feature = "nts-smol")]
pub mod smol_nts_ke_server;

/// NTP broadcast mode (mode 5) packet building per RFC 5905 Section 8.
///
/// Deprecated by BCP 223 (RFC 8633) but implemented for spec completeness.
#[cfg(all(
    feature = "broadcast",
    any(feature = "tokio", feature = "smol-runtime")
))]
pub mod broadcast;

/// IPv6 multicast NTP discovery support.
///
/// Extends broadcast mode with IPv6-specific multicast group management
/// using `socket2` for `IPV6_JOIN_GROUP` socket options.
#[cfg(feature = "socket-opts")]
pub mod multicast;
