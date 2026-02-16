// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP server library with tokio/smol runtime support and NTS-KE.
//!
//! This crate provides NTPv4 server implementations using either the tokio
//! or smol async runtimes, with optional NTS (Network Time Security) support.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

// Re-export protocol types from ntp_proto for convenience.
pub use ntp_proto::{error, extension, protocol, unix_time};

/// Shared NTS logic re-exported from `ntp_proto`.
#[cfg(any(feature = "nts", feature = "nts-smol"))]
pub(crate) use ntp_proto::nts_common;

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
