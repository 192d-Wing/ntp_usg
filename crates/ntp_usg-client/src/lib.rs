// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

/*!
NTP client library with synchronous, async (tokio/smol), and NTS support.

# Example
Shows how to use the ntp_client library to fetch the current time according
to the requested ntp server.

```rust,no_run
extern crate chrono;
extern crate ntp_client;

use chrono::TimeZone;

fn main() {
    let address = "time.nist.gov:123";
    let result = ntp_client::request(address).unwrap();
    let unix_time = ntp_client::unix_time::Instant::from(result.transmit_timestamp);
    let local_time = chrono::Local.timestamp_opt(unix_time.secs(), unix_time.subsec_nanos() as _).unwrap();
    println!("{}", local_time);
    println!("Offset: {:.6} seconds", result.offset_seconds);
}
```

# Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `tokio` | no | Async client and helpers using the tokio runtime. |
| `smol-runtime` | no | Async client and helpers using the smol runtime. |
| `nts` | no | Network Time Security (RFC 8915) via tokio + tokio-rustls. Implies `tokio`. |
| `nts-smol` | no | NTS via smol + futures-rustls. Implies `smol-runtime`. Cannot be combined with `nts` (different TLS backends). |
| `pq-nts` | no | Enable post-quantum key exchange for NTS (ML-KEM via aws-lc-rs). |
| `clock` | no | System clock step/slew functions (`libc`/`windows-sys`). |
| `discipline` | no | PLL/FLL clock discipline algorithm. Implies `clock`. |
| `symmetric` | no | NTP symmetric active/passive mode (RFC 5905 modes 1 & 2). |
| `broadcast` | no | NTP broadcast client (mode 5). Deprecated by RFC 8633. |
| `refclock` | no | Reference clock abstraction layer. Implies `tokio`. |
| `gps` | no | GPS reference clock driver. Implies `refclock`. |
| `pps` | no | PPS reference clock driver. Implies `refclock`. |
| `hwts` | no | Hardware timestamping support. Implies `refclock`. |
| `roughtime` | no | Roughtime client (draft-ietf-ntp-roughtime). Implies `tokio`. |
| `socket-opts` | no | DSCP and `IPV6_V6ONLY` socket options via `socket2`. |
| `ipv4` | no | Default to `0.0.0.0` instead of `[::]` for listen addresses. |
| `ntpv5` | no | NTPv5 draft support (draft-ietf-ntp-ntpv5). |
*/

#![warn(missing_docs)]

// Re-export protocol types from ntp_proto for convenience.
pub use ntp_proto::{error, extension, protocol, unix_time};

/// Shared NTS logic re-exported from `ntp_proto`.
#[cfg(any(feature = "nts", feature = "nts-smol"))]
pub(crate) use ntp_proto::nts_common;

/// TLS configuration for NTS (crypto provider selection).
#[cfg(any(feature = "nts", feature = "nts-smol"))]
pub(crate) mod tls_config;

/// Clock sample filtering for the continuous NTP client.
///
/// Implements a simplified version of the RFC 5905 Section 10 clock filter
/// algorithm.
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
pub mod filter;

/// Peer selection, clustering, and combining algorithms per RFC 5905 Section 11.2.
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
pub mod selection;

/// Shared types and logic for the continuous NTP client.
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
pub mod client_common;

/// Continuous NTP client with adaptive poll interval management and interleaved mode.
#[cfg(feature = "tokio")]
pub mod client;

/// Network Time Security (NTS) client (RFC 8915).
///
/// Provides authenticated NTP using TLS 1.3 key establishment and AEAD
/// per-packet authentication.
#[cfg(feature = "nts")]
pub mod nts;

/// System clock adjustment utilities for applying NTP corrections.
///
/// Provides platform-specific functions for slewing (gradual) and stepping
/// (immediate) the system clock. Requires elevated privileges (root/admin).
#[cfg(feature = "clock")]
pub mod clock;

/// Clock discipline algorithm (PLL/FLL) per RFC 5905 Section 11.3.
///
/// Converts raw offset measurements into phase and frequency corrections
/// using a hybrid phase-locked / frequency-locked loop state machine.
#[cfg(feature = "discipline")]
pub mod discipline;

/// Periodic clock adjustment process per RFC 5905 Section 12.
///
/// Drains residual phase error and applies frequency corrections on a
/// 1-second tick cycle.
#[cfg(feature = "discipline")]
pub mod clock_adjust;

/// Symmetric active/passive mode support per RFC 5905 Sections 8-9.
///
/// Enables peer-to-peer time synchronization using NTP modes 1 and 2.
#[cfg(feature = "symmetric")]
pub mod symmetric;

/// NTP broadcast client support per RFC 5905 Section 8.
///
/// Parses and validates mode-5 broadcast packets and computes clock offset
/// using a calibrated one-way delay. Deprecated by BCP 223 (RFC 8633).
#[cfg(feature = "broadcast")]
pub mod broadcast_client;

/// Reference clock abstraction layer for hardware time sources.
///
/// Provides a unified interface for GPS receivers, PPS signals, and other
/// precision time sources that can serve as Stratum 1 references.
#[cfg(any(feature = "refclock", feature = "gps", feature = "pps"))]
pub mod refclock;

/// Simple Network Time Protocol (SNTP) client per RFC 4330.
///
/// SNTP is a simplified subset of NTP for clients that perform single-shot
/// time queries without the full NTP discipline algorithms. This module provides
/// an RFC 4330 compliant SNTP API that wraps the underlying NTP implementation.
///
/// See [`sntp`] module documentation for usage examples.
pub mod sntp;

/// Async NTP client functions using the Tokio runtime.
///
/// See [`async_ntp::request`] and [`async_ntp::request_with_timeout`] for details.
#[cfg(feature = "tokio")]
pub mod async_ntp;

/// Async NTP client functions using the smol runtime.
///
/// See [`smol_ntp::request`] and [`smol_ntp::request_with_timeout`] for details.
#[cfg(feature = "smol-runtime")]
pub mod smol_ntp;

/// Continuous NTP client using the smol runtime.
#[cfg(feature = "smol-runtime")]
pub mod smol_client;

/// Network Time Security (NTS) client using the smol runtime (RFC 8915).
///
/// Provides the same NTS functionality as the `nts` module but using smol
/// and futures-rustls instead of tokio and tokio-rustls.
#[cfg(feature = "nts-smol")]
pub mod smol_nts;

/// Roughtime client for authenticated coarse time (draft-ietf-ntp-roughtime-15).
///
/// Provides sync and async (tokio) APIs for querying Roughtime servers with
/// Ed25519 signature verification and SHA-512 Merkle tree proofs.
#[cfg(feature = "roughtime")]
pub mod roughtime;

/// Socket options for `IPV6_V6ONLY` and DSCP/Traffic Class control.
///
/// When the `socket-opts` feature is enabled, uses `socket2` for cross-platform
/// socket option control. Always compiled (zero-sized type when disabled).
#[cfg(any(feature = "tokio", feature = "smol-runtime"))]
mod socket_opts;

// Core request types and blocking networking functions.
mod request;

pub use request::{KissOfDeathError, NtpResult, request, request_with_timeout};
