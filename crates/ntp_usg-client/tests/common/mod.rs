// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for integration tests.

// Integration test helpers are `pub` so each `tests/*.rs` file can import them
// via `mod common`, but clippy flags them as unreachable outside the crate.
#![allow(unreachable_pub)]

/// Returns `true` if the I/O error indicates a network-level failure that
/// should cause the test to be **skipped** (not panicked).
///
/// CI runners occasionally lack outbound UDP/123 access, causing errors such
/// as `ENETUNREACH` (101) or `EHOSTUNREACH` (113) in addition to the usual
/// `TimedOut` / `WouldBlock`.
pub fn is_network_skip_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::AddrNotAvailable
    ) || e.raw_os_error() == Some(101) // ENETUNREACH  (Network is unreachable)
      || e.raw_os_error() == Some(113) // EHOSTUNREACH (No route to host)
      || e.to_string().contains("Network is unreachable")
      || e.to_string().contains("No route to host")
      || e.to_string().contains("timed out")
      || e.to_string().contains("Connection refused")
      || e.to_string().contains("Connection reset")
      || e.to_string().contains("close_notify")
}
