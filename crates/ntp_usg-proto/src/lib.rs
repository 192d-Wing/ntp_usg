// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP protocol types, extension fields, and NTS cryptographic primitives.
//!
//! This crate provides the foundational types and parsing logic for the
//! Network Time Protocol (RFC 5905) and Network Time Security (RFC 8915).

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Custom error types for buffer-based NTP packet parsing and serialization.
pub mod error;

/// NTP extension field parsing and NTS extension types.
pub mod extension;

/// NTP protocol types and constants (RFC 5905).
pub mod protocol;

/// Unix time conversion utilities for NTP timestamps.
pub mod unix_time;

/// Shared NTS logic: AEAD encryption, key establishment records, and NTS packet building.
///
/// Used by both client and server NTS implementations.
#[cfg(feature = "nts")]
pub mod nts_common;

/// Roughtime protocol types, wire format, and cryptographic verification.
///
/// Provides Ed25519 signature verification and SHA-512 Merkle tree proofs
/// for authenticated coarse time (draft-ietf-ntp-roughtime-15).
#[cfg(feature = "roughtime")]
pub mod roughtime;

/// NTPv5 extension field constants and typed wrappers (`draft-ietf-ntp-ntpv5-07`).
///
/// Defines provisional extension field type codes (0xF5xx range) and typed
/// structs for NTPv5-specific extension fields including Draft Identification,
/// Server Information, Reference IDs, and Reference Timestamp.
#[cfg(feature = "ntpv5")]
pub mod ntpv5_ext;
