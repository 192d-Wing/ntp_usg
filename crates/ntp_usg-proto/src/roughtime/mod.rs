// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Roughtime protocol types, wire format, and cryptographic verification.
//!
//! Roughtime (draft-ietf-ntp-roughtime-15) is an authenticated coarse time
//! protocol (~1s accuracy) using Ed25519 signatures and SHA-512 Merkle trees.
//!
//! # Usage
//!
//! ```no_run
//! use ntp_proto::roughtime::{build_request, verify_response};
//!
//! // Build a request (generates a random 32-byte nonce).
//! let (request_bytes, nonce) = build_request();
//!
//! // Send `request_bytes` via UDP to a Roughtime server, receive `response_bytes`.
//! # let response_bytes = vec![];
//! # let server_public_key = [0u8; 32];
//!
//! // Verify and extract the time.
//! let result = verify_response(&response_bytes, &nonce, &server_public_key).unwrap();
//! println!("Time: {} seconds since epoch (±{}s)",
//!     result.midpoint_seconds(), result.radius_seconds());
//! ```

mod crypto;
mod error;
mod types;
mod wire;

pub use crypto::verify_response;
pub use error::RoughtimeError;
pub use types::{
    ROUGHTIME_VERSION, RoughtimeResult, build_chained_request, build_request,
    build_request_with_nonce, tag,
};
pub use wire::{TagValueMap, build_tag_value_map, decode_envelope, encode_envelope};
