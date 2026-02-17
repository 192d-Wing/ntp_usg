// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Roughtime types, tag constants, and request builders.

use super::error::RoughtimeError;
use super::wire::{build_tag_value_map, encode_envelope};

/// Roughtime protocol version.
pub const ROUGHTIME_VERSION: u32 = 1;

/// Well-known Roughtime tag constants.
///
/// Tags are 4-byte ASCII values compared as little-endian `u32` for sort order.
pub mod tag {
    /// Certificate: contains nested DELE and SIG.
    pub const CERT: [u8; 4] = *b"CERT";
    /// Delegation: contains MINT, MAXT, PUBK.
    pub const DELE: [u8; 4] = *b"DELE";
    /// Index into the Merkle tree.
    pub const INDX: [u8; 4] = *b"INDX";
    /// Delegated public key (32 bytes, Ed25519).
    pub const PUBK: [u8; 4] = *b"PUBK";
    /// Midpoint timestamp (microseconds since Unix epoch).
    pub const MIDP: [u8; 4] = *b"MIDP";
    /// Minimum delegation time (microseconds since Unix epoch).
    pub const MINT: [u8; 4] = *b"MINT";
    /// Maximum delegation time (microseconds since Unix epoch).
    pub const MAXT: [u8; 4] = *b"MAXT";
    /// Nonce (32 bytes).
    pub const NONC: [u8; 4] = *b"NONC";
    /// Merkle tree path (32-byte nodes).
    pub const PATH: [u8; 4] = *b"PATH";
    /// Radius of uncertainty (microseconds).
    pub const RADI: [u8; 4] = *b"RADI";
    /// Merkle tree root (32 bytes).
    pub const ROOT: [u8; 4] = *b"ROOT";
    /// Ed25519 signature (64 bytes).
    pub const SIG: [u8; 4] = *b"SIG\0";
    /// Signed response: contains MIDP, RADI, ROOT, VER/VERS.
    pub const SREP: [u8; 4] = *b"SREP";
    /// Message type (0 = request, 1 = response).
    pub const TYPE: [u8; 4] = *b"TYPE";
    /// Protocol version (single u32).
    pub const VER: [u8; 4] = *b"VER\0";
    /// Supported versions list.
    pub const VERS: [u8; 4] = *b"VERS";
    /// Padding (zero-filled, used to reach 1024 bytes).
    pub const ZZZZ: [u8; 4] = *b"ZZZZ";
}

/// Result of a verified Roughtime response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoughtimeResult {
    /// Midpoint timestamp in microseconds since Unix epoch.
    pub midpoint_us: u64,
    /// Radius of uncertainty in microseconds.
    pub radius_us: u32,
}

impl RoughtimeResult {
    /// Midpoint as seconds since Unix epoch (truncated).
    pub fn midpoint_seconds(&self) -> u64 {
        self.midpoint_us / 1_000_000
    }

    /// Radius as seconds (rounded up).
    pub fn radius_seconds(&self) -> u32 {
        self.radius_us.div_ceil(1_000_000)
    }
}

/// Build a Roughtime request envelope.
///
/// Returns `(envelope_bytes, nonce)` where `nonce` is the 32-byte random nonce
/// that must be used to verify the response.
pub fn build_request() -> (Vec<u8>, [u8; 32]) {
    let mut nonce = [0u8; 32];
    rand::fill(&mut nonce);
    let envelope = build_request_with_nonce(&nonce);
    (envelope, nonce)
}

/// Build a Roughtime request envelope with a specific nonce (for testing or chaining).
pub fn build_request_with_nonce(nonce: &[u8; 32]) -> Vec<u8> {
    let ver = ROUGHTIME_VERSION.to_le_bytes();
    let msg_type = 0u32.to_le_bytes();

    // Tags must be sorted by LE u32 value.
    // NONC = 0x434e4f4e, SIG\0 = 0x00474953, TYPE = 0x45505954,
    // VER\0 = 0x00524556, ZZZZ = 0x5a5a5a5a
    // Sorted: SIG\0 < VER\0 < NONC < TYPE < ZZZZ

    // Build map without padding first to determine padding size.
    let map_without_pad = build_tag_value_map(&[
        (&tag::SIG, &[0u8; 64]),
        (&tag::VER, &ver),
        (&tag::NONC, nonce.as_slice()),
        (&tag::TYPE, &msg_type),
    ]);

    // Pad to 1024 bytes total message. Envelope adds 12 bytes.
    let target_msg_size: usize = 1024;
    let pad_size = target_msg_size.saturating_sub(map_without_pad.len());

    // Rebuild with ZZZZ padding. The map_without_pad didn't include ZZZZ in tag
    // count/offsets, so we must rebuild from scratch.
    let padding = vec![0u8; pad_size];
    let message = build_tag_value_map(&[
        (&tag::SIG, &[0u8; 64]),
        (&tag::VER, &ver),
        (&tag::NONC, nonce.as_slice()),
        (&tag::TYPE, &msg_type),
        (&tag::ZZZZ, &padding),
    ]);

    encode_envelope(&message)
}

/// Build a chained Roughtime request using a previous response for auditability.
///
/// The nonce is derived as `SHA-512(prev_response || blind)[..32]`.
/// Returns `(envelope_bytes, nonce)`.
pub fn build_chained_request(prev_response: &[u8], blind: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    use ring::digest;

    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(prev_response);
    ctx.update(blind);
    let hash = ctx.finish();

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&hash.as_ref()[..32]);

    let envelope = build_request_with_nonce(&nonce);
    (envelope, nonce)
}

/// Extract `midpoint_us` (u64 LE) from an 8-byte slice.
pub(crate) fn read_u64_le(data: &[u8], tag: &[u8; 4]) -> Result<u64, RoughtimeError> {
    if data.len() != 8 {
        return Err(RoughtimeError::InvalidTagLength {
            tag: *tag,
            expected: 8,
            actual: data.len(),
        });
    }
    Ok(u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]))
}

/// Extract a `u32` LE from a 4-byte slice.
pub(crate) fn read_u32_le(data: &[u8], tag: &[u8; 4]) -> Result<u32, RoughtimeError> {
    if data.len() != 4 {
        return Err(RoughtimeError::InvalidTagLength {
            tag: *tag,
            expected: 4,
            actual: data.len(),
        });
    }
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roughtime_result_conversions() {
        let result = RoughtimeResult {
            midpoint_us: 1_700_000_500_000,
            radius_us: 1_500_000,
        };
        assert_eq!(result.midpoint_seconds(), 1_700_000);
        assert_eq!(result.radius_seconds(), 2); // rounds up
    }

    #[test]
    fn test_roughtime_result_exact_second() {
        let result = RoughtimeResult {
            midpoint_us: 2_000_000_000_000,
            radius_us: 1_000_000,
        };
        assert_eq!(result.midpoint_seconds(), 2_000_000);
        assert_eq!(result.radius_seconds(), 1); // exact
    }

    #[test]
    fn test_build_request_with_nonce() {
        let nonce = [0xAA; 32];
        let envelope = build_request_with_nonce(&nonce);

        // Should be an envelope: 12-byte header + message.
        assert!(envelope.len() >= 12);

        // Verify magic.
        let magic = u64::from_le_bytes(envelope[..8].try_into().unwrap());
        assert_eq!(magic, 0x4d49_5448_4755_4f52);

        // Decode and parse the inner message.
        let msg = super::super::wire::decode_envelope(&envelope).unwrap();
        let map = super::super::wire::TagValueMap::parse(msg).unwrap();

        // Check nonce.
        assert_eq!(map.require(&tag::NONC).unwrap(), &[0xAA; 32]);

        // Check TYPE = 0.
        let type_val = map.require(&tag::TYPE).unwrap();
        assert_eq!(type_val, &0u32.to_le_bytes());

        // Check VER.
        let ver_val = map.require(&tag::VER).unwrap();
        assert_eq!(ver_val, &1u32.to_le_bytes());

        // ZZZZ should exist (padding).
        assert!(map.get(&tag::ZZZZ).is_some());
    }

    #[test]
    fn test_build_request_generates_nonce() {
        let (envelope1, nonce1) = build_request();
        let (envelope2, nonce2) = build_request();

        // Nonces should be different (with overwhelming probability).
        assert_ne!(nonce1, nonce2);

        // Both should be valid envelopes.
        assert!(envelope1.len() >= 12);
        assert!(envelope2.len() >= 12);
    }

    #[test]
    fn test_read_u64_le() {
        let data = 42u64.to_le_bytes();
        assert_eq!(read_u64_le(&data, b"MIDP").unwrap(), 42);
    }

    #[test]
    fn test_read_u64_le_wrong_length() {
        assert_eq!(
            read_u64_le(&[0; 4], b"MIDP"),
            Err(RoughtimeError::InvalidTagLength {
                tag: *b"MIDP",
                expected: 8,
                actual: 4,
            })
        );
    }

    #[test]
    fn test_read_u32_le() {
        let data = 99u32.to_le_bytes();
        assert_eq!(read_u32_le(&data, b"RADI").unwrap(), 99);
    }

    #[test]
    fn test_chained_request_deterministic() {
        let prev = b"previous response data";
        let blind = [0xBB; 32];

        let (env1, nonce1) = build_chained_request(prev, &blind);
        let (env2, nonce2) = build_chained_request(prev, &blind);

        // Same inputs → same nonce.
        assert_eq!(nonce1, nonce2);

        // Nonce should not be all zeros.
        assert_ne!(nonce1, [0u8; 32]);

        // Envelopes should be identical (deterministic).
        assert_eq!(env1, env2);
    }
}
