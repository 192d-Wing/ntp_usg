// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Roughtime types, tag constants, and request builders.

use super::error::RoughtimeError;
use super::wire::{TagValueMap, build_tag_value_map, decode_envelope, encode_envelope};

/// Roughtime protocol version number for the published protocol
/// (draft-ietf-ntp-roughtime-15 §4.3: "The version of Roughtime specified by
/// this memo has version number 1").
pub const ROUGHTIME_VERSION: u32 = 1;

/// Version number servers use while the specification is still a draft
/// (draft-15 §4.3: "For testing this draft of the memo, a version number of
/// 0x8000000c is used"). Public servers may answer only to this value until
/// the RFC is published.
pub const ROUGHTIME_DRAFT_VERSION: u32 = 0x8000_000c;

/// Versions this client offers in a request's VER list and accepts in a
/// response's VER tag. Draft-15 and version 1 share the same wire format.
pub const SUPPORTED_VERSIONS: [u32; 2] = [ROUGHTIME_VERSION, ROUGHTIME_DRAFT_VERSION];

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
///
/// Draft-15 carries MIDP as a `uint64` count of **seconds** since the Unix
/// epoch and RADI as a `uint32` number of **seconds** (§4.1.4, §5.2.5). The
/// pre-IETF Google protocol used microseconds; that is not what this type
/// holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoughtimeResult {
    /// Midpoint timestamp (MIDP) in seconds since the Unix epoch.
    pub midpoint_secs: u64,
    /// Radius of uncertainty (RADI) in seconds.
    pub radius_secs: u32,
    /// Protocol version the server chose for this response (SREP VER).
    pub version: u32,
}

impl RoughtimeResult {
    /// Midpoint as seconds since Unix epoch.
    pub fn midpoint_seconds(&self) -> u64 {
        self.midpoint_secs
    }

    /// Radius as seconds.
    pub fn radius_seconds(&self) -> u32 {
        self.radius_secs
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
///
/// Per draft-15 §5.1 the request carries VER (the list of versions we
/// support), NONC, TYPE = 0 and ZZZZ padding to reach 1024 bytes. Keep the
/// returned bytes: the server's Merkle leaf is computed over this exact
/// packet, so [`verify_response`](super::verify_response) needs it.
pub fn build_request_with_nonce(nonce: &[u8; 32]) -> Vec<u8> {
    let mut ver = Vec::with_capacity(4 * SUPPORTED_VERSIONS.len());
    for v in SUPPORTED_VERSIONS {
        ver.extend_from_slice(&v.to_le_bytes());
    }
    let msg_type = 0u32.to_le_bytes();

    // Tags must be sorted by LE u32 value.
    // VER\0 = 0x00524556, NONC = 0x434e4f4e, TYPE = 0x45505954, ZZZZ = 0x5a5a5a5a

    // Build map without padding first to determine padding size.
    let map_without_pad = build_tag_value_map(&[
        (&tag::VER, &ver),
        (&tag::NONC, nonce.as_slice()),
        (&tag::TYPE, &msg_type),
    ]);

    // Pad to 1024 bytes total message (§5.1). Adding the ZZZZ tag costs 8
    // bytes (one more tag header slot and one more offset).
    let target_msg_size: usize = 1024;
    let pad_size = target_msg_size.saturating_sub(map_without_pad.len() + 8);

    let padding = vec![0u8; pad_size];
    let message = build_tag_value_map(&[
        (&tag::VER, &ver),
        (&tag::NONC, nonce.as_slice()),
        (&tag::TYPE, &msg_type),
        (&tag::ZZZZ, &padding),
    ]);

    encode_envelope(&message)
}

/// Extract the NONC value from a request packet built by this crate.
pub(crate) fn request_nonce(request: &[u8]) -> Result<[u8; 32], RoughtimeError> {
    let msg = decode_envelope(request)?;
    let map = TagValueMap::parse(msg)?;
    let nonc = map.require(&tag::NONC)?;
    if nonc.len() != 32 {
        return Err(RoughtimeError::InvalidTagLength {
            tag: tag::NONC,
            expected: 32,
            actual: nonc.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(nonc);
    Ok(out)
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

/// Read a little-endian u64 tag value from an 8-byte slice.
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
    fn test_roughtime_result_is_in_seconds() {
        // MIDP/RADI are seconds on the wire (draft-15); no unit conversion.
        let result = RoughtimeResult {
            midpoint_secs: 1_700_000_500,
            radius_secs: 2,
            version: ROUGHTIME_VERSION,
        };
        assert_eq!(result.midpoint_seconds(), 1_700_000_500);
        assert_eq!(result.radius_seconds(), 2);
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

        // Check VER: a list of every version we support, version 1 first.
        let ver_val = map.require(&tag::VER).unwrap();
        let mut expected = Vec::new();
        for v in SUPPORTED_VERSIONS {
            expected.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(ver_val, expected.as_slice());
        assert_eq!(&ver_val[..4], &1u32.to_le_bytes());
        assert_eq!(&ver_val[4..8], &0x8000_000cu32.to_le_bytes());

        // SIG is a response-only tag and must not appear in a request.
        assert!(map.get(&tag::SIG).is_none());

        // ZZZZ should exist (padding) and bring the message to exactly 1024
        // bytes (§5.1), i.e. a 1036-byte datagram with the 12-byte envelope.
        assert!(map.get(&tag::ZZZZ).is_some());
        assert_eq!(msg.len(), 1024);
        assert_eq!(envelope.len(), 1036);

        // The nonce is recoverable from the packet for verification.
        assert_eq!(request_nonce(&envelope).unwrap(), nonce);
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
