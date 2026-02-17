// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Roughtime Ed25519 signature verification and SHA-512 Merkle tree verification.

use ring::{digest, signature};

use super::error::RoughtimeError;
use super::types::{self, RoughtimeResult, tag};
use super::wire::{TagValueMap, decode_envelope};

/// Context string prepended to delegation signatures.
const DELEGATION_CONTEXT: &[u8] = b"RoughTime v1 delegation signature\0";

/// Context string prepended to response signatures.
const RESPONSE_CONTEXT: &[u8] = b"RoughTime v1 response signature\0";

/// Verify an Ed25519 delegation signature.
///
/// The signed message is `DELEGATION_CONTEXT || dele_bytes`.
fn verify_delegation(
    long_term_pk: &[u8; 32],
    dele_bytes: &[u8],
    sig: &[u8],
) -> Result<(), RoughtimeError> {
    let pk = signature::UnparsedPublicKey::new(&signature::ED25519, long_term_pk);

    let mut msg = Vec::with_capacity(DELEGATION_CONTEXT.len() + dele_bytes.len());
    msg.extend_from_slice(DELEGATION_CONTEXT);
    msg.extend_from_slice(dele_bytes);

    pk.verify(&msg, sig)
        .map_err(|_| RoughtimeError::SignatureVerificationFailed)
}

/// Verify an Ed25519 response signature.
///
/// The signed message is `RESPONSE_CONTEXT || srep_bytes`.
fn verify_response_sig(
    delegated_pk: &[u8; 32],
    srep_bytes: &[u8],
    sig: &[u8],
) -> Result<(), RoughtimeError> {
    let pk = signature::UnparsedPublicKey::new(&signature::ED25519, delegated_pk);

    let mut msg = Vec::with_capacity(RESPONSE_CONTEXT.len() + srep_bytes.len());
    msg.extend_from_slice(RESPONSE_CONTEXT);
    msg.extend_from_slice(srep_bytes);

    pk.verify(&msg, sig)
        .map_err(|_| RoughtimeError::SignatureVerificationFailed)
}

/// Verify a Merkle tree path from leaf nonce to root.
///
/// - `leaf = SHA-512(0x00 || nonce)[..32]`
/// - For each node: `SHA-512(0x01 || left || right)[..32]`
/// - Bit `i` of `index` determines left/right placement at level `i`.
fn verify_merkle_tree(
    nonce: &[u8; 32],
    root: &[u8],
    path: &[u8],
    index: u32,
) -> Result<(), RoughtimeError> {
    if root.len() != 32 {
        return Err(RoughtimeError::InvalidTagLength {
            tag: tag::ROOT,
            expected: 32,
            actual: root.len(),
        });
    }
    if !path.len().is_multiple_of(32) {
        return Err(RoughtimeError::MerkleVerificationFailed);
    }

    // Leaf hash: SHA-512(0x00 || nonce)[..32]
    let mut leaf_input = [0u8; 33];
    leaf_input[0] = 0x00;
    leaf_input[1..33].copy_from_slice(nonce);
    let leaf_hash = digest::digest(&digest::SHA512, &leaf_input);
    let mut current = [0u8; 32];
    current.copy_from_slice(&leaf_hash.as_ref()[..32]);

    // Walk the path.
    let num_nodes = path.len() / 32;
    for i in 0..num_nodes {
        let sibling = &path[i * 32..(i + 1) * 32];
        let mut node_input = [0u8; 65];
        node_input[0] = 0x01;

        if (index >> i) & 1 == 0 {
            // Current is left child.
            node_input[1..33].copy_from_slice(&current);
            node_input[33..65].copy_from_slice(sibling);
        } else {
            // Current is right child.
            node_input[1..33].copy_from_slice(sibling);
            node_input[33..65].copy_from_slice(&current);
        }

        let node_hash = digest::digest(&digest::SHA512, &node_input);
        current.copy_from_slice(&node_hash.as_ref()[..32]);
    }

    if current != root[..32] {
        return Err(RoughtimeError::MerkleVerificationFailed);
    }

    Ok(())
}

/// Fully verify a Roughtime response and extract the time result.
///
/// This performs the complete verification pipeline:
/// 1. Decode envelope
/// 2. Parse outer tag-value map
/// 3. Verify delegation certificate (CERT → SIG over DELE)
/// 4. Verify response signature (SIG over SREP)
/// 5. Check delegation validity (MINT ≤ MIDP ≤ MAXT)
/// 6. Verify Merkle tree path
/// 7. Verify TYPE = 1
/// 8. Return `RoughtimeResult`
pub fn verify_response(
    response_bytes: &[u8],
    nonce: &[u8; 32],
    long_term_pk: &[u8; 32],
) -> Result<RoughtimeResult, RoughtimeError> {
    // 1. Decode envelope.
    let message = decode_envelope(response_bytes)?;

    // 2. Parse outer map.
    let outer = TagValueMap::parse(message)?;

    // 3. Verify delegation: CERT contains nested (DELE, SIG).
    let cert_bytes = outer.require(&tag::CERT)?;
    let cert = TagValueMap::parse(cert_bytes)?;
    let dele_bytes = cert.require(&tag::DELE)?;
    let cert_sig = cert.require(&tag::SIG)?;
    if cert_sig.len() != 64 {
        return Err(RoughtimeError::InvalidTagLength {
            tag: tag::SIG,
            expected: 64,
            actual: cert_sig.len(),
        });
    }
    verify_delegation(long_term_pk, dele_bytes, cert_sig)?;

    // Extract delegated public key from DELE.
    let dele = TagValueMap::parse(dele_bytes)?;
    let pubk = dele.require(&tag::PUBK)?;
    if pubk.len() != 32 {
        return Err(RoughtimeError::InvalidTagLength {
            tag: tag::PUBK,
            expected: 32,
            actual: pubk.len(),
        });
    }
    let mut delegated_pk = [0u8; 32];
    delegated_pk.copy_from_slice(pubk);

    // 4. Verify response signature over SREP.
    let outer_sig = outer.require(&tag::SIG)?;
    if outer_sig.len() != 64 {
        return Err(RoughtimeError::InvalidTagLength {
            tag: tag::SIG,
            expected: 64,
            actual: outer_sig.len(),
        });
    }
    let srep_bytes = outer.require(&tag::SREP)?;
    verify_response_sig(&delegated_pk, srep_bytes, outer_sig)?;

    // Parse SREP for time values.
    let srep = TagValueMap::parse(srep_bytes)?;
    let midp = types::read_u64_le(srep.require(&tag::MIDP)?, &tag::MIDP)?;
    let radi = types::read_u32_le(srep.require(&tag::RADI)?, &tag::RADI)?;
    let root = srep.require(&tag::ROOT)?;

    // 5. Check delegation validity: MINT ≤ MIDP ≤ MAXT.
    let mint = types::read_u64_le(dele.require(&tag::MINT)?, &tag::MINT)?;
    let maxt = types::read_u64_le(dele.require(&tag::MAXT)?, &tag::MAXT)?;
    if midp < mint || midp > maxt {
        return Err(RoughtimeError::DelegationExpired);
    }

    // 6. Verify Merkle tree.
    let indx = types::read_u32_le(outer.require(&tag::INDX)?, &tag::INDX)?;
    let path = outer.require(&tag::PATH)?;
    verify_merkle_tree(nonce, root, path, indx)?;

    // 7. Verify TYPE = 1 (response) if present.
    if let Some(type_data) = outer.get(&tag::TYPE) {
        let type_val = types::read_u32_le(type_data, &tag::TYPE)?;
        if type_val != 1 {
            return Err(RoughtimeError::InvalidType { value: type_val });
        }
    }

    Ok(RoughtimeResult {
        midpoint_us: midp,
        radius_us: radi,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        // With an empty path and index 0, the root should equal the leaf hash.
        let nonce = [0x42u8; 32];

        // Compute expected leaf hash.
        let mut leaf_input = [0u8; 33];
        leaf_input[0] = 0x00;
        leaf_input[1..33].copy_from_slice(&nonce);
        let leaf_hash = digest::digest(&digest::SHA512, &leaf_input);
        let root = &leaf_hash.as_ref()[..32];

        // Empty path, index 0.
        assert!(verify_merkle_tree(&nonce, root, &[], 0).is_ok());
    }

    #[test]
    fn test_merkle_tree_wrong_root() {
        let nonce = [0x42u8; 32];
        let wrong_root = [0xFF; 32];
        assert_eq!(
            verify_merkle_tree(&nonce, &wrong_root, &[], 0),
            Err(RoughtimeError::MerkleVerificationFailed)
        );
    }

    #[test]
    fn test_merkle_tree_invalid_root_length() {
        let nonce = [0u8; 32];
        assert_eq!(
            verify_merkle_tree(&nonce, &[0; 16], &[], 0),
            Err(RoughtimeError::InvalidTagLength {
                tag: tag::ROOT,
                expected: 32,
                actual: 16,
            })
        );
    }

    #[test]
    fn test_merkle_tree_invalid_path_length() {
        let nonce = [0u8; 32];
        let root = [0u8; 32];
        // Path not a multiple of 32.
        assert_eq!(
            verify_merkle_tree(&nonce, &root, &[0; 17], 0),
            Err(RoughtimeError::MerkleVerificationFailed)
        );
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        // Simulate a 2-leaf Merkle tree.
        let nonce_left = [0xAA; 32];
        let nonce_right = [0xBB; 32];

        // Compute leaf hashes.
        let left_hash = {
            let mut input = [0u8; 33];
            input[0] = 0x00;
            input[1..33].copy_from_slice(&nonce_left);
            let h = digest::digest(&digest::SHA512, &input);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.as_ref()[..32]);
            out
        };
        let right_hash = {
            let mut input = [0u8; 33];
            input[0] = 0x00;
            input[1..33].copy_from_slice(&nonce_right);
            let h = digest::digest(&digest::SHA512, &input);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.as_ref()[..32]);
            out
        };

        // Root = SHA-512(0x01 || left || right)[..32].
        let root = {
            let mut input = [0u8; 65];
            input[0] = 0x01;
            input[1..33].copy_from_slice(&left_hash);
            input[33..65].copy_from_slice(&right_hash);
            let h = digest::digest(&digest::SHA512, &input);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.as_ref()[..32]);
            out
        };

        // Verify left leaf (index 0): path = [right_hash].
        assert!(verify_merkle_tree(&nonce_left, &root, &right_hash, 0).is_ok());

        // Verify right leaf (index 1): path = [left_hash].
        assert!(verify_merkle_tree(&nonce_right, &root, &left_hash, 1).is_ok());

        // Wrong index should fail.
        assert!(verify_merkle_tree(&nonce_left, &root, &right_hash, 1).is_err());
    }
}
