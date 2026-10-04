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

/// Merkle leaf value for a client request (draft-15 §5.3).
fn leaf_hash(request_packet: &[u8]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(&[0x00]);
    ctx.update(request_packet);
    let h = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.as_ref()[..32]);
    out
}

/// Verify a Merkle tree path from leaf nonce to root.
///
/// - `leaf = SHA-512(0x00 || nonce)[..32]`
/// - For each node: `SHA-512(0x01 || left || right)[..32]`
/// - Bit `i` of `index` determines left/right placement at level `i`.
fn verify_merkle_tree(
    request_packet: &[u8],
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

    // Leaf hash (draft-15 §5.3): SHA-512(0x00 || request packet)[..32], where
    // the request packet is the full datagram the client sent, "ROUGHTIM"
    // header and ZZZZ padding included. (The pre-IETF protocol hashed only
    // the nonce; a server following the draft never matches that.)
    let mut current = leaf_hash(request_packet);

    // Walk the path. A u32 leaf index addresses at most 32 tree levels, so a
    // longer path is malformed; rejecting it also prevents the `index >> i`
    // shift below from overflowing (`i >= 32` panics in debug builds and is a
    // logic error in release). `path` is attacker-controlled and unsigned.
    let num_nodes = path.len() / 32;
    if num_nodes > 32 {
        return Err(RoughtimeError::MerkleVerificationFailed);
    }
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
    request_bytes: &[u8],
    long_term_pk: &[u8; 32],
) -> Result<RoughtimeResult, RoughtimeError> {
    let nonce = types::request_nonce(request_bytes)?;

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

    // Parse SREP for time values. MIDP is uint64 seconds, RADI uint32 seconds
    // (draft-15 §4.1.4, §5.2.5).
    let srep = TagValueMap::parse(srep_bytes)?;
    let midp = types::read_u64_le(srep.require(&tag::MIDP)?, &tag::MIDP)?;
    let radi = types::read_u32_le(srep.require(&tag::RADI)?, &tag::RADI)?;
    let root = srep.require(&tag::ROOT)?;

    // The response VER is a single version and SHOULD be one we offered
    // (§5.2.5). We cannot interpret a version we do not know, so reject.
    let version = types::read_u32_le(srep.require(&tag::VER)?, &tag::VER)?;
    if !types::SUPPORTED_VERSIONS.contains(&version) {
        return Err(RoughtimeError::UnsupportedVersion { version });
    }

    // 5. Check delegation validity: MINT ≤ MIDP ≤ MAXT.
    let mint = types::read_u64_le(dele.require(&tag::MINT)?, &tag::MINT)?;
    let maxt = types::read_u64_le(dele.require(&tag::MAXT)?, &tag::MAXT)?;
    if midp < mint || midp > maxt {
        return Err(RoughtimeError::DelegationExpired);
    }

    // 6. Verify Merkle tree: the leaf is our exact request packet.
    let indx = types::read_u32_le(outer.require(&tag::INDX)?, &tag::INDX)?;
    let path = outer.require(&tag::PATH)?;
    verify_merkle_tree(request_bytes, root, path, indx)?;

    // 6b. The response NONC, if present, must echo our nonce.
    if let Some(nonc) = outer.get(&tag::NONC)
        && nonc != nonce
    {
        return Err(RoughtimeError::NonceMismatch);
    }

    // 7. Verify TYPE = 1 (response) if present.
    if let Some(type_data) = outer.get(&tag::TYPE) {
        let type_val = types::read_u32_le(type_data, &tag::TYPE)?;
        if type_val != 1 {
            return Err(RoughtimeError::InvalidType { value: type_val });
        }
    }

    Ok(RoughtimeResult {
        midpoint_secs: midp,
        radius_secs: radi,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(input: &[u8]) -> [u8; 32] {
        let d = digest::digest(&digest::SHA512, input);
        let mut out = [0u8; 32];
        out.copy_from_slice(&d.as_ref()[..32]);
        out
    }

    #[test]
    fn test_leaf_hash_covers_whole_request_packet() {
        // draft-15 §5.3: H(0x00 || full request incl. "ROUGHTIM" header).
        let req = types::build_request_with_nonce(&[0x42u8; 32]);
        assert_eq!(&req[..8], b"ROUGHTIM");
        let mut expected = vec![0x00u8];
        expected.extend_from_slice(&req);
        assert_eq!(leaf_hash(&req), h(&expected));

        // Hashing only the nonce (the old, pre-IETF behaviour) must differ.
        let mut only_nonce = vec![0x00u8];
        only_nonce.extend_from_slice(&[0x42u8; 32]);
        assert_ne!(leaf_hash(&req), h(&only_nonce));
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        // With an empty path and index 0, the root should equal the leaf hash.
        let req = types::build_request_with_nonce(&[0x42u8; 32]);
        let root = leaf_hash(&req);
        assert!(verify_merkle_tree(&req, &root, &[], 0).is_ok());
    }

    #[test]
    fn test_merkle_tree_wrong_root() {
        let req = types::build_request_with_nonce(&[0x42u8; 32]);
        let wrong_root = [0xFF; 32];
        assert_eq!(
            verify_merkle_tree(&req, &wrong_root, &[], 0),
            Err(RoughtimeError::MerkleVerificationFailed)
        );
    }

    #[test]
    fn test_merkle_tree_invalid_root_length() {
        assert_eq!(
            verify_merkle_tree(&[0u8; 40], &[0; 16], &[], 0),
            Err(RoughtimeError::InvalidTagLength {
                tag: tag::ROOT,
                expected: 32,
                actual: 16,
            })
        );
    }

    #[test]
    fn test_merkle_tree_invalid_path_length() {
        // Path not a multiple of 32.
        assert_eq!(
            verify_merkle_tree(&[0u8; 40], &[0u8; 32], &[0; 17], 0),
            Err(RoughtimeError::MerkleVerificationFailed)
        );
    }

    #[test]
    fn test_merkle_tree_overlong_path_rejected() {
        // A path with more than 32 nodes is malformed (a u32 index addresses at
        // most 32 levels). This previously panicked on `index >> i` (i >= 32) in
        // debug builds; it must now be rejected cleanly. `index` is set so the
        // shift would reach bit 32 if the loop were allowed to run that far.
        let path = vec![0u8; 33 * 32];
        assert_eq!(
            verify_merkle_tree(&[0u8; 40], &[0u8; 32], &path, u32::MAX),
            Err(RoughtimeError::MerkleVerificationFailed)
        );
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        // Simulate a 2-leaf Merkle tree built from two client requests.
        let req_left = types::build_request_with_nonce(&[0xAA; 32]);
        let req_right = types::build_request_with_nonce(&[0xBB; 32]);
        let left_hash = leaf_hash(&req_left);
        let right_hash = leaf_hash(&req_right);

        // Root = SHA-512(0x01 || left || right)[..32].
        let mut input = [0u8; 65];
        input[0] = 0x01;
        input[1..33].copy_from_slice(&left_hash);
        input[33..65].copy_from_slice(&right_hash);
        let root = h(&input);

        // Verify left leaf (index 0): path = [right_hash].
        assert!(verify_merkle_tree(&req_left, &root, &right_hash, 0).is_ok());

        // Verify right leaf (index 1): path = [left_hash].
        assert!(verify_merkle_tree(&req_right, &root, &left_hash, 1).is_ok());

        // Wrong index should fail.
        assert!(verify_merkle_tree(&req_left, &root, &right_hash, 1).is_err());
    }

    // ── Full response verification against a synthetic draft-15 server ──

    use super::super::wire::{build_tag_value_map, encode_envelope};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Build a tag-value map from entries in any order.
    fn map(mut entries: Vec<(&'static [u8; 4], Vec<u8>)>) -> Vec<u8> {
        entries.sort_by_key(|(t, _)| u32::from_le_bytes(**t));
        let refs: Vec<(&[u8; 4], &[u8])> =
            entries.iter().map(|(t, v)| (*t, v.as_slice())).collect();
        build_tag_value_map(&refs)
    }

    fn keypair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn pk32(kp: &Ed25519KeyPair) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(kp.public_key().as_ref());
        out
    }

    struct Server {
        long_term: Ed25519KeyPair,
        online: Ed25519KeyPair,
        mint: u64,
        maxt: u64,
    }

    impl Server {
        fn new() -> Self {
            Server {
                long_term: keypair(1),
                online: keypair(2),
                mint: 1_700_000_000,
                maxt: 1_800_000_000,
            }
        }

        /// Produce a draft-15 response for `request` with the given MIDP/RADI
        /// (seconds) and VER, as a server with a single-leaf Merkle tree.
        fn respond(&self, request: &[u8], midp: u64, radi: u32, ver: u32) -> Vec<u8> {
            self.respond_with_leaf(request, leaf_hash(request), midp, radi, ver)
        }

        fn respond_with_leaf(
            &self,
            request: &[u8],
            root: [u8; 32],
            midp: u64,
            radi: u32,
            ver: u32,
        ) -> Vec<u8> {
            let nonce = types::request_nonce(request).unwrap();

            let dele = map(vec![
                (&tag::PUBK, pk32(&self.online).to_vec()),
                (&tag::MINT, self.mint.to_le_bytes().to_vec()),
                (&tag::MAXT, self.maxt.to_le_bytes().to_vec()),
            ]);
            let mut dmsg = DELEGATION_CONTEXT.to_vec();
            dmsg.extend_from_slice(&dele);
            let dsig = self.long_term.sign(&dmsg);
            let cert = map(vec![
                (&tag::SIG, dsig.as_ref().to_vec()),
                (&tag::DELE, dele),
            ]);

            let mut vers = Vec::new();
            for v in types::SUPPORTED_VERSIONS {
                vers.extend_from_slice(&v.to_le_bytes());
            }
            let srep = map(vec![
                (&tag::VER, ver.to_le_bytes().to_vec()),
                (&tag::RADI, radi.to_le_bytes().to_vec()),
                (&tag::MIDP, midp.to_le_bytes().to_vec()),
                (&tag::VERS, vers),
                (&tag::ROOT, root.to_vec()),
            ]);
            let mut rmsg = RESPONSE_CONTEXT.to_vec();
            rmsg.extend_from_slice(&srep);
            let rsig = self.online.sign(&rmsg);

            let outer = map(vec![
                (&tag::SIG, rsig.as_ref().to_vec()),
                (&tag::NONC, nonce.to_vec()),
                (&tag::TYPE, 1u32.to_le_bytes().to_vec()),
                (&tag::PATH, Vec::new()),
                (&tag::SREP, srep),
                (&tag::CERT, cert),
                (&tag::INDX, 0u32.to_le_bytes().to_vec()),
            ]);
            encode_envelope(&outer)
        }
    }

    #[test]
    fn test_verify_response_conforming_server_seconds_units() {
        let server = Server::new();
        let (req, _) = types::build_request();
        // A real server's MIDP is ~1.7e9 *seconds*; interpreted as microseconds
        // (the old code) that would be 1970-01-01T00:28, which no sane client
        // would accept.
        let resp = server.respond(&req, 1_750_000_000, 1, types::ROUGHTIME_DRAFT_VERSION);
        let result = verify_response(&resp, &req, &pk32(&server.long_term)).unwrap();
        assert_eq!(result.midpoint_secs, 1_750_000_000);
        assert_eq!(result.midpoint_seconds(), 1_750_000_000);
        assert_eq!(result.radius_secs, 1);
        assert_eq!(result.version, types::ROUGHTIME_DRAFT_VERSION);

        // Version 1 is accepted as well.
        let resp = server.respond(&req, 1_750_000_000, 1, types::ROUGHTIME_VERSION);
        assert!(verify_response(&resp, &req, &pk32(&server.long_term)).is_ok());
    }

    #[test]
    fn test_verify_response_rejects_nonce_only_leaf() {
        // A server that hashes 0x00 || NONC (pre-IETF behaviour) must not
        // verify: that is exactly the bug this fixes, in the other direction.
        let server = Server::new();
        let (req, nonce) = types::build_request();
        let mut old_leaf_input = vec![0x00u8];
        old_leaf_input.extend_from_slice(&nonce);
        let old_leaf = {
            let d = digest::digest(&digest::SHA512, &old_leaf_input);
            let mut out = [0u8; 32];
            out.copy_from_slice(&d.as_ref()[..32]);
            out
        };
        let resp = server.respond_with_leaf(&req, old_leaf, 1_750_000_000, 1, 1);
        assert_eq!(
            verify_response(&resp, &req, &pk32(&server.long_term)),
            Err(RoughtimeError::MerkleVerificationFailed)
        );
    }

    #[test]
    fn test_verify_response_binds_to_exact_request_bytes() {
        // A response for one request must not verify against another request
        // with the same nonce but different bytes (e.g. different padding).
        let server = Server::new();
        let (req, nonce) = types::build_request();
        let resp = server.respond(&req, 1_750_000_000, 1, 1);
        let mut other = types::build_request_with_nonce(&nonce);
        // Flip a padding byte: same nonce, different packet.
        let last = other.len() - 1;
        other[last] ^= 0x01;
        assert_eq!(
            verify_response(&resp, &other, &pk32(&server.long_term)),
            Err(RoughtimeError::MerkleVerificationFailed)
        );
    }

    #[test]
    fn test_verify_response_rejects_unknown_version_and_expired_delegation() {
        let server = Server::new();
        let (req, _) = types::build_request();
        let pk = pk32(&server.long_term);

        let resp = server.respond(&req, 1_750_000_000, 1, 0x8000_0001);
        assert_eq!(
            verify_response(&resp, &req, &pk),
            Err(RoughtimeError::UnsupportedVersion {
                version: 0x8000_0001
            })
        );

        let resp = server.respond(&req, server.maxt + 1, 1, 1);
        assert_eq!(
            verify_response(&resp, &req, &pk),
            Err(RoughtimeError::DelegationExpired)
        );
    }

    #[test]
    fn test_verify_response_rejects_wrong_long_term_key_and_tampering() {
        let server = Server::new();
        let (req, _) = types::build_request();
        let resp = server.respond(&req, 1_750_000_000, 1, 1);

        assert_eq!(
            verify_response(&resp, &req, &pk32(&keypair(9))),
            Err(RoughtimeError::SignatureVerificationFailed)
        );

        // Flip a bit somewhere inside the signed SREP (after the envelope and
        // the outer SIG): the response signature must fail.
        let mut tampered = resp.clone();
        let idx = tampered.len() - 100;
        tampered[idx] ^= 0x80;
        assert!(verify_response(&tampered, &req, &pk32(&server.long_term)).is_err());
    }
}
