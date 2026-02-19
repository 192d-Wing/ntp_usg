// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared NTS server logic: cookie generation/validation, master key management,
//! and server-side NTS NTP request processing.
//!
//! This module provides the pure-computation server-side NTS functions used by
//! both the tokio-based [`crate::nts_ke_server`] and smol-based
//! [`crate::smol_nts_ke_server`] modules.
//!
//! # Cookie Format
//!
//! NTS cookies are opaque to the client (RFC 8915 Section 6). The server-internal
//! format is:
//!
//! ```text
//! [key_id: 4 bytes][nonce: 16 bytes][ciphertext: variable]
//! ```
//!
//! The ciphertext is AES-SIV-CMAC-512 encrypted with the server's master key.
//! The plaintext contains the negotiated AEAD algorithm ID and the C2S/S2C keys.

use std::io;
use std::time::{Duration, Instant};

use crate::error::{NtpServerError, NtsError, ProtocolError};
use crate::extension::{
    self, ExtensionField, NtsAuthenticator, NtsCookie, UNIQUE_IDENTIFIER, UniqueIdentifier,
};
use crate::nts_common::{
    self, AEAD_AES_SIV_CMAC_512, aead_decrypt, aead_encrypt, aead_key_length,
    find_authenticator_offset,
};
use crate::protocol::{self, ConstPackedSizeBytes, WriteBytes};

// ============================================================================
// Cookie contents
// ============================================================================

/// The decrypted contents of an NTS cookie.
///
/// Contains the session keys and AEAD algorithm negotiated between client
/// and server during NTS-KE.
pub struct CookieContents {
    /// AEAD algorithm negotiated during NTS-KE.
    pub aead_algorithm: u16,
    /// Client-to-server AEAD key.
    pub c2s_key: Vec<u8>,
    /// Server-to-client AEAD key.
    pub s2c_key: Vec<u8>,
}

/// Serialize cookie contents to plaintext bytes.
///
/// Format: `aead_algorithm (u16 BE) || c2s_key || s2c_key`
fn serialize_cookie_plaintext(contents: &CookieContents) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(2 + contents.c2s_key.len() + contents.s2c_key.len());
    plaintext.extend_from_slice(&contents.aead_algorithm.to_be_bytes());
    plaintext.extend_from_slice(&contents.c2s_key);
    plaintext.extend_from_slice(&contents.s2c_key);
    plaintext
}

/// Deserialize cookie contents from plaintext bytes.
fn deserialize_cookie_plaintext(plaintext: &[u8]) -> io::Result<CookieContents> {
    if plaintext.len() < 2 {
        return Err(
            NtpServerError::Nts(NtsError::Other("cookie plaintext too short".to_string())).into(),
        );
    }
    let aead_algorithm = u16::from_be_bytes([plaintext[0], plaintext[1]]);
    let key_len = aead_key_length(aead_algorithm)?;
    let expected = 2 + 2 * key_len;
    if plaintext.len() != expected {
        return Err(NtpServerError::Nts(NtsError::Other(format!(
            "cookie plaintext length mismatch: expected {}, got {}",
            expected,
            plaintext.len()
        )))
        .into());
    }
    let c2s_key = plaintext[2..2 + key_len].to_vec();
    let s2c_key = plaintext[2 + key_len..].to_vec();
    Ok(CookieContents {
        aead_algorithm,
        c2s_key,
        s2c_key,
    })
}

// ============================================================================
// Master key management
// ============================================================================

/// A server master key used to encrypt/decrypt NTS cookies.
///
/// Each key has a unique numeric identifier embedded in cookie headers
/// and a creation timestamp for implementing key rotation policies.
#[derive(Clone)]
pub struct MasterKey {
    /// Unique key identifier, embedded in cookie headers.
    pub key_id: u32,
    /// 64-byte AES-SIV-CMAC-512 key material (256-bit AES).
    key: [u8; 64],
    /// When this key was created.
    created: Instant,
}

impl MasterKey {
    /// Generate a new master key with random key material.
    pub fn generate(key_id: u32) -> Self {
        let mut key = [0u8; 64];
        rand::fill(&mut key);
        MasterKey {
            key_id,
            key,
            created: Instant::now(),
        }
    }
}

/// Manages a set of server master keys with support for key rotation.
///
/// The key store maintains a current (active) key for encrypting new cookies
/// and retains previous keys for a configurable grace period to decrypt
/// cookies issued before rotation.
///
/// # Thread Safety
///
/// This type is not `Sync` — callers should wrap it in `Arc<RwLock<MasterKeyStore>>`
/// when sharing between the NTS-KE handler and the NTP packet handler.
pub struct MasterKeyStore {
    /// The current key used for encrypting new cookies.
    current: MasterKey,
    /// Previous keys retained for decrypting old cookies. Newest-first.
    retired: Vec<MasterKey>,
    /// How long retired keys remain valid for decryption.
    grace_period: Duration,
    /// Counter for generating unique key IDs.
    next_key_id: u32,
}

impl MasterKeyStore {
    /// Create a new key store with a freshly generated master key.
    ///
    /// # Arguments
    /// * `grace_period` - Duration to retain old keys after rotation
    pub fn new(grace_period: Duration) -> Self {
        let key = MasterKey::generate(1);
        MasterKeyStore {
            current: key,
            retired: Vec::new(),
            grace_period,
            next_key_id: 2,
        }
    }

    /// Rotate to a new master key.
    ///
    /// The current key becomes retired (still valid for decryption during the
    /// grace period). A new key becomes current.
    pub fn rotate(&mut self) {
        let old = std::mem::replace(&mut self.current, MasterKey::generate(self.next_key_id));
        self.next_key_id += 1;
        self.retired.insert(0, old); // Newest-first.
        self.purge_expired();
    }

    /// Remove expired retired keys (older than grace_period).
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.retired
            .retain(|k| now.duration_since(k.created) < self.grace_period);
    }

    /// Encrypt a cookie using the current master key.
    ///
    /// Returns the opaque cookie bytes ready to send to the client.
    pub fn encrypt_cookie(&self, contents: &CookieContents) -> io::Result<Vec<u8>> {
        let plaintext = serialize_cookie_plaintext(contents);

        // AAD = key_id bytes.
        let aad = self.current.key_id.to_be_bytes();

        // AES-SIV encrypt using the current master key (CMAC-512 / 256-bit AES).
        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_512, &self.current.key, &aad, &plaintext)?;

        // Assemble cookie: key_id || nonce || ciphertext.
        let mut cookie = Vec::with_capacity(4 + nonce.len() + ciphertext.len());
        cookie.extend_from_slice(&aad);
        cookie.extend_from_slice(&nonce);
        cookie.extend_from_slice(&ciphertext);
        Ok(cookie)
    }

    /// Decrypt a cookie, trying the current key first, then retired keys.
    ///
    /// Returns `None` if no key can decrypt the cookie (expired or invalid).
    pub fn decrypt_cookie(&self, cookie_bytes: &[u8]) -> io::Result<Option<CookieContents>> {
        // Minimum: 4 (key_id) + 16 (nonce) + 16 (AES-SIV tag, minimum ciphertext).
        if cookie_bytes.len() < 36 {
            return Ok(None);
        }

        let key_id = u32::from_be_bytes([
            cookie_bytes[0],
            cookie_bytes[1],
            cookie_bytes[2],
            cookie_bytes[3],
        ]);
        let nonce = &cookie_bytes[4..20];
        let ciphertext = &cookie_bytes[20..];
        let aad = &cookie_bytes[0..4];

        // Find the key matching this key_id.
        let key = if self.current.key_id == key_id {
            Some(&self.current)
        } else {
            self.retired.iter().find(|k| k.key_id == key_id)
        };

        let key = match key {
            Some(k) => k,
            None => return Ok(None), // Unknown key_id.
        };

        // Decrypt.
        let plaintext = match aead_decrypt(AEAD_AES_SIV_CMAC_512, &key.key, aad, nonce, ciphertext)
        {
            Ok(pt) => pt,
            Err(_) => return Ok(None), // Decryption failed.
        };

        // Parse plaintext.
        match deserialize_cookie_plaintext(&plaintext) {
            Ok(contents) => Ok(Some(contents)),
            Err(_) => Ok(None),
        }
    }
}

// ============================================================================
// NTS NTP request processing
// ============================================================================

/// Context extracted from an NTS-authenticated request, used to build the response.
#[derive(Debug)]
pub struct NtsRequestContext {
    /// Unique Identifier to echo back.
    pub uid_data: Vec<u8>,
    /// Server-to-client AEAD key (recovered from cookie).
    pub s2c_key: Vec<u8>,
    /// Negotiated AEAD algorithm.
    pub aead_algorithm: u16,
    /// New cookies to include in the response.
    pub new_cookies: Vec<Vec<u8>>,
}

/// Process an incoming NTS-authenticated NTP request.
///
/// Validates the AEAD authenticator, decrypts the cookie to recover session
/// keys, and prepares replacement cookies.
///
/// Returns the NTS context needed to build the authenticated response.
pub fn process_nts_extensions(
    request_buf: &[u8],
    request_len: usize,
    key_store: &MasterKeyStore,
) -> io::Result<NtsRequestContext> {
    // 1. Parse extension fields after the 48-byte header.
    if request_len <= protocol::Packet::PACKED_SIZE_BYTES {
        return Err(NtpServerError::Protocol(ProtocolError::NoExtensionFields).into());
    }
    let ext_data = &request_buf[protocol::Packet::PACKED_SIZE_BYTES..request_len];
    let ext_fields = extension::parse_extension_fields(ext_data)?;

    // 2. Extract the Unique Identifier (MUST be echoed back).
    let uid_ef = ext_fields
        .iter()
        .find(|ef| ef.field_type == UNIQUE_IDENTIFIER)
        .ok_or_else(|| -> io::Error {
            NtpServerError::Nts(NtsError::MissingExtension {
                field: "Unique Identifier",
            })
            .into()
        })?;
    let uid_data = uid_ef.value.clone();

    // 3. Extract the NTS Cookie (exactly one).
    let cookie_ef = ext_fields
        .iter()
        .find(|ef| ef.field_type == extension::NTS_COOKIE)
        .ok_or_else(|| -> io::Error {
            NtpServerError::Nts(NtsError::MissingExtension {
                field: "NTS Cookie",
            })
            .into()
        })?;

    // 4. Decrypt the cookie to recover session keys.
    let cookie_contents =
        key_store
            .decrypt_cookie(&cookie_ef.value)?
            .ok_or_else(|| -> io::Error {
                NtpServerError::Nts(NtsError::CookieDecryptionFailed).into()
            })?;

    // 5. Extract the NTS Authenticator.
    let auth_ef = ext_fields
        .iter()
        .find(|ef| ef.field_type == extension::NTS_AUTHENTICATOR)
        .ok_or_else(|| -> io::Error {
            NtpServerError::Nts(NtsError::MissingExtension {
                field: "NTS Authenticator",
            })
            .into()
        })?;
    let auth = NtsAuthenticator::from_extension_field(auth_ef)?.ok_or_else(|| -> io::Error {
        NtpServerError::Nts(NtsError::AuthenticatorParseFailed).into()
    })?;

    // 6. Build AAD for verification: NTP header + extensions before authenticator.
    let auth_offset = find_authenticator_offset(ext_data, &ext_fields)?;
    let mut aad = Vec::new();
    aad.extend_from_slice(&request_buf[..protocol::Packet::PACKED_SIZE_BYTES]);
    aad.extend_from_slice(&ext_data[..auth_offset]);

    // 7. Verify AEAD authenticator using C2S key.
    aead_decrypt(
        cookie_contents.aead_algorithm,
        &cookie_contents.c2s_key,
        &aad,
        &auth.nonce,
        &auth.ciphertext,
    )?;

    // 8. Count cookie placeholders.
    let placeholder_count = ext_fields
        .iter()
        .filter(|ef| ef.field_type == extension::NTS_COOKIE_PLACEHOLDER)
        .count();

    // 9. Generate new cookies (one for consumed cookie + one per placeholder).
    let new_cookie_count = 1 + placeholder_count;
    let new_cookies: Vec<Vec<u8>> = (0..new_cookie_count)
        .map(|_| key_store.encrypt_cookie(&cookie_contents))
        .collect::<io::Result<Vec<_>>>()?;

    Ok(NtsRequestContext {
        uid_data,
        s2c_key: cookie_contents.s2c_key,
        aead_algorithm: cookie_contents.aead_algorithm,
        new_cookies,
    })
}

/// Build an NTS-authenticated server response.
///
/// Takes the NTP response packet (with timestamps set) and the NTS context
/// from [`process_nts_extensions`], and returns the complete serialized response
/// including extension fields and AEAD authenticator.
pub fn build_nts_response(
    response_packet: &protocol::Packet,
    ctx: &NtsRequestContext,
) -> io::Result<Vec<u8>> {
    // Serialize response NTP header.
    let mut resp_header = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut resp_header[..]).write_bytes(*response_packet)?;

    // Build pre-authenticator extension fields.
    let uid = UniqueIdentifier::new(ctx.uid_data.clone());
    let mut pre_auth_fields: Vec<ExtensionField> = vec![uid.to_extension_field()];
    for cookie in &ctx.new_cookies {
        let nts_cookie = NtsCookie::new(cookie.clone());
        pre_auth_fields.push(nts_cookie.to_extension_field());
    }
    let pre_auth_bytes = extension::write_extension_fields(&pre_auth_fields)?;

    // Build response AAD = header + pre-auth extensions.
    let mut resp_aad = Vec::with_capacity(resp_header.len() + pre_auth_bytes.len());
    resp_aad.extend_from_slice(&resp_header);
    resp_aad.extend_from_slice(&pre_auth_bytes);

    // AEAD encrypt with S2C key (empty plaintext for basic NTS).
    let (nonce, ciphertext) = nts_common::aead_encrypt(
        ctx.aead_algorithm,
        &ctx.s2c_key,
        &resp_aad,
        &[], // No encrypted extensions.
    )?;

    // Build NTS Authenticator extension field.
    let resp_auth = NtsAuthenticator::new(nonce, ciphertext);
    let auth_bytes = extension::write_extension_fields(&[resp_auth.to_extension_field()])?;

    // Assemble complete response.
    let mut response = Vec::with_capacity(resp_aad.len() + auth_bytes.len());
    response.extend_from_slice(&resp_aad);
    response.extend_from_slice(&auth_bytes);

    Ok(response)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nts_common::AEAD_AES_SIV_CMAC_256;

    // ── Cookie roundtrip ──────────────────────────────────────────

    #[test]
    fn test_cookie_roundtrip_256() {
        let store = MasterKeyStore::new(Duration::from_secs(3600));
        let contents = CookieContents {
            aead_algorithm: AEAD_AES_SIV_CMAC_256,
            c2s_key: vec![0x42u8; 32],
            s2c_key: vec![0x43u8; 32],
        };
        let cookie = store.encrypt_cookie(&contents).unwrap();
        let decrypted = store.decrypt_cookie(&cookie).unwrap().unwrap();
        assert_eq!(decrypted.aead_algorithm, AEAD_AES_SIV_CMAC_256);
        assert_eq!(decrypted.c2s_key, vec![0x42u8; 32]);
        assert_eq!(decrypted.s2c_key, vec![0x43u8; 32]);
    }

    #[test]
    fn test_cookie_roundtrip_512() {
        let store = MasterKeyStore::new(Duration::from_secs(3600));
        let contents = CookieContents {
            aead_algorithm: AEAD_AES_SIV_CMAC_512,
            c2s_key: vec![0xAAu8; 64],
            s2c_key: vec![0xBBu8; 64],
        };
        let cookie = store.encrypt_cookie(&contents).unwrap();
        let decrypted = store.decrypt_cookie(&cookie).unwrap().unwrap();
        assert_eq!(decrypted.aead_algorithm, AEAD_AES_SIV_CMAC_512);
        assert_eq!(decrypted.c2s_key, vec![0xAAu8; 64]);
        assert_eq!(decrypted.s2c_key, vec![0xBBu8; 64]);
    }

    #[test]
    fn test_cookie_tampered() {
        let store = MasterKeyStore::new(Duration::from_secs(3600));
        let contents = CookieContents {
            aead_algorithm: AEAD_AES_SIV_CMAC_256,
            c2s_key: vec![0x42u8; 32],
            s2c_key: vec![0x43u8; 32],
        };
        let mut cookie = store.encrypt_cookie(&contents).unwrap();
        // Tamper with the ciphertext.
        if let Some(b) = cookie.last_mut() {
            *b ^= 0xFF;
        }
        let result = store.decrypt_cookie(&cookie).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cookie_too_short() {
        let store = MasterKeyStore::new(Duration::from_secs(3600));
        let result = store.decrypt_cookie(&[0u8; 10]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cookie_unknown_key_id() {
        let store = MasterKeyStore::new(Duration::from_secs(3600));
        let contents = CookieContents {
            aead_algorithm: AEAD_AES_SIV_CMAC_256,
            c2s_key: vec![0x42u8; 32],
            s2c_key: vec![0x43u8; 32],
        };
        let mut cookie = store.encrypt_cookie(&contents).unwrap();
        // Change key_id to something unknown.
        cookie[0] = 0xFF;
        cookie[1] = 0xFF;
        cookie[2] = 0xFF;
        cookie[3] = 0xFF;
        let result = store.decrypt_cookie(&cookie).unwrap();
        assert!(result.is_none());
    }

    // ── Key rotation ──────────────────────────────────────────────

    #[test]
    fn test_key_rotation_old_cookie_decrypts() {
        let mut store = MasterKeyStore::new(Duration::from_secs(3600));
        let contents = CookieContents {
            aead_algorithm: AEAD_AES_SIV_CMAC_256,
            c2s_key: vec![0x42u8; 32],
            s2c_key: vec![0x43u8; 32],
        };
        let cookie = store.encrypt_cookie(&contents).unwrap();

        // Rotate the key.
        store.rotate();

        // Old cookie should still decrypt.
        let decrypted = store.decrypt_cookie(&cookie).unwrap().unwrap();
        assert_eq!(decrypted.c2s_key, vec![0x42u8; 32]);
    }

    #[test]
    fn test_key_rotation_new_cookie_uses_new_key() {
        let mut store = MasterKeyStore::new(Duration::from_secs(3600));
        let old_key_id = store.current.key_id;

        store.rotate();

        let new_key_id = store.current.key_id;
        assert_ne!(old_key_id, new_key_id);

        let contents = CookieContents {
            aead_algorithm: AEAD_AES_SIV_CMAC_256,
            c2s_key: vec![0x42u8; 32],
            s2c_key: vec![0x43u8; 32],
        };
        let cookie = store.encrypt_cookie(&contents).unwrap();

        // The cookie should have the new key_id.
        let cookie_key_id = u32::from_be_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]);
        assert_eq!(cookie_key_id, new_key_id);
    }

    // ── Cookie size consistency ───────────────────────────────────

    #[test]
    fn test_cookie_size_consistent() {
        let mut store = MasterKeyStore::new(Duration::from_secs(3600));
        let contents = CookieContents {
            aead_algorithm: AEAD_AES_SIV_CMAC_256,
            c2s_key: vec![0x42u8; 32],
            s2c_key: vec![0x43u8; 32],
        };

        let cookie1 = store.encrypt_cookie(&contents).unwrap();
        store.rotate();
        let cookie2 = store.encrypt_cookie(&contents).unwrap();

        // Cookies should have the same size regardless of key rotation.
        assert_eq!(cookie1.len(), cookie2.len());
    }

    // ── NTS request/response roundtrip ────────────────────────────

    #[test]
    fn test_nts_request_response_roundtrip() {
        let store = MasterKeyStore::new(Duration::from_secs(3600));
        let c2s_key = vec![0x42u8; 32];
        let s2c_key = vec![0x43u8; 32];
        let aead_algorithm = AEAD_AES_SIV_CMAC_256;

        // Create a cookie as the NTS-KE server would.
        let contents = CookieContents {
            aead_algorithm,
            c2s_key: c2s_key.clone(),
            s2c_key: s2c_key.clone(),
        };
        let cookie = store.encrypt_cookie(&contents).unwrap();

        // Client builds an NTS request.
        let (request_buf, t1, uid_data) =
            nts_common::build_nts_request(&c2s_key, aead_algorithm, cookie).unwrap();

        // Server validates the NTS extensions.
        let ctx = process_nts_extensions(&request_buf, request_buf.len(), &store).unwrap();

        // Verify context.
        assert_eq!(ctx.uid_data, uid_data);
        assert_eq!(ctx.aead_algorithm, aead_algorithm);
        assert!(!ctx.new_cookies.is_empty());

        // Server builds the NTP response.
        let response_packet = protocol::Packet {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            version: protocol::Version::V4,
            mode: protocol::Mode::Server,
            stratum: protocol::Stratum(2),
            poll: 6,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: t1,
            receive_timestamp: protocol::TimestampFormat {
                seconds: t1.seconds,
                fraction: t1.fraction.wrapping_add(1000),
            },
            transmit_timestamp: protocol::TimestampFormat {
                seconds: t1.seconds,
                fraction: t1.fraction.wrapping_add(2000),
            },
        };

        let response_buf = build_nts_response(&response_packet, &ctx).unwrap();

        // Client validates the NTS response.
        let new_cookies = nts_common::validate_nts_response(
            &s2c_key,
            aead_algorithm,
            &uid_data,
            &response_buf,
            response_buf.len(),
        )
        .unwrap();

        assert!(!new_cookies.is_empty());

        // New cookies should be decryptable by the server.
        for nc in &new_cookies {
            let decrypted = store.decrypt_cookie(nc).unwrap().unwrap();
            assert_eq!(decrypted.aead_algorithm, aead_algorithm);
            assert_eq!(decrypted.c2s_key, c2s_key);
            assert_eq!(decrypted.s2c_key, s2c_key);
        }
    }

    #[test]
    fn test_nts_request_missing_extensions() {
        let store = MasterKeyStore::new(Duration::from_secs(3600));
        // Just a bare 48-byte header.
        let buf = [0u8; 48];
        let result = process_nts_extensions(&buf, 48, &store);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no extension fields")
        );
    }
}
