// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared NTS constants, types, and pure functions used by both client
//! and server NTS implementations.

// NOTE: The `fips-aead` feature flag is defined in Cargo.toml as a placeholder.
// It currently activates `nts` (the default AES-SIV-CMAC backend). When a FIPS
// 140-3 certified AES-SIV-CMAC implementation becomes available for Rust, this
// feature will switch to a validated backend. See docs/CRYPTO.md.

use std::io;

use aes_siv::aead::Aead;
use aes_siv::aead::KeyInit;
use aes_siv::{Aes128SivAead, Aes256SivAead};

use crate::extension::{
    self, ExtensionField, NtsAuthenticator, NtsCookie, NtsCookiePlaceholder, UNIQUE_IDENTIFIER,
    UniqueIdentifier,
};
use crate::protocol::{self, ConstPackedSizeBytes, WriteBytes};
use crate::unix_time;

/// NTS protocol-level errors for AEAD and response validation.
#[derive(Clone, Debug)]
pub enum NtsProtoError {
    /// The negotiated AEAD algorithm is not supported.
    UnsupportedAeadAlgorithm {
        /// The algorithm ID that was not recognized.
        algorithm: u16,
    },
    /// AEAD key initialization failed (wrong key length or format).
    AeadKeyInit,
    /// AEAD encryption failed.
    AeadEncryptFailed,
    /// AEAD decryption/authentication failed — response may be tampered.
    AeadDecryptFailed,
    /// A required NTS extension field is missing from the response.
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },
    /// NTS response validation failed.
    ValidationFailed {
        /// Description of what failed.
        detail: &'static str,
    },
}

impl core::fmt::Display for NtsProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NtsProtoError::UnsupportedAeadAlgorithm { algorithm } => {
                write!(f, "unsupported AEAD algorithm: {}", algorithm)
            }
            NtsProtoError::AeadKeyInit => write!(f, "AEAD key initialization failed"),
            NtsProtoError::AeadEncryptFailed => write!(f, "AEAD encryption failed"),
            NtsProtoError::AeadDecryptFailed => {
                write!(f, "AEAD authentication failed — response may be tampered")
            }
            NtsProtoError::MissingField { field } => {
                write!(f, "NTS response missing {}", field)
            }
            NtsProtoError::ValidationFailed { detail } => {
                write!(f, "NTS validation failed: {}", detail)
            }
        }
    }
}

impl std::error::Error for NtsProtoError {}

impl From<NtsProtoError> for io::Error {
    fn from(err: NtsProtoError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}

/// Trait abstracting NTS AEAD operations for future FIPS 140-3 backend swap.
///
/// The default implementation (`AesSivCmacAead`) uses the `aes-siv` RustCrypto
/// crate. When a FIPS 140-3 certified AES-SIV-CMAC implementation becomes
/// available for Rust, a second implementation can be provided behind the
/// `fips-aead` feature flag.
pub trait NtsAead: Send + Sync {
    /// Encrypt plaintext with associated data, returning `(nonce, ciphertext)`.
    fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)>;

    /// Decrypt ciphertext with associated data and nonce.
    fn decrypt(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>>;

    /// The IANA AEAD algorithm identifier (e.g., 15 for AES-SIV-CMAC-256).
    fn algorithm_id(&self) -> u16;

    /// The required key length in bytes.
    fn key_length(&self) -> usize;
}

/// Default AES-SIV-CMAC AEAD implementation using the `aes-siv` RustCrypto crate.
pub struct AesSivCmacAead {
    algorithm: u16,
    key: Vec<u8>,
}

impl AesSivCmacAead {
    /// Create a new instance for the given algorithm and key.
    ///
    /// Returns an error if the algorithm is unsupported or the key length is wrong.
    pub fn new(algorithm: u16, key: Vec<u8>) -> io::Result<Self> {
        let expected_len = aead_key_length(algorithm)?;
        if key.len() != expected_len {
            return Err(NtsProtoError::AeadKeyInit.into());
        }
        Ok(Self { algorithm, key })
    }
}

impl NtsAead for AesSivCmacAead {
    fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        aead_encrypt(self.algorithm, &self.key, aad, plaintext)
    }

    fn decrypt(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        aead_decrypt(self.algorithm, &self.key, aad, nonce, ciphertext)
    }

    fn algorithm_id(&self) -> u16 {
        self.algorithm
    }

    fn key_length(&self) -> usize {
        self.key.len()
    }
}

// NTS-KE record types (RFC 8915 Section 4).

/// End of Message NTS-KE record type.
pub const NTS_KE_END_OF_MESSAGE: u16 = 0;
/// NTS Next Protocol Negotiation record type.
pub const NTS_KE_NEXT_PROTOCOL: u16 = 1;
/// Error record type.
pub const NTS_KE_ERROR: u16 = 2;
/// Warning record type.
pub const NTS_KE_WARNING: u16 = 3;
/// AEAD Algorithm Negotiation record type.
pub const NTS_KE_AEAD_ALGORITHM: u16 = 4;
/// New Cookie for NTPv4 record type.
pub const NTS_KE_NEW_COOKIE: u16 = 5;
/// NTPv4 Server Negotiation record type.
pub const NTS_KE_SERVER: u16 = 6;
/// NTPv4 Port Negotiation record type.
pub const NTS_KE_PORT: u16 = 7;

/// NTPv4 protocol ID for NTS Next Protocol Negotiation.
pub const NTS_PROTOCOL_NTPV4: u16 = 0;

/// NTPv5 protocol ID for NTS Next Protocol Negotiation (provisional, 0x8001).
#[cfg(feature = "ntpv5")]
pub const NTS_PROTOCOL_NTPV5: u16 = 0x8001;

/// Default NTS-KE port (RFC 8915 Section 4).
pub const NTS_KE_DEFAULT_PORT: u16 = 4460;

/// AEAD_AES_SIV_CMAC_256 algorithm ID (RFC 8915 Section 5.1).
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;

/// AEAD_AES_SIV_CMAC_512 algorithm ID.
pub const AEAD_AES_SIV_CMAC_512: u16 = 17;

/// TLS exporter label for NTS (RFC 8915 Section 4.2).
pub const NTS_EXPORTER_LABEL: &str = "EXPORTER-network-time-security";

/// Number of cookie placeholders to include in NTS requests.
pub const COOKIE_PLACEHOLDER_COUNT: usize = 7;

/// Cookie count threshold below which re-keying should be attempted.
pub const COOKIE_REKEY_THRESHOLD: usize = 2;

/// Result of NTS Key Establishment.
#[derive(Clone, Debug)]
pub struct NtsKeResult {
    /// Client-to-server AEAD key.
    pub c2s_key: Vec<u8>,
    /// Server-to-client AEAD key.
    pub s2c_key: Vec<u8>,
    /// Cookies for NTP requests (each used exactly once).
    pub cookies: Vec<Vec<u8>>,
    /// Negotiated AEAD algorithm ID.
    pub aead_algorithm: u16,
    /// NTP server hostname (may differ from NTS-KE server).
    pub ntp_server: String,
    /// NTP server port (default 123).
    pub ntp_port: u16,
    /// Negotiated NTP protocol ID (0 = NTPv4, 0x8001 = NTPv5).
    pub next_protocol: u16,
}

/// NTS-KE record as read from the TLS stream.
pub struct NtsKeRecord {
    /// Whether this record has the critical bit set.
    pub critical: bool,
    /// The NTS-KE record type identifier.
    pub record_type: u16,
    /// The record body payload.
    pub body: Vec<u8>,
}

/// Write a single NTS-KE record to a buffer.
pub fn write_ke_record(buf: &mut Vec<u8>, critical: bool, record_type: u16, body: &[u8]) {
    let raw_type = if critical {
        record_type | 0x8000
    } else {
        record_type
    };
    buf.extend_from_slice(&raw_type.to_be_bytes());
    buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    buf.extend_from_slice(body);
}

/// Read a big-endian u16 from a byte slice of length >= 2.
pub fn read_be_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

/// Get the AEAD key length for the given algorithm.
pub fn aead_key_length(algorithm: u16) -> io::Result<usize> {
    match algorithm {
        AEAD_AES_SIV_CMAC_256 => Ok(32),
        AEAD_AES_SIV_CMAC_512 => Ok(64),
        _ => Err(NtsProtoError::UnsupportedAeadAlgorithm { algorithm }.into()),
    }
}

/// Build an NTS-authenticated NTP request packet.
///
/// Constructs the NTP header with extension fields (Unique Identifier, NTS Cookie,
/// cookie placeholders) and an AEAD authenticator.
///
/// Returns `(send_buf, t1, uid_data)` where:
/// - `send_buf` is the complete serialized packet ready to send
/// - `t1` is the origin timestamp
/// - `uid_data` is the Unique Identifier bytes for response validation
pub fn build_nts_request(
    c2s_key: &[u8],
    aead_algorithm: u16,
    cookie: Vec<u8>,
) -> io::Result<(Vec<u8>, protocol::TimestampFormat, Vec<u8>)> {
    let cookie_len = cookie.len();

    // Build the NTP header.
    let packet = protocol::Packet {
        leap_indicator: protocol::LeapIndicator::default(),
        version: protocol::Version::V4,
        mode: protocol::Mode::Client,
        stratum: protocol::Stratum::UNSPECIFIED,
        poll: 0,
        precision: 0,
        root_delay: protocol::ShortFormat::default(),
        root_dispersion: protocol::ShortFormat::default(),
        reference_id: protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Null),
        reference_timestamp: protocol::TimestampFormat::default(),
        origin_timestamp: protocol::TimestampFormat::default(),
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: unix_time::Instant::now().into(),
    };
    let t1 = packet.transmit_timestamp;

    let mut header_buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut header_buf[..]).write_bytes(packet)?;

    // Build extension fields (unencrypted).
    let mut uid_data = vec![0u8; 32];
    rand::fill(&mut uid_data[..]);
    let uid = UniqueIdentifier::new(uid_data.clone());
    let nts_cookie = NtsCookie::new(cookie);

    // Build extension fields before the authenticator (these are AAD).
    let mut pre_auth_fields = vec![uid.to_extension_field(), nts_cookie.to_extension_field()];

    // Add cookie placeholders so the server sends replacement cookies.
    for _ in 0..COOKIE_PLACEHOLDER_COUNT {
        let placeholder = NtsCookiePlaceholder::new(cookie_len);
        pre_auth_fields.push(placeholder.to_extension_field());
    }

    let pre_auth_bytes = extension::write_extension_fields(&pre_auth_fields)?;

    // Build AAD = NTP header + all extension fields before authenticator.
    let mut aad = Vec::with_capacity(header_buf.len() + pre_auth_bytes.len());
    aad.extend_from_slice(&header_buf);
    aad.extend_from_slice(&pre_auth_bytes);

    // AEAD encrypt (plaintext is empty for basic NTS client — no encrypted extensions).
    let (nonce, ciphertext) = aead_encrypt(aead_algorithm, c2s_key, &aad, &[])?;

    // Build the NTS Authenticator extension field.
    let authenticator = NtsAuthenticator::new(nonce, ciphertext);
    let auth_ef = authenticator.to_extension_field();
    let auth_bytes = extension::write_extension_fields(&[auth_ef])?;

    // Assemble the complete packet.
    let mut send_buf = Vec::with_capacity(aad.len() + auth_bytes.len());
    send_buf.extend_from_slice(&aad);
    send_buf.extend_from_slice(&auth_bytes);

    Ok((send_buf, t1, uid_data))
}

/// Validate NTS extension fields in an NTP response.
///
/// Verifies the Unique Identifier matches, authenticates the response via AEAD,
/// and extracts new cookies from the server.
///
/// Returns the list of new cookies provided by the server.
pub fn validate_nts_response(
    s2c_key: &[u8],
    aead_algorithm: u16,
    uid_data: &[u8],
    recv_buf: &[u8],
    recv_len: usize,
) -> io::Result<Vec<Vec<u8>>> {
    // Parse extension fields from the response.
    if recv_len <= protocol::Packet::PACKED_SIZE_BYTES {
        return Err(NtsProtoError::ValidationFailed {
            detail: "response has no extension fields",
        }
        .into());
    }
    let ext_data = &recv_buf[protocol::Packet::PACKED_SIZE_BYTES..recv_len];
    let ext_fields = extension::parse_extension_fields(ext_data)?;

    // Find the Unique Identifier and verify it matches.
    let resp_uid = ext_fields
        .iter()
        .find(|ef| ef.field_type == UNIQUE_IDENTIFIER)
        .ok_or(NtsProtoError::MissingField {
            field: "Unique Identifier",
        })?;
    if resp_uid.value != uid_data {
        return Err(NtsProtoError::ValidationFailed {
            detail: "Unique Identifier mismatch",
        }
        .into());
    }

    // Find the NTS Authenticator.
    let auth_ef = ext_fields
        .iter()
        .find(|ef| ef.field_type == extension::NTS_AUTHENTICATOR)
        .ok_or(NtsProtoError::MissingField {
            field: "NTS Authenticator",
        })?;
    let resp_auth = NtsAuthenticator::from_extension_field(auth_ef)?.ok_or(
        NtsProtoError::ValidationFailed {
            detail: "failed to parse NTS Authenticator",
        },
    )?;

    // Build AAD for response verification: NTP header + extension fields before authenticator.
    let auth_ef_start = find_authenticator_offset(ext_data, &ext_fields)?;
    let mut resp_aad = Vec::new();
    resp_aad.extend_from_slice(&recv_buf[..protocol::Packet::PACKED_SIZE_BYTES]);
    resp_aad.extend_from_slice(&ext_data[..auth_ef_start]);

    // AEAD decrypt/verify.
    let _plaintext = aead_decrypt(
        aead_algorithm,
        s2c_key,
        &resp_aad,
        &resp_auth.nonce,
        &resp_auth.ciphertext,
    )?;

    // Extract new cookies from the response.
    let mut new_cookies = Vec::new();
    for ef in &ext_fields {
        if let Some(cookie) = NtsCookie::from_extension_field(ef) {
            new_cookies.push(cookie.0);
        }
    }

    Ok(new_cookies)
}

/// Find the byte offset of the NTS Authenticator extension field within the
/// extension data (relative to the start of the extension data, not the packet).
pub fn find_authenticator_offset(
    ext_data: &[u8],
    ext_fields: &[ExtensionField],
) -> io::Result<usize> {
    let mut offset = 0usize;
    for ef in ext_fields {
        if ef.field_type == extension::NTS_AUTHENTICATOR {
            return Ok(offset);
        }
        let field_length = 4 + ef.value.len();
        let padded = (field_length + 3) & !3;
        offset += padded;
        if offset > ext_data.len() {
            break;
        }
    }
    Err(NtsProtoError::ValidationFailed {
        detail: "could not locate authenticator offset",
    }
    .into())
}

/// AEAD encrypt using the negotiated algorithm.
///
/// Returns `(nonce, ciphertext)`.
pub fn aead_encrypt(
    algorithm: u16,
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    match algorithm {
        AEAD_AES_SIV_CMAC_256 => {
            let cipher =
                Aes128SivAead::new_from_slice(key).map_err(|_| NtsProtoError::AeadKeyInit)?;
            let mut nonce_bytes = [0u8; 16];
            rand::fill(&mut nonce_bytes);

            let payload = aes_siv::aead::Payload {
                msg: plaintext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher
                .encrypt(nonce, payload)
                .map_err(|_| NtsProtoError::AeadEncryptFailed)?;

            Ok((nonce_bytes.to_vec(), ciphertext))
        }
        AEAD_AES_SIV_CMAC_512 => {
            let cipher =
                Aes256SivAead::new_from_slice(key).map_err(|_| NtsProtoError::AeadKeyInit)?;
            let mut nonce_bytes = [0u8; 16];
            rand::fill(&mut nonce_bytes);

            let payload = aes_siv::aead::Payload {
                msg: plaintext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher
                .encrypt(nonce, payload)
                .map_err(|_| NtsProtoError::AeadEncryptFailed)?;

            Ok((nonce_bytes.to_vec(), ciphertext))
        }
        _ => Err(NtsProtoError::UnsupportedAeadAlgorithm { algorithm }.into()),
    }
}

/// AEAD decrypt using the negotiated algorithm.
pub fn aead_decrypt(
    algorithm: u16,
    key: &[u8],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    match algorithm {
        AEAD_AES_SIV_CMAC_256 => {
            let cipher =
                Aes128SivAead::new_from_slice(key).map_err(|_| NtsProtoError::AeadKeyInit)?;
            let payload = aes_siv::aead::Payload {
                msg: ciphertext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(nonce);
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| NtsProtoError::AeadDecryptFailed.into())
        }
        AEAD_AES_SIV_CMAC_512 => {
            let cipher =
                Aes256SivAead::new_from_slice(key).map_err(|_| NtsProtoError::AeadKeyInit)?;
            let payload = aes_siv::aead::Payload {
                msg: ciphertext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(nonce);
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| NtsProtoError::AeadDecryptFailed.into())
        }
        _ => Err(NtsProtoError::UnsupportedAeadAlgorithm { algorithm }.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_key_length() {
        assert_eq!(aead_key_length(AEAD_AES_SIV_CMAC_256).unwrap(), 32);
        assert_eq!(aead_key_length(AEAD_AES_SIV_CMAC_512).unwrap(), 64);
        assert!(aead_key_length(99).is_err());
    }

    #[test]
    fn test_aead_roundtrip_256() {
        let key = vec![0x42u8; 32];
        let aad = b"test associated data";
        let plaintext = b"hello NTS";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, plaintext).unwrap();
        let decrypted =
            aead_decrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_roundtrip_512() {
        let key = vec![0x42u8; 64];
        let aad = b"test associated data";
        let plaintext = b"hello NTS 512";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_512, &key, aad, plaintext).unwrap();
        let decrypted =
            aead_decrypt(AEAD_AES_SIV_CMAC_512, &key, aad, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_tampered_ciphertext() {
        let key = vec![0x42u8; 32];
        let aad = b"test aad";
        let plaintext = b"secret";

        let (nonce, mut ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, plaintext).unwrap();
        // Tamper with the ciphertext.
        if let Some(b) = ciphertext.first_mut() {
            *b ^= 0xFF;
        }
        let result = aead_decrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_wrong_aad() {
        let key = vec![0x42u8; 32];
        let aad = b"correct aad";
        let plaintext = b"secret";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, plaintext).unwrap();
        let result = aead_decrypt(
            AEAD_AES_SIV_CMAC_256,
            &key,
            b"wrong aad",
            &nonce,
            &ciphertext,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_write_ke_record() {
        let mut buf = Vec::new();
        write_ke_record(&mut buf, true, NTS_KE_NEXT_PROTOCOL, &[0x00, 0x00]);
        // Critical bit set: 0x8001, body length 2.
        assert_eq!(buf, [0x80, 0x01, 0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_write_ke_record_non_critical() {
        let mut buf = Vec::new();
        write_ke_record(&mut buf, false, NTS_KE_AEAD_ALGORITHM, &[0x00, 0x0F]);
        // No critical bit: 0x0004, body length 2.
        assert_eq!(buf, [0x00, 0x04, 0x00, 0x02, 0x00, 0x0F]);
    }

    #[test]
    fn test_find_authenticator_offset() {
        let fields = vec![
            ExtensionField {
                field_type: UNIQUE_IDENTIFIER,
                value: vec![0u8; 32],
            },
            ExtensionField {
                field_type: extension::NTS_COOKIE,
                value: vec![0u8; 100],
            },
            ExtensionField {
                field_type: extension::NTS_AUTHENTICATOR,
                value: vec![0u8; 48],
            },
        ];
        let ext_data = extension::write_extension_fields(&fields).unwrap();
        let offset = find_authenticator_offset(&ext_data, &fields).unwrap();
        // First field: 4 + 32 = 36 bytes. Second field: 4 + 100 = 104 bytes.
        assert_eq!(offset, 36 + 104);
    }

    #[test]
    fn test_aead_empty_plaintext() {
        let key = vec![0x42u8; 32];
        let aad = b"NTP header + extension fields";

        let (nonce, ciphertext) = aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &[]).unwrap();
        let decrypted =
            aead_decrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &nonce, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aead_unsupported_algorithm() {
        let key = vec![0u8; 32];
        assert!(aead_encrypt(99, &key, b"aad", b"msg").is_err());
        assert!(aead_decrypt(99, &key, b"aad", &[0; 16], b"ct").is_err());
    }

    #[test]
    fn test_build_nts_request_structure() {
        use crate::protocol::ReadBytes;

        let key = vec![0x42u8; 32];
        let cookie = vec![0xABu8; 100];
        let (send_buf, t1, uid_data) =
            build_nts_request(&key, AEAD_AES_SIV_CMAC_256, cookie.clone()).unwrap();

        // Packet should be at least 48 bytes (header).
        assert!(send_buf.len() > protocol::Packet::PACKED_SIZE_BYTES);

        // Parse the header and verify structure.
        let pkt: protocol::Packet = (&send_buf[..protocol::Packet::PACKED_SIZE_BYTES])
            .read_bytes()
            .unwrap();
        assert_eq!(pkt.version, protocol::Version::V4);
        assert_eq!(pkt.mode, protocol::Mode::Client);
        assert_eq!(pkt.transmit_timestamp, t1);
        assert!(t1.seconds != 0 || t1.fraction != 0);

        // UID should be 32 bytes.
        assert_eq!(uid_data.len(), 32);

        // Parse extension fields and verify expected types.
        let ext_data = &send_buf[protocol::Packet::PACKED_SIZE_BYTES..];
        let fields = extension::parse_extension_fields(ext_data).unwrap();

        // Should contain: UID, Cookie, 7 placeholders, Authenticator.
        let uid_count = fields
            .iter()
            .filter(|f| f.field_type == UNIQUE_IDENTIFIER)
            .count();
        let cookie_count = fields
            .iter()
            .filter(|f| f.field_type == extension::NTS_COOKIE)
            .count();
        let placeholder_count = fields
            .iter()
            .filter(|f| f.field_type == extension::NTS_COOKIE_PLACEHOLDER)
            .count();
        let auth_count = fields
            .iter()
            .filter(|f| f.field_type == extension::NTS_AUTHENTICATOR)
            .count();

        assert_eq!(uid_count, 1);
        assert_eq!(cookie_count, 1);
        assert_eq!(placeholder_count, COOKIE_PLACEHOLDER_COUNT);
        assert_eq!(auth_count, 1);
    }

    #[test]
    fn test_validate_nts_response_roundtrip() {
        // Build a request, then construct a matching response and validate it.
        let c2s_key = vec![0x42u8; 32];
        let s2c_key = vec![0x43u8; 32];
        let cookie = vec![0xABu8; 100];
        let (_send_buf, t1, uid_data) =
            build_nts_request(&c2s_key, AEAD_AES_SIV_CMAC_256, cookie).unwrap();

        // Build a fake server response.
        let response_pkt = protocol::Packet {
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
        let mut resp_header = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
        (&mut resp_header[..]).write_bytes(response_pkt).unwrap();

        // Build response extension fields: UID + Cookie + Authenticator.
        let uid = UniqueIdentifier::new(uid_data.clone());
        let new_cookie_data = vec![0xCDu8; 100];
        let resp_cookie = NtsCookie::new(new_cookie_data.clone());
        let pre_auth_fields = vec![uid.to_extension_field(), resp_cookie.to_extension_field()];
        let pre_auth_bytes = extension::write_extension_fields(&pre_auth_fields).unwrap();

        // Build AAD = header + pre-auth fields.
        let mut resp_aad = Vec::new();
        resp_aad.extend_from_slice(&resp_header);
        resp_aad.extend_from_slice(&pre_auth_bytes);

        // Encrypt with s2c_key (empty plaintext).
        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &s2c_key, &resp_aad, &[]).unwrap();

        // Build authenticator extension field.
        let auth = NtsAuthenticator::new(nonce, ciphertext);
        let auth_bytes = extension::write_extension_fields(&[auth.to_extension_field()]).unwrap();

        // Assemble full response.
        let mut recv_buf = vec![0u8; 2048];
        let mut pos = 0;
        recv_buf[pos..pos + resp_header.len()].copy_from_slice(&resp_header);
        pos += resp_header.len();
        recv_buf[pos..pos + pre_auth_bytes.len()].copy_from_slice(&pre_auth_bytes);
        pos += pre_auth_bytes.len();
        recv_buf[pos..pos + auth_bytes.len()].copy_from_slice(&auth_bytes);
        pos += auth_bytes.len();
        let recv_len = pos;

        // Validate!
        let new_cookies = validate_nts_response(
            &s2c_key,
            AEAD_AES_SIV_CMAC_256,
            &uid_data,
            &recv_buf,
            recv_len,
        )
        .unwrap();

        assert_eq!(new_cookies.len(), 1);
        assert_eq!(new_cookies[0], new_cookie_data);
    }

    #[test]
    fn test_validate_nts_response_uid_mismatch() {
        let c2s_key = vec![0x42u8; 32];
        let s2c_key = vec![0x43u8; 32];
        let cookie = vec![0xABu8; 100];
        let (_, t1, _uid_data) =
            build_nts_request(&c2s_key, AEAD_AES_SIV_CMAC_256, cookie).unwrap();

        // Build response with a different UID.
        let wrong_uid = vec![0xFFu8; 32];
        let uid = UniqueIdentifier::new(wrong_uid);
        let pre_auth_fields = vec![uid.to_extension_field()];
        let pre_auth_bytes = extension::write_extension_fields(&pre_auth_fields).unwrap();

        let response_pkt = protocol::Packet {
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
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 1,
                fraction: 0,
            },
        };
        let mut resp_header = [0u8; 48];
        (&mut resp_header[..]).write_bytes(response_pkt).unwrap();

        let mut resp_aad = Vec::new();
        resp_aad.extend_from_slice(&resp_header);
        resp_aad.extend_from_slice(&pre_auth_bytes);

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &s2c_key, &resp_aad, &[]).unwrap();
        let auth = NtsAuthenticator::new(nonce, ciphertext);
        let auth_bytes = extension::write_extension_fields(&[auth.to_extension_field()]).unwrap();

        let mut recv_buf = vec![0u8; 2048];
        let mut pos = 0;
        recv_buf[..48].copy_from_slice(&resp_header);
        pos += 48;
        recv_buf[pos..pos + pre_auth_bytes.len()].copy_from_slice(&pre_auth_bytes);
        pos += pre_auth_bytes.len();
        recv_buf[pos..pos + auth_bytes.len()].copy_from_slice(&auth_bytes);
        pos += auth_bytes.len();

        let original_uid = vec![0x00u8; 32]; // doesn't match 0xFF
        let result = validate_nts_response(
            &s2c_key,
            AEAD_AES_SIV_CMAC_256,
            &original_uid,
            &recv_buf,
            pos,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unique Identifier mismatch")
        );
    }

    #[test]
    fn test_validate_nts_response_no_extensions() {
        let key = vec![0x42u8; 32];
        let uid = vec![0u8; 32];
        // Buffer with only a 48-byte header, no extensions.
        let buf = [0u8; 48];
        let result = validate_nts_response(&key, AEAD_AES_SIV_CMAC_256, &uid, &buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no extension fields")
        );
    }

    #[test]
    fn test_validate_nts_response_multiple_cookies() {
        // Server returns 3 cookies in a single response.
        let c2s_key = vec![0x42u8; 32];
        let s2c_key = vec![0x43u8; 32];
        let cookie = vec![0xABu8; 100];
        let (_, t1, uid_data) = build_nts_request(&c2s_key, AEAD_AES_SIV_CMAC_256, cookie).unwrap();

        let response_pkt = protocol::Packet {
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
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: t1.seconds,
                fraction: t1.fraction.wrapping_add(1000),
            },
        };
        let mut resp_header = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
        (&mut resp_header[..]).write_bytes(response_pkt).unwrap();

        let uid = UniqueIdentifier::new(uid_data.clone());
        let cookie1 = NtsCookie::new(vec![0xC1u8; 80]);
        let cookie2 = NtsCookie::new(vec![0xC2u8; 80]);
        let cookie3 = NtsCookie::new(vec![0xC3u8; 80]);
        let pre_auth_fields = vec![
            uid.to_extension_field(),
            cookie1.to_extension_field(),
            cookie2.to_extension_field(),
            cookie3.to_extension_field(),
        ];
        let pre_auth_bytes = extension::write_extension_fields(&pre_auth_fields).unwrap();

        let mut resp_aad = Vec::new();
        resp_aad.extend_from_slice(&resp_header);
        resp_aad.extend_from_slice(&pre_auth_bytes);

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &s2c_key, &resp_aad, &[]).unwrap();
        let auth = NtsAuthenticator::new(nonce, ciphertext);
        let auth_bytes = extension::write_extension_fields(&[auth.to_extension_field()]).unwrap();

        let mut recv_buf = vec![0u8; 2048];
        let mut pos = 0;
        recv_buf[..resp_header.len()].copy_from_slice(&resp_header);
        pos += resp_header.len();
        recv_buf[pos..pos + pre_auth_bytes.len()].copy_from_slice(&pre_auth_bytes);
        pos += pre_auth_bytes.len();
        recv_buf[pos..pos + auth_bytes.len()].copy_from_slice(&auth_bytes);
        pos += auth_bytes.len();

        let new_cookies =
            validate_nts_response(&s2c_key, AEAD_AES_SIV_CMAC_256, &uid_data, &recv_buf, pos)
                .unwrap();

        assert_eq!(new_cookies.len(), 3);
        assert_eq!(new_cookies[0], vec![0xC1u8; 80]);
        assert_eq!(new_cookies[1], vec![0xC2u8; 80]);
        assert_eq!(new_cookies[2], vec![0xC3u8; 80]);
    }

    #[test]
    fn test_write_ke_record_empty_body() {
        let mut buf = Vec::new();
        write_ke_record(&mut buf, true, NTS_KE_END_OF_MESSAGE, &[]);
        assert_eq!(buf, [0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_read_be_u16() {
        assert_eq!(read_be_u16(&[0x00, 0x00]), 0);
        assert_eq!(read_be_u16(&[0xFF, 0xFF]), 0xFFFF);
        assert_eq!(read_be_u16(&[0x12, 0x34]), 0x1234);
    }

    #[test]
    fn test_ke_constants_match_rfc8915() {
        assert_eq!(NTS_KE_END_OF_MESSAGE, 0);
        assert_eq!(NTS_KE_NEXT_PROTOCOL, 1);
        assert_eq!(NTS_KE_ERROR, 2);
        assert_eq!(NTS_KE_WARNING, 3);
        assert_eq!(NTS_KE_AEAD_ALGORITHM, 4);
        assert_eq!(NTS_KE_NEW_COOKIE, 5);
        assert_eq!(NTS_KE_SERVER, 6);
        assert_eq!(NTS_KE_PORT, 7);
        assert_eq!(NTS_KE_DEFAULT_PORT, 4460);
        assert_eq!(NTS_PROTOCOL_NTPV4, 0);
        assert_eq!(AEAD_AES_SIV_CMAC_256, 15);
        assert_eq!(AEAD_AES_SIV_CMAC_512, 17);
    }

    #[test]
    fn test_aead_wrong_key() {
        let key = vec![0x42u8; 32];
        let wrong_key = vec![0x99u8; 32];
        let aad = b"test aad";
        let plaintext = b"secret";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, plaintext).unwrap();
        let result = aead_decrypt(AEAD_AES_SIV_CMAC_256, &wrong_key, aad, &nonce, &ciphertext);
        assert!(result.is_err());
    }
}
