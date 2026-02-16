// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP extension field parsing and NTS (Network Time Security) extension types.
//!
//! Extension fields follow the NTPv4 extension field format defined in RFC 7822,
//! appended after the 48-byte NTP packet header. NTS (RFC 8915) defines specific
//! extension field types for authenticated NTP.
//!
//! # Extension Field Format (RFC 7822)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Field Type           |        Field Length           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! .                                                               .
//! .                       Field Value (variable)                  .
//! .                                                               .
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use byteorder::{BE, ReadBytesExt, WriteBytesExt};
use std::io;

/// Minimum extension field length per RFC 7822.
pub const MIN_EXTENSION_FIELD_LENGTH: u16 = 16;

// NTS extension field type codes (RFC 8915 Section 5.7).

/// Unique Identifier extension field type.
pub const UNIQUE_IDENTIFIER: u16 = 0x0104;

/// NTS Cookie extension field type.
pub const NTS_COOKIE: u16 = 0x0204;

/// NTS Cookie Placeholder extension field type.
pub const NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;

/// NTS Authenticator and Encrypted Extensions extension field type.
pub const NTS_AUTHENTICATOR: u16 = 0x0404;

/// A generic NTP extension field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionField {
    /// The extension field type code.
    pub field_type: u16,
    /// The extension field value (variable length, excluding the 4-byte header).
    pub value: Vec<u8>,
}

/// Parse extension fields from data following the 48-byte NTP header.
///
/// Returns a vector of parsed extension fields. Stops when the remaining
/// data is too short for another extension field header.
pub fn parse_extension_fields(data: &[u8]) -> io::Result<Vec<ExtensionField>> {
    let mut fields = Vec::new();
    let mut cursor = io::Cursor::new(data);
    let data_len = data.len() as u64;

    while cursor.position() + 4 <= data_len {
        let field_type = cursor.read_u16::<BE>()?;
        let field_length = cursor.read_u16::<BE>()?;

        // Field length includes the 4-byte header.
        if field_length < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extension field length less than 4",
            ));
        }

        let value_length = (field_length - 4) as usize;
        let pos = cursor.position() as usize;

        if pos + value_length > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extension field value extends beyond packet",
            ));
        }

        let value = data[pos..pos + value_length].to_vec();
        cursor.set_position((pos + value_length) as u64);

        // Skip padding to 4-byte boundary.
        let padded = (field_length as usize + 3) & !3;
        let pad_bytes = padded - field_length as usize;
        let new_pos = cursor.position() as usize + pad_bytes;
        if new_pos <= data.len() {
            cursor.set_position(new_pos as u64);
        }

        fields.push(ExtensionField { field_type, value });
    }

    Ok(fields)
}

/// Serialize extension fields to a byte vector.
///
/// Each field is padded to a 4-byte boundary with zero bytes.
pub fn write_extension_fields(fields: &[ExtensionField]) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();

    for field in fields {
        let field_length = 4 + field.value.len() as u16;
        buf.write_u16::<BE>(field.field_type)?;
        buf.write_u16::<BE>(field_length)?;
        buf.extend_from_slice(&field.value);

        // Pad to 4-byte boundary.
        let padded = ((field_length as usize) + 3) & !3;
        let pad_bytes = padded - field_length as usize;
        buf.extend(std::iter::repeat_n(0u8, pad_bytes));
    }

    Ok(buf)
}

/// NTS Unique Identifier extension field (RFC 8915 Section 5.3).
///
/// Contains random data for replay protection at the NTS level.
/// The client generates this value and the server echoes it back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniqueIdentifier(pub Vec<u8>);

impl UniqueIdentifier {
    /// Create a Unique Identifier from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        UniqueIdentifier(data)
    }

    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: UNIQUE_IDENTIFIER,
            value: self.0.clone(),
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type == UNIQUE_IDENTIFIER {
            Some(UniqueIdentifier(ef.value.clone()))
        } else {
            None
        }
    }
}

/// NTS Cookie extension field (RFC 8915 Section 5.4).
///
/// Contains an opaque cookie provided by the NTS-KE server.
/// Each cookie is used exactly once per NTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtsCookie(pub Vec<u8>);

impl NtsCookie {
    /// Create an NTS Cookie from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        NtsCookie(data)
    }

    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: NTS_COOKIE,
            value: self.0.clone(),
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type == NTS_COOKIE {
            Some(NtsCookie(ef.value.clone()))
        } else {
            None
        }
    }
}

/// NTS Cookie Placeholder extension field (RFC 8915 Section 5.5).
///
/// Signals to the server that the client wants to receive additional cookies.
/// The placeholder size should match the expected cookie size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtsCookiePlaceholder {
    /// Size of the placeholder body in bytes.
    pub size: usize,
}

impl NtsCookiePlaceholder {
    /// Create a cookie placeholder of the given size.
    pub fn new(size: usize) -> Self {
        NtsCookiePlaceholder { size }
    }

    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: NTS_COOKIE_PLACEHOLDER,
            value: vec![0u8; self.size],
        }
    }
}

/// NTS Authenticator and Encrypted Extensions extension field (RFC 8915 Section 5.6).
///
/// Contains the AEAD nonce and ciphertext. The ciphertext includes any
/// encrypted extension fields plus the AEAD authentication tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtsAuthenticator {
    /// The AEAD nonce.
    pub nonce: Vec<u8>,
    /// The AEAD ciphertext (encrypted extensions + authentication tag).
    pub ciphertext: Vec<u8>,
}

impl NtsAuthenticator {
    /// Create an NTS Authenticator.
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        NtsAuthenticator { nonce, ciphertext }
    }

    /// Convert to a generic extension field.
    ///
    /// The value format is: nonce_length (u16) + nonce + ciphertext_length (u16) + ciphertext.
    pub fn to_extension_field(&self) -> ExtensionField {
        let mut value = Vec::new();
        // Nonce length (u16 BE) + nonce.
        let _ = value.write_u16::<BE>(self.nonce.len() as u16);
        value.extend_from_slice(&self.nonce);
        // Pad nonce to 4-byte boundary.
        let nonce_padded = (2 + self.nonce.len() + 3) & !3;
        let nonce_pad = nonce_padded - (2 + self.nonce.len());
        value.extend(std::iter::repeat_n(0u8, nonce_pad));
        // Ciphertext length (u16 BE) + ciphertext.
        let _ = value.write_u16::<BE>(self.ciphertext.len() as u16);
        value.extend_from_slice(&self.ciphertext);

        ExtensionField {
            field_type: NTS_AUTHENTICATOR,
            value,
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> io::Result<Option<Self>> {
        if ef.field_type != NTS_AUTHENTICATOR {
            return Ok(None);
        }

        let mut cursor = io::Cursor::new(&ef.value);
        let nonce_len = cursor.read_u16::<BE>()? as usize;

        let pos = cursor.position() as usize;
        if pos + nonce_len > ef.value.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS authenticator nonce extends beyond field",
            ));
        }
        let nonce = ef.value[pos..pos + nonce_len].to_vec();

        // Skip to padded boundary.
        let nonce_padded = (2 + nonce_len + 3) & !3;
        let ct_offset = nonce_padded;
        if ct_offset + 2 > ef.value.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS authenticator missing ciphertext length",
            ));
        }

        cursor.set_position(ct_offset as u64);
        let ct_len = cursor.read_u16::<BE>()? as usize;
        let ct_start = cursor.position() as usize;

        if ct_start + ct_len > ef.value.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS authenticator ciphertext extends beyond field",
            ));
        }
        let ciphertext = ef.value[ct_start..ct_start + ct_len].to_vec();

        Ok(Some(NtsAuthenticator { nonce, ciphertext }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let fields = parse_extension_fields(&[]).unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn test_roundtrip_single_field() {
        let field = ExtensionField {
            field_type: UNIQUE_IDENTIFIER,
            value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };
        let buf = write_extension_fields(std::slice::from_ref(&field)).unwrap();
        let parsed = parse_extension_fields(&buf).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], field);
    }

    #[test]
    fn test_roundtrip_multiple_fields() {
        let fields = vec![
            ExtensionField {
                field_type: UNIQUE_IDENTIFIER,
                value: vec![0xAA; 32],
            },
            ExtensionField {
                field_type: NTS_COOKIE,
                value: vec![0xBB; 64],
            },
        ];
        let buf = write_extension_fields(&fields).unwrap();
        let parsed = parse_extension_fields(&buf).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], fields[0]);
        assert_eq!(parsed[1], fields[1]);
    }

    #[test]
    fn test_padding() {
        // Value of 5 bytes: 4 header + 5 value = 9 bytes, padded to 12.
        let field = ExtensionField {
            field_type: 0x1234,
            value: vec![1, 2, 3, 4, 5],
        };
        let buf = write_extension_fields(&[field]).unwrap();
        assert_eq!(buf.len(), 12); // 4 header + 5 value + 3 padding
    }

    #[test]
    fn test_unique_identifier_conversion() {
        let uid = UniqueIdentifier::new(vec![0x42; 32]);
        let ef = uid.to_extension_field();
        assert_eq!(ef.field_type, UNIQUE_IDENTIFIER);
        let back = UniqueIdentifier::from_extension_field(&ef).unwrap();
        assert_eq!(back.0, vec![0x42; 32]);
    }

    #[test]
    fn test_nts_cookie_conversion() {
        let cookie = NtsCookie::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let ef = cookie.to_extension_field();
        assert_eq!(ef.field_type, NTS_COOKIE);
        let back = NtsCookie::from_extension_field(&ef).unwrap();
        assert_eq!(back.0, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_nts_authenticator_roundtrip() {
        let auth = NtsAuthenticator::new(vec![0x11; 16], vec![0x22; 48]);
        let ef = auth.to_extension_field();
        assert_eq!(ef.field_type, NTS_AUTHENTICATOR);
        let back = NtsAuthenticator::from_extension_field(&ef)
            .unwrap()
            .unwrap();
        assert_eq!(back.nonce, vec![0x11; 16]);
        assert_eq!(back.ciphertext, vec![0x22; 48]);
    }

    #[test]
    fn test_cookie_placeholder() {
        let placeholder = NtsCookiePlaceholder::new(100);
        let ef = placeholder.to_extension_field();
        assert_eq!(ef.field_type, NTS_COOKIE_PLACEHOLDER);
        assert_eq!(ef.value.len(), 100);
        assert!(ef.value.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_parse_truncated_field() {
        // Only 3 bytes: not enough for the 4-byte header.
        let data = [0x01, 0x04, 0x00];
        let fields = parse_extension_fields(&data).unwrap();
        assert!(fields.is_empty()); // Silently stops, not enough for header
    }

    #[test]
    fn test_parse_invalid_length() {
        // field_length=2 (less than 4).
        let data = [0x01, 0x04, 0x00, 0x02];
        let result = parse_extension_fields(&data);
        assert!(result.is_err());
    }
}
