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

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::io;

use crate::error::ParseError;

/// A borrowed view of an extension field (no allocation).
///
/// This type references data within the original byte buffer, avoiding
/// the heap allocation required by [`ExtensionField`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionFieldRef<'a> {
    /// The extension field type code.
    pub field_type: u16,
    /// The extension field value (variable length, excluding the 4-byte header).
    pub value: &'a [u8],
}

/// Iterator over extension fields in a byte buffer.
///
/// Yields [`ExtensionFieldRef`] values without heap allocation.
/// Created by [`iter_extension_fields`].
pub struct ExtensionFieldIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for ExtensionFieldIter<'a> {
    type Item = Result<ExtensionFieldRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = &self.data[self.offset..];
        if remaining.len() < 4 {
            return None;
        }

        let field_type = u16::from_be_bytes([remaining[0], remaining[1]]);
        let field_length = u16::from_be_bytes([remaining[2], remaining[3]]);

        if field_length < 4 {
            return Some(Err(ParseError::InvalidExtensionLength {
                declared: field_length,
            }));
        }

        let value_length = (field_length - 4) as usize;
        let value_start = self.offset + 4;

        if value_start + value_length > self.data.len() {
            return Some(Err(ParseError::ExtensionOverflow));
        }

        let value = &self.data[value_start..value_start + value_length];

        // Advance past value and padding to 4-byte boundary.
        let padded = (field_length as usize + 3) & !3;
        let next_offset = self.offset + padded;
        self.offset = next_offset.min(self.data.len());

        Some(Ok(ExtensionFieldRef { field_type, value }))
    }
}

/// Create an iterator over extension fields without allocating.
///
/// This is the zero-allocation alternative to [`parse_extension_fields`].
/// Each item yields a borrowed view of the extension field data.
pub fn iter_extension_fields(data: &[u8]) -> ExtensionFieldIter<'_> {
    ExtensionFieldIter { data, offset: 0 }
}

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
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionField {
    /// The extension field type code.
    pub field_type: u16,
    /// The extension field value (variable length, excluding the 4-byte header).
    pub value: Vec<u8>,
}

/// Parse extension fields from a byte buffer without using `std::io`.
///
/// Returns a vector of parsed extension fields. Stops when the remaining
/// data is too short for another extension field header.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn parse_extension_fields_buf(data: &[u8]) -> Result<Vec<ExtensionField>, ParseError> {
    iter_extension_fields(data)
        .map(|r| {
            r.map(|ef_ref| ExtensionField {
                field_type: ef_ref.field_type,
                value: ef_ref.value.to_vec(),
            })
        })
        .collect()
}

/// Serialize extension fields into a byte buffer without using `std::io`.
///
/// Each field is padded to a 4-byte boundary with zero bytes.
/// Returns the number of bytes written.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn write_extension_fields_buf(
    fields: &[ExtensionField],
    buf: &mut [u8],
) -> Result<usize, ParseError> {
    let mut offset = 0;

    for field in fields {
        let field_length = 4 + field.value.len();
        let padded = (field_length + 3) & !3;

        if offset + padded > buf.len() {
            return Err(ParseError::BufferTooShort {
                needed: offset + padded,
                available: buf.len(),
            });
        }

        let fl = field_length as u16;
        buf[offset..offset + 2].copy_from_slice(&field.field_type.to_be_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&fl.to_be_bytes());
        buf[offset + 4..offset + 4 + field.value.len()].copy_from_slice(&field.value);

        // Zero-fill padding.
        for b in &mut buf[offset + field_length..offset + padded] {
            *b = 0;
        }

        offset += padded;
    }

    Ok(offset)
}

/// Parse extension fields from data following the 48-byte NTP header.
///
/// Returns a vector of parsed extension fields. Stops when the remaining
/// data is too short for another extension field header.
#[cfg(feature = "std")]
pub fn parse_extension_fields(data: &[u8]) -> io::Result<Vec<ExtensionField>> {
    parse_extension_fields_buf(data).map_err(io::Error::from)
}

/// Serialize extension fields to a byte vector.
///
/// Each field is padded to a 4-byte boundary with zero bytes.
#[cfg(feature = "std")]
pub fn write_extension_fields(fields: &[ExtensionField]) -> io::Result<Vec<u8>> {
    // Calculate total size needed.
    let total: usize = fields.iter().map(|f| ((4 + f.value.len()) + 3) & !3).sum();
    let mut buf = vec![0u8; total];
    write_extension_fields_buf(fields, &mut buf)?;
    Ok(buf)
}

/// NTS Unique Identifier extension field (RFC 8915 Section 5.3).
///
/// Contains random data for replay protection at the NTS level.
/// The client generates this value and the server echoes it back.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniqueIdentifier(pub Vec<u8>);

#[cfg(any(feature = "alloc", feature = "std"))]
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
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtsCookie(pub Vec<u8>);

#[cfg(any(feature = "alloc", feature = "std"))]
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
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtsCookiePlaceholder {
    /// Size of the placeholder body in bytes.
    pub size: usize,
}

#[cfg(any(feature = "alloc", feature = "std"))]
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
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtsAuthenticator {
    /// The AEAD nonce.
    pub nonce: Vec<u8>,
    /// The AEAD ciphertext (encrypted extensions + authentication tag).
    pub ciphertext: Vec<u8>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
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
        value.extend_from_slice(&(self.nonce.len() as u16).to_be_bytes());
        value.extend_from_slice(&self.nonce);
        // Pad nonce to 4-byte boundary.
        let nonce_padded = (2 + self.nonce.len() + 3) & !3;
        let nonce_pad = nonce_padded - (2 + self.nonce.len());
        value.extend(core::iter::repeat_n(0u8, nonce_pad));
        // Ciphertext length (u16 BE) + ciphertext.
        value.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        value.extend_from_slice(&self.ciphertext);

        ExtensionField {
            field_type: NTS_AUTHENTICATOR,
            value,
        }
    }

    /// Try to extract from a generic extension field.
    #[cfg(feature = "std")]
    pub fn from_extension_field(ef: &ExtensionField) -> io::Result<Option<Self>> {
        Self::from_extension_field_buf(ef).map_err(io::Error::from)
    }

    /// Try to extract from a generic extension field without using `std::io`.
    pub fn from_extension_field_buf(ef: &ExtensionField) -> Result<Option<Self>, ParseError> {
        if ef.field_type != NTS_AUTHENTICATOR {
            return Ok(None);
        }

        let data = &ef.value;
        if data.len() < 2 {
            return Err(ParseError::BufferTooShort {
                needed: 2,
                available: data.len(),
            });
        }

        let nonce_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let nonce_start = 2;

        if nonce_start + nonce_len > data.len() {
            return Err(ParseError::ExtensionOverflow);
        }
        let nonce = data[nonce_start..nonce_start + nonce_len].to_vec();

        // Skip to padded boundary.
        let nonce_padded = (2 + nonce_len + 3) & !3;
        let ct_offset = nonce_padded;
        if ct_offset + 2 > data.len() {
            return Err(ParseError::BufferTooShort {
                needed: ct_offset + 2,
                available: data.len(),
            });
        }

        let ct_len = u16::from_be_bytes([data[ct_offset], data[ct_offset + 1]]) as usize;
        let ct_start = ct_offset + 2;

        if ct_start + ct_len > data.len() {
            return Err(ParseError::ExtensionOverflow);
        }
        let ciphertext = data[ct_start..ct_start + ct_len].to_vec();

        Ok(Some(NtsAuthenticator { nonce, ciphertext }))
    }
}

#[cfg(all(test, feature = "std"))]
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

    // Buffer-based API tests.

    #[test]
    fn test_buf_parse_empty() {
        let fields = parse_extension_fields_buf(&[]).unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn test_buf_roundtrip_single_field() {
        let field = ExtensionField {
            field_type: UNIQUE_IDENTIFIER,
            value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        // Write to Vec via io API, then to fixed buffer via buf API.
        let io_buf = write_extension_fields(std::slice::from_ref(&field)).unwrap();
        let mut buf = vec![0u8; 256];
        let written = write_extension_fields_buf(std::slice::from_ref(&field), &mut buf).unwrap();
        assert_eq!(&io_buf[..], &buf[..written]);

        // Parse with buf API.
        let parsed = parse_extension_fields_buf(&buf[..written]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], field);
    }

    #[test]
    fn test_buf_equivalence_with_io_api() {
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

        let io_buf = write_extension_fields(&fields).unwrap();
        let mut raw_buf = vec![0u8; 512];
        let written = write_extension_fields_buf(&fields, &mut raw_buf).unwrap();

        // Same output.
        assert_eq!(&io_buf[..], &raw_buf[..written]);

        // Same parse result.
        let io_parsed = parse_extension_fields(&io_buf).unwrap();
        let buf_parsed = parse_extension_fields_buf(&raw_buf[..written]).unwrap();
        assert_eq!(io_parsed, buf_parsed);
    }

    #[test]
    fn test_buf_write_buffer_too_short() {
        let field = ExtensionField {
            field_type: UNIQUE_IDENTIFIER,
            value: vec![0xAA; 32],
        };
        let mut tiny_buf = [0u8; 4]; // Too small for 4 header + 32 value.
        let result = write_extension_fields_buf(&[field], &mut tiny_buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_buf_parse_invalid_length() {
        let data = [0x01, 0x04, 0x00, 0x02]; // field_length=2 (< 4).
        let result = parse_extension_fields_buf(&data);
        assert!(matches!(
            result,
            Err(ParseError::InvalidExtensionLength { declared: 2 })
        ));
    }

    #[test]
    fn test_iter_extension_fields() {
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
        let io_buf = write_extension_fields(&fields).unwrap();

        let mut iter = iter_extension_fields(&io_buf);

        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.field_type, UNIQUE_IDENTIFIER);
        assert_eq!(first.value, &[0xAA; 32][..]);

        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.field_type, NTS_COOKIE);
        assert_eq!(second.value, &[0xBB; 64][..]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_iter_extension_fields_empty() {
        let mut iter = iter_extension_fields(&[]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_nts_authenticator_buf_roundtrip() {
        let auth = NtsAuthenticator::new(vec![0x11; 16], vec![0x22; 48]);
        let ef = auth.to_extension_field();
        let back = NtsAuthenticator::from_extension_field_buf(&ef)
            .unwrap()
            .unwrap();
        assert_eq!(back.nonce, vec![0x11; 16]);
        assert_eq!(back.ciphertext, vec![0x22; 48]);
    }
}
