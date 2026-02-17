// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Error types for Roughtime protocol parsing and verification.
//!
//! [`RoughtimeError`] follows the same pattern as [`crate::error::ParseError`]:
//! `no_std`-compatible via `core::fmt::Display`, with [`std::error::Error`] and
//! [`From<RoughtimeError> for std::io::Error`] behind `#[cfg(feature = "std")]`.

use core::fmt;

/// Errors that can occur during Roughtime message parsing or verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoughtimeError {
    /// The envelope magic bytes do not match `ROUGHTIM` (LE).
    InvalidMagic,
    /// The message is shorter than the minimum required length.
    MessageTooShort {
        /// Number of bytes needed.
        needed: usize,
        /// Number of bytes available.
        available: usize,
    },
    /// Tags in a tag-value map are not in ascending order.
    InvalidTagOrder,
    /// A tag-value offset points beyond the value region.
    OffsetOutOfBounds,
    /// A required tag is missing from the message.
    MissingTag {
        /// The 4-byte ASCII tag that was expected.
        tag: [u8; 4],
    },
    /// A tag's value has an unexpected length.
    InvalidTagLength {
        /// The 4-byte ASCII tag.
        tag: [u8; 4],
        /// The expected length.
        expected: usize,
        /// The actual length.
        actual: usize,
    },
    /// Ed25519 signature verification failed.
    SignatureVerificationFailed,
    /// The delegation certificate has expired (MIDP outside MINT..MAXT).
    DelegationExpired,
    /// Merkle tree path verification failed.
    MerkleVerificationFailed,
    /// The nonce in the response does not match the request.
    NonceMismatch,
    /// The TYPE tag has an unexpected value.
    InvalidType {
        /// The TYPE value encountered.
        value: u32,
    },
}

impl fmt::Display for RoughtimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoughtimeError::InvalidMagic => write!(f, "invalid Roughtime envelope magic"),
            RoughtimeError::MessageTooShort { needed, available } => {
                write!(
                    f,
                    "message too short: needed {} bytes, got {}",
                    needed, available
                )
            }
            RoughtimeError::InvalidTagOrder => write!(f, "tags not in ascending order"),
            RoughtimeError::OffsetOutOfBounds => write!(f, "tag-value offset out of bounds"),
            RoughtimeError::MissingTag { tag } => {
                write!(
                    f,
                    "missing required tag: {}",
                    core::str::from_utf8(tag).unwrap_or("????")
                )
            }
            RoughtimeError::InvalidTagLength {
                tag,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "tag {} has invalid length: expected {}, got {}",
                    core::str::from_utf8(tag).unwrap_or("????"),
                    expected,
                    actual
                )
            }
            RoughtimeError::SignatureVerificationFailed => {
                write!(f, "Ed25519 signature verification failed")
            }
            RoughtimeError::DelegationExpired => write!(f, "delegation certificate expired"),
            RoughtimeError::MerkleVerificationFailed => {
                write!(f, "Merkle tree path verification failed")
            }
            RoughtimeError::NonceMismatch => write!(f, "nonce mismatch"),
            RoughtimeError::InvalidType { value } => {
                write!(f, "invalid TYPE value: {}", value)
            }
        }
    }
}

#[cfg(feature = "std")]
impl From<RoughtimeError> for std::io::Error {
    fn from(err: RoughtimeError) -> std::io::Error {
        let kind = match &err {
            RoughtimeError::MessageTooShort { .. } => std::io::ErrorKind::UnexpectedEof,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RoughtimeError {}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_display_invalid_magic() {
        let err = RoughtimeError::InvalidMagic;
        assert_eq!(err.to_string(), "invalid Roughtime envelope magic");
    }

    #[test]
    fn test_display_message_too_short() {
        let err = RoughtimeError::MessageTooShort {
            needed: 12,
            available: 4,
        };
        assert_eq!(err.to_string(), "message too short: needed 12 bytes, got 4");
    }

    #[test]
    fn test_display_missing_tag() {
        let err = RoughtimeError::MissingTag { tag: *b"NONC" };
        assert_eq!(err.to_string(), "missing required tag: NONC");
    }

    #[test]
    fn test_display_invalid_tag_length() {
        let err = RoughtimeError::InvalidTagLength {
            tag: *b"SIG\0",
            expected: 64,
            actual: 32,
        };
        assert_eq!(
            err.to_string(),
            "tag SIG\0 has invalid length: expected 64, got 32"
        );
    }

    #[test]
    fn test_into_io_error() {
        let err = RoughtimeError::SignatureVerificationFailed;
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_message_too_short_io_error_kind() {
        let err = RoughtimeError::MessageTooShort {
            needed: 12,
            available: 0,
        };
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_roughtime_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(RoughtimeError::NonceMismatch);
        assert_eq!(err.to_string(), "nonce mismatch");
    }
}
