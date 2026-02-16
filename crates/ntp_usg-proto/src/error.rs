// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Custom error types for buffer-based NTP packet parsing and serialization.
//!
//! [`ParseError`] is designed to be `no_std`-compatible, using no heap allocation.
//! When the `std` feature is enabled, it also implements [`std::error::Error`] and
//! can be converted to [`std::io::Error`].

use core::fmt;

/// Errors that can occur during buffer-based NTP packet parsing or serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The buffer is too short for the expected data.
    BufferTooShort {
        /// Number of bytes needed.
        needed: usize,
        /// Number of bytes available.
        available: usize,
    },
    /// An invalid or unrecognized field value was encountered.
    InvalidField {
        /// Name of the field that was invalid.
        field: &'static str,
        /// The invalid value.
        value: u32,
    },
    /// Extension field has an invalid length (less than 4 bytes).
    InvalidExtensionLength {
        /// The declared length that was invalid.
        declared: u16,
    },
    /// Extension field data extends beyond the buffer.
    ExtensionOverflow,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BufferTooShort { needed, available } => {
                write!(
                    f,
                    "buffer too short: needed {} bytes, got {}",
                    needed, available
                )
            }
            ParseError::InvalidField { field, value } => {
                write!(f, "invalid {} value: {}", field, value)
            }
            ParseError::InvalidExtensionLength { declared } => {
                write!(f, "extension field length less than 4: {}", declared)
            }
            ParseError::ExtensionOverflow => {
                write!(f, "extension field value extends beyond packet")
            }
        }
    }
}

#[cfg(feature = "std")]
impl From<ParseError> for std::io::Error {
    fn from(err: ParseError) -> std::io::Error {
        let kind = match &err {
            ParseError::BufferTooShort { .. } => std::io::ErrorKind::UnexpectedEof,
            ParseError::InvalidField { .. } => std::io::ErrorKind::InvalidData,
            ParseError::InvalidExtensionLength { .. } => std::io::ErrorKind::InvalidData,
            ParseError::ExtensionOverflow => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_display_buffer_too_short() {
        let err = ParseError::BufferTooShort {
            needed: 48,
            available: 10,
        };
        assert_eq!(err.to_string(), "buffer too short: needed 48 bytes, got 10");
    }

    #[test]
    fn test_display_invalid_field() {
        let err = ParseError::InvalidField {
            field: "leap indicator",
            value: 5,
        };
        assert_eq!(err.to_string(), "invalid leap indicator value: 5");
    }

    #[test]
    fn test_display_invalid_extension_length() {
        let err = ParseError::InvalidExtensionLength { declared: 2 };
        assert_eq!(err.to_string(), "extension field length less than 4: 2");
    }

    #[test]
    fn test_display_extension_overflow() {
        let err = ParseError::ExtensionOverflow;
        assert_eq!(
            err.to_string(),
            "extension field value extends beyond packet"
        );
    }

    #[test]
    fn test_into_io_error() {
        let parse_err = ParseError::BufferTooShort {
            needed: 48,
            available: 0,
        };
        let io_err: std::io::Error = parse_err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_parse_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ParseError::ExtensionOverflow);
        assert_eq!(
            err.to_string(),
            "extension field value extends beyond packet"
        );
    }
}
