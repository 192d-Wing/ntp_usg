// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Custom error types for the NTP server.
//!
//! All public APIs continue to return `io::Result<T>` for backward compatibility.
//! Internally, errors are constructed as `NtpServerError` variants and converted
//! to `io::Error` automatically via `From<NtpServerError> for io::Error`.
//!
//! Users who want programmatic error matching can downcast via
//! `io::Error::get_ref()`:
//!
//! ```no_run
//! use ntp_server::error::NtpServerError;
//!
//! # fn example(result: std::io::Result<()>) {
//! match result {
//!     Ok(()) => println!("server running"),
//!     Err(e) => {
//!         if let Some(srv_err) = e.get_ref()
//!             .and_then(|inner| inner.downcast_ref::<NtpServerError>())
//!         {
//!             match srv_err {
//!                 NtpServerError::Protocol(p) => eprintln!("protocol error: {p}"),
//!                 NtpServerError::Nts(n) => eprintln!("NTS error: {n}"),
//!                 _ => eprintln!("server error: {srv_err}"),
//!             }
//!         }
//!     }
//! }
//! # }
//! ```

// Re-export proto error types for backward compatibility.
pub use ntp_proto::error::ParseError;

use std::fmt;
use std::io;

/// Errors that can occur during NTP server operations.
#[derive(Debug)]
pub enum NtpServerError {
    /// NTP protocol validation failure (malformed requests, unexpected fields).
    Protocol(ProtocolError),
    /// NTS key establishment or authentication failure.
    Nts(NtsError),
    /// Invalid configuration (bad addresses, invalid TLS credentials).
    Config(ConfigError),
    /// Underlying I/O error (socket bind, send/recv, etc.).
    Io(io::Error),
}

/// NTP protocol validation errors for incoming client requests.
///
/// These correspond to the checks performed in
/// `server_common::validation` per RFC 5905 Section 8.
#[derive(Clone, Debug)]
pub enum ProtocolError {
    /// Request packet too short (< 48 bytes).
    RequestTooShort {
        /// Number of bytes received.
        received: usize,
    },
    /// Request has unexpected mode (expected Client or SymmetricActive).
    UnexpectedMode {
        /// The mode value received.
        mode: u8,
    },
    /// Unsupported NTP version in request.
    UnsupportedVersion {
        /// The version value received.
        version: u8,
    },
    /// Client transmit timestamp is zero.
    ZeroTransmitTimestamp,
    /// Request has no extension fields (expected for NTS).
    NoExtensionFields,
    /// Generic protocol error.
    Other(String),
}

/// NTS (Network Time Security) server-side errors.
///
/// These cover NTS-KE negotiation failures, cookie decryption errors, and
/// AEAD authentication failures encountered while processing NTS-authenticated
/// NTP requests.
#[derive(Clone, Debug)]
pub enum NtsError {
    /// Missing required NTS extension field in client request.
    MissingExtension {
        /// Name of the missing extension field.
        field: &'static str,
    },
    /// Failed to decrypt NTS cookie (expired or invalid master key).
    CookieDecryptionFailed,
    /// Failed to parse NTS Authenticator extension field.
    AuthenticatorParseFailed,
    /// NTS AEAD authentication failed (C2S key verification).
    AuthenticationFailed,
    /// TLS key export failed during NTS-KE.
    KeyExportFailed {
        /// Detail about the failure.
        detail: String,
    },
    /// Master key store lock poisoned.
    KeyStorePoisoned,
    /// Unrecognized critical NTS-KE record from client.
    UnrecognizedCriticalRecord {
        /// The unrecognized record type.
        record_type: u16,
    },
    /// Client did not send a supported Next Protocol (NTPv4).
    MissingNextProtocol,
    /// Generic NTS error.
    Other(String),
}

/// Server configuration errors.
#[derive(Clone, Debug)]
pub enum ConfigError {
    /// Invalid listen address.
    InvalidListenAddress {
        /// The address that was invalid.
        address: String,
        /// Detail about why it is invalid.
        detail: String,
    },
    /// Invalid TLS certificate or private key.
    InvalidTlsCredentials {
        /// Detail about the failure.
        detail: String,
    },
    /// Generic configuration error.
    Other(String),
}

// ── Display implementations ─────────────────────────────────────────

impl fmt::Display for NtpServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtpServerError::Protocol(e) => write!(f, "NTP server protocol error: {e}"),
            NtpServerError::Nts(e) => write!(f, "NTS server error: {e}"),
            NtpServerError::Config(e) => write!(f, "NTP server config error: {e}"),
            NtpServerError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::RequestTooShort { received } => {
                write!(f, "NTP request too short ({received} bytes)")
            }
            ProtocolError::UnexpectedMode { mode } => {
                write!(f, "unexpected request mode: {mode}")
            }
            ProtocolError::UnsupportedVersion { version } => {
                write!(f, "unsupported NTP version: {version}")
            }
            ProtocolError::ZeroTransmitTimestamp => {
                write!(f, "client transmit timestamp is zero")
            }
            ProtocolError::NoExtensionFields => {
                write!(f, "request has no extension fields")
            }
            ProtocolError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for NtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtsError::MissingExtension { field } => {
                write!(f, "missing NTS extension field: {field}")
            }
            NtsError::CookieDecryptionFailed => {
                write!(f, "failed to decrypt NTS cookie (expired or invalid)")
            }
            NtsError::AuthenticatorParseFailed => {
                write!(f, "failed to parse NTS Authenticator")
            }
            NtsError::AuthenticationFailed => {
                write!(f, "NTS AEAD authentication failed")
            }
            NtsError::KeyExportFailed { detail } => {
                write!(f, "TLS key export failed: {detail}")
            }
            NtsError::KeyStorePoisoned => {
                write!(f, "master key store lock poisoned")
            }
            NtsError::UnrecognizedCriticalRecord { record_type } => {
                write!(f, "unrecognized critical NTS-KE record type: {record_type}")
            }
            NtsError::MissingNextProtocol => {
                write!(f, "client did not send a supported Next Protocol")
            }
            NtsError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidListenAddress { address, detail } => {
                write!(f, "invalid listen address '{address}': {detail}")
            }
            ConfigError::InvalidTlsCredentials { detail } => {
                write!(f, "invalid TLS credentials: {detail}")
            }
            ConfigError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

// ── Error trait implementations ─────────────────────────────────────

impl std::error::Error for NtpServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NtpServerError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl std::error::Error for ProtocolError {}
impl std::error::Error for NtsError {}
impl std::error::Error for ConfigError {}

// ── From conversions ────────────────────────────────────────────────

impl From<NtpServerError> for io::Error {
    fn from(err: NtpServerError) -> io::Error {
        let kind = match &err {
            NtpServerError::Protocol(_) => io::ErrorKind::InvalidData,
            NtpServerError::Nts(NtsError::KeyExportFailed { .. }) => io::ErrorKind::Other,
            NtpServerError::Nts(NtsError::KeyStorePoisoned) => io::ErrorKind::Other,
            NtpServerError::Nts(_) => io::ErrorKind::InvalidData,
            NtpServerError::Config(_) => io::ErrorKind::InvalidInput,
            NtpServerError::Io(e) => e.kind(),
        };
        // Preserve the original io::Error directly for the Io variant.
        if let NtpServerError::Io(e) = err {
            return e;
        }
        io::Error::new(kind, err)
    }
}

impl From<io::Error> for NtpServerError {
    fn from(err: io::Error) -> NtpServerError {
        NtpServerError::Io(err)
    }
}

impl From<ProtocolError> for NtpServerError {
    fn from(err: ProtocolError) -> NtpServerError {
        NtpServerError::Protocol(err)
    }
}

impl From<NtsError> for NtpServerError {
    fn from(err: NtsError) -> NtpServerError {
        NtpServerError::Nts(err)
    }
}

impl From<ConfigError> for NtpServerError {
    fn from(err: ConfigError) -> NtpServerError {
        NtpServerError::Config(err)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_error_display() {
        let e = ProtocolError::RequestTooShort { received: 10 };
        assert_eq!(e.to_string(), "NTP request too short (10 bytes)");
    }

    #[test]
    fn test_protocol_error_unexpected_mode() {
        let e = ProtocolError::UnexpectedMode { mode: 5 };
        assert_eq!(e.to_string(), "unexpected request mode: 5");
    }

    #[test]
    fn test_protocol_error_unsupported_version() {
        let e = ProtocolError::UnsupportedVersion { version: 2 };
        assert_eq!(e.to_string(), "unsupported NTP version: 2");
    }

    #[test]
    fn test_protocol_error_zero_transmit() {
        let e = ProtocolError::ZeroTransmitTimestamp;
        assert_eq!(e.to_string(), "client transmit timestamp is zero");
    }

    #[test]
    fn test_protocol_error_no_extensions() {
        let e = ProtocolError::NoExtensionFields;
        assert_eq!(e.to_string(), "request has no extension fields");
    }

    #[test]
    fn test_nts_error_display() {
        let e = NtsError::MissingExtension {
            field: "Unique Identifier",
        };
        assert_eq!(
            e.to_string(),
            "missing NTS extension field: Unique Identifier"
        );
    }

    #[test]
    fn test_nts_error_cookie_decryption() {
        let e = NtsError::CookieDecryptionFailed;
        assert_eq!(
            e.to_string(),
            "failed to decrypt NTS cookie (expired or invalid)"
        );
    }

    #[test]
    fn test_nts_error_authentication() {
        let e = NtsError::AuthenticationFailed;
        assert_eq!(e.to_string(), "NTS AEAD authentication failed");
    }

    #[test]
    fn test_nts_error_key_export() {
        let e = NtsError::KeyExportFailed {
            detail: "no session".to_string(),
        };
        assert_eq!(e.to_string(), "TLS key export failed: no session");
    }

    #[test]
    fn test_nts_error_key_store_poisoned() {
        let e = NtsError::KeyStorePoisoned;
        assert_eq!(e.to_string(), "master key store lock poisoned");
    }

    #[test]
    fn test_config_error_display() {
        let e = ConfigError::InvalidListenAddress {
            address: "bad:addr".to_string(),
            detail: "not a valid socket address".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "invalid listen address 'bad:addr': not a valid socket address"
        );
    }

    #[test]
    fn test_config_error_tls() {
        let e = ConfigError::InvalidTlsCredentials {
            detail: "bad PEM".to_string(),
        };
        assert_eq!(e.to_string(), "invalid TLS credentials: bad PEM");
    }

    #[test]
    fn test_server_error_to_io_error_kind() {
        let cases: Vec<(NtpServerError, io::ErrorKind)> = vec![
            (
                NtpServerError::Protocol(ProtocolError::ZeroTransmitTimestamp),
                io::ErrorKind::InvalidData,
            ),
            (
                NtpServerError::Nts(NtsError::AuthenticationFailed),
                io::ErrorKind::InvalidData,
            ),
            (
                NtpServerError::Nts(NtsError::KeyStorePoisoned),
                io::ErrorKind::Other,
            ),
            (
                NtpServerError::Config(ConfigError::Other("test".to_string())),
                io::ErrorKind::InvalidInput,
            ),
        ];
        for (srv_err, expected_kind) in cases {
            let io_err: io::Error = srv_err.into();
            assert_eq!(io_err.kind(), expected_kind);
        }
    }

    #[test]
    fn test_server_error_downcast_roundtrip() {
        let err = NtpServerError::Protocol(ProtocolError::RequestTooShort { received: 10 });
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let inner = io_err
            .get_ref()
            .unwrap()
            .downcast_ref::<NtpServerError>()
            .unwrap();
        assert!(matches!(
            inner,
            NtpServerError::Protocol(ProtocolError::RequestTooShort { received: 10 })
        ));
    }

    #[test]
    fn test_io_error_passthrough() {
        let orig = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let kind = orig.kind();
        let srv_err = NtpServerError::Io(orig);
        let io_err: io::Error = srv_err.into();
        assert_eq!(io_err.kind(), kind);
        assert_eq!(io_err.to_string(), "reset");
    }

    #[test]
    fn test_from_io_error() {
        let orig = io::Error::new(io::ErrorKind::BrokenPipe, "broken");
        let srv_err: NtpServerError = orig.into();
        assert!(matches!(srv_err, NtpServerError::Io(_)));
    }

    #[test]
    fn test_from_protocol_error() {
        let proto_err = ProtocolError::ZeroTransmitTimestamp;
        let srv_err: NtpServerError = proto_err.into();
        assert!(matches!(srv_err, NtpServerError::Protocol(_)));
    }

    #[test]
    fn test_from_nts_error() {
        let nts_err = NtsError::AuthenticationFailed;
        let srv_err: NtpServerError = nts_err.into();
        assert!(matches!(srv_err, NtpServerError::Nts(_)));
    }

    #[test]
    fn test_from_config_error() {
        let cfg_err = ConfigError::Other("test".to_string());
        let srv_err: NtpServerError = cfg_err.into();
        assert!(matches!(srv_err, NtpServerError::Config(_)));
    }

    #[test]
    fn test_ntp_server_error_source() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "broken");
        let srv_err = NtpServerError::Io(io_err);
        assert!(std::error::Error::source(&srv_err).is_some());

        let proto_err = NtpServerError::Protocol(ProtocolError::ZeroTransmitTimestamp);
        assert!(std::error::Error::source(&proto_err).is_none());
    }
}
