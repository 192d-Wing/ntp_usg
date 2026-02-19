// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Custom error types for the NTP client.
//!
//! All public APIs continue to return `io::Result<T>` for backward compatibility.
//! Internally, errors are constructed as `NtpError` variants and converted to
//! `io::Error` automatically via `From<NtpError> for io::Error`.
//!
//! Users who want programmatic error matching can downcast via
//! `io::Error::get_ref()`:
//!
//! ```no_run
//! use ntp_client::error::NtpError;
//!
//! match ntp_client::request("time.nist.gov:123") {
//!     Ok(result) => println!("Offset: {:.6}s", result.offset_seconds),
//!     Err(e) => {
//!         if let Some(ntp_err) = e.get_ref()
//!             .and_then(|inner| inner.downcast_ref::<NtpError>())
//!         {
//!             match ntp_err {
//!                 NtpError::Protocol(p) => eprintln!("protocol error: {p}"),
//!                 NtpError::Timeout(t) => eprintln!("timeout: {t}"),
//!                 _ => eprintln!("NTP error: {ntp_err}"),
//!             }
//!         }
//!     }
//! }
//! ```

// Re-export proto error types for backward compatibility.
pub use ntp_proto::error::ParseError;

use std::fmt;
use std::io;

use crate::KissOfDeathError;

/// Errors that can occur during NTP client operations.
#[derive(Debug)]
pub enum NtpError {
    /// NTP protocol validation failure (malformed packets, unexpected fields).
    Protocol(ProtocolError),
    /// Operation timed out.
    Timeout(TimeoutError),
    /// Invalid configuration (bad addresses, missing servers).
    Config(ConfigError),
    /// NTS key establishment or authentication failure.
    Nts(NtsError),
    /// Kiss-o'-Death packet received from the server.
    KissOfDeath(KissOfDeathError),
    /// Underlying I/O error (socket bind, DNS resolution, etc.).
    Io(io::Error),
}

/// NTP protocol validation errors.
#[derive(Clone, Debug)]
pub enum ProtocolError {
    /// Response packet too short (< 48 bytes).
    ResponseTooShort {
        /// Number of bytes received.
        received: usize,
    },
    /// Response from unexpected source address.
    UnexpectedSource,
    /// Response has wrong mode (expected Server).
    UnexpectedMode,
    /// Origin timestamp does not match our request.
    OriginTimestampMismatch,
    /// Server transmit timestamp is zero (unsent).
    ZeroTransmitTimestamp,
    /// Server reports unsynchronized clock (LI=3 or Stratum=0).
    UnsynchronizedServer,
    /// NTPv5 client cookie mismatch.
    ClientCookieMismatch,
    /// NTPv5 missing or mismatched Draft Identification.
    MissingDraftId,
    /// Generic protocol error.
    Other(String),
}

/// Timeout errors for NTP operations.
#[derive(Clone, Debug)]
pub enum TimeoutError {
    /// NTP send operation timed out.
    Send,
    /// NTP receive operation timed out.
    Recv,
    /// Entire NTP request timed out.
    Request,
    /// NTS-KE request timed out.
    NtsKe,
    /// Roughtime request timed out.
    Roughtime,
}

/// Configuration errors.
#[derive(Clone, Debug)]
pub enum ConfigError {
    /// No server addresses provided.
    NoServers,
    /// Address resolved to no socket addresses.
    NoAddresses {
        /// The address that failed to resolve.
        address: String,
    },
    /// Invalid server name for TLS.
    InvalidServerName {
        /// Detail about the invalid name.
        detail: String,
    },
}

/// NTS (Network Time Security) errors.
#[derive(Clone, Debug)]
pub enum NtsError {
    /// NTS-KE server sent an error record.
    ServerError {
        /// Error code from the server.
        code: u16,
    },
    /// NTS-KE protocol record body too short.
    RecordTooShort {
        /// Which record type was too short.
        record_type: &'static str,
    },
    /// Unsupported NTS-KE next protocol.
    UnsupportedProtocol {
        /// The unsupported protocol ID.
        protocol: u16,
    },
    /// Unrecognized critical NTS-KE record.
    UnrecognizedCriticalRecord {
        /// The unrecognized record type.
        record_type: u16,
    },
    /// Server did not send a required NTS-KE record.
    MissingRecord {
        /// Name of the missing record.
        record: &'static str,
    },
    /// No NTS cookies remaining.
    NoCookies,
    /// NTS AEAD authentication failed.
    AuthenticationFailed,
    /// TLS key export failed.
    KeyExportFailed {
        /// Detail about the failure.
        detail: String,
    },
    /// Generic NTS error.
    Other(String),
}

// ── Display implementations ─────────────────────────────────────────

impl fmt::Display for NtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtpError::Protocol(e) => write!(f, "NTP protocol error: {e}"),
            NtpError::Timeout(e) => write!(f, "NTP timeout: {e}"),
            NtpError::Config(e) => write!(f, "NTP config error: {e}"),
            NtpError::Nts(e) => write!(f, "NTS error: {e}"),
            NtpError::KissOfDeath(e) => write!(f, "{e}"),
            NtpError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::ResponseTooShort { received } => {
                write!(f, "NTP response too short ({received} bytes)")
            }
            ProtocolError::UnexpectedSource => write!(f, "response from unexpected source address"),
            ProtocolError::UnexpectedMode => {
                write!(f, "unexpected response mode (expected Server)")
            }
            ProtocolError::OriginTimestampMismatch => {
                write!(
                    f,
                    "origin timestamp mismatch: response does not match our request"
                )
            }
            ProtocolError::ZeroTransmitTimestamp => {
                write!(f, "server transmit timestamp is zero")
            }
            ProtocolError::UnsynchronizedServer => {
                write!(f, "server reports unsynchronized clock")
            }
            ProtocolError::ClientCookieMismatch => {
                write!(f, "NTPv5 client cookie mismatch")
            }
            ProtocolError::MissingDraftId => {
                write!(f, "NTPv5 missing or mismatched Draft Identification")
            }
            ProtocolError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutError::Send => write!(f, "NTP send timed out"),
            TimeoutError::Recv => write!(f, "NTP recv timed out"),
            TimeoutError::Request => write!(f, "NTP request timed out"),
            TimeoutError::NtsKe => write!(f, "NTS-KE request timed out"),
            TimeoutError::Roughtime => write!(f, "Roughtime request timed out"),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NoServers => write!(f, "at least one server address is required"),
            ConfigError::NoAddresses { address } => {
                write!(f, "address resolved to no socket addresses: {address}")
            }
            ConfigError::InvalidServerName { detail } => {
                write!(f, "invalid server name: {detail}")
            }
        }
    }
}

impl fmt::Display for NtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtsError::ServerError { code } => write!(f, "NTS-KE server error: code {code}"),
            NtsError::RecordTooShort { record_type } => {
                write!(f, "NTS-KE record too short: {record_type}")
            }
            NtsError::UnsupportedProtocol { protocol } => {
                write!(f, "unsupported NTS-KE protocol: 0x{protocol:04X}")
            }
            NtsError::UnrecognizedCriticalRecord { record_type } => {
                write!(f, "unrecognized critical NTS-KE record type: {record_type}")
            }
            NtsError::MissingRecord { record } => write!(f, "missing NTS-KE record: {record}"),
            NtsError::NoCookies => write!(f, "no NTS cookies remaining"),
            NtsError::AuthenticationFailed => write!(f, "NTS AEAD authentication failed"),
            NtsError::KeyExportFailed { detail } => {
                write!(f, "TLS key export failed: {detail}")
            }
            NtsError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

// ── Error trait implementations ─────────────────────────────────────

impl std::error::Error for NtpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NtpError::Io(e) => Some(e),
            NtpError::KissOfDeath(e) => Some(e),
            _ => None,
        }
    }
}

impl std::error::Error for ProtocolError {}
impl std::error::Error for TimeoutError {}
impl std::error::Error for ConfigError {}
impl std::error::Error for NtsError {}

// ── From conversions ────────────────────────────────────────────────

impl From<NtpError> for io::Error {
    fn from(err: NtpError) -> io::Error {
        let kind = match &err {
            NtpError::Protocol(_) => io::ErrorKind::InvalidData,
            NtpError::Timeout(_) => io::ErrorKind::TimedOut,
            NtpError::Config(_) => io::ErrorKind::InvalidInput,
            NtpError::Nts(NtsError::ServerError { .. }) => io::ErrorKind::ConnectionRefused,
            NtpError::Nts(_) => io::ErrorKind::InvalidData,
            NtpError::KissOfDeath(_) => io::ErrorKind::ConnectionRefused,
            NtpError::Io(e) => e.kind(),
        };
        // Preserve the original io::Error directly for the Io variant.
        if let NtpError::Io(e) = err {
            return e;
        }
        io::Error::new(kind, err)
    }
}

impl From<io::Error> for NtpError {
    fn from(err: io::Error) -> NtpError {
        NtpError::Io(err)
    }
}

impl From<KissOfDeathError> for NtpError {
    fn from(err: KissOfDeathError) -> NtpError {
        NtpError::KissOfDeath(err)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_error_display() {
        let e = ProtocolError::ResponseTooShort { received: 10 };
        assert_eq!(e.to_string(), "NTP response too short (10 bytes)");
    }

    #[test]
    fn test_timeout_error_display() {
        assert_eq!(TimeoutError::Send.to_string(), "NTP send timed out");
        assert_eq!(TimeoutError::Recv.to_string(), "NTP recv timed out");
        assert_eq!(TimeoutError::Request.to_string(), "NTP request timed out");
    }

    #[test]
    fn test_config_error_display() {
        let e = ConfigError::NoServers;
        assert_eq!(e.to_string(), "at least one server address is required");
    }

    #[test]
    fn test_nts_error_display() {
        let e = NtsError::ServerError { code: 42 };
        assert_eq!(e.to_string(), "NTS-KE server error: code 42");
    }

    #[test]
    fn test_ntp_error_to_io_error_kind() {
        let cases: Vec<(NtpError, io::ErrorKind)> = vec![
            (
                NtpError::Protocol(ProtocolError::UnexpectedSource),
                io::ErrorKind::InvalidData,
            ),
            (
                NtpError::Timeout(TimeoutError::Send),
                io::ErrorKind::TimedOut,
            ),
            (
                NtpError::Config(ConfigError::NoServers),
                io::ErrorKind::InvalidInput,
            ),
            (
                NtpError::Nts(NtsError::ServerError { code: 1 }),
                io::ErrorKind::ConnectionRefused,
            ),
            (
                NtpError::Nts(NtsError::NoCookies),
                io::ErrorKind::InvalidData,
            ),
        ];
        for (ntp_err, expected_kind) in cases {
            let io_err: io::Error = ntp_err.into();
            assert_eq!(io_err.kind(), expected_kind);
        }
    }

    #[test]
    fn test_ntp_error_downcast_roundtrip() {
        let err = NtpError::Protocol(ProtocolError::ResponseTooShort { received: 10 });
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let inner = io_err
            .get_ref()
            .unwrap()
            .downcast_ref::<NtpError>()
            .unwrap();
        assert!(matches!(
            inner,
            NtpError::Protocol(ProtocolError::ResponseTooShort { received: 10 })
        ));
    }

    #[test]
    fn test_io_error_passthrough() {
        let orig = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let kind = orig.kind();
        let ntp_err = NtpError::Io(orig);
        let io_err: io::Error = ntp_err.into();
        assert_eq!(io_err.kind(), kind);
        assert_eq!(io_err.to_string(), "reset");
    }

    #[test]
    fn test_from_io_error() {
        let orig = io::Error::new(io::ErrorKind::BrokenPipe, "broken");
        let ntp_err: NtpError = orig.into();
        assert!(matches!(ntp_err, NtpError::Io(_)));
    }
}
