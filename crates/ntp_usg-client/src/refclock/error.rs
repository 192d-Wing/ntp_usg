// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Error types for reference clock subsystems (NMEA, PPS).

use std::io;

/// NMEA sentence parsing errors.
#[derive(Clone, Debug)]
pub enum NmeaError {
    /// Computed checksum does not match the expected value.
    ChecksumMismatch {
        /// Expected checksum from the sentence.
        expected: u8,
        /// Computed checksum over the sentence body.
        actual: u8,
    },
    /// The checksum field could not be parsed as a hex byte.
    InvalidChecksum,
    /// A required field could not be parsed.
    ParseField {
        /// NMEA sentence type (e.g., "GGA", "RMC", "ZDA", "time", "date").
        sentence: &'static str,
        /// Name of the field that failed to parse.
        field: &'static str,
    },
    /// The sentence has an invalid format (e.g., too short).
    InvalidFormat {
        /// Description of the format violation.
        detail: &'static str,
    },
}

impl core::fmt::Display for NmeaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NmeaError::ChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {:02X}, got {:02X}",
                    expected, actual
                )
            }
            NmeaError::InvalidChecksum => write!(f, "invalid checksum format"),
            NmeaError::ParseField { sentence, field } => {
                write!(f, "invalid {} in {} sentence", field, sentence)
            }
            NmeaError::InvalidFormat { detail } => write!(f, "invalid NMEA format: {}", detail),
        }
    }
}

impl std::error::Error for NmeaError {}

impl From<NmeaError> for io::Error {
    fn from(err: NmeaError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}

/// PPS (Pulse Per Second) errors.
#[derive(Clone, Debug)]
pub enum PpsError {
    /// PPS sequence number did not advance (no new event).
    SequenceStale,
}

impl core::fmt::Display for PpsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PpsError::SequenceStale => write!(f, "no new PPS event received"),
        }
    }
}

impl std::error::Error for PpsError {}

impl From<PpsError> for io::Error {
    fn from(err: PpsError) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, err)
    }
}
