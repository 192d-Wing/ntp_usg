// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared types and logic for the continuous NTP client, used by both the
//! tokio-based [`crate::client`] and smol-based [`crate::smol_client`] modules.

use std::io;

use crate::filter::ClockSample;
use crate::{compute_offset_delay, protocol, unix_time};

/// The current synchronization state published by the continuous NTP client.
///
/// Available to consumers via `tokio::sync::watch::Receiver<NtpSyncState>`
/// (tokio client) or `Arc<RwLock<NtpSyncState>>` (smol client).
#[derive(Clone, Debug)]
pub struct NtpSyncState {
    /// Best estimated clock offset in seconds (positive = local clock behind server).
    pub offset: f64,
    /// Best estimated round-trip delay in seconds.
    pub delay: f64,
    /// RMS jitter of recent samples in seconds.
    pub jitter: f64,
    /// Stratum of the best peer.
    pub stratum: u8,
    /// Whether interleaved mode is active for the best peer.
    pub interleaved: bool,
    /// When this state was last updated.
    pub last_update: std::time::Instant,
    /// Number of successful responses received across all peers.
    pub total_responses: u64,
    /// Whether the best peer is using NTS authentication.
    pub nts_authenticated: bool,
}

impl Default for NtpSyncState {
    fn default() -> Self {
        NtpSyncState {
            offset: 0.0,
            delay: 0.0,
            jitter: 0.0,
            stratum: protocol::MAXSTRAT,
            interleaved: false,
            last_update: std::time::Instant::now(),
            total_responses: 0,
            nts_authenticated: false,
        }
    }
}

/// Classify an NTP response as basic or interleaved mode and compute
/// the clock offset and delay.
///
/// Returns `(sample, interleaved)` where `interleaved` indicates whether
/// the server used interleaved mode (RFC 9769).
pub(crate) fn classify_and_compute(
    response: &protocol::Packet,
    t4: protocol::TimestampFormat,
    current_t1: protocol::TimestampFormat,
    prev_t1: Option<protocol::TimestampFormat>,
    prev_t4: Option<protocol::TimestampFormat>,
) -> io::Result<(ClockSample, bool)> {
    if response.origin_timestamp == current_t1 {
        // Basic mode: all timestamps from the same exchange.
        let t4_instant = unix_time::Instant::from(t4);
        let t1_instant = unix_time::timestamp_to_instant(current_t1, &t4_instant);
        let t2_instant = unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
        let t3_instant = unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);
        let (offset, delay) =
            compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);
        Ok((
            ClockSample {
                offset,
                delay,
                age: 0.0,
            },
            false,
        ))
    } else if let (Some(pt1), Some(pt4)) = (prev_t1, prev_t4) {
        if response.origin_timestamp == pt1 {
            // Interleaved mode: server returned more accurate timestamps
            // for the previous exchange.
            let t4_instant = unix_time::Instant::from(pt4);
            let t1_instant = unix_time::timestamp_to_instant(pt1, &t4_instant);
            let t2_instant =
                unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
            let t3_instant =
                unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);
            let (offset, delay) =
                compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);
            Ok((
                ClockSample {
                    offset,
                    delay,
                    age: 0.0,
                },
                true,
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "origin timestamp mismatch: neither basic nor interleaved",
            ))
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "origin timestamp mismatch: response does not match our request",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_basic_mode() {
        let t1 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = protocol::Packet {
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
            origin_timestamp: t1, // Matches current T1 = basic mode
            receive_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 500_000_000,
            },
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 500_000_001,
            },
        };

        let (sample, interleaved) = classify_and_compute(&response, t4, t1, None, None).unwrap();
        assert!(!interleaved);
        assert!(sample.offset.is_finite());
        assert!(sample.delay.is_finite());
    }

    #[test]
    fn test_classify_interleaved_mode() {
        let prev_t1 = protocol::TimestampFormat {
            seconds: 3_913_055_990,
            fraction: 0,
        };
        let prev_t4 = protocol::TimestampFormat {
            seconds: 3_913_055_991,
            fraction: 0,
        };
        let current_t1 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = protocol::Packet {
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
            origin_timestamp: prev_t1, // Matches previous T1 = interleaved mode
            receive_timestamp: protocol::TimestampFormat {
                seconds: 3_913_055_990,
                fraction: 500_000_000,
            },
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_913_055_990,
                fraction: 500_000_001,
            },
        };

        let (sample, interleaved) =
            classify_and_compute(&response, t4, current_t1, Some(prev_t1), Some(prev_t4)).unwrap();
        assert!(interleaved);
        assert!(sample.offset.is_finite());
        assert!(sample.delay.is_finite());
    }

    #[test]
    fn test_classify_mismatch_rejected() {
        let t1 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = protocol::Packet {
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
            origin_timestamp: protocol::TimestampFormat {
                seconds: 999_999_999, // Matches nothing
                fraction: 0,
            },
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 1,
                fraction: 0,
            },
        };

        let result = classify_and_compute(&response, t4, t1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_classify_mismatch_with_prev_values() {
        // Origin doesn't match current OR previous T1.
        let current_t1 = protocol::TimestampFormat {
            seconds: 100,
            fraction: 0,
        };
        let prev_t1 = protocol::TimestampFormat {
            seconds: 90,
            fraction: 0,
        };
        let prev_t4 = protocol::TimestampFormat {
            seconds: 91,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 101,
            fraction: 0,
        };
        let response = protocol::Packet {
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
            origin_timestamp: protocol::TimestampFormat {
                seconds: 999,
                fraction: 0,
            },
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 1,
                fraction: 0,
            },
        };

        let result = classify_and_compute(&response, t4, current_t1, Some(prev_t1), Some(prev_t4));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("neither basic nor interleaved")
        );
    }

    #[test]
    fn test_sync_state_default() {
        let state = NtpSyncState::default();
        assert_eq!(state.offset, 0.0);
        assert_eq!(state.delay, 0.0);
        assert_eq!(state.jitter, 0.0);
        assert_eq!(state.stratum, protocol::MAXSTRAT);
        assert!(!state.interleaved);
        assert_eq!(state.total_responses, 0);
        assert!(!state.nts_authenticated);
    }
}
