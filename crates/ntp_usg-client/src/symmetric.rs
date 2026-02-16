// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Symmetric active/passive mode support per RFC 5905 Sections 8-9.
//!
//! Symmetric mode enables peer-to-peer time synchronization where both
//! endpoints can contribute clock information. In this mode:
//! - We send **mode 1** (symmetric active) requests, including our own
//!   stratum, root delay, root dispersion, and reference information.
//! - The peer responds with **mode 2** (symmetric passive) or mode 1
//!   if it also has an active association with us.
//!
//! # Differences from Client Mode
//!
//! | Field | Client Mode (3) | Symmetric Active (1) |
//! |-------|----------------|---------------------|
//! | Mode  | 3 (Client)     | 1 (SymmetricActive) |
//! | Stratum | 0            | Our stratum         |
//! | Root delay | 0         | Our root delay      |
//! | Root dispersion | 0    | Our root dispersion |
//! | Reference ID | 0       | Our reference ID    |
//! | Reference timestamp | 0 | Our ref timestamp  |

use crate::protocol;
use crate::protocol::{ConstPackedSizeBytes, WriteBytes};
use crate::unix_time;
use std::io;

/// Local system state included in symmetric active request packets.
///
/// These fields describe our clock quality to the peer, enabling mutual
/// synchronization per RFC 5905 Section 9.
#[derive(Clone, Debug)]
pub struct LocalSystemState {
    /// Our stratum level.
    pub stratum: protocol::Stratum,
    /// Our root delay.
    pub root_delay: protocol::ShortFormat,
    /// Our root dispersion.
    pub root_dispersion: protocol::ShortFormat,
    /// Our reference identifier.
    pub reference_id: protocol::ReferenceIdentifier,
    /// When our clock was last set or corrected.
    pub reference_timestamp: protocol::TimestampFormat,
}

impl Default for LocalSystemState {
    fn default() -> Self {
        LocalSystemState {
            stratum: protocol::Stratum(16), // Unsynchronized
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([0; 4]),
            reference_timestamp: protocol::TimestampFormat::default(),
        }
    }
}

/// Build a symmetric active (mode 1) NTP request packet.
///
/// Unlike a client request (mode 3), a symmetric active request includes
/// the local system state so the peer can evaluate our clock quality.
///
/// Returns `(packet_bytes, t1_timestamp)`.
pub fn build_symmetric_request(
    local_state: &LocalSystemState,
) -> io::Result<(Vec<u8>, protocol::TimestampFormat)> {
    let t1_instant = unix_time::Instant::now();
    let t1: protocol::TimestampFormat = t1_instant.into();

    let packet = protocol::Packet {
        leap_indicator: protocol::LeapIndicator::NoWarning,
        version: protocol::Version::V4,
        mode: protocol::Mode::SymmetricActive,
        stratum: local_state.stratum,
        poll: 6, // Default poll exponent
        precision: -20,
        root_delay: local_state.root_delay,
        root_dispersion: local_state.root_dispersion,
        reference_id: local_state.reference_id,
        reference_timestamp: local_state.reference_timestamp,
        origin_timestamp: protocol::TimestampFormat::default(),
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: t1,
    };

    let mut buf = vec![0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut buf[..]).write_bytes(packet)?;
    Ok((buf, t1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ReadBytes;

    #[test]
    fn test_build_symmetric_request_mode() {
        let state = LocalSystemState::default();
        let (buf, _t1) = build_symmetric_request(&state).unwrap();
        let packet: protocol::Packet = (&buf[..protocol::Packet::PACKED_SIZE_BYTES])
            .read_bytes()
            .unwrap();
        assert_eq!(packet.mode, protocol::Mode::SymmetricActive);
    }

    #[test]
    fn test_build_symmetric_request_includes_state() {
        let state = LocalSystemState {
            stratum: protocol::Stratum(2),
            root_delay: protocol::ShortFormat {
                seconds: 0,
                fraction: 100,
            },
            root_dispersion: protocol::ShortFormat {
                seconds: 0,
                fraction: 200,
            },
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 0,
            },
        };
        let (buf, _t1) = build_symmetric_request(&state).unwrap();
        let packet: protocol::Packet = (&buf[..protocol::Packet::PACKED_SIZE_BYTES])
            .read_bytes()
            .unwrap();

        assert_eq!(packet.stratum, protocol::Stratum(2));
        assert_eq!(packet.root_delay.fraction, 100);
        assert_eq!(packet.root_dispersion.fraction, 200);
        assert_eq!(packet.reference_timestamp.seconds, 3_913_056_000);
    }

    #[test]
    fn test_build_symmetric_request_has_transmit_timestamp() {
        let state = LocalSystemState::default();
        let (buf, t1) = build_symmetric_request(&state).unwrap();
        let packet: protocol::Packet = (&buf[..protocol::Packet::PACKED_SIZE_BYTES])
            .read_bytes()
            .unwrap();
        assert_eq!(packet.transmit_timestamp, t1);
        assert!(t1.seconds > 0);
    }

    #[test]
    fn test_local_system_state_default() {
        let state = LocalSystemState::default();
        assert_eq!(state.stratum.0, 16); // Unsynchronized
        assert_eq!(state.root_delay.seconds, 0);
        assert_eq!(state.root_dispersion.seconds, 0);
    }

    #[test]
    fn test_build_symmetric_request_version() {
        let state = LocalSystemState::default();
        let (buf, _) = build_symmetric_request(&state).unwrap();
        let packet: protocol::Packet = (&buf[..protocol::Packet::PACKED_SIZE_BYTES])
            .read_bytes()
            .unwrap();
        assert_eq!(packet.version, protocol::Version::V4);
    }

    #[test]
    fn test_symmetric_request_packet_size() {
        let state = LocalSystemState::default();
        let (buf, _) = build_symmetric_request(&state).unwrap();
        assert_eq!(buf.len(), protocol::Packet::PACKED_SIZE_BYTES);
    }
}
