// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP broadcast client support per RFC 5905 Section 8.
//!
//! A broadcast client listens for unsolicited mode-5 NTP packets from a
//! broadcast or multicast server. On first receipt it performs a client/server
//! exchange to calibrate the one-way delay, then applies that calibration to
//! subsequent broadcast packets to compute clock offset.
//!
//! # Security Warning
//!
//! Broadcast mode is deprecated by BCP 223 (RFC 8633) due to vulnerability
//! to spoofing attacks. Use only on trusted networks.
//!
//! # Calibration
//!
//! Since broadcast packets only contain T3 (server transmit time), the
//! one-way delay cannot be measured from a single packet. The client
//! performs an initial unicast exchange to measure the round-trip delay,
//! then uses `delay / 2` as the estimated one-way propagation delay.
//!
//! For subsequent broadcast packets:
//! - `offset = T3 + calibration_delay - T4`
//!
//! where T3 is the broadcast transmit timestamp and T4 is the local receive
//! time.

use crate::protocol;
use crate::unix_time;
use std::io;

/// Result of parsing a broadcast NTP packet.
#[derive(Clone, Debug)]
pub struct BroadcastPacket {
    /// The parsed NTP packet (mode 5).
    pub packet: protocol::Packet,
    /// Local receive timestamp (T4).
    pub destination_timestamp: protocol::TimestampFormat,
}

/// Validate and parse a received broadcast (mode 5) NTP packet.
///
/// Checks that:
/// - The packet is at least 48 bytes
/// - Mode is Broadcast (5)
/// - Transmit timestamp is non-zero
/// - The server is synchronized (LI != Unknown with non-zero stratum)
///
/// Returns the parsed packet and the local receive timestamp (T4).
pub fn parse_broadcast_packet(
    recv_buf: &[u8],
    recv_len: usize,
) -> io::Result<BroadcastPacket> {
    use protocol::{ConstPackedSizeBytes, ReadBytes};

    // Record T4 immediately.
    let t4_instant = unix_time::Instant::now();
    let t4: protocol::TimestampFormat = t4_instant.into();

    if recv_len < protocol::Packet::PACKED_SIZE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broadcast packet too short",
        ));
    }

    let packet: protocol::Packet =
        (&recv_buf[..protocol::Packet::PACKED_SIZE_BYTES]).read_bytes()?;

    if packet.mode != protocol::Mode::Broadcast {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected broadcast mode (5), got {:?}",
                packet.mode
            ),
        ));
    }

    if packet.transmit_timestamp.seconds == 0 && packet.transmit_timestamp.fraction == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broadcast transmit timestamp is zero",
        ));
    }

    if packet.leap_indicator == protocol::LeapIndicator::Unknown
        && packet.stratum != protocol::Stratum::UNSPECIFIED
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broadcast server reports unsynchronized clock",
        ));
    }

    Ok(BroadcastPacket {
        packet,
        destination_timestamp: t4,
    })
}

/// Compute clock offset from a broadcast packet using a calibrated one-way delay.
///
/// The offset is computed as:
///   `offset = T3 - T4 + calibration_delay`
///
/// where:
/// - T3 = broadcast transmit timestamp (server time)
/// - T4 = local receive timestamp (client time)
/// - calibration_delay = estimated one-way propagation delay (from unicast calibration)
///
/// A positive offset means the local clock is behind the server.
pub fn compute_broadcast_offset(
    broadcast: &BroadcastPacket,
    calibration_delay: f64,
) -> f64 {
    let t3 = unix_time::Instant::from(broadcast.packet.transmit_timestamp);
    let t4 = unix_time::Instant::from(broadcast.destination_timestamp);

    let t3_secs = t3.secs() as f64 + (t3.subsec_nanos() as f64 / 1e9);
    let t4_secs = t4.secs() as f64 + (t4.subsec_nanos() as f64 / 1e9);

    (t3_secs - t4_secs) + calibration_delay
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::WriteBytes;

    fn make_broadcast_packet(
        stratum: protocol::Stratum,
        li: protocol::LeapIndicator,
        xmt_seconds: u32,
    ) -> [u8; 48] {
        let pkt = protocol::Packet {
            leap_indicator: li,
            version: protocol::Version::V4,
            mode: protocol::Mode::Broadcast,
            stratum,
            poll: 6,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat {
                seconds: 3_913_000_000,
                fraction: 0,
            },
            origin_timestamp: protocol::TimestampFormat::default(),
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: xmt_seconds,
                fraction: 0,
            },
        };
        let mut buf = [0u8; 48];
        (&mut buf[..]).write_bytes(pkt).unwrap();
        buf
    }

    #[test]
    fn test_parse_valid_broadcast() {
        let buf = make_broadcast_packet(
            protocol::Stratum(2),
            protocol::LeapIndicator::NoWarning,
            3_913_056_000,
        );
        let result = parse_broadcast_packet(&buf, 48);
        assert!(result.is_ok());
        let bcast = result.unwrap();
        assert_eq!(bcast.packet.mode, protocol::Mode::Broadcast);
        assert_eq!(bcast.packet.stratum, protocol::Stratum(2));
        assert_eq!(bcast.packet.transmit_timestamp.seconds, 3_913_056_000);
    }

    #[test]
    fn test_parse_rejects_short_packet() {
        let buf = [0u8; 48];
        let result = parse_broadcast_packet(&buf, 47);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_parse_rejects_non_broadcast_mode() {
        // Build a mode-4 (Server) packet
        let pkt = protocol::Packet {
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
            origin_timestamp: protocol::TimestampFormat::default(),
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 1,
            },
        };
        let mut buf = [0u8; 48];
        (&mut buf[..]).write_bytes(pkt).unwrap();
        let result = parse_broadcast_packet(&buf, 48);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("broadcast mode"));
    }

    #[test]
    fn test_parse_rejects_zero_transmit() {
        let buf = make_broadcast_packet(
            protocol::Stratum(2),
            protocol::LeapIndicator::NoWarning,
            0,
        );
        let result = parse_broadcast_packet(&buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("transmit timestamp is zero")
        );
    }

    #[test]
    fn test_parse_rejects_unsynchronized() {
        let buf = make_broadcast_packet(
            protocol::Stratum(2),
            protocol::LeapIndicator::Unknown,
            3_913_056_000,
        );
        let result = parse_broadcast_packet(&buf, 48);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsynchronized"));
    }

    #[test]
    fn test_parse_allows_li_unknown_stratum_zero() {
        // LI=Unknown with stratum 0 is acceptable (reference clock or KoD)
        let buf = make_broadcast_packet(
            protocol::Stratum::UNSPECIFIED,
            protocol::LeapIndicator::Unknown,
            3_913_056_000,
        );
        let result = parse_broadcast_packet(&buf, 48);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_broadcast_offset_zero_delay() {
        // When T3 == T4 and delay == 0, offset should be ~0
        let t = unix_time::Instant::now();
        let ts: protocol::TimestampFormat = t.into();
        let bcast = BroadcastPacket {
            packet: protocol::Packet {
                leap_indicator: protocol::LeapIndicator::NoWarning,
                version: protocol::Version::V4,
                mode: protocol::Mode::Broadcast,
                stratum: protocol::Stratum(2),
                poll: 6,
                precision: -20,
                root_delay: protocol::ShortFormat::default(),
                root_dispersion: protocol::ShortFormat::default(),
                reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
                reference_timestamp: protocol::TimestampFormat::default(),
                origin_timestamp: protocol::TimestampFormat::default(),
                receive_timestamp: protocol::TimestampFormat::default(),
                transmit_timestamp: ts,
            },
            destination_timestamp: ts,
        };
        let offset = compute_broadcast_offset(&bcast, 0.0);
        assert!(
            offset.abs() < 0.001,
            "expected ~0 offset, got {offset}"
        );
    }

    #[test]
    fn test_compute_broadcast_offset_with_delay() {
        // T3 and T4 are the same, but there's a 0.05s calibration delay
        let t = unix_time::Instant::now();
        let ts: protocol::TimestampFormat = t.into();
        let bcast = BroadcastPacket {
            packet: protocol::Packet {
                leap_indicator: protocol::LeapIndicator::NoWarning,
                version: protocol::Version::V4,
                mode: protocol::Mode::Broadcast,
                stratum: protocol::Stratum(2),
                poll: 6,
                precision: -20,
                root_delay: protocol::ShortFormat::default(),
                root_dispersion: protocol::ShortFormat::default(),
                reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
                reference_timestamp: protocol::TimestampFormat::default(),
                origin_timestamp: protocol::TimestampFormat::default(),
                receive_timestamp: protocol::TimestampFormat::default(),
                transmit_timestamp: ts,
            },
            destination_timestamp: ts,
        };
        let offset = compute_broadcast_offset(&bcast, 0.05);
        assert!(
            (offset - 0.05).abs() < 0.001,
            "expected ~0.05 offset, got {offset}"
        );
    }

    #[test]
    fn test_broadcast_packet_has_destination_timestamp() {
        let buf = make_broadcast_packet(
            protocol::Stratum(2),
            protocol::LeapIndicator::NoWarning,
            3_913_056_000,
        );
        let bcast = parse_broadcast_packet(&buf, 48).unwrap();
        assert!(
            bcast.destination_timestamp.seconds > 0,
            "destination timestamp should be non-zero"
        );
    }
}
