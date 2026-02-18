// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP broadcast mode (mode 5) support per RFC 5905 Section 8.
//!
//! Broadcast mode enables a server to send unsolicited time packets to a
//! multicast or broadcast address at a configured interval. This is
//! deprecated by BCP 223 (RFC 8633) due to security concerns but is
//! implemented here for RFC 5905 spec completeness.
//!
//! # Security Warning
//!
//! Broadcast mode provides no authentication by default and is vulnerable
//! to spoofing attacks. Use only on trusted networks. Consider using NTS
//! (RFC 8915) for authenticated time synchronization instead.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::protocol::{self, ConstPackedSizeBytes, WriteBytes};
use crate::server_common::ServerSystemState;
use crate::unix_time;

/// Configuration for broadcast mode transmission.
#[derive(Clone, Debug)]
pub struct BroadcastConfig {
    /// Destination address for broadcast/multicast packets.
    ///
    /// Typical values:
    /// - `224.0.1.1:123` — NTP multicast group (IPv4)
    /// - `[ff02::101]:123` — NTP multicast group (IPv6, link-local)
    /// - `255.255.255.255:123` — Limited broadcast (IPv4)
    pub dest_addr: SocketAddr,
    /// Interval between broadcast packets in seconds.
    pub interval_secs: u64,
    /// Poll exponent included in broadcast packets (log2 seconds).
    pub poll_exponent: u8,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        BroadcastConfig {
            dest_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 1, 1), 123)),
            interval_secs: 64,
            poll_exponent: 6,
        }
    }
}

/// Build a broadcast (mode 5) NTP packet.
///
/// Per RFC 5905 Section 8, a broadcast packet contains the server's system
/// state fields (stratum, root delay, root dispersion, reference ID, etc.)
/// with mode set to 5 (Broadcast). The transmit timestamp (T3) is set to
/// the current time.
///
/// The origin and receive timestamps are zero since there is no client
/// request to echo.
pub fn build_broadcast_packet(
    server_state: &ServerSystemState,
    poll_exponent: u8,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: server_state.leap_indicator,
        version: protocol::Version::V4,
        mode: protocol::Mode::Broadcast,
        stratum: server_state.stratum,
        poll: poll_exponent as i8,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_timestamp: server_state.reference_timestamp,
        origin_timestamp: protocol::TimestampFormat::default(),
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: unix_time::Instant::now().into(),
    }
}

/// Serialize a broadcast packet to bytes ready for transmission.
///
/// Returns the serialized 48-byte NTP packet.
pub fn serialize_broadcast_packet(
    server_state: &ServerSystemState,
    poll_exponent: u8,
) -> io::Result<[u8; protocol::Packet::PACKED_SIZE_BYTES]> {
    let packet = build_broadcast_packet(server_state, poll_exponent);
    let mut buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut buf[..]).write_bytes(packet)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ReadBytes;

    fn test_server_state() -> ServerSystemState {
        ServerSystemState {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            stratum: protocol::Stratum(2),
            precision: -20,
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
                seconds: 3_913_000_000,
                fraction: 0,
            },
            #[cfg(feature = "ntpv5")]
            timescale: ntp_proto::protocol::ntpv5::Timescale::Utc,
            #[cfg(feature = "ntpv5")]
            era: 0,
            #[cfg(feature = "ntpv5")]
            bloom_filter: ntp_proto::protocol::bloom::BloomFilter::new(),
            #[cfg(feature = "ntpv5")]
            v5_reference_id: [0u8; 15],
        }
    }

    #[test]
    fn test_broadcast_packet_mode() {
        let state = test_server_state();
        let packet = build_broadcast_packet(&state, 6);
        assert_eq!(packet.mode, protocol::Mode::Broadcast);
    }

    #[test]
    fn test_broadcast_packet_version() {
        let state = test_server_state();
        let packet = build_broadcast_packet(&state, 6);
        assert_eq!(packet.version, protocol::Version::V4);
    }

    #[test]
    fn test_broadcast_packet_server_state() {
        let state = test_server_state();
        let packet = build_broadcast_packet(&state, 10);
        assert_eq!(packet.stratum, protocol::Stratum(2));
        assert_eq!(packet.precision, -20);
        assert_eq!(packet.root_delay.fraction, 100);
        assert_eq!(packet.root_dispersion.fraction, 200);
        assert_eq!(packet.reference_timestamp.seconds, 3_913_000_000);
        assert_eq!(packet.poll, 10);
    }

    #[test]
    fn test_broadcast_packet_has_transmit_timestamp() {
        let state = test_server_state();
        let packet = build_broadcast_packet(&state, 6);
        assert!(
            packet.transmit_timestamp.seconds > 0,
            "transmit timestamp should be non-zero"
        );
    }

    #[test]
    fn test_broadcast_packet_origin_receive_zero() {
        let state = test_server_state();
        let packet = build_broadcast_packet(&state, 6);
        assert_eq!(packet.origin_timestamp.seconds, 0);
        assert_eq!(packet.origin_timestamp.fraction, 0);
        assert_eq!(packet.receive_timestamp.seconds, 0);
        assert_eq!(packet.receive_timestamp.fraction, 0);
    }

    #[test]
    fn test_serialize_broadcast_packet() {
        let state = test_server_state();
        let buf = serialize_broadcast_packet(&state, 6).unwrap();
        assert_eq!(buf.len(), protocol::Packet::PACKED_SIZE_BYTES);

        let parsed: protocol::Packet = (&buf[..protocol::Packet::PACKED_SIZE_BYTES])
            .read_bytes()
            .unwrap();
        assert_eq!(parsed.mode, protocol::Mode::Broadcast);
        assert_eq!(parsed.stratum, protocol::Stratum(2));
    }

    #[test]
    fn test_broadcast_config_default() {
        let config = BroadcastConfig::default();
        assert_eq!(
            config.dest_addr,
            "224.0.1.1:123".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.interval_secs, 64);
        assert_eq!(config.poll_exponent, 6);
    }

    #[test]
    fn test_broadcast_packet_leap_indicator() {
        let mut state = test_server_state();
        state.leap_indicator = protocol::LeapIndicator::AddOne;
        let packet = build_broadcast_packet(&state, 6);
        assert_eq!(packet.leap_indicator, protocol::LeapIndicator::AddOne);
    }
}
