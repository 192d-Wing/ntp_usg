// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for broadcast mode NTP parsing and offset computation.

#![cfg(feature = "broadcast")]

use ntp_client::broadcast_client::{compute_broadcast_offset, parse_broadcast_packet};
use ntp_proto::protocol::{
    ConstPackedSizeBytes, LeapIndicator, Mode, Packet, PrimarySource, ReferenceIdentifier,
    ShortFormat, Stratum, TimestampFormat, WriteBytes,
};

fn make_broadcast_buf(
    stratum: Stratum,
    li: LeapIndicator,
    xmt: TimestampFormat,
) -> [u8; Packet::PACKED_SIZE_BYTES] {
    let pkt = Packet {
        leap_indicator: li,
        version: ntp_proto::protocol::Version::V4,
        mode: Mode::Broadcast,
        stratum,
        poll: 6,
        precision: -20,
        root_delay: ShortFormat::default(),
        root_dispersion: ShortFormat::default(),
        reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Gps),
        reference_timestamp: TimestampFormat::default(),
        origin_timestamp: TimestampFormat::default(),
        receive_timestamp: TimestampFormat::default(),
        transmit_timestamp: xmt,
    };
    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
    (&mut buf[..]).write_bytes(pkt).unwrap();
    buf
}

#[test]
fn test_parse_valid_broadcast_packet() {
    let xmt = TimestampFormat {
        seconds: 3_913_056_000,
        fraction: 0x8000_0000,
    };
    let buf = make_broadcast_buf(Stratum(2), LeapIndicator::NoWarning, xmt);

    let bcast = parse_broadcast_packet(&buf, Packet::PACKED_SIZE_BYTES).unwrap();
    assert_eq!(bcast.packet.mode, Mode::Broadcast);
    assert_eq!(bcast.packet.transmit_timestamp, xmt);
}

#[test]
fn test_parse_rejects_client_mode_packet() {
    let mut buf = make_broadcast_buf(
        Stratum(2),
        LeapIndicator::NoWarning,
        TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        },
    );
    // Overwrite mode field: byte 0 bits [2:0] from Broadcast (5) to Client (3).
    buf[0] = (buf[0] & 0xF8) | Mode::Client as u8;

    let result = parse_broadcast_packet(&buf, Packet::PACKED_SIZE_BYTES);
    assert!(result.is_err());
}

#[test]
fn test_parse_rejects_zero_transmit() {
    let buf = make_broadcast_buf(
        Stratum(2),
        LeapIndicator::NoWarning,
        TimestampFormat::default(), // all zeros
    );

    let result = parse_broadcast_packet(&buf, Packet::PACKED_SIZE_BYTES);
    assert!(result.is_err());
}

#[test]
fn test_parse_rejects_short_buffer() {
    let buf = [0u8; 10];
    let result = parse_broadcast_packet(&buf, 10);
    assert!(result.is_err());
}

#[test]
fn test_compute_offset_with_calibration_delay() {
    let xmt = TimestampFormat {
        seconds: 3_913_056_000,
        fraction: 0,
    };
    let buf = make_broadcast_buf(Stratum(2), LeapIndicator::NoWarning, xmt);
    let bcast = parse_broadcast_packet(&buf, Packet::PACKED_SIZE_BYTES).unwrap();

    let offset_with_delay = compute_broadcast_offset(&bcast, 0.050);
    let offset_without_delay = compute_broadcast_offset(&bcast, 0.0);

    // Calibration delay shifts the offset by exactly that amount.
    let delta = (offset_with_delay - offset_without_delay - 0.050).abs();
    assert!(delta < 1e-6, "delay difference is {}", delta);
}
