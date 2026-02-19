// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for symmetric active/passive NTP mode.

#![cfg(feature = "symmetric")]

use ntp_client::symmetric::{LocalSystemState, build_symmetric_request};
use ntp_proto::protocol::{
    ConstPackedSizeBytes, Mode, Packet, ReadBytes, Stratum, TimestampFormat, Version,
};

#[test]
fn test_symmetric_request_is_mode_1() {
    let state = LocalSystemState::default();
    let (buf, _t1) = build_symmetric_request(&state).unwrap();

    let pkt: Packet = (&buf[..Packet::PACKED_SIZE_BYTES]).read_bytes().unwrap();
    assert_eq!(pkt.mode, Mode::SymmetricActive);
    assert_eq!(pkt.version, Version::V4);
}

#[test]
fn test_symmetric_request_carries_local_state() {
    let state = LocalSystemState {
        stratum: Stratum(3),
        ..LocalSystemState::default()
    };
    let (buf, _t1) = build_symmetric_request(&state).unwrap();

    let pkt: Packet = (&buf[..Packet::PACKED_SIZE_BYTES]).read_bytes().unwrap();
    assert_eq!(pkt.stratum, Stratum(3));
}

#[test]
fn test_symmetric_request_has_nonzero_transmit() {
    let state = LocalSystemState::default();
    let (buf, t1) = build_symmetric_request(&state).unwrap();

    let pkt: Packet = (&buf[..Packet::PACKED_SIZE_BYTES]).read_bytes().unwrap();
    assert_eq!(pkt.transmit_timestamp, t1);
    assert!(
        t1.seconds != 0 || t1.fraction != 0,
        "transmit timestamp should be non-zero"
    );
}

#[test]
fn test_symmetric_default_state_is_unsynchronized() {
    let state = LocalSystemState::default();
    assert_eq!(state.stratum, Stratum(16));
    assert_eq!(state.reference_timestamp, TimestampFormat::default());
}
