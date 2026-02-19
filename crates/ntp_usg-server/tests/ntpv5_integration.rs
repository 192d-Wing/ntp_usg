// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for NTPv5 client-server communication.

#![cfg(all(feature = "tokio", feature = "ntpv5"))]

mod common;

use std::time::Duration;

use ntp_proto::extension::write_extension_fields_buf;
use ntp_proto::ntpv5_ext::{DraftIdentification, Padding};
use ntp_proto::protocol::ntpv5::{NtpV5Flags, PacketV5, Time32, Timescale};
use ntp_proto::protocol::{
    ConstPackedSizeBytes, FromBytes, LeapIndicator, Mode, Stratum, TimestampFormat, ToBytes,
    Version,
};
use ntp_server::server::NtpServer;

use common::{build_client_packet, parse_response, send_receive_raw, spawn_test_server};

/// Build a V5 client request with Draft Identification + padding to 228 bytes.
fn build_v5_client_buf(client_cookie: u64) -> Vec<u8> {
    let target_len = 228usize;
    let pkt = PacketV5 {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V5,
        mode: Mode::Client,
        stratum: Stratum::UNSPECIFIED,
        poll: 6,
        precision: 0,
        root_delay: Time32(0),
        root_dispersion: Time32(0),
        timescale: Timescale::Utc,
        era: 0,
        flags: NtpV5Flags(0),
        server_cookie: 0,
        client_cookie,
        receive_timestamp: TimestampFormat::default(),
        transmit_timestamp: TimestampFormat {
            seconds: 0xE000_0000,
            fraction: 0x1234_5678,
        },
    };

    let mut buf = vec![0u8; target_len];
    pkt.to_bytes(&mut buf[..PacketV5::PACKED_SIZE_BYTES])
        .unwrap();

    // Write Draft Identification extension.
    let draft_ext = DraftIdentification::current().to_extension_field();
    let ext_written =
        write_extension_fields_buf(&[draft_ext], &mut buf[PacketV5::PACKED_SIZE_BYTES..]).unwrap();

    // Fill remaining with Padding.
    let used = PacketV5::PACKED_SIZE_BYTES + ext_written;
    let remaining = target_len - used;
    if remaining >= 4 {
        let pad = Padding {
            size: remaining - 4,
        }
        .to_extension_field();
        write_extension_fields_buf(&[pad], &mut buf[used..]).unwrap();
    }

    buf
}

/// Send a V5 client request and verify the server responds with V5.
#[tokio::test]
async fn test_v5_request_gets_v5_response() {
    let addr = spawn_test_server(NtpServer::builder()).await;

    let client_cookie = 0xDEAD_BEEF_CAFE_BABE_u64;
    let send_buf = build_v5_client_buf(client_cookie);

    let resp = send_receive_raw(addr, &send_buf, Duration::from_secs(2))
        .await
        .expect("no response from server for V5 request");

    // Response should be parseable as V5.
    assert!(resp.len() >= PacketV5::PACKED_SIZE_BYTES);
    let (resp_pkt, _) = PacketV5::from_bytes(&resp).expect("failed to parse V5 response");
    assert_eq!(resp_pkt.version, Version::V5);
    assert_eq!(resp_pkt.mode, Mode::Server);
    assert_eq!(resp_pkt.client_cookie, client_cookie);
}

/// A V4 client should still get a V4 response even when the server supports V5.
#[tokio::test]
async fn test_v4_client_still_works_with_v5_server() {
    let addr = spawn_test_server(NtpServer::builder()).await;

    let request = build_client_packet();
    let resp = send_receive_raw(addr, &request, Duration::from_secs(2))
        .await
        .expect("no response from server");

    let pkt = parse_response(&resp);
    assert_eq!(pkt.version, Version::V4);
    assert_eq!(pkt.mode, Mode::Server);
}

/// V5 response length should match request length.
#[tokio::test]
async fn test_v5_response_matches_request_length() {
    let addr = spawn_test_server(NtpServer::builder()).await;

    let send_buf = build_v5_client_buf(0xCAFE_BABE_1234_5678);

    let resp = send_receive_raw(addr, &send_buf, Duration::from_secs(2))
        .await
        .expect("no response from server");

    assert_eq!(
        resp.len(),
        send_buf.len(),
        "V5 response should match request length"
    );
}
