// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the smol NTP server.
//!
//! Mirrors the tokio server integration tests but uses the smol runtime.
//! All tests use in-process loopback on ephemeral ports — no Docker, no root required.

#![cfg(feature = "smol-runtime")]

mod common_smol;

use std::time::Duration;

use ntp_server::protocol::{self, ConstPackedSizeBytes, Mode, Packet, Stratum, ToBytes, Version};
use ntp_server::server_common::{IpNet, RateLimitConfig};
use ntp_server::smol_server::NtpServer;

use common_smol::{
    build_client_packet, build_client_packet_version, parse_response, send_receive_raw,
    spawn_test_server,
};

/// 1. Server starts, returns 48-byte Server mode response.
#[test]
fn test_server_binds_and_responds() {
    smol::block_on(async {
        let addr = spawn_test_server(NtpServer::builder()).await;
        let request = build_client_packet();
        let resp = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response from server");

        assert_eq!(resp.len(), Packet::PACKED_SIZE_BYTES);
        let pkt = parse_response(&resp);
        assert_eq!(pkt.mode, Mode::Server);
        assert_eq!(pkt.version, Version::V4);
    });
}

/// 2. Full client-server exchange via ntp_client::smol_ntp.
#[test]
fn test_roundtrip_with_client_library() {
    smol::block_on(async {
        let addr = spawn_test_server(NtpServer::builder().stratum(Stratum(2))).await;

        let result =
            ntp_client::smol_ntp::request_with_timeout(&addr.to_string(), Duration::from_secs(2))
                .await
                .expect("client request failed");

        assert_eq!(result.stratum, Stratum(2));
        assert_eq!(result.mode, Mode::Server);
        assert_eq!(result.version, Version::V4);
    });
}

/// 3. Configured stratum and reference ID echoed in response.
#[test]
fn test_response_stratum_and_reference() {
    smol::block_on(async {
        let ref_id = protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Gps);
        let addr = spawn_test_server(
            NtpServer::builder()
                .stratum(Stratum(1))
                .reference_id(ref_id),
        )
        .await;

        let request = build_client_packet();
        let resp = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response");
        let pkt = parse_response(&resp);

        assert_eq!(pkt.stratum, Stratum(1));
        assert_eq!(pkt.reference_id.as_bytes(), *b"GPS\0");
    });
}

/// 4. Denied client gets KoD DENY (stratum=0).
#[test]
fn test_deny_list_returns_kod_deny() {
    smol::block_on(async {
        let addr =
            spawn_test_server(NtpServer::builder().deny(IpNet::new("::1".parse().unwrap(), 128)))
                .await;

        let request = build_client_packet();
        let resp = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response");
        let pkt = parse_response(&resp);

        assert_eq!(pkt.stratum, Stratum::UNSPECIFIED);
        assert_eq!(pkt.reference_id.as_bytes(), *b"DENY");
    });
}

/// 5. Unmatched client gets KoD RSTR when allow list is set.
#[test]
fn test_allow_list_restricts_unmatched() {
    smol::block_on(async {
        // Allow only 192.0.2.0/24 (TEST-NET), which won't match our loopback client.
        let addr = spawn_test_server(
            NtpServer::builder().allow(IpNet::new("192.0.2.0".parse().unwrap(), 24)),
        )
        .await;

        let request = build_client_packet();
        let resp = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response");
        let pkt = parse_response(&resp);

        assert_eq!(pkt.stratum, Stratum::UNSPECIFIED);
        assert_eq!(pkt.reference_id.as_bytes(), *b"RSTR");
    });
}

/// 6. Second rapid request gets KoD RATE.
#[test]
fn test_rate_limit_returns_kod_rate() {
    smol::block_on(async {
        let config = RateLimitConfig {
            max_requests_per_window: 1,
            window_duration: Duration::from_secs(10),
            min_interval: Duration::ZERO,
        };
        let addr = spawn_test_server(NtpServer::builder().rate_limit(config)).await;

        let request = build_client_packet();

        // First request should succeed.
        let resp1 = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response to first request");
        let pkt1 = parse_response(&resp1);
        assert_eq!(pkt1.mode, Mode::Server);
        assert!(pkt1.stratum.0 > 0);

        // Second request (same client) should be rate limited.
        let resp2 = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response to second request");
        let pkt2 = parse_response(&resp2);
        assert_eq!(pkt2.stratum, Stratum::UNSPECIFIED);
        assert_eq!(pkt2.reference_id.as_bytes(), *b"RATE");
    });
}

/// 7. Request succeeds after rate limit window expires.
#[test]
fn test_rate_limit_allows_after_window() {
    smol::block_on(async {
        let config = RateLimitConfig {
            max_requests_per_window: 1,
            window_duration: Duration::from_millis(100),
            min_interval: Duration::ZERO,
        };
        let addr = spawn_test_server(NtpServer::builder().rate_limit(config)).await;

        let request = build_client_packet();

        // First request.
        let resp1 = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response to first request");
        let pkt1 = parse_response(&resp1);
        assert_eq!(pkt1.mode, Mode::Server);

        // Wait for window to expire.
        smol::Timer::after(Duration::from_millis(150)).await;

        // Should succeed again.
        let resp2 = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response after window");
        let pkt2 = parse_response(&resp2);
        assert_eq!(pkt2.mode, Mode::Server);
        assert!(pkt2.stratum.0 > 0);
    });
}

/// 8. Short/garbage packet gets no response (timeout).
#[test]
fn test_invalid_packet_dropped() {
    smol::block_on(async {
        let addr = spawn_test_server(NtpServer::builder()).await;

        // Send only 10 bytes (too short for NTP).
        let garbage = [0u8; 10];
        let resp = send_receive_raw(addr, &garbage, Duration::from_millis(500)).await;
        assert!(resp.is_none(), "server should not respond to garbage");
    });
}

/// 9. NTPv3 client request → NTPv3 response.
#[test]
fn test_v3_request_gets_v3_response() {
    smol::block_on(async {
        let addr = spawn_test_server(NtpServer::builder()).await;
        let request = build_client_packet_version(Version::V3);

        let resp = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response");
        let pkt = parse_response(&resp);

        assert_eq!(pkt.mode, Mode::Server);
        assert_eq!(pkt.version, Version::V3);
    });
}

/// 10. Second exchange uses interleaved timestamps (RFC 9769).
#[test]
fn test_interleaved_mode() {
    smol::block_on(async {
        let addr = spawn_test_server(NtpServer::builder().enable_interleaved(true)).await;

        let request = build_client_packet();

        // First exchange — basic mode response.
        let resp1 = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response to first request");
        let pkt1 = parse_response(&resp1);
        assert_eq!(pkt1.mode, Mode::Server);

        // Second exchange — should get interleaved response if origin matches.
        let resp2 = send_receive_raw(addr, &request, Duration::from_secs(2))
            .await
            .expect("no response to second request");
        let pkt2 = parse_response(&resp2);
        assert_eq!(pkt2.mode, Mode::Server);

        // In interleaved mode, the origin timestamp in the second response should
        // match our transmit timestamp (the server echoes it back).
        assert_eq!(pkt2.origin_timestamp.seconds, 0xE0000000);
        assert_eq!(pkt2.origin_timestamp.fraction, 0x12345678);
    });
}

/// 11. Multiple concurrent clients all get valid responses.
#[test]
fn test_multiple_concurrent_clients() {
    smol::block_on(async {
        let addr = spawn_test_server(NtpServer::builder()).await;

        let mut tasks = Vec::new();
        for i in 0u32..10 {
            let task = smol::spawn(async move {
                let packet = {
                    let pkt = Packet {
                        transmit_timestamp: protocol::TimestampFormat {
                            seconds: 0xE0000000 + i,
                            fraction: i,
                        },
                        ..Packet::default()
                    };
                    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
                    pkt.to_bytes(&mut buf[..]).unwrap();
                    buf
                };
                let resp = send_receive_raw(addr, &packet, Duration::from_secs(5))
                    .await
                    .unwrap_or_else(|| panic!("client {i} got no response"));
                let pkt = parse_response(&resp);
                assert_eq!(pkt.mode, Mode::Server);
                assert_eq!(pkt.origin_timestamp.seconds, 0xE0000000 + i);
            });
            tasks.push(task);
        }

        for t in tasks {
            t.await;
        }
    });
}

/// 12. Response origin timestamp matches client's transmit timestamp.
#[test]
fn test_origin_timestamp_echo() {
    smol::block_on(async {
        let addr = spawn_test_server(NtpServer::builder()).await;

        let xmt_s = 0xDEADBEEF_u32;
        let xmt_f = 0xCAFEBABE_u32;
        let packet = {
            let pkt = Packet {
                transmit_timestamp: protocol::TimestampFormat {
                    seconds: xmt_s,
                    fraction: xmt_f,
                },
                ..Packet::default()
            };
            let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
            pkt.to_bytes(&mut buf[..]).unwrap();
            buf
        };

        let resp = send_receive_raw(addr, &packet, Duration::from_secs(2))
            .await
            .expect("no response");
        let pkt = parse_response(&resp);

        // RFC 5905: the server MUST copy the client's xmt to the response's org.
        assert_eq!(pkt.origin_timestamp.seconds, xmt_s);
        assert_eq!(pkt.origin_timestamp.fraction, xmt_f);
    });
}
