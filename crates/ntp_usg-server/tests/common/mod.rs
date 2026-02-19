// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for server integration tests.

use std::net::SocketAddr;
use std::time::Duration;

use ntp_server::protocol::{self, ConstPackedSizeBytes, FromBytes, Packet, ToBytes, Version};
use tokio::net::UdpSocket;

/// Spawn a test server on an ephemeral port and return its bound address.
///
/// The server runs in a background tokio task. It will shut down when the
/// tokio runtime is dropped.
pub(crate) async fn spawn_test_server(builder: ntp_server::server::NtpServerBuilder) -> SocketAddr {
    let server = builder
        .listen("[::]:0")
        .build()
        .await
        .expect("failed to bind test server");
    let bound = server.local_addr().expect("failed to get local addr");
    // Replace unspecified address with loopback for test connectivity.
    let addr = SocketAddr::new(
        if bound.ip().is_unspecified() {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        } else {
            bound.ip()
        },
        bound.port(),
    );
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    // Small yield to ensure the server task is running.
    tokio::time::sleep(Duration::from_millis(10)).await;
    addr
}

/// Build a minimal valid NTPv4 client request packet (48 bytes).
pub(crate) fn build_client_packet() -> [u8; Packet::PACKED_SIZE_BYTES] {
    let packet = Packet {
        transmit_timestamp: protocol::TimestampFormat {
            seconds: 0xE0000000,
            fraction: 0x12345678,
        },
        ..Packet::default()
    };
    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
    packet.to_bytes(&mut buf[..]).expect("failed to serialize");
    buf
}

/// Build a client request with a specific NTP version.
#[allow(dead_code)]
pub(crate) fn build_client_packet_version(version: Version) -> [u8; Packet::PACKED_SIZE_BYTES] {
    let packet = Packet {
        version,
        transmit_timestamp: protocol::TimestampFormat {
            seconds: 0xE0000000,
            fraction: 0xAABBCCDD,
        },
        ..Packet::default()
    };
    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
    packet.to_bytes(&mut buf[..]).expect("failed to serialize");
    buf
}

/// Send a raw UDP packet to `addr` and receive the response with a timeout.
///
/// Returns `None` if the server doesn't respond within the timeout.
pub(crate) async fn send_receive_raw(
    addr: SocketAddr,
    packet: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("[::]:0").await.expect("bind failed");
    sock.send_to(packet, addr).await.expect("send failed");

    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            buf.truncate(len);
            Some(buf)
        }
        _ => None,
    }
}

/// Parse a response buffer into a Packet.
pub(crate) fn parse_response(buf: &[u8]) -> Packet {
    let (pkt, _) = Packet::from_bytes(buf).expect("failed to parse response");
    pkt
}
