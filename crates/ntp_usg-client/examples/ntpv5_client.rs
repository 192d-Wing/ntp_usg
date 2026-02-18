// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTPv5 client request demonstration (draft-ietf-ntp-ntpv5).
//!
//! Shows how to build and send NTPv5 packets. NTPv5 introduces
//! timescale negotiation, era numbers, and cookie-based interleaved
//! mode as improvements over NTPv4.
//!
//! Note: NTPv5 is a draft protocol. Most public servers do not
//! support it yet. This example demonstrates packet construction
//! and parsing against a local server.
//!
//! Run with:
//! ```sh
//! cargo run -p ntp_usg-client --example ntpv5_client --features "ntpv5,tokio"
//! ```

use std::io;
use std::time::Duration;

use ntp_client::protocol::ntpv5::{NtpV5Flags, PacketV5, Time32, Timescale};
use ntp_client::protocol::{
    ConstPackedSizeBytes, LeapIndicator, Mode, Stratum, TimestampFormat, ToBytes, Version,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1123".to_string());

    println!("NTPv5 Client Demo (draft-ietf-ntp-ntpv5)");
    println!("=========================================");
    println!("Target: {server}");

    // Build an NTPv5 client request.
    let client_cookie: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let request = PacketV5 {
        leap_indicator: LeapIndicator::Unknown,
        version: Version::V5,
        mode: Mode::Client,
        stratum: Stratum::UNSPECIFIED,
        poll: 4,
        precision: -20,
        root_delay: Time32::ZERO,
        root_dispersion: Time32::ZERO,
        timescale: Timescale::Utc,
        era: 0,
        flags: NtpV5Flags(0),
        server_cookie: 0,
        client_cookie,
        receive_timestamp: TimestampFormat {
            seconds: 0,
            fraction: 0,
        },
        transmit_timestamp: TimestampFormat {
            seconds: 0xE800_0000,
            fraction: 0x1234_5678,
        },
    };

    let mut buf = [0u8; PacketV5::PACKED_SIZE_BYTES];
    request.to_bytes(&mut buf)?;

    println!("\nRequest packet ({} bytes):", buf.len());
    println!("  Version:       {:?}", request.version);
    println!("  Mode:          {:?}", request.mode);
    println!("  Timescale:     {:?}", request.timescale);
    println!("  Client cookie: 0x{:016X}", client_cookie);

    // Send the request.
    let sock = tokio::net::UdpSocket::bind("[::]:0").await?;
    sock.send_to(&buf, &server).await?;

    // Receive with timeout.
    let mut recv_buf = [0u8; 2048];
    let len = match tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut recv_buf)).await {
        Ok(Ok(len)) => len,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            eprintln!("\nTimeout — no NTPv5 server at {server}.");
            eprintln!(
                "Start one with: cargo run -p ntp_usg-server --example ntpv5_server --features 'ntpv5,tokio'"
            );
            return Ok(());
        }
    };

    println!("\nResponse ({len} bytes):");

    // Try to parse as NTPv5 first; fall back to V4 detection.
    use ntp_client::protocol::FromBytes;
    match PacketV5::from_bytes(&recv_buf[..len]) {
        Ok((resp, _)) => {
            println!("  Version:       {:?}", resp.version);
            println!("  Mode:          {:?}", resp.mode);
            println!("  Stratum:       {:?}", resp.stratum);
            println!("  Timescale:     {:?}", resp.timescale);
            println!("  Era:           {}", resp.era);
            println!("  Flags:         {:?}", resp.flags);
            println!("  Server cookie: 0x{:016X}", resp.server_cookie);
            println!("  Client cookie: 0x{:016X}", resp.client_cookie);
            println!(
                "  Receive TS:    {}.{:08X}",
                resp.receive_timestamp.seconds, resp.receive_timestamp.fraction
            );
            println!(
                "  Transmit TS:   {}.{:08X}",
                resp.transmit_timestamp.seconds, resp.transmit_timestamp.fraction
            );
        }
        Err(e) => {
            eprintln!("  Failed to parse NTPv5 response: {e}");
            eprintln!("  (Server may have responded with NTPv4 instead)");
        }
    }

    Ok(())
}
