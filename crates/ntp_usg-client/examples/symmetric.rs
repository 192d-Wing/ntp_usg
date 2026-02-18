// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP symmetric active/passive mode demonstration (RFC 5905 modes 1 & 2).
//!
//! Symmetric mode is used for peer-to-peer time synchronization between
//! two NTP servers of similar stratum. Unlike client/server mode, both
//! peers exchange time information bidirectionally.
//!
//! This example sends a symmetric active request to a server and
//! displays the response. In a real deployment, both peers would
//! continuously exchange symmetric packets.
//!
//! Run with:
//! ```sh
//! cargo run -p ntp_usg-client --example symmetric --features "symmetric,tokio"
//! ```

use std::io;
use std::time::Duration;

use ntp_client::protocol::{self, ConstPackedSizeBytes, FromBytes, Mode, Packet, Stratum};
use ntp_client::symmetric::{LocalSystemState, build_symmetric_request};

#[tokio::main]
async fn main() -> io::Result<()> {
    let peer = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:123".to_string());

    println!("NTP Symmetric Mode Demo (RFC 5905 modes 1 & 2)");
    println!("================================================");
    println!("Peer: {peer}");

    // Our local system state — in a real deployment this would
    // reflect our actual synchronization status.
    let local_state = LocalSystemState {
        stratum: Stratum(3),
        reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
        ..LocalSystemState::default()
    };

    println!("\nLocal state:");
    println!("  Stratum:      {}", local_state.stratum.0);
    println!("  Reference ID: {:?}", local_state.reference_id);

    // Build a symmetric active request (mode 1).
    let (packet_bytes, t1) = build_symmetric_request(&local_state)?;

    println!("\nSending symmetric active request (mode 1)...");
    println!("  Transmit timestamp: {}.{:08X}", t1.seconds, t1.fraction);

    // Send to peer.
    let sock = tokio::net::UdpSocket::bind("[::]:0").await?;
    sock.send_to(&packet_bytes, &peer).await?;

    // Receive response with timeout.
    let mut recv_buf = [0u8; 2048];
    let len = match tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut recv_buf)).await {
        Ok(Ok(len)) => len,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            eprintln!("\nTimeout — peer at {peer} did not respond.");
            eprintln!("(Most servers respond to symmetric active with server mode.)");
            return Ok(());
        }
    };

    // Parse response.
    if len < Packet::PACKED_SIZE_BYTES {
        eprintln!("Response too short ({len} bytes)");
        return Ok(());
    }
    let (resp, _) = Packet::from_bytes(&recv_buf[..len]).map_err(io::Error::other)?;

    println!("\nResponse ({len} bytes):");
    println!("  Mode:            {:?}", resp.mode);
    println!("  Stratum:         {}", resp.stratum.0);
    println!("  Reference ID:    {:?}", resp.reference_id);
    println!(
        "  Origin TS:       {}.{:08X}",
        resp.origin_timestamp.seconds, resp.origin_timestamp.fraction
    );
    println!(
        "  Receive TS:      {}.{:08X}",
        resp.receive_timestamp.seconds, resp.receive_timestamp.fraction
    );
    println!(
        "  Transmit TS:     {}.{:08X}",
        resp.transmit_timestamp.seconds, resp.transmit_timestamp.fraction
    );

    match resp.mode {
        Mode::SymmetricPassive => {
            println!("\nPeer responded in symmetric passive mode (mode 2) — ");
            println!("bidirectional peering established.");
        }
        Mode::Server => {
            println!("\nPeer responded in server mode (mode 4) — ");
            println!("standard server, not configured for symmetric peering.");
        }
        other => {
            println!("\nUnexpected response mode: {other:?}");
        }
    }

    Ok(())
}
