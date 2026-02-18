// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Socket options for precision NTP deployments.
//!
//! Demonstrates DSCP (Differentiated Services Code Point) and
//! IPV6_V6ONLY socket configuration for NTP traffic. DSCP marking
//! with EF (Expedited Forwarding, value 46) ensures NTP packets
//! receive priority queuing in managed networks.
//!
//! Run with:
//! ```sh
//! cargo run -p ntp_usg-client --example socket_opts --features "socket-opts,tokio"
//! ```

use std::io;
use std::time::Duration;

use ntp_client::client::NtpClient;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "time.nist.gov:123".to_string());

    println!("Socket Options Demo");
    println!("====================");
    println!("Server: {server}");
    println!();
    println!("Socket options:");
    println!("  DSCP:     46 (EF — Expedited Forwarding)");
    println!("  V6ONLY:   true (separate IPv4/IPv6 sockets)");
    println!();

    // Build a continuous client with socket options.
    let (client, mut state_rx) = NtpClient::builder()
        .server(&server)
        .min_poll(4) // 16 seconds
        .max_poll(6) // 64 seconds
        // DSCP 46 (EF) marks NTP packets for priority queuing.
        // This is important in enterprise networks where NTP precision
        // depends on consistent low-latency paths.
        .dscp(46)
        // IPV6_V6ONLY prevents an IPv6 socket from accepting IPv4
        // connections. Required when binding to separate v4/v6 addresses.
        .v6only(true)
        .build()
        .await?;

    println!("Client started. Monitoring synchronization state...\n");

    // Spawn the client in the background.
    tokio::spawn(client.run());

    // Monitor state for a few updates.
    let mut updates = 0;
    loop {
        if state_rx.changed().await.is_err() {
            break;
        }
        let state = state_rx.borrow();
        println!(
            "Update {:2}: offset={:+.6}s  delay={:.6}s  jitter={:.6}s  stratum={}",
            updates + 1,
            state.offset,
            state.delay,
            state.jitter,
            state.stratum,
        );
        updates += 1;
        if updates >= 5 {
            break;
        }
    }

    println!("\nDone. DSCP marking ensures NTP traffic gets priority treatment");
    println!("in QoS-aware networks, improving synchronization accuracy.");

    // Allow a brief moment for any pending I/O.
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}
