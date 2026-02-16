// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example: Continuous NTP client with adaptive polling.
//!
//! Run with: `cargo run --example continuous --features tokio`

use ntp::client::NtpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting continuous NTP client...");
    println!("Press Ctrl+C to stop.\n");

    let (client, mut state_rx) = NtpClient::builder()
        .server("pool.ntp.org:123")
        .server("time.google.com:123")
        .min_poll(4) // 16 seconds
        .max_poll(6) // 64 seconds (short for demo)
        .build()
        .await?;

    // Spawn the poll loop in the background.
    tokio::spawn(client.run());

    // Periodically print the current sync state.
    loop {
        state_rx.changed().await?;
        let state = state_rx.borrow();
        println!(
            "Offset: {:+.6}s | Delay: {:.6}s | Jitter: {:.6}s | Stratum: {} | Interleaved: {} | Responses: {}",
            state.offset, state.delay, state.jitter, state.stratum, state.interleaved, state.total_responses
        );
    }
}
