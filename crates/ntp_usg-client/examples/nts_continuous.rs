// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example: Continuous NTP client with NTS authentication.
//!
//! Run with: `cargo run --example nts_continuous --features nts`

use ntp_client::client::NtpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting continuous NTS-authenticated NTP client...");
    println!("Performing NTS-KE with time.cloudflare.com...");

    let (client, mut state_rx) = NtpClient::builder()
        .nts_server("time.cloudflare.com")
        .min_poll(4) // 16 seconds
        .max_poll(6) // 64 seconds (short for demo)
        .build()
        .await?;

    println!("NTS-KE complete. Press Ctrl+C to stop.\n");

    // Spawn the poll loop in the background.
    tokio::spawn(client.run());

    // Periodically print the current sync state.
    loop {
        state_rx.changed().await?;
        let state = state_rx.borrow();
        println!(
            "Offset: {:+.6}s | Delay: {:.6}s | Jitter: {:.6}s | Stratum: {} | NTS: {} | Responses: {}",
            state.offset,
            state.delay,
            state.jitter,
            state.stratum,
            state.nts_authenticated,
            state.total_responses
        );
    }
}
