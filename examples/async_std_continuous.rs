// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example: Continuous NTP client using async-std.
//!
//! Run with: `cargo run --example async_std_continuous --features async-std-runtime`

use ntp::async_std_client::NtpClient;
use std::time::Duration;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting continuous NTP client (async-std)...");
    println!("Press Ctrl+C to stop.\n");

    let (client, state) = NtpClient::builder()
        .server("pool.ntp.org:123")
        .server("time.google.com:123")
        .min_poll(4) // 16 seconds
        .max_poll(6) // 64 seconds (short for demo)
        .build()
        .await?;

    // Spawn the poll loop in the background.
    async_std::task::spawn(client.run());

    // Periodically print the current sync state.
    loop {
        async_std::task::sleep(Duration::from_secs(5)).await;
        let s = state.read().unwrap();
        if s.total_responses > 0 {
            println!(
                "Offset: {:+.6}s | Delay: {:.6}s | Jitter: {:.6}s | Stratum: {} | Interleaved: {} | Responses: {}",
                s.offset, s.delay, s.jitter, s.stratum, s.interleaved, s.total_responses
            );
        } else {
            println!("Waiting for first response...");
        }
    }
}
