// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example: Continuous NTP client using smol.
//!
//! Run with: `cargo run --example smol_continuous --features smol-runtime`

use ntp::smol_client::NtpClient;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    smol::block_on(async {
        println!("Starting continuous NTP client (smol)...");
        println!("Press Ctrl+C to stop.\n");

        let (client, state) = NtpClient::builder()
            .server("time.nist.gov:123")
            .server("time-a-g.nist.gov:123")
            .min_poll(4) // 16 seconds
            .max_poll(6) // 64 seconds (short for demo)
            .build()
            .await?;

        // Spawn the poll loop in the background.
        smol::spawn(client.run()).detach();

        // Periodically print the current sync state.
        loop {
            smol::Timer::after(Duration::from_secs(5)).await;
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
    })
}
