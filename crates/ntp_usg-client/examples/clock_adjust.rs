// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example: NTP clock adjustment using the continuous client.
//!
//! This example polls NTP servers and applies clock corrections to the
//! system clock. Requires root/admin privileges.
//!
//! Run with: `sudo cargo run --example clock_adjust --features clock,tokio`

use ntp_client::client::NtpClient;
use ntp_client::clock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting NTP client with clock adjustment...");
    println!("This requires root/admin privileges.");
    println!("Press Ctrl+C to stop.\n");

    let (client, mut state_rx) = NtpClient::builder()
        .server("time.nist.gov:123")
        .server("time-a-g.nist.gov:123")
        .min_poll(4) // 16 seconds
        .max_poll(6) // 64 seconds
        .build()
        .await?;

    // Spawn the poll loop in the background.
    tokio::spawn(client.run());

    // Apply corrections as sync state updates arrive.
    loop {
        state_rx.changed().await?;
        let state = state_rx.borrow().clone();

        println!(
            "Offset: {:+.6}s | Delay: {:.6}s | Responses: {}",
            state.offset, state.delay, state.total_responses
        );

        // Only apply corrections after receiving at least a few responses.
        if state.total_responses >= 3 {
            match clock::apply_correction(state.offset) {
                Ok(method) => {
                    println!("  Applied correction: {:?}", method);
                }
                Err(clock::ClockError::PermissionDenied) => {
                    eprintln!("  Error: Permission denied. Run with sudo.");
                    return Err("Permission denied".into());
                }
                Err(e) => {
                    eprintln!("  Error adjusting clock: {}", e);
                }
            }
        }
    }
}
