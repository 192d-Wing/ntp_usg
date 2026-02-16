// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating async NTP requests using tokio.
//!
//! Run with: `cargo run --example async_request --features tokio`

use std::time::Duration;

#[tokio::main]
async fn main() {
    let servers = [
        "time.nist.gov:123",
        "time-a-g.nist.gov:123",
        "time-b-g.nist.gov:123",
    ];

    println!("Querying NTP servers concurrently...\n");

    // Fire all requests concurrently.
    let handles: Vec<_> = servers
        .iter()
        .map(|&server| {
            tokio::spawn(async move {
                let result =
                    ntp_client::async_ntp::request_with_timeout(server, Duration::from_secs(5))
                        .await;
                (server, result)
            })
        })
        .collect();

    for handle in handles {
        let (server, result) = handle.await.unwrap();
        match result {
            Ok(response) => {
                println!(
                    "{}: offset={:.6}s, delay={:.6}s, stratum={}",
                    server, response.offset_seconds, response.delay_seconds, response.stratum.0
                );
            }
            Err(e) => {
                println!("{}: error: {}", server, e);
            }
        }
    }
}
