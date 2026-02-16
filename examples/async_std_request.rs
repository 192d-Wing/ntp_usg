// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating async NTP requests using async-std.
//!
//! Run with: `cargo run --example async_std_request --features async-std-runtime`

use std::time::Duration;

#[async_std::main]
async fn main() {
    let servers = [
        "0.pool.ntp.org:123",
        "time.google.com:123",
        "time.cloudflare.com:123",
    ];

    println!("Querying NTP servers concurrently...\n");

    // Fire all requests concurrently.
    let handles: Vec<_> = servers
        .iter()
        .map(|&server| {
            async_std::task::spawn(async move {
                let result =
                    ntp::async_std_ntp::request_with_timeout(server, Duration::from_secs(5)).await;
                (server, result)
            })
        })
        .collect();

    for handle in handles {
        let (server, result) = handle.await;
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
