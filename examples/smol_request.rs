// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating async NTP requests using smol.
//!
//! Run with: `cargo run --example smol_request --features smol-runtime`

use std::time::Duration;

fn main() {
    smol::block_on(async {
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
                smol::spawn(async move {
                    let result =
                        ntp::smol_ntp::request_with_timeout(server, Duration::from_secs(5)).await;
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
    });
}
