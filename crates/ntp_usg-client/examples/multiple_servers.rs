// Copyright 2016 Jeff Belgum
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating how to query multiple NTP servers.
//!
//! This example shows a common pattern for improving reliability by
//! querying multiple NTP servers and selecting the best response.

use chrono::TimeZone;
use std::time::Duration;

fn main() {
    // List of NTP servers to query
    let ntp_servers = [
        "time.nist.gov:123",
        "time-a-g.nist.gov:123",
        "time-b-g.nist.gov:123",
        "time-c-g.nist.gov:123",
        "time-d-g.nist.gov:123",
    ];

    println!("Querying multiple NTP servers...\n");

    let mut successful_responses = Vec::new();

    // Query each server
    for server in &ntp_servers {
        print!("Querying {}... ", server);
        match ntp_client::request_with_timeout(server, Duration::from_secs(3)) {
            Ok(response) => {
                println!("✓");
                println!("  Stratum: {:?}", response.stratum);

                let unix_time = ntp_client::unix_time::Instant::from(response.transmit_timestamp);
                let local_time = chrono::Local
                    .timestamp_opt(unix_time.secs(), unix_time.subsec_nanos() as _)
                    .unwrap();

                println!("  Time: {}", local_time);
                println!("  Offset: {:.6} seconds", response.offset_seconds);
                successful_responses.push((server, response));
            }
            Err(e) => {
                println!("✗ Error: {}", e);
            }
        }
        println!();
    }

    // Report results
    println!("Summary:");
    println!(
        "  Successful queries: {}/{}",
        successful_responses.len(),
        ntp_servers.len()
    );

    if !successful_responses.is_empty() {
        println!(
            "\nBest practice: Use responses from Stratum 1 or 2 servers for highest accuracy."
        );

        // Find the server with the lowest stratum (most accurate)
        if let Some((server, response)) =
            successful_responses.iter().min_by_key(|(_, r)| r.stratum.0)
        {
            println!(
                "  Lowest stratum server: {} (Stratum {})",
                server, response.stratum.0
            );
        }
    }
}
