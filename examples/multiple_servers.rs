//! Example demonstrating how to query multiple NTP servers.
//!
//! This example shows a common pattern for improving reliability by
//! querying multiple NTP servers and selecting the best response.

use chrono::TimeZone;
use std::time::Duration;

fn main() {
    // List of NTP servers to query
    let ntp_servers = [
        "0.pool.ntp.org:123",
        "1.pool.ntp.org:123",
        "2.pool.ntp.org:123",
        "time.google.com:123",
        "time.cloudflare.com:123",
    ];

    println!("Querying multiple NTP servers...\n");

    let mut successful_responses = Vec::new();

    // Query each server
    for server in &ntp_servers {
        print!("Querying {}... ", server);
        match ntp::request_with_timeout(server, Duration::from_secs(3)) {
            Ok(response) => {
                println!("✓");
                println!("  Stratum: {:?}", response.stratum);

                let unix_time = ntp::unix_time::Instant::from(response.transmit_timestamp);
                let local_time = chrono::Local
                    .timestamp_opt(unix_time.secs(), unix_time.subsec_nanos() as _)
                    .unwrap();

                println!("  Time: {}", local_time);
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
    println!("  Successful queries: {}/{}", successful_responses.len(), ntp_servers.len());

    if !successful_responses.is_empty() {
        println!("\nBest practice: Use responses from Stratum 1 or 2 servers for highest accuracy.");

        // Find the server with the lowest stratum (most accurate)
        if let Some((server, response)) = successful_responses.iter().min_by_key(|(_, r)| r.stratum.0) {
            println!("  Lowest stratum server: {} (Stratum {})", server, response.stratum.0);
        }
    }
}
