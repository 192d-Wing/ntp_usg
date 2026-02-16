// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTS-authenticated NTP request example.
//!
//! Performs NTS Key Establishment with a server, then sends an
//! authenticated NTP request and prints the result.
//!
//! Usage:
//!   cargo run --example nts_request --features nts

use std::time::Duration;

use ntp::nts::NtsSession;

#[tokio::main]
async fn main() {
    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "time.cloudflare.com".to_string());

    println!("Performing NTS-KE with {}...", server);

    let mut session = match NtsSession::from_ke(&server).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("NTS-KE failed: {}", e);
            std::process::exit(1);
        }
    };

    println!(
        "NTS-KE complete, {} cookies available",
        session.cookie_count()
    );

    println!("Sending NTS-protected NTP request...");

    match session.request_with_timeout(Duration::from_secs(10)).await {
        Ok(result) => {
            let unix_time = ntp::unix_time::Instant::from(result.transmit_timestamp);
            println!("Server time (Unix): {}.{:09}", unix_time.secs(), unix_time.subsec_nanos());
            println!("Stratum: {:?}", result.stratum);
            println!("Offset:  {:.6} seconds", result.offset_seconds);
            println!("Delay:   {:.6} seconds", result.delay_seconds);
            println!("Cookies remaining: {}", session.cookie_count());
        }
        Err(e) => {
            eprintln!("NTS request failed: {}", e);
            std::process::exit(1);
        }
    }
}
