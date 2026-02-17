// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Query a Roughtime server for authenticated coarse time.
//!
//! Roughtime provides cryptographically verified time with ~1 second accuracy
//! using Ed25519 signatures and SHA-512 Merkle tree proofs.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example roughtime --features roughtime
//! ```

fn main() {
    env_logger::init();

    // Cloudflare Roughtime server.
    let server = "roughtime.cloudflare.com:2003";
    let public_key_b64 = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=";

    let pk = ntp_client::roughtime::decode_public_key(public_key_b64).expect("invalid public key");

    println!("Querying Roughtime server: {server}");

    match ntp_client::roughtime::request(server, &pk) {
        Ok(result) => {
            let secs = result.midpoint_seconds();
            let radius = result.radius_seconds();
            println!("Midpoint:  {secs} seconds since Unix epoch");
            println!("Radius:    ±{radius}s ({} µs)", result.radius_us);
            println!("Raw MIDP:  {} µs", result.midpoint_us);

            // Compare with NTP.
            match ntp_client::request("time.cloudflare.com:123") {
                Ok(ntp_result) => {
                    let ntp_time =
                        ntp_client::unix_time::Instant::from(ntp_result.transmit_timestamp);
                    let ntp_secs = ntp_time.secs();
                    let diff = secs as i64 - ntp_secs;
                    println!("\nNTP time:  {ntp_secs} seconds since Unix epoch");
                    println!("Difference: {diff}s (Roughtime accuracy: ±{radius}s)");
                }
                Err(e) => {
                    eprintln!("NTP comparison failed: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("Roughtime request failed: {e}");
            std::process::exit(1);
        }
    }
}
