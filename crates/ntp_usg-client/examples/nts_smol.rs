// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTS-secured NTP request using the smol runtime.
//!
//! Demonstrates Network Time Security (RFC 8915) with the smol async
//! runtime, as an alternative to the tokio-based `nts_request` example.
//!
//! The flow:
//! 1. NTS-KE (Key Establishment) over TLS 1.3 to negotiate cookies
//! 2. Authenticated NTP request using AEAD encryption
//!
//! Run with:
//! ```sh
//! cargo run -p ntp_usg-client --example nts_smol --features nts-smol
//! ```

use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "time.cloudflare.com".to_string());

    smol::block_on(async {
        println!("NTS Request via smol runtime");
        println!("============================");
        println!("Server: {server}");

        // Step 1: NTS-KE (Key Establishment) over TLS 1.3.
        println!("\n1. Performing NTS-KE handshake...");
        let mut session = ntp_client::smol_nts::NtsSession::from_ke(&server).await?;
        println!(
            "   NTS-KE complete. Received {} cookie(s).",
            session.cookie_count()
        );

        // Step 2: Authenticated NTP request.
        println!("\n2. Sending authenticated NTP request...");
        let result = session
            .request_with_timeout(Duration::from_secs(10))
            .await?;

        let unix_time = ntp_client::unix_time::Instant::from(result.transmit_timestamp);
        println!("\nResults:");
        println!("  Stratum:     {}", result.stratum.0);
        println!("  Offset:      {:+.6} seconds", result.offset_seconds);
        println!("  Delay:       {:.6} seconds", result.delay_seconds);
        println!("  Unix time:   {} s", unix_time.secs());
        println!("  Cookies left: {}", session.cookie_count());

        Ok(())
    })
}
