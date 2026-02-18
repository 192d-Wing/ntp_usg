// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTPv5 server demonstration (draft-ietf-ntp-ntpv5).
//!
//! Starts an NTP server that accepts both NTPv4 and NTPv5 clients.
//! NTPv5 introduces timescale negotiation and cookie-based interleaved
//! mode.
//!
//! Run with:
//! ```sh
//! cargo run -p ntp_usg-server --example ntpv5_server --features "ntpv5,tokio"
//! ```
//!
//! Test with the NTPv5 client example:
//! ```sh
//! cargo run -p ntp_usg-client --example ntpv5_client --features "ntpv5,tokio" -- 127.0.0.1:1123
//! ```

use ntp_server::protocol::Stratum;
use ntp_server::server::NtpServer;
use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let listen_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "[::]:1123".to_string());

    println!("NTPv5 Server Demo (draft-ietf-ntp-ntpv5)");
    println!("=========================================");

    let server = NtpServer::builder()
        .listen(&listen_addr)
        .stratum(Stratum(2))
        .build()
        .await?;

    let addr = server.local_addr()?;
    println!("Listening on {addr}");
    println!("Accepts both NTPv4 and NTPv5 clients.");
    println!("Press Ctrl+C to stop.\n");

    server.run().await
}
