// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example NTPv4 server using tokio.
//!
//! Run with: `cargo run --example server --features tokio`

use ntp_server::protocol::Stratum;
use ntp_server::server::NtpServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server = NtpServer::builder()
        .listen("[::]:1123")
        .stratum(Stratum(2))
        .build()
        .await?;

    println!("NTP server listening on {}", server.local_addr()?);

    server.run().await
}
