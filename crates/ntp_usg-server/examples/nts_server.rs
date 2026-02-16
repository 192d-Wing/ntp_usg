// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Example NTS-authenticated NTP server with NTS-KE TLS endpoint.
//!
//! This example runs both an NTS-KE server (TLS key establishment) and an
//! NTP server that validates NTS-authenticated requests.
//!
//! You must provide TLS certificate and key files:
//!
//! ```sh
//! cargo run --example nts_server --features nts -- \
//!     --cert server.crt --key server.key
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use ntp_server::nts_ke_server::{NtsKeServer, NtsKeServerConfig};
use ntp_server::nts_server_common::MasterKeyStore;
use ntp_server::protocol::Stratum;
use ntp_server::server::NtpServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (cert_path, key_path) = parse_args(&args)?;

    let cert_pem = std::fs::read(&cert_path)?;
    let key_pem = std::fs::read(&key_path)?;

    // Shared master key store with 24-hour grace period for retired keys.
    let key_store = Arc::new(RwLock::new(MasterKeyStore::new(Duration::from_secs(86400))));

    // NTS-KE server (TLS on port 4460).
    let ke_config = NtsKeServerConfig::from_pem(&cert_pem, &key_pem)?;
    let ke_server = NtsKeServer::new(ke_config, key_store.clone())?;

    // NTP server (UDP on port 1123).
    let ntp_server = NtpServer::builder()
        .listen("0.0.0.0:1123")
        .stratum(Stratum(2))
        .build()
        .await?;

    println!("NTP server listening on {}", ntp_server.local_addr()?);
    println!("NTS-KE server listening on 0.0.0.0:4460");

    // Run both servers concurrently.
    tokio::select! {
        result = ntp_server.run() => result,
        result = ke_server.run() => result,
    }
}

fn parse_args(args: &[String]) -> std::io::Result<(String, String)> {
    let mut cert = None;
    let mut key = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--cert" => {
                i += 1;
                cert = args.get(i).cloned();
            }
            "--key" => {
                i += 1;
                key = args.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }

    let cert = cert.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: nts_server --cert <cert.pem> --key <key.pem>",
        )
    })?;
    let key = key.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: nts_server --cert <cert.pem> --key <key.pem>",
        )
    })?;
    Ok((cert, key))
}
