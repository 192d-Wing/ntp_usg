// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP server with rate limiting and access control.
//!
//! Demonstrates per-client rate limiting (RFC 8633 BCP 223), IP-based access
//! control lists, and maximum client caps. Clients that exceed limits receive
//! Kiss-of-Death (KoD) responses:
//!
//!   RATE — exceeded per-client rate limit (reduce polling interval)
//!   DENY — on the explicit deny list (stop sending)
//!   RSTR — not on the allow list (access restricted)
//!
//! Run with:
//!   cargo run -p ntp_usg-server --example rate_limiter --features tokio
//!
//! Test with:
//!   ntpdate -q 127.0.0.1:2123
//!   (repeat rapidly to trigger rate limiting)

use std::net::IpAddr;
use std::time::Duration;

use ntp_server::protocol::Stratum;
use ntp_server::server::NtpServer;
use ntp_server::server_common::{IpNet, RateLimitConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    // ── Access control rules ───────────────────────────────────────────
    //
    // Deny is checked before allow. A client matching both is denied.
    // Clients not matching any allow rule get KoD RSTR.

    // Allow: localhost and RFC 1918 private networks.
    let loopback = IpNet::new("127.0.0.0".parse::<IpAddr>()?, 8);
    let private_10 = IpNet::new("10.0.0.0".parse::<IpAddr>()?, 8);
    let private_172 = IpNet::new("172.16.0.0".parse::<IpAddr>()?, 12);
    let private_192 = IpNet::new("192.168.0.0".parse::<IpAddr>()?, 16);

    // Deny: hypothetical abusive subnet.
    let abusive_subnet = IpNet::new("10.0.99.0".parse::<IpAddr>()?, 24);

    // ── Rate limiting ──────────────────────────────────────────────────
    //
    // Deliberately strict values for demo purposes. Production deployments
    // should use more relaxed settings (e.g. 20 req/min, 2s min interval).

    let rate_config = RateLimitConfig {
        max_requests_per_window: 5,
        window_duration: Duration::from_secs(60),
        min_interval: Duration::from_secs(4),
    };

    // ── Build and start the server ─────────────────────────────────────

    let server = NtpServer::builder()
        .listen("0.0.0.0:2123")
        .stratum(Stratum(2))
        // Access control (deny checked before allow)
        .deny(abusive_subnet)
        .allow(loopback)
        .allow(private_10)
        .allow(private_172)
        .allow(private_192)
        // Rate limiting
        .rate_limit(rate_config)
        // Client table cap (default is 100,000; smaller for demo)
        .max_clients(1_000)
        // Interleaved mode for better accuracy (RFC 9769)
        .enable_interleaved(true)
        .build()
        .await?;

    let local_addr = server.local_addr()?;

    println!();
    println!("NTP Rate Limiter + Access Control Example");
    println!("==========================================");
    println!();
    println!("Access Control (deny checked first):");
    println!("  DENY: 10.0.99.0/24            -> KoD DENY");
    println!("  ALLOW: 127.0.0.0/8            -> served");
    println!("  ALLOW: 10.0.0.0/8             -> served (except 10.0.99.0/24)");
    println!("  ALLOW: 172.16.0.0/12          -> served");
    println!("  ALLOW: 192.168.0.0/16         -> served");
    println!("  Other addresses               -> KoD RSTR");
    println!();
    println!("Rate Limiting (per client IP, per RFC 8633):");
    println!("  Max requests/window: 5         -> KoD RATE when exceeded");
    println!("  Window duration:     60s");
    println!("  Min interval:        4s        -> KoD RATE if too frequent");
    println!();
    println!("Client Table:");
    println!("  Max tracked clients: 1,000");
    println!();
    println!("Interleaved mode: enabled (RFC 9769)");
    println!("Stratum: 2");
    println!("Listening on: {}", local_addr);
    println!();
    println!("Set RUST_LOG=debug to see per-request KoD logs.");
    println!("Test: ntpdate -q 127.0.0.1:2123");
    println!("      (send 6+ requests within 60s to trigger RATE KoD)");
    println!();

    server.run().await?;
    Ok(())
}
