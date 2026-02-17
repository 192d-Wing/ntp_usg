// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the Roughtime client.
//!
//! These tests query live Roughtime servers and verify responses.
//! Set `SKIP_NETWORK_TESTS=1` to skip them in offline environments.

#![cfg(feature = "roughtime")]

use std::time::Duration;

fn skip_network() -> bool {
    std::env::var("SKIP_NETWORK_TESTS").is_ok()
}

/// Cloudflare Roughtime public key.
fn cloudflare_pk() -> [u8; 32] {
    ntp_client::roughtime::decode_public_key("0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=")
        .unwrap()
}

#[test]
fn test_roughtime_sync_cloudflare() {
    if skip_network() {
        eprintln!("skipping: SKIP_NETWORK_TESTS is set");
        return;
    }

    let pk = cloudflare_pk();
    match ntp_client::roughtime::request_with_timeout(
        "roughtime.cloudflare.com:2003",
        &pk,
        Duration::from_secs(10),
    ) {
        Ok(result) => {
            // Verify the result is a reasonable Unix timestamp (after 2024).
            assert!(
                result.midpoint_seconds() > 1_700_000_000,
                "midpoint too old: {}",
                result.midpoint_seconds()
            );
            // Radius should be less than 60 seconds for a healthy server.
            assert!(
                result.radius_seconds() < 60,
                "radius too large: {}s",
                result.radius_seconds()
            );
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            eprintln!("skipping: Roughtime server unreachable ({e})");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn test_roughtime_async_cloudflare() {
    if skip_network() {
        eprintln!("skipping: SKIP_NETWORK_TESTS is set");
        return;
    }

    let pk = cloudflare_pk();
    match ntp_client::roughtime::async_request_with_timeout(
        "roughtime.cloudflare.com:2003",
        &pk,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(result) => {
            assert!(
                result.midpoint_seconds() > 1_700_000_000,
                "midpoint too old: {}",
                result.midpoint_seconds()
            );
            assert!(
                result.radius_seconds() < 60,
                "radius too large: {}s",
                result.radius_seconds()
            );
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            eprintln!("skipping: Roughtime server unreachable ({e})");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}
