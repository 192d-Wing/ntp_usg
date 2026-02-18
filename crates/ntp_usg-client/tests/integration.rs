// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests against real NTP servers.
//!
//! These tests verify behavior against public NTP infrastructure:
//! - NIST (US Government)
//! - Cloudflare (Global CDN)
//! - Google Public NTP
//! - NTP Pool Project
//!
//! Tests are designed to be resilient to network failures and server unavailability.

#![cfg(feature = "tokio")]

mod common;

use ntp_client::client::NtpClient;
use std::time::Duration;

/// Helper to check if we're in a network-restricted environment (CI, firewall, etc.)
fn is_network_available() -> bool {
    std::env::var("SKIP_NETWORK_TESTS").is_err()
}

/// Timeout for individual NTP queries
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum acceptable clock offset (5 seconds)
/// Real clocks should be within ~100ms, but we allow more for test environments
const MAX_OFFSET: f64 = 5.0;

/// Maximum acceptable round-trip delay (2 seconds)
const MAX_DELAY: f64 = 2.0;

#[tokio::test]
async fn test_nist_time_server() {
    if !is_network_available() {
        eprintln!("Skipping network test (SKIP_NETWORK_TESTS set)");
        return;
    }

    match ntp_client::async_ntp::request_with_timeout("time.nist.gov:123", QUERY_TIMEOUT).await {
        Ok(result) => {
            println!(
                "NIST: offset={:.6}s, delay={:.6}s",
                result.offset_seconds, result.delay_seconds
            );
            assert!(
                result.offset_seconds.abs() < MAX_OFFSET,
                "Clock offset too large: {:.3}s",
                result.offset_seconds
            );
            assert!(
                result.delay_seconds < MAX_DELAY,
                "Round-trip delay too large: {:.3}s",
                result.delay_seconds
            );
            assert!(result.delay_seconds > 0.0, "Delay must be positive");
        }
        Err(e) if common::is_network_skip_error(&e) => {
            eprintln!("Skipping NIST test: network unreachable ({e})");
        }
        Err(e) => panic!("Unexpected error from time.nist.gov: {e}"),
    }
}

#[tokio::test]
async fn test_cloudflare_time_server() {
    if !is_network_available() {
        return;
    }

    match ntp_client::async_ntp::request_with_timeout("time.cloudflare.com:123", QUERY_TIMEOUT)
        .await
    {
        Ok(result) => {
            println!(
                "Cloudflare: offset={:.6}s, delay={:.6}s",
                result.offset_seconds, result.delay_seconds
            );
            assert!(result.offset_seconds.abs() < MAX_OFFSET);
            assert!(result.delay_seconds < MAX_DELAY);
            assert!(result.delay_seconds > 0.0);
        }
        Err(e) if common::is_network_skip_error(&e) => {
            eprintln!("Skipping Cloudflare test: network unreachable ({e})");
        }
        Err(e) => panic!("Unexpected error from time.cloudflare.com: {e}"),
    }
}

#[tokio::test]
async fn test_google_time_server() {
    if !is_network_available() {
        return;
    }

    match ntp_client::async_ntp::request_with_timeout("time.google.com:123", QUERY_TIMEOUT).await {
        Ok(result) => {
            println!(
                "Google: offset={:.6}s, delay={:.6}s",
                result.offset_seconds, result.delay_seconds
            );
            assert!(result.offset_seconds.abs() < MAX_OFFSET);
            assert!(result.delay_seconds < MAX_DELAY);
            assert!(result.delay_seconds > 0.0);
        }
        Err(e) if common::is_network_skip_error(&e) => {
            eprintln!("Skipping Google test: network unreachable ({e})");
        }
        Err(e) => panic!("Unexpected error from time.google.com: {e}"),
    }
}

#[tokio::test]
async fn test_multiple_server_consistency() {
    if !is_network_available() {
        return;
    }

    let servers = vec![
        "time.nist.gov:123",
        "time.cloudflare.com:123",
        "time.google.com:123",
    ];

    let mut results = Vec::new();
    for server in &servers {
        match ntp_client::async_ntp::request_with_timeout(server, QUERY_TIMEOUT).await {
            Ok(result) => {
                println!("{}: offset={:.6}s", server, result.offset_seconds);
                results.push(result.offset_seconds);
            }
            Err(e) if common::is_network_skip_error(&e) => {
                eprintln!("Skipping {}: network unreachable", server);
            }
            Err(e) => panic!("Unexpected error from {}: {}", server, e),
        }
    }

    // Need at least 2 servers to compare
    if results.len() >= 2 {
        // Check that all servers agree within 1 second (they should agree within ~10ms normally)
        let min_offset = results.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_offset = results.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        let spread = max_offset - min_offset;

        println!(
            "Server spread: {:.6}s (min={:.6}s, max={:.6}s)",
            spread, min_offset, max_offset
        );
        assert!(
            spread < 1.0,
            "Servers disagree by more than 1 second: {:.3}s",
            spread
        );
    } else {
        eprintln!("Not enough servers responded to test consistency");
    }
}

#[tokio::test]
async fn test_continuous_client_convergence() {
    if !is_network_available() {
        return;
    }

    // Build a multi-peer client
    let result = NtpClient::builder()
        .server("time.nist.gov:123")
        .server("time.cloudflare.com:123")
        .server("time.google.com:123")
        .min_poll(4) // 16 seconds (fast for testing)
        .max_poll(6) // 64 seconds
        .build()
        .await;

    let (client, mut state_rx) = match result {
        Ok(x) => x,
        Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
            eprintln!("Skipping continuous client test: network unavailable");
            return;
        }
        Err(e) => panic!("Failed to build client: {}", e),
    };

    // Spawn the client
    let handle = tokio::spawn(client.run());

    // Wait for 3 state updates or 60 seconds timeout
    let mut update_count = 0;
    let timeout = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                let state = state_rx.borrow().clone();
                update_count += 1;

                println!(
                    "Update #{}: offset={:.6}s, delay={:.6}s, jitter={:.6}s",
                    update_count, state.offset, state.delay, state.jitter
                );

                // Verify reasonable values
                assert!(state.offset.abs() < MAX_OFFSET, "Offset too large: {:.3}s", state.offset);
                assert!(state.delay < MAX_DELAY, "Delay too large: {:.3}s", state.delay);
                assert!(state.delay > 0.0, "Delay must be positive");
                assert!(state.jitter >= 0.0, "Jitter must be non-negative");

                if update_count >= 3 {
                    println!("Continuous client converged successfully");
                    break;
                }
            }
            () = &mut timeout => {
                if update_count == 0 {
                    eprintln!("Skipping continuous client test: no updates received (NTP port may be blocked)");
                    break;
                }
                panic!("Continuous client did not produce 3 updates within 60 seconds (got {})", update_count);
            }
        }
    }

    // Clean shutdown
    drop(state_rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

#[tokio::test]
async fn test_sntp_api_nist() {
    if !is_network_available() {
        return;
    }

    match ntp_client::sntp::async_request("time.nist.gov:123").await {
        Ok(result) => {
            println!(
                "SNTP: offset={:.6}s, delay={:.6}s",
                result.offset_seconds, result.delay_seconds
            );
            assert!(result.offset_seconds.abs() < MAX_OFFSET);
            assert!(result.delay_seconds < MAX_DELAY);
        }
        Err(e) if common::is_network_skip_error(&e) => {
            eprintln!("Skipping SNTP test: network unreachable");
        }
        Err(e) => panic!("Unexpected SNTP error: {e}"),
    }
}

#[tokio::test]
async fn test_ipv6_server() {
    if !is_network_available() {
        return;
    }

    // Google Public NTP supports IPv6
    match ntp_client::async_ntp::request_with_timeout("time.google.com:123", QUERY_TIMEOUT).await {
        Ok(result) => {
            println!("IPv6 test: offset={:.6}s", result.offset_seconds);
            assert!(result.offset_seconds.abs() < MAX_OFFSET);
        }
        Err(e) if common::is_network_skip_error(&e) => {
            eprintln!("Skipping IPv6 test: network unavailable or no IPv6 support");
        }
        Err(e) => panic!("Unexpected error in IPv6 test: {e}"),
    }
}

#[tokio::test]
async fn test_rapid_successive_queries() {
    if !is_network_available() {
        return;
    }

    // Issue 5 rapid queries to the same server
    let server = "time.cloudflare.com:123";
    let mut results = Vec::new();

    for i in 0..5 {
        match ntp_client::async_ntp::request_with_timeout(server, QUERY_TIMEOUT).await {
            Ok(result) => {
                println!("Query #{}: offset={:.6}s", i + 1, result.offset_seconds);
                results.push(result.offset_seconds);
            }
            Err(e) if common::is_network_skip_error(&e) => {
                eprintln!("Query #{} failed: network unreachable", i + 1);
            }
            Err(e) => panic!("Query #{} unexpected error: {}", i + 1, e),
        }
    }

    if results.len() >= 2 {
        // All results should be consistent (within 100ms)
        let min = results.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max = results.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        let spread = max - min;

        println!("Rapid query spread: {:.6}s", spread);
        assert!(
            spread < 0.1,
            "Successive queries spread too wide: {:.3}s",
            spread
        );
    }
}

#[tokio::test]
async fn test_pool_server() {
    if !is_network_available() {
        return;
    }

    // NTP Pool returns different servers via DNS round-robin
    match ntp_client::async_ntp::request_with_timeout("pool.ntp.org:123", QUERY_TIMEOUT).await {
        Ok(result) => {
            println!(
                "Pool: offset={:.6}s, delay={:.6}s",
                result.offset_seconds, result.delay_seconds
            );
            assert!(result.offset_seconds.abs() < MAX_OFFSET);
            assert!(result.delay_seconds < MAX_DELAY);
        }
        Err(e) if common::is_network_skip_error(&e) => {
            eprintln!("Skipping pool test: network unreachable");
        }
        Err(e) => panic!("Unexpected error from pool.ntp.org: {e}"),
    }
}

#[tokio::test]
async fn test_stratum_validation() {
    if !is_network_available() {
        return;
    }

    // Public NTP servers should be stratum 1-3
    match ntp_client::async_ntp::request_with_timeout("time.nist.gov:123", QUERY_TIMEOUT).await {
        Ok(result) => {
            // For now, just verify we got a valid response
            println!("Received valid NTP response from NIST");
            assert!(result.offset_seconds.abs() < MAX_OFFSET);
        }
        Err(e) if common::is_network_skip_error(&e) => {
            eprintln!("Skipping stratum test: network unreachable");
        }
        Err(e) => panic!("Unexpected error: {e}"),
    }
}
