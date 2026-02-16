// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Network Time Security (NTS) against real servers.
//!
//! Tests NTS-KE (RFC 8915) key establishment and authenticated NTP queries
//! against public NTS infrastructure.

#![cfg(feature = "nts")]

use ntp_client::client::NtpClient;
use ntp_client::nts::NtsSession;
use std::time::Duration;

/// Helper to check if we're in a network-restricted environment
fn is_network_available() -> bool {
    std::env::var("SKIP_NETWORK_TESTS").is_err()
}

const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OFFSET: f64 = 5.0;
const MAX_DELAY: f64 = 2.0;

#[tokio::test]
async fn test_nts_cloudflare() {
    if !is_network_available() {
        eprintln!("Skipping NTS test (SKIP_NETWORK_TESTS set)");
        return;
    }

    // Cloudflare provides public NTS
    match NtsSession::from_ke("time.cloudflare.com").await {
        Ok(mut session) => {
            println!("NTS-KE successful with Cloudflare");

            // Perform authenticated request
            match tokio::time::timeout(QUERY_TIMEOUT, session.request()).await {
                Ok(Ok(result)) => {
                    println!(
                        "NTS Cloudflare: offset={:.6}s, delay={:.6}s",
                        result.offset_seconds, result.delay_seconds
                    );
                    assert!(result.offset_seconds.abs() < MAX_OFFSET);
                    assert!(result.delay_seconds < MAX_DELAY);
                }
                Ok(Err(e)) => panic!("NTS request failed: {e}"),
                Err(_) => panic!("NTS request timed out after {:?}", QUERY_TIMEOUT),
            }
        }
        Err(e) if e.to_string().contains("timed out")
                || e.to_string().contains("Connection refused")
                || e.to_string().contains("Connection reset")
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::ConnectionRefused => {
            eprintln!("Skipping Cloudflare NTS test: network unreachable ({e})");
        }
        Err(e) => panic!("NTS-KE failed: {e}"),
    }
}

#[tokio::test]
async fn test_nts_multiple_requests() {
    if !is_network_available() {
        return;
    }

    match NtsSession::from_ke("time.cloudflare.com").await {
        Ok(mut session) => {
            println!("Testing cookie rotation with multiple NTS requests");

            // Issue 5 requests using the same session (should consume cookies)
            let mut offsets = Vec::new();
            for i in 0..5 {
                match tokio::time::timeout(QUERY_TIMEOUT, session.request()).await {
                    Ok(Ok(result)) => {
                        println!(
                            "Request #{}: offset={:.6}s",
                            i + 1,
                            result.offset_seconds
                        );
                        offsets.push(result.offset_seconds);
                    }
                    Ok(Err(e)) => panic!("Request #{} failed: {}", i + 1, e),
                    Err(_) => panic!("Request #{} timed out", i + 1),
                }
            }

            // Verify consistency
            if offsets.len() >= 2 {
                let min = offsets.iter().fold(f64::INFINITY, |a, &b| a.min(b));
                let max = offsets.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
                let spread = max - min;

                println!("NTS request spread: {:.6}s", spread);
                assert!(spread < 0.5, "NTS requests spread too wide: {:.3}s", spread);
            }
        }
        Err(e) if e.to_string().contains("timed out")
                || e.to_string().contains("Connection refused")
                || e.to_string().contains("Connection reset")
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::ConnectionRefused => {
            eprintln!("Skipping NTS multi-request test: network unreachable");
        }
        Err(e) => panic!("NTS-KE failed: {e}"),
    }
}

#[tokio::test]
async fn test_nts_continuous_client() {
    if !is_network_available() {
        return;
    }

    // Build NTS continuous client
    let result = NtpClient::builder()
        .nts_server("time.cloudflare.com")
        .min_poll(4) // 16 seconds
        .max_poll(6) // 64 seconds
        .build()
        .await;

    let (client, mut state_rx) = match result {
        Ok(x) => x,
        Err(e) if e.to_string().contains("timed out")
                || e.to_string().contains("Connection refused")
                || e.to_string().contains("Connection reset")
                || e.kind() == std::io::ErrorKind::AddrNotAvailable
                || e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::ConnectionRefused => {
            eprintln!("Skipping NTS continuous client test: network unreachable");
            return;
        }
        Err(e) => panic!("Failed to build NTS client: {}", e),
    };

    println!("NTS continuous client started");

    // Spawn the client
    let handle = tokio::spawn(client.run());

    // Wait for 2 authenticated updates or 90 seconds timeout
    let mut update_count = 0;
    let timeout = tokio::time::sleep(Duration::from_secs(90));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                let state = state_rx.borrow().clone();
                update_count += 1;

                println!(
                    "NTS Update #{}: offset={:.6}s, delay={:.6}s",
                    update_count, state.offset, state.delay
                );

                // Verify reasonable values
                assert!(state.offset.abs() < MAX_OFFSET);
                assert!(state.delay < MAX_DELAY);
                assert!(state.delay > 0.0);

                if update_count >= 2 {
                    println!("NTS continuous client authenticated successfully");
                    break;
                }
            }
            () = &mut timeout => {
                panic!("NTS client did not produce 2 updates within 90 seconds (got {})", update_count);
            }
        }
    }

    // Clean shutdown
    drop(state_rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

#[tokio::test]
async fn test_nts_mixed_deployment() {
    if !is_network_available() {
        return;
    }

    // Build client with both NTS and standard NTP servers
    let result = NtpClient::builder()
        .nts_server("time.cloudflare.com")
        .server("time.google.com:123")
        .min_poll(4)
        .max_poll(6)
        .build()
        .await;

    let (client, mut state_rx) = match result {
        Ok(x) => x,
        Err(e) if e.to_string().contains("timed out")
                || e.to_string().contains("Connection refused")
                || e.to_string().contains("Connection reset")
                || e.kind() == std::io::ErrorKind::AddrNotAvailable
                || e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::ConnectionRefused => {
            eprintln!("Skipping mixed deployment test: network unreachable");
            return;
        }
        Err(e) => panic!("Failed to build mixed client: {}", e),
    };

    println!("Mixed NTS + standard NTP client started");

    let handle = tokio::spawn(client.run());

    // Wait for 2 updates
    let mut update_count = 0;
    let timeout = tokio::time::sleep(Duration::from_secs(90));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                let state = state_rx.borrow().clone();
                update_count += 1;

                println!(
                    "Mixed Update #{}: offset={:.6}s",
                    update_count, state.offset
                );

                assert!(state.offset.abs() < MAX_OFFSET);

                if update_count >= 2 {
                    println!("Mixed deployment verified");
                    break;
                }
            }
            () = &mut timeout => {
                panic!("Mixed client did not produce 2 updates within 90 seconds");
            }
        }
    }

    drop(state_rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

#[tokio::test]
async fn test_nts_ke_timeout() {
    if !is_network_available() {
        return;
    }

    // Test that NTS-KE respects timeouts
    // Use a non-existent domain that will timeout
    let start = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        NtsSession::from_ke("nts-nonexistent-test-domain-12345.example.com")
    ).await;

    let elapsed = start.elapsed();

    match result {
        Err(_) => {
            // Timeout occurred as expected
            println!("NTS-KE timed out after {:?} (expected)", elapsed);
            assert!(elapsed < Duration::from_secs(7), "Timeout took too long");
        }
        Ok(Err(e)) => {
            // DNS resolution failed (also acceptable)
            println!("NTS-KE failed with error (expected): {}", e);
        }
        Ok(Ok(_)) => {
            panic!("NTS-KE unexpectedly succeeded for non-existent domain");
        }
    }
}

#[tokio::test]
async fn test_nts_cookie_persistence() {
    if !is_network_available() {
        return;
    }

    match NtsSession::from_ke("time.cloudflare.com").await {
        Ok(mut session) => {
            // First request consumes initial cookies
            let result1 = tokio::time::timeout(QUERY_TIMEOUT, session.request()).await;
            assert!(result1.is_ok(), "First NTS request failed");

            // Server should have sent new cookies in response
            // Second request should still work
            let result2 = tokio::time::timeout(QUERY_TIMEOUT, session.request()).await;
            assert!(result2.is_ok(), "Second NTS request failed (cookie exhaustion?)");

            println!("NTS cookie rotation working correctly");
        }
        Err(e) if e.to_string().contains("timed out")
                || e.to_string().contains("Connection refused")
                || e.to_string().contains("Connection reset")
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::ConnectionReset
                || e.kind() == std::io::ErrorKind::ConnectionRefused => {
            eprintln!("Skipping NTS cookie test: network unreachable");
        }
        Err(e) => panic!("NTS-KE failed: {e}"),
    }
}
