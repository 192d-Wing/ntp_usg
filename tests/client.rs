// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]

use std::time::Duration;

use ntp::client::NtpClient;

#[tokio::test]
async fn test_continuous_client_single_poll() {
    let (client, mut state_rx) = NtpClient::builder()
        .server("pool.ntp.org:123")
        .min_poll(4)
        .max_poll(4)
        .build()
        .await
        .expect("failed to build client");

    // Spawn the poll loop.
    let handle = tokio::spawn(client.run());

    // Wait for the first state update (with timeout).
    let result = tokio::time::timeout(Duration::from_secs(10), state_rx.changed()).await;
    assert!(result.is_ok(), "timed out waiting for first poll");
    assert!(result.unwrap().is_ok(), "watch channel closed unexpectedly");

    let state = state_rx.borrow();
    assert!(state.offset.is_finite());
    assert!(state.delay.is_finite());
    assert!(state.total_responses >= 1);

    // Abort the poll loop.
    handle.abort();
}

#[tokio::test]
async fn test_builder_validation() {
    // Empty servers should fail.
    let result = NtpClient::builder().build().await;
    assert!(result.is_err());

    // Invalid hostname should fail.
    let result = NtpClient::builder()
        .server("this.hostname.definitely.does.not.exist.invalid:123")
        .build()
        .await;
    assert!(result.is_err());
}
