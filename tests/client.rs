// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]

use std::time::Duration;

use ntp::client::NtpClient;

#[tokio::test]
async fn test_continuous_client_single_poll() {
    let build_result = NtpClient::builder()
        .server("time.nist.gov:123")
        .min_poll(4)
        .max_poll(4)
        .build()
        .await;

    let (client, mut state_rx) = match build_result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("skipping test_continuous_client_single_poll: failed to build client ({e})");
            return;
        }
    };

    // Spawn the poll loop.
    let handle = tokio::spawn(client.run());

    // Wait for the first state update (with timeout).
    match tokio::time::timeout(Duration::from_secs(10), state_rx.changed()).await {
        Ok(Ok(())) => {
            let state = state_rx.borrow();
            assert!(state.offset.is_finite());
            assert!(state.delay.is_finite());
            assert!(state.total_responses >= 1);
        }
        Ok(Err(e)) => panic!("watch channel closed unexpectedly: {e}"),
        Err(_) => {
            eprintln!(
                "skipping test_continuous_client_single_poll: timed out waiting for NTP response"
            );
        }
    }

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
