// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "smol-runtime")]

use std::time::Duration;

use ntp::smol_client::NtpClient;

#[test]
fn test_smol_continuous_client_single_poll() {
    smol::block_on(async {
        let (client, state) = NtpClient::builder()
            .server("time.nist.gov:123")
            .min_poll(4)
            .max_poll(4)
            .build()
            .await
            .expect("failed to build client");

        // Spawn the poll loop.
        let task = smol::spawn(client.run());

        // Wait for the first response (with timeout).
        let deadline = smol::Timer::after(Duration::from_secs(10));
        let got_response = async {
            loop {
                smol::Timer::after(Duration::from_millis(250)).await;
                let s = state.read().unwrap();
                if s.total_responses >= 1 {
                    break;
                }
            }
        };

        futures_lite::future::or(got_response, async {
            deadline.await;
            panic!("timed out waiting for first poll");
        })
        .await;

        let s = state.read().unwrap();
        assert!(s.offset.is_finite());
        assert!(s.delay.is_finite());
        assert!(s.total_responses >= 1);

        // Cancel the poll loop.
        drop(task);
    });
}

#[test]
fn test_smol_builder_validation() {
    smol::block_on(async {
        // Empty servers should fail.
        let result = NtpClient::builder().build().await;
        assert!(result.is_err());

        // Invalid hostname should fail.
        let result = NtpClient::builder()
            .server("this.hostname.definitely.does.not.exist.invalid:123")
            .build()
            .await;
        assert!(result.is_err());
    });
}
