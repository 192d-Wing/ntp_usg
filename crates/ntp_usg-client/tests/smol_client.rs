// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "smol-runtime")]

use std::time::Duration;

use ntp_client::smol_client::NtpClient;

#[test]
fn test_smol_continuous_client_single_poll() {
    smol::block_on(async {
        let build_result = NtpClient::builder()
            .server("time.nist.gov:123")
            .min_poll(4)
            .max_poll(4)
            .build()
            .await;

        let (client, state) = match build_result {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "skipping test_smol_continuous_client_single_poll: failed to build client ({e})"
                );
                return;
            }
        };

        // Spawn the poll loop.
        let task = smol::spawn(client.run());

        // Wait for the first response (with timeout).
        let deadline = smol::Timer::after(Duration::from_secs(10));
        let got_response = async {
            loop {
                smol::Timer::after(Duration::from_millis(250)).await;
                let s = state.read().unwrap();
                if s.total_responses >= 1 {
                    return true;
                }
            }
        };

        let responded = futures_lite::future::or(got_response, async {
            deadline.await;
            false
        })
        .await;

        if responded {
            let s = state.read().unwrap();
            assert!(s.offset.is_finite());
            assert!(s.delay.is_finite());
            assert!(s.total_responses >= 1);
        } else {
            eprintln!(
                "skipping test_smol_continuous_client_single_poll: timed out waiting for NTP response"
            );
        }

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
