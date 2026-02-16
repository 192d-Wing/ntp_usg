// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]

use std::time::Duration;

#[tokio::test]
async fn test_async_request_nist() {
    let res = ntp::async_ntp::request("time.nist.gov:123").await;
    let _ = res.expect("Failed to get an NTP packet from time.nist.gov");
}

#[tokio::test]
async fn test_async_request_nist_alt() {
    let res = ntp::async_ntp::request("time-a-g.nist.gov:123").await;
    let _ = res.expect("Failed to get an NTP packet from time-a-g.nist.gov");
}

#[tokio::test]
async fn test_async_request_timeout() {
    let res =
        ntp::async_ntp::request_with_timeout("time.nist.gov:123", Duration::from_nanos(1)).await;
    assert!(res.is_err());
}
