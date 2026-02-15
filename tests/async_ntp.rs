// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]

use std::time::Duration;

#[tokio::test]
async fn test_async_request_ntp_org() {
    let res = ntp::async_ntp::request("0.pool.ntp.org:123").await;
    let _ = res.expect("Failed to get an NTP packet from ntp.org");
}

#[tokio::test]
async fn test_async_request_google() {
    let res = ntp::async_ntp::request("time.google.com:123").await;
    let _ = res.expect("Failed to get an NTP packet from time.google.com");
}

#[tokio::test]
async fn test_async_request_timeout() {
    let res =
        ntp::async_ntp::request_with_timeout("pool.ntp.org:123", Duration::from_nanos(1)).await;
    assert!(res.is_err());
}
