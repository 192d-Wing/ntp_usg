// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]

use std::time::Duration;

#[tokio::test]
async fn test_async_request_nist() {
    match ntp_client::async_ntp::request_with_timeout("time.nist.gov:123", Duration::from_secs(10))
        .await
    {
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            eprintln!("skipping test_async_request_nist: NTP port unreachable ({e})");
        }
        Err(e) => panic!("unexpected error from time.nist.gov: {e}"),
    }
}

#[tokio::test]
async fn test_async_request_nist_alt() {
    match ntp_client::async_ntp::request_with_timeout(
        "time-a-g.nist.gov:123",
        Duration::from_secs(10),
    )
    .await
    {
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            eprintln!("skipping test_async_request_nist_alt: NTP port unreachable ({e})");
        }
        Err(e) => panic!("unexpected error from time-a-g.nist.gov: {e}"),
    }
}

#[tokio::test]
async fn test_async_request_timeout() {
    let res =
        ntp_client::async_ntp::request_with_timeout("time.nist.gov:123", Duration::from_nanos(1))
            .await;
    assert!(res.is_err());
}
