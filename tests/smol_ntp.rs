// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "smol-runtime")]

use std::time::Duration;

#[test]
fn test_smol_request_nist() {
    smol::block_on(async {
        match ntp::smol_ntp::request_with_timeout("time.nist.gov:123", Duration::from_secs(10))
            .await
        {
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                eprintln!("skipping test_smol_request_nist: NTP port unreachable ({e})");
            }
            Err(e) => panic!("unexpected error from time.nist.gov: {e}"),
        }
    });
}

#[test]
fn test_smol_request_nist_alt() {
    smol::block_on(async {
        match ntp::smol_ntp::request_with_timeout("time-a-g.nist.gov:123", Duration::from_secs(10))
            .await
        {
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                eprintln!("skipping test_smol_request_nist_alt: NTP port unreachable ({e})");
            }
            Err(e) => panic!("unexpected error from time-a-g.nist.gov: {e}"),
        }
    });
}

#[test]
fn test_smol_request_timeout() {
    smol::block_on(async {
        let res =
            ntp::smol_ntp::request_with_timeout("time.nist.gov:123", Duration::from_nanos(1)).await;
        assert!(res.is_err());
    });
}
