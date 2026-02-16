// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "nts")]

use ntp::nts::{NtsSession, nts_ke};

#[tokio::test]
async fn test_nts_ke_cloudflare() {
    let result = nts_ke("time.cloudflare.com").await;
    match result {
        Ok(ke) => {
            assert!(!ke.cookies.is_empty(), "expected at least one cookie");
            assert!(!ke.c2s_key.is_empty(), "expected non-empty C2S key");
            assert!(!ke.s2c_key.is_empty(), "expected non-empty S2C key");
            assert_eq!(ke.c2s_key.len(), ke.s2c_key.len());
        }
        Err(e) => {
            // Network tests may fail in CI — skip gracefully.
            eprintln!("NTS-KE test skipped (network error): {}", e);
        }
    }
}

#[tokio::test]
async fn test_nts_request_cloudflare() {
    let session = NtsSession::from_ke("time.cloudflare.com").await;
    let mut session = match session {
        Ok(s) => s,
        Err(e) => {
            eprintln!("NTS session test skipped (network error): {}", e);
            return;
        }
    };

    let result = session.request().await;
    match result {
        Ok(ntp_result) => {
            assert!(ntp_result.offset_seconds.is_finite());
            assert!(ntp_result.delay_seconds.is_finite());
            assert!(session.cookie_count() > 0, "should have replenished cookies");
        }
        Err(e) => {
            eprintln!("NTS request test skipped (network error): {}", e);
        }
    }
}
