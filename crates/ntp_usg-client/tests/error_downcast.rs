// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Tests for error type downcasting through the io::Error boundary.

use std::io;

use ntp_client::KissOfDeathError;
use ntp_client::error::{ConfigError, NtpError, NtsError, ProtocolError, TimeoutError};

#[test]
fn test_protocol_error_roundtrip() {
    let err = NtpError::Protocol(ProtocolError::ResponseTooShort { received: 10 });
    let io_err: io::Error = err.into();

    assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

    let inner = io_err
        .get_ref()
        .unwrap()
        .downcast_ref::<NtpError>()
        .unwrap();
    assert!(matches!(
        inner,
        NtpError::Protocol(ProtocolError::ResponseTooShort { received: 10 })
    ));
}

#[test]
fn test_timeout_error_roundtrip() {
    let err = NtpError::Timeout(TimeoutError::Recv);
    let io_err: io::Error = err.into();

    assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);

    let inner = io_err
        .get_ref()
        .unwrap()
        .downcast_ref::<NtpError>()
        .unwrap();
    assert!(matches!(inner, NtpError::Timeout(TimeoutError::Recv)));
}

#[test]
fn test_config_error_roundtrip() {
    let err = NtpError::Config(ConfigError::NoServers);
    let io_err: io::Error = err.into();

    assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);

    let inner = io_err
        .get_ref()
        .unwrap()
        .downcast_ref::<NtpError>()
        .unwrap();
    assert!(matches!(inner, NtpError::Config(ConfigError::NoServers)));
}

#[test]
fn test_nts_error_roundtrip() {
    let err = NtpError::Nts(NtsError::NoCookies);
    let io_err: io::Error = err.into();

    assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

    let inner = io_err
        .get_ref()
        .unwrap()
        .downcast_ref::<NtpError>()
        .unwrap();
    assert!(matches!(inner, NtpError::Nts(NtsError::NoCookies)));
}

#[test]
fn test_kiss_of_death_error_roundtrip() {
    let kod = KissOfDeathError {
        code: ntp_proto::protocol::KissOfDeath::Deny,
    };
    let err = NtpError::KissOfDeath(kod);
    let io_err: io::Error = err.into();

    let inner = io_err
        .get_ref()
        .unwrap()
        .downcast_ref::<NtpError>()
        .unwrap();
    assert!(matches!(inner, NtpError::KissOfDeath(_)));
}

#[test]
fn test_all_protocol_variants_downcast() {
    let variants: Vec<NtpError> = vec![
        NtpError::Protocol(ProtocolError::UnexpectedSource),
        NtpError::Protocol(ProtocolError::UnexpectedMode),
        NtpError::Protocol(ProtocolError::OriginTimestampMismatch),
        NtpError::Protocol(ProtocolError::ZeroTransmitTimestamp),
        NtpError::Protocol(ProtocolError::UnsynchronizedServer),
    ];

    for err in variants {
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
        assert!(
            io_err
                .get_ref()
                .unwrap()
                .downcast_ref::<NtpError>()
                .is_some(),
            "failed to downcast: {}",
            io_err
        );
    }
}

#[test]
fn test_display_messages_are_nonempty() {
    let errors: Vec<NtpError> = vec![
        NtpError::Protocol(ProtocolError::ResponseTooShort { received: 5 }),
        NtpError::Timeout(TimeoutError::Send),
        NtpError::Config(ConfigError::NoServers),
        NtpError::Nts(NtsError::NoCookies),
        NtpError::KissOfDeath(KissOfDeathError {
            code: ntp_proto::protocol::KissOfDeath::Rate,
        }),
    ];

    for err in errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "display should not be empty");
    }
}
