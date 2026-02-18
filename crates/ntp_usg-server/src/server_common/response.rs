use std::io;

use crate::protocol::{self, ConstPackedSizeBytes, WriteBytes};
use crate::unix_time;

use super::ServerSystemState;

/// Build an NTP server response packet for a client request.
///
/// Per RFC 5905 Section 8:
/// - `origin_timestamp` is set to the client's `transmit_timestamp` (anti-replay)
/// - `receive_timestamp` is T2 (when the request arrived)
/// - `transmit_timestamp` is left as default (caller patches T3 just before sending)
/// - `version` echoes the client's version
/// - `mode` is `Server`
pub(crate) fn build_server_response(
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    t2: protocol::TimestampFormat,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: server_state.leap_indicator,
        version: request.version,
        mode: protocol::Mode::Server,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_timestamp: server_state.reference_timestamp,
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: t2,
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Build a symmetric passive response (mode 2) for a symmetric active request.
///
/// Per RFC 5905 Section 8, a symmetric passive response is identical to a
/// server response but uses `Mode::SymmetricPassive` instead of `Mode::Server`.
#[cfg(feature = "symmetric")]
pub(crate) fn build_symmetric_passive_response(
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    t2: protocol::TimestampFormat,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: server_state.leap_indicator,
        version: request.version,
        mode: protocol::Mode::SymmetricPassive,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_timestamp: server_state.reference_timestamp,
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: t2,
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Build a Kiss-o'-Death (KoD) response packet.
///
/// Per RFC 5905 Section 7.4, KoD packets have stratum 0 and the reference
/// identifier set to the kiss code.
pub(crate) fn build_kod_response(
    request: &protocol::Packet,
    kod: protocol::KissOfDeath,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: protocol::LeapIndicator::Unknown,
        version: request.version,
        mode: protocol::Mode::Server,
        stratum: protocol::Stratum::UNSPECIFIED,
        poll: request.poll,
        precision: 0,
        root_delay: protocol::ShortFormat::default(),
        root_dispersion: protocol::ShortFormat::default(),
        reference_id: protocol::ReferenceIdentifier::KissOfDeath(kod),
        reference_timestamp: protocol::TimestampFormat::default(),
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Serialize a response packet to bytes and patch T3 (transmit timestamp)
/// as late as possible for maximum accuracy.
///
/// Returns the serialized buffer ready to send.
pub fn serialize_response_with_t3(
    response: &protocol::Packet,
) -> io::Result<[u8; protocol::Packet::PACKED_SIZE_BYTES]> {
    let mut buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];

    // Serialize the packet with a placeholder T3.
    (&mut buf[..]).write_bytes(*response)?;

    // Patch T3 at offset 40..48 with the current time.
    let t3: protocol::TimestampFormat = unix_time::Instant::now().into();
    let t3_bytes_sec = t3.seconds.to_be_bytes();
    let t3_bytes_frac = t3.fraction.to_be_bytes();
    buf[40..44].copy_from_slice(&t3_bytes_sec);
    buf[44..48].copy_from_slice(&t3_bytes_frac);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ConstPackedSizeBytes, KissOfDeath, LeapIndicator, Mode, Packet, ReferenceIdentifier,
        ShortFormat, Stratum, TimestampFormat, Version,
    };

    fn test_request() -> Packet {
        Packet {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V4,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 8,
            precision: 0,
            root_delay: ShortFormat::default(),
            root_dispersion: ShortFormat::default(),
            reference_id: ReferenceIdentifier::default(),
            reference_timestamp: TimestampFormat::default(),
            origin_timestamp: TimestampFormat::default(),
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat {
                seconds: 12345,
                fraction: 67890,
            },
        }
    }

    fn test_server_state() -> ServerSystemState {
        ServerSystemState::default()
    }

    #[test]
    fn server_response_mode() {
        let req = test_request();
        let state = test_server_state();
        let t2 = TimestampFormat {
            seconds: 100,
            fraction: 200,
        };
        let resp = build_server_response(&req, &state, t2);
        assert_eq!(resp.mode, Mode::Server);
    }

    #[test]
    fn server_response_echoes_version() {
        let req = test_request();
        let state = test_server_state();
        let t2 = TimestampFormat::default();
        let resp = build_server_response(&req, &state, t2);
        assert_eq!(resp.version, Version::V4);
    }

    #[test]
    fn server_response_echoes_poll() {
        let req = test_request();
        let state = test_server_state();
        let t2 = TimestampFormat::default();
        let resp = build_server_response(&req, &state, t2);
        assert_eq!(resp.poll, 8);
    }

    #[test]
    fn server_response_origin_is_client_xmt() {
        let req = test_request();
        let state = test_server_state();
        let t2 = TimestampFormat::default();
        let resp = build_server_response(&req, &state, t2);
        assert_eq!(resp.origin_timestamp, req.transmit_timestamp);
    }

    #[test]
    fn server_response_receive_is_t2() {
        let req = test_request();
        let state = test_server_state();
        let t2 = TimestampFormat {
            seconds: 999,
            fraction: 888,
        };
        let resp = build_server_response(&req, &state, t2);
        assert_eq!(resp.receive_timestamp, t2);
    }

    #[test]
    fn server_response_stratum() {
        let req = test_request();
        let state = test_server_state();
        let t2 = TimestampFormat::default();
        let resp = build_server_response(&req, &state, t2);
        assert_eq!(resp.stratum, state.stratum);
    }

    #[test]
    fn kod_response_stratum_zero() {
        let req = test_request();
        let resp = build_kod_response(&req, KissOfDeath::Deny);
        assert_eq!(resp.stratum, Stratum::UNSPECIFIED);
    }

    #[test]
    fn kod_response_deny() {
        let req = test_request();
        let resp = build_kod_response(&req, KissOfDeath::Deny);
        assert_eq!(
            resp.reference_id,
            ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny)
        );
    }

    #[test]
    fn kod_response_rate() {
        let req = test_request();
        let resp = build_kod_response(&req, KissOfDeath::Rate);
        assert_eq!(
            resp.reference_id,
            ReferenceIdentifier::KissOfDeath(KissOfDeath::Rate)
        );
    }

    #[test]
    fn serialize_response_length() {
        let req = test_request();
        let state = test_server_state();
        let t2 = TimestampFormat::default();
        let resp = build_server_response(&req, &state, t2);
        let buf = serialize_response_with_t3(&resp).unwrap();
        assert_eq!(buf.len(), Packet::PACKED_SIZE_BYTES);
        assert_eq!(buf.len(), 48);
    }
}
