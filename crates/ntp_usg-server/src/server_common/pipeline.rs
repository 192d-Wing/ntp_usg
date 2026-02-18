use std::net::IpAddr;
use std::time::Instant;

use log::debug;

use crate::protocol::{self, ConstPackedSizeBytes};
use crate::unix_time;

use super::{
    AccessControl, AccessResult, ClientTable, RateLimitConfig, RateLimitResult, ServerSystemState,
    build_interleaved_response, build_kod_response, build_server_response, check_rate_limit,
    serialize_response_with_t3, update_client_state, validate_client_request,
};

/// The complete result of handling a client request.
pub(crate) enum HandleResult {
    /// Send this response buffer to the client (NTPv4, fixed 48 bytes).
    Response([u8; protocol::Packet::PACKED_SIZE_BYTES]),
    /// Send this response buffer to the client (NTPv5, variable length).
    #[cfg(feature = "ntpv5")]
    V5Response(Vec<u8>),
    /// Drop the packet (invalid request, silently ignored).
    Drop,
}

/// Handle a single incoming NTP request (pure logic, no I/O).
///
/// This is the main request processing pipeline called by both the tokio
/// and smol server loops.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_request(
    recv_buf: &[u8],
    recv_len: usize,
    src_ip: IpAddr,
    server_state: &ServerSystemState,
    access_control: &AccessControl,
    rate_limit_config: Option<&RateLimitConfig>,
    client_table: &mut ClientTable,
    enable_interleaved: bool,
) -> HandleResult {
    // 0. NTPv5 version dispatch: peek at VN field in byte 0.
    #[cfg(feature = "ntpv5")]
    {
        if recv_len >= 1 {
            let vn = (recv_buf[0] >> 3) & 0b111;
            if vn == 5 {
                return super::ntpv5::handle_v5_request(
                    recv_buf,
                    recv_len,
                    src_ip,
                    server_state,
                    access_control,
                    rate_limit_config,
                    client_table,
                );
            }
        }
    }

    // 1. Validate the request.
    let request = match validate_client_request(recv_buf, recv_len) {
        Ok(req) => req,
        Err(e) => {
            debug!("dropping invalid request from {}: {}", src_ip, e);
            return HandleResult::Drop;
        }
    };

    // 2. Access control.
    match access_control.check(&src_ip) {
        AccessResult::Allow => {}
        AccessResult::Deny => {
            let kod = build_kod_response(&request, protocol::KissOfDeath::Deny);
            match serialize_response_with_t3(&kod) {
                Ok(buf) => return HandleResult::Response(buf),
                Err(_) => return HandleResult::Drop,
            }
        }
        AccessResult::Restrict => {
            let kod = build_kod_response(&request, protocol::KissOfDeath::Rstr);
            match serialize_response_with_t3(&kod) {
                Ok(buf) => return HandleResult::Response(buf),
                Err(_) => return HandleResult::Drop,
            }
        }
    }

    let now = Instant::now();

    // 3. Rate limiting.
    if let Some(config) = rate_limit_config {
        let client = client_table.get_or_insert(src_ip, now);
        match check_rate_limit(client, now, config) {
            RateLimitResult::Allow => {}
            RateLimitResult::RateExceeded => {
                let kod = build_kod_response(&request, protocol::KissOfDeath::Rate);
                match serialize_response_with_t3(&kod) {
                    Ok(buf) => return HandleResult::Response(buf),
                    Err(_) => return HandleResult::Drop,
                }
            }
        }
    }

    // 4. Record T2 (receive timestamp).
    let t2: protocol::TimestampFormat = unix_time::Instant::now().into();

    // 5. Check for interleaved mode.
    let response = if enable_interleaved {
        if let Some(client_state) = client_table.get(&src_ip) {
            build_interleaved_response(&request, server_state, client_state, t2)
        } else {
            None
        }
    } else {
        None
    };

    // 6. Build response (basic, interleaved, or symmetric passive).
    let mut response = response.unwrap_or_else(|| {
        #[cfg(feature = "symmetric")]
        if request.mode == protocol::Mode::SymmetricActive {
            return super::build_symmetric_passive_response(&request, server_state, t2);
        }
        build_server_response(&request, server_state, t2)
    });

    // 6b. NTPv5 version negotiation: echo magic in V4 reference timestamp.
    #[cfg(feature = "ntpv5")]
    {
        let magic_secs = (ntp_proto::ntpv5_ext::NEGOTIATION_MAGIC_DRAFT >> 32) as u32;
        let magic_frac = ntp_proto::ntpv5_ext::NEGOTIATION_MAGIC_DRAFT as u32;
        if request.reference_timestamp.seconds == magic_secs
            && request.reference_timestamp.fraction == magic_frac
        {
            response.reference_timestamp = request.reference_timestamp;
        }
    }

    // 7. Serialize with T3.
    let buf = match serialize_response_with_t3(&response) {
        Ok(buf) => buf,
        Err(e) => {
            debug!("failed to serialize response for {}: {}", src_ip, e);
            return HandleResult::Drop;
        }
    };

    // 8. Extract the actual T3 we just wrote for client state update.
    let t3_seconds = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
    let t3_fraction = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);
    let t3 = protocol::TimestampFormat {
        seconds: t3_seconds,
        fraction: t3_fraction,
    };

    // 9. Update per-client state.
    let client = client_table.get_or_insert(src_ip, now);
    update_client_state(client, t2, t3, request.transmit_timestamp);

    HandleResult::Response(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ReadBytes, WriteBytes};
    use crate::server_common::{
        ClientState, ClientTable, IpNet, build_interleaved_response, build_kod_response,
        build_server_response, serialize_response_with_t3, validate_client_request,
    };

    fn make_client_request_packet(version: protocol::Version) -> protocol::Packet {
        protocol::Packet {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            version,
            mode: protocol::Mode::Client,
            stratum: protocol::Stratum::UNSPECIFIED,
            poll: 6,
            precision: 0,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::PrimarySource(
                protocol::PrimarySource::Null,
            ),
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: protocol::TimestampFormat::default(),
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 12345,
            },
        }
    }

    fn serialize_packet(pkt: &protocol::Packet) -> [u8; 48] {
        let mut buf = [0u8; 48];
        (&mut buf[..]).write_bytes(*pkt).unwrap();
        buf
    }

    fn test_server_state() -> ServerSystemState {
        ServerSystemState {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            stratum: protocol::Stratum(2),
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat {
                seconds: 3_913_000_000,
                fraction: 0,
            },
            #[cfg(feature = "ntpv5")]
            timescale: ntp_proto::protocol::ntpv5::Timescale::Utc,
            #[cfg(feature = "ntpv5")]
            era: 0,
            #[cfg(feature = "ntpv5")]
            bloom_filter: ntp_proto::protocol::bloom::BloomFilter::new(),
            #[cfg(feature = "ntpv5")]
            v5_reference_id: [0u8; 15],
        }
    }

    // ── validate_client_request ──────────────────────────────────

    #[test]
    fn test_validate_accepts_v4_client() {
        let pkt = make_client_request_packet(protocol::Version::V4);
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.mode, protocol::Mode::Client);
        assert_eq!(parsed.version, protocol::Version::V4);
    }

    #[test]
    fn test_validate_accepts_v3_client() {
        let pkt = make_client_request_packet(protocol::Version::V3);
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_short_packet() {
        let buf = [0u8; 48];
        let result = validate_client_request(&buf, 47);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_validate_rejects_server_mode() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.mode = protocol::Mode::Server;
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unexpected request mode")
        );
    }

    #[test]
    fn test_validate_rejects_v2() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.version = protocol::Version::V2;
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported NTP version")
        );
    }

    #[test]
    fn test_validate_rejects_zero_transmit() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.transmit_timestamp = protocol::TimestampFormat {
            seconds: 0,
            fraction: 0,
        };
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("transmit timestamp is zero")
        );
    }

    // ── build_server_response ─────────────────────────────────────

    #[test]
    fn test_response_copies_client_xmt_to_origin() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.origin_timestamp, request.transmit_timestamp);
    }

    #[test]
    fn test_response_mode_is_server() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat::default();
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.mode, protocol::Mode::Server);
    }

    #[test]
    fn test_response_echoes_version() {
        let request = make_client_request_packet(protocol::Version::V3);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat::default();
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.version, protocol::Version::V3);
    }

    #[test]
    fn test_response_sets_t2() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 999,
        };
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.receive_timestamp, t2);
    }

    #[test]
    fn test_response_uses_server_state() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat::default();
        let response = build_server_response(&request, &state, t2);
        assert_eq!(response.stratum, state.stratum);
        assert_eq!(response.precision, state.precision);
        assert_eq!(response.leap_indicator, state.leap_indicator);
        assert_eq!(response.reference_id, state.reference_id);
    }

    // ── build_kod_response ────────────────────────────────────────

    #[test]
    fn test_kod_deny() {
        let request = make_client_request_packet(protocol::Version::V4);
        let kod = build_kod_response(&request, protocol::KissOfDeath::Deny);
        assert_eq!(kod.stratum, protocol::Stratum::UNSPECIFIED);
        assert_eq!(kod.mode, protocol::Mode::Server);
        assert_eq!(
            kod.reference_id,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Deny)
        );
        assert_eq!(kod.origin_timestamp, request.transmit_timestamp);
        assert_eq!(kod.leap_indicator, protocol::LeapIndicator::Unknown);
    }

    #[test]
    fn test_kod_rate() {
        let request = make_client_request_packet(protocol::Version::V4);
        let kod = build_kod_response(&request, protocol::KissOfDeath::Rate);
        assert_eq!(
            kod.reference_id,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Rate)
        );
    }

    #[test]
    fn test_kod_rstr() {
        let request = make_client_request_packet(protocol::Version::V4);
        let kod = build_kod_response(&request, protocol::KissOfDeath::Rstr);
        assert_eq!(
            kod.reference_id,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Rstr)
        );
    }

    // ── serialize_response_with_t3 ────────────────────────────────

    #[test]
    fn test_serialize_patches_t3() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = build_server_response(&request, &state, t2);
        let buf = serialize_response_with_t3(&response).unwrap();

        // Parse it back.
        let parsed: protocol::Packet = (&buf[..48]).read_bytes().unwrap();
        // T3 should be non-zero (patched to current time).
        assert!(parsed.transmit_timestamp.seconds != 0 || parsed.transmit_timestamp.fraction != 0);
    }

    // ── Interleaved mode ──────────────────────────────────────────

    #[test]
    fn test_interleaved_not_detected_first_exchange() {
        let request = make_client_request_packet(protocol::Version::V4);
        let state = test_server_state();
        let client = ClientState::new(std::time::Instant::now());
        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        // No previous state → basic mode.
        let result = build_interleaved_response(&request, &state, &client, t2);
        assert!(result.is_none());
    }

    #[test]
    fn test_interleaved_detected() {
        let state = test_server_state();
        let prev_t3 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 500,
        };
        let prev_t2 = protocol::TimestampFormat {
            seconds: 3_913_055_999,
            fraction: 999,
        };
        let prev_client_xmt = protocol::TimestampFormat {
            seconds: 3_913_055_998,
            fraction: 0,
        };

        let mut client = ClientState::new(std::time::Instant::now());
        client.last_t3 = prev_t3;
        client.last_t2 = prev_t2;
        client.last_client_xmt = prev_client_xmt;

        // Client sends origin = our previous T3 → interleaved.
        let mut request = make_client_request_packet(protocol::Version::V4);
        request.origin_timestamp = prev_t3;

        let t2 = protocol::TimestampFormat {
            seconds: 3_913_056_010,
            fraction: 0,
        };
        let result = build_interleaved_response(&request, &state, &client, t2);
        assert!(result.is_some());
        let pkt = result.unwrap();
        assert_eq!(pkt.origin_timestamp, prev_client_xmt);
        assert_eq!(pkt.receive_timestamp, prev_t2);
    }

    #[test]
    fn test_interleaved_not_detected_mismatch() {
        let state = test_server_state();
        let mut client = ClientState::new(std::time::Instant::now());
        client.last_t3 = protocol::TimestampFormat {
            seconds: 100,
            fraction: 0,
        };

        let mut request = make_client_request_packet(protocol::Version::V4);
        request.origin_timestamp = protocol::TimestampFormat {
            seconds: 999,
            fraction: 0,
        }; // Doesn't match

        let t2 = protocol::TimestampFormat::default();
        let result = build_interleaved_response(&request, &state, &client, t2);
        assert!(result.is_none());
    }

    // ── handle_request pipeline ───────────────────────────────────

    #[test]
    fn test_handle_valid_request() {
        let request = make_client_request_packet(protocol::Version::V4);
        let buf = serialize_packet(&request);
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );
        assert!(matches!(result, HandleResult::Response(_)));

        if let HandleResult::Response(resp_buf) = result {
            let response: protocol::Packet = (&resp_buf[..48]).read_bytes().unwrap();
            assert_eq!(response.mode, protocol::Mode::Server);
            assert_eq!(response.origin_timestamp, request.transmit_timestamp);
            assert_eq!(response.stratum, state.stratum);
        }
    }

    #[test]
    fn test_handle_denied_ip() {
        let request = make_client_request_packet(protocol::Version::V4);
        let buf = serialize_packet(&request);
        let state = test_server_state();
        let ac = AccessControl::new(
            None,
            Some(vec![IpNet::new("127.0.0.0".parse().unwrap(), 8)]),
        );
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );
        if let HandleResult::Response(resp_buf) = result {
            let response: protocol::Packet = (&resp_buf[..48]).read_bytes().unwrap();
            assert_eq!(response.stratum, protocol::Stratum::UNSPECIFIED);
            assert_eq!(
                response.reference_id,
                protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Deny)
            );
        } else {
            panic!("expected Response, got Drop");
        }
    }

    #[test]
    fn test_handle_drops_invalid_packet() {
        let buf = [0u8; 48]; // All zeros → zero xmt timestamp
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );
        assert!(matches!(result, HandleResult::Drop));
    }

    // ── symmetric mode ─────────────────────────────────────────────

    #[cfg(feature = "symmetric")]
    #[test]
    fn test_validate_accepts_symmetric_active() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.mode = protocol::Mode::SymmetricActive;
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mode, protocol::Mode::SymmetricActive);
    }

    #[cfg(feature = "symmetric")]
    #[test]
    fn test_symmetric_passive_response_mode() {
        use crate::server_common::build_symmetric_passive_response;
        let request = protocol::Packet {
            mode: protocol::Mode::SymmetricActive,
            ..make_client_request_packet(protocol::Version::V4)
        };
        let state = test_server_state();
        let t2 = protocol::TimestampFormat {
            seconds: 100,
            fraction: 0,
        };
        let response = build_symmetric_passive_response(&request, &state, t2);
        assert_eq!(response.mode, protocol::Mode::SymmetricPassive);
        assert_eq!(response.origin_timestamp, request.transmit_timestamp);
        assert_eq!(response.receive_timestamp, t2);
        assert_eq!(response.stratum, state.stratum);
    }

    #[cfg(feature = "symmetric")]
    #[test]
    fn test_handle_symmetric_active_returns_passive() {
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.mode = protocol::Mode::SymmetricActive;
        let buf = serialize_packet(&pkt);
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );

        match result {
            HandleResult::Response(response_buf) => {
                let response: protocol::Packet = (&response_buf
                    [..protocol::Packet::PACKED_SIZE_BYTES])
                    .read_bytes()
                    .unwrap();
                assert_eq!(response.mode, protocol::Mode::SymmetricPassive);
            }
            #[cfg(feature = "ntpv5")]
            HandleResult::V5Response(_) => panic!("expected V4 Response, got V5Response"),
            HandleResult::Drop => panic!("expected Response, got Drop"),
        }
    }

    #[test]
    fn test_validate_still_rejects_symmetric_without_feature() {
        // Without the symmetric feature, SymmetricActive should be rejected.
        // With the symmetric feature, this test verifies that Server mode is
        // still rejected (the feature only adds SymmetricActive acceptance).
        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.mode = protocol::Mode::Server;
        let buf = serialize_packet(&pkt);
        let result = validate_client_request(&buf, 48);
        assert!(result.is_err());
    }

    // ── NTPv5 version negotiation ─────────────────────────────────

    #[cfg(feature = "ntpv5")]
    #[test]
    fn test_v4_negotiation_magic_echo() {
        use ntp_proto::ntpv5_ext::NEGOTIATION_MAGIC_DRAFT;

        let magic_secs = (NEGOTIATION_MAGIC_DRAFT >> 32) as u32;
        let magic_frac = NEGOTIATION_MAGIC_DRAFT as u32;

        let mut pkt = make_client_request_packet(protocol::Version::V4);
        pkt.reference_timestamp = protocol::TimestampFormat {
            seconds: magic_secs,
            fraction: magic_frac,
        };
        let buf = serialize_packet(&pkt);
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            48,
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );

        if let HandleResult::Response(resp_buf) = result {
            let response: protocol::Packet = (&resp_buf[..48]).read_bytes().unwrap();
            assert_eq!(response.reference_timestamp.seconds, magic_secs);
            assert_eq!(response.reference_timestamp.fraction, magic_frac);
        } else {
            panic!("expected Response");
        }
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn test_v5_request_dispatches_to_v5_handler() {
        use ntp_proto::extension::write_extension_fields_buf;
        use ntp_proto::ntpv5_ext::{DraftIdentification, Padding};
        use ntp_proto::protocol::ntpv5::{NtpV5Flags, PacketV5, Time32, Timescale};
        use ntp_proto::protocol::{LeapIndicator, ToBytes};

        let pkt = PacketV5 {
            leap_indicator: LeapIndicator::NoWarning,
            version: protocol::Version::V5,
            mode: protocol::Mode::Client,
            stratum: protocol::Stratum::UNSPECIFIED,
            poll: 6,
            precision: 0,
            root_delay: Time32::ZERO,
            root_dispersion: Time32::ZERO,
            timescale: Timescale::Utc,
            era: 0,
            flags: NtpV5Flags::default(),
            server_cookie: 0,
            client_cookie: 0xDEAD_BEEF_CAFE_BABE,
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat::default(),
        };

        let mut buf = vec![0u8; 228];
        pkt.to_bytes(&mut buf[..48]).unwrap();
        let draft_id = DraftIdentification::current().to_extension_field();
        let ext_written = write_extension_fields_buf(&[draft_id], &mut buf[48..]).unwrap();
        // Fill remaining with Padding extension.
        let used = 48 + ext_written;
        let remaining = 228 - used;
        if remaining >= 4 {
            let pad = Padding {
                size: remaining - 4,
            }
            .to_extension_field();
            write_extension_fields_buf(&[pad], &mut buf[used..]).unwrap();
        }

        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_request(
            &buf,
            buf.len(),
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
            false,
        );

        // Should get a V5Response, not a V4 Response.
        assert!(matches!(result, HandleResult::V5Response(_)));
    }
}
