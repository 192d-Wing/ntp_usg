// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTPv5 server request handling (`draft-ietf-ntp-ntpv5-07`).
//!
//! Validates NTPv5 client requests, builds server responses, and handles
//! extension fields (Draft Identification, Reference IDs, Server Info,
//! Reference Timestamp, Padding) with response length matching.

use std::io;
use std::net::IpAddr;

use log::debug;

use ntp_proto::extension::{ExtensionField, parse_extension_fields, write_extension_fields_buf};
use ntp_proto::ntpv5_ext::{
    DRAFT_IDENTIFICATION, DraftIdentification, Padding, RefIdsRequest, RefIdsResponse,
    ReferenceTimestamp, SERVER_INFO, ServerInfo,
};
use ntp_proto::protocol::ntpv5::{NtpV5Flags, PacketV5, Time32};
use ntp_proto::protocol::{
    ConstPackedSizeBytes, FromBytes, Mode, Stratum, TimestampFormat, ToBytes, Version,
};

use crate::unix_time;

use super::{
    AccessControl, AccessResult, ClientTable, HandleResult, RateLimitConfig, RateLimitResult,
    ServerSystemState, check_rate_limit,
};

/// Validate an incoming NTPv5 client request.
///
/// Checks VN=5, Mode=Client, non-zero client cookie, and presence of a
/// matching Draft Identification extension field.
pub(crate) fn validate_v5_client_request(
    recv_buf: &[u8],
    recv_len: usize,
) -> io::Result<(PacketV5, Vec<ExtensionField>)> {
    if recv_len < PacketV5::PACKED_SIZE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTPv5 request too short",
        ));
    }

    let (request, _) = PacketV5::from_bytes(&recv_buf[..recv_len])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("V5 parse error: {e}")))?;

    if request.version != Version::V5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected NTPv5"));
    }

    if request.mode != Mode::Client {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected V5 mode: expected Client, got {:?}",
                request.mode
            ),
        ));
    }

    if request.client_cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "V5 client cookie is zero",
        ));
    }

    // Parse extension fields after the 48-byte header.
    let ext_data = &recv_buf[PacketV5::PACKED_SIZE_BYTES..recv_len];
    let extensions = parse_extension_fields(ext_data)?;

    // Verify Draft Identification is present and matches our draft version.
    let has_draft_id = extensions.iter().any(|ef| {
        ef.field_type == DRAFT_IDENTIFICATION
            && DraftIdentification::from_extension_field(ef).is_some_and(|di| di.is_current())
    });

    if !has_draft_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing or incompatible Draft Identification extension",
        ));
    }

    Ok((request, extensions))
}

/// Build a V5 server response packet (header only, T3 is placeholder).
fn build_v5_server_response(
    request: &PacketV5,
    server_state: &ServerSystemState,
    t2: TimestampFormat,
) -> PacketV5 {
    let mut flags = NtpV5Flags(0);
    if server_state.stratum != Stratum::UNSPECIFIED {
        flags.0 |= NtpV5Flags::SYNCHRONIZED;
    }

    // Generate server cookie (random-ish value for interleaved mode tracking).
    let server_cookie = {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let s = RandomState::new();
        let mut h = s.build_hasher();
        h.write_u64(request.client_cookie);
        let now = unix_time::Instant::now();
        h.write_i64(now.secs());
        h.write_i32(now.subsec_nanos());
        h.finish()
    };

    PacketV5 {
        leap_indicator: server_state.leap_indicator,
        version: Version::V5,
        mode: Mode::Server,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: Time32::from_short_format(server_state.root_delay),
        root_dispersion: Time32::from_short_format(server_state.root_dispersion),
        timescale: server_state.timescale,
        era: server_state.era,
        flags,
        server_cookie,
        client_cookie: request.client_cookie,
        receive_timestamp: t2,
        transmit_timestamp: TimestampFormat::default(), // Patched later
    }
}

/// Build response extension fields based on client's request extensions.
fn build_v5_response_extensions(
    request_extensions: &[ExtensionField],
    server_state: &ServerSystemState,
) -> Vec<ExtensionField> {
    let mut response_ext = Vec::new();

    // Always include Draft Identification.
    response_ext.push(DraftIdentification::current().to_extension_field());

    // Always include Reference Timestamp.
    response_ext.push(
        ReferenceTimestamp {
            timestamp: server_state.reference_timestamp,
        }
        .to_extension_field(),
    );

    // Include Server Info if requested.
    if request_extensions
        .iter()
        .any(|ef| ef.field_type == SERVER_INFO)
    {
        let si = ServerInfo {
            supported_versions: (1 << 4) | (1 << 5),
        };
        response_ext.push(si.to_extension_field());
    }

    // Include RefIds Response if requested.
    for ef in request_extensions {
        if let Some(req) = RefIdsRequest::from_extension_field(ef) {
            let chunk = server_state.bloom_filter.chunk(req.offset, 64);
            response_ext.push(
                RefIdsResponse {
                    data: chunk.to_vec(),
                }
                .to_extension_field(),
            );
            break; // Only one RefIds Response per packet
        }
    }

    response_ext
}

/// Serialize a V5 response to bytes, matching the target length exactly.
///
/// Returns `None` if the required extension fields exceed the available space.
fn serialize_v5_response(
    response: &PacketV5,
    extensions: &[ExtensionField],
    target_len: usize,
) -> Option<Vec<u8>> {
    if target_len < PacketV5::PACKED_SIZE_BYTES {
        return None;
    }

    let mut buf = vec![0u8; target_len];

    // 1. Serialize 48-byte header.
    response
        .to_bytes(&mut buf[..PacketV5::PACKED_SIZE_BYTES])
        .ok()?;

    // 2. Write extension fields after header.
    let ext_start = PacketV5::PACKED_SIZE_BYTES;
    let ext_written =
        write_extension_fields_buf(extensions, &mut buf[ext_start..target_len]).ok()?;

    // 3. Add padding to fill remaining space.
    let used = ext_start + ext_written;
    let remaining = target_len - used;
    if remaining >= 4 {
        let pad_value_len = remaining - 4;
        let pad_ef = Padding {
            size: pad_value_len,
        }
        .to_extension_field();
        let _ = write_extension_fields_buf(&[pad_ef], &mut buf[used..target_len]);
    }

    // 4. Patch T3 at offset 40..48 with current time.
    let t3: TimestampFormat = unix_time::Instant::now().into();
    buf[40..44].copy_from_slice(&t3.seconds.to_be_bytes());
    buf[44..48].copy_from_slice(&t3.fraction.to_be_bytes());

    Some(buf)
}

/// Handle a V5 request through the full server pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_v5_request(
    recv_buf: &[u8],
    recv_len: usize,
    src_ip: IpAddr,
    server_state: &ServerSystemState,
    access_control: &AccessControl,
    rate_limit_config: Option<&RateLimitConfig>,
    client_table: &mut ClientTable,
) -> HandleResult {
    // 1. Validate V5 request.
    let (request, extensions) = match validate_v5_client_request(recv_buf, recv_len) {
        Ok(r) => r,
        Err(e) => {
            debug!("dropping invalid V5 request from {}: {}", src_ip, e);
            return HandleResult::Drop;
        }
    };

    // 2. Access control.
    match access_control.check(&src_ip) {
        AccessResult::Allow => {}
        AccessResult::Deny | AccessResult::Restrict => {
            debug!("V5 access denied for {}", src_ip);
            return HandleResult::Drop;
        }
    }

    let now = std::time::Instant::now();

    // 3. Rate limiting.
    if let Some(config) = rate_limit_config {
        let client = client_table.get_or_insert(src_ip, now);
        match check_rate_limit(client, now, config) {
            RateLimitResult::Allow => {}
            RateLimitResult::RateExceeded => {
                debug!("V5 rate limit exceeded for {}", src_ip);
                return HandleResult::Drop;
            }
        }
    }

    // 4. Record T2.
    let t2: TimestampFormat = unix_time::Instant::now().into();

    // 5. Build V5 response header.
    let response = build_v5_server_response(&request, server_state, t2);

    // 6. Build response extension fields.
    let response_ext = build_v5_response_extensions(&extensions, server_state);

    // 7. Serialize response, matching request length exactly.
    match serialize_v5_response(&response, &response_ext, recv_len) {
        Some(buf) => HandleResult::V5Response(buf),
        None => {
            debug!(
                "V5 response exceeds request length ({} bytes) for {}",
                recv_len, src_ip
            );
            HandleResult::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntp_proto::protocol::LeapIndicator;
    use ntp_proto::protocol::ntpv5::{NtpV5Flags, Timescale};

    fn make_v5_client_buf() -> Vec<u8> {
        make_v5_client_buf_with_exts(&[])
    }

    fn make_v5_client_buf_with_exts(extra_exts: &[ExtensionField]) -> Vec<u8> {
        let pkt = PacketV5 {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V5,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 6,
            precision: 0,
            root_delay: Time32::ZERO,
            root_dispersion: Time32::ZERO,
            timescale: Timescale::Utc,
            era: 0,
            flags: NtpV5Flags::default(),
            server_cookie: 0,
            client_cookie: 0xDEAD_BEEF_CAFE_BABE,
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat::default(),
        };

        let target_len = 228usize;
        let mut buf = vec![0u8; target_len];
        pkt.to_bytes(&mut buf[..48]).unwrap();

        // Write Draft ID + any extra extensions.
        let mut exts = vec![DraftIdentification::current().to_extension_field()];
        exts.extend_from_slice(extra_exts);
        let ext_written = write_extension_fields_buf(&exts, &mut buf[48..]).unwrap();

        // Fill remaining space with a Padding extension.
        let used = 48 + ext_written;
        let remaining = target_len - used;
        if remaining >= 4 {
            let pad = Padding {
                size: remaining - 4,
            }
            .to_extension_field();
            write_extension_fields_buf(&[pad], &mut buf[used..]).unwrap();
        }

        buf
    }

    fn test_server_state() -> ServerSystemState {
        ServerSystemState {
            leap_indicator: LeapIndicator::NoWarning,
            stratum: Stratum(2),
            precision: -20,
            root_delay: ntp_proto::protocol::ShortFormat::default(),
            root_dispersion: ntp_proto::protocol::ShortFormat::default(),
            reference_id: ntp_proto::protocol::ReferenceIdentifier::SecondaryOrClient([
                127, 0, 0, 1,
            ]),
            reference_timestamp: TimestampFormat {
                seconds: 3_913_000_000,
                fraction: 0,
            },
            timescale: Timescale::Utc,
            era: 0,
            bloom_filter: ntp_proto::protocol::bloom::BloomFilter::new(),
            v5_reference_id: [0u8; 15],
        }
    }

    // ── validate_v5_client_request ───────────────────────────────

    #[test]
    fn test_validate_valid_v5_request() {
        let buf = make_v5_client_buf();
        let (pkt, exts) = validate_v5_client_request(&buf, buf.len()).unwrap();
        assert_eq!(pkt.version, Version::V5);
        assert_eq!(pkt.mode, Mode::Client);
        assert_eq!(pkt.client_cookie, 0xDEAD_BEEF_CAFE_BABE);
        assert!(exts.iter().any(|ef| ef.field_type == DRAFT_IDENTIFICATION));
    }

    #[test]
    fn test_validate_rejects_missing_draft_id() {
        // Send 48 bytes with no extension fields.
        let pkt = PacketV5 {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V5,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 6,
            precision: 0,
            root_delay: Time32::ZERO,
            root_dispersion: Time32::ZERO,
            timescale: Timescale::Utc,
            era: 0,
            flags: NtpV5Flags::default(),
            server_cookie: 0,
            client_cookie: 0xDEAD_BEEF_CAFE_BABE,
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat::default(),
        };
        let mut buf = vec![0u8; 48];
        pkt.to_bytes(&mut buf[..48]).unwrap();

        let result = validate_v5_client_request(&buf, buf.len());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Draft Identification")
        );
    }

    #[test]
    fn test_validate_rejects_zero_cookie() {
        let pkt = PacketV5 {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V5,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 6,
            precision: 0,
            root_delay: Time32::ZERO,
            root_dispersion: Time32::ZERO,
            timescale: Timescale::Utc,
            era: 0,
            flags: NtpV5Flags::default(),
            server_cookie: 0,
            client_cookie: 0, // Zero cookie
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat::default(),
        };
        let mut buf = vec![0u8; 228];
        pkt.to_bytes(&mut buf[..48]).unwrap();
        let draft_id = DraftIdentification::current().to_extension_field();
        write_extension_fields_buf(&[draft_id], &mut buf[48..]).unwrap();

        let result = validate_v5_client_request(&buf, buf.len());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cookie"));
    }

    #[test]
    fn test_validate_rejects_server_mode() {
        let pkt = PacketV5 {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V5,
            mode: Mode::Server,
            stratum: Stratum(2),
            poll: 6,
            precision: -20,
            root_delay: Time32::ZERO,
            root_dispersion: Time32::ZERO,
            timescale: Timescale::Utc,
            era: 0,
            flags: NtpV5Flags(NtpV5Flags::SYNCHRONIZED),
            server_cookie: 0x1234,
            client_cookie: 0xDEAD,
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat::default(),
        };
        let mut buf = vec![0u8; 228];
        pkt.to_bytes(&mut buf[..48]).unwrap();
        let draft_id = DraftIdentification::current().to_extension_field();
        write_extension_fields_buf(&[draft_id], &mut buf[48..]).unwrap();

        let result = validate_v5_client_request(&buf, buf.len());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mode"));
    }

    #[test]
    fn test_validate_rejects_too_short() {
        let buf = [0u8; 47];
        let result = validate_v5_client_request(&buf, buf.len());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    // ── build_v5_server_response ─────────────────────────────────

    #[test]
    fn test_v5_response_echoes_client_cookie() {
        let buf = make_v5_client_buf();
        let (request, _) = validate_v5_client_request(&buf, buf.len()).unwrap();
        let state = test_server_state();
        let t2 = TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };

        let response = build_v5_server_response(&request, &state, t2);
        assert_eq!(response.client_cookie, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(response.mode, Mode::Server);
        assert_eq!(response.version, Version::V5);
        assert_eq!(response.stratum, Stratum(2));
        assert!(response.flags.is_synchronized());
        assert_ne!(response.server_cookie, 0);
    }

    #[test]
    fn test_v5_response_converts_root_delay() {
        let mut state = test_server_state();
        state.root_delay = ntp_proto::protocol::ShortFormat {
            seconds: 1,
            fraction: 0,
        };
        let buf = make_v5_client_buf();
        let (request, _) = validate_v5_client_request(&buf, buf.len()).unwrap();
        let t2 = TimestampFormat::default();

        let response = build_v5_server_response(&request, &state, t2);
        let delay_secs = response.root_delay.to_seconds_f64();
        assert!((delay_secs - 1.0).abs() < 1e-7);
    }

    // ── serialize_v5_response ────────────────────────────────────

    #[test]
    fn test_serialize_matches_target_length() {
        let buf = make_v5_client_buf();
        let (request, exts) = validate_v5_client_request(&buf, buf.len()).unwrap();
        let state = test_server_state();
        let t2 = TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };

        let response = build_v5_server_response(&request, &state, t2);
        let response_ext = build_v5_response_extensions(&exts, &state);
        let result = serialize_v5_response(&response, &response_ext, 228);

        assert!(result.is_some());
        let resp_buf = result.unwrap();
        assert_eq!(resp_buf.len(), 228);
    }

    #[test]
    fn test_serialize_patches_t3() {
        let buf = make_v5_client_buf();
        let (request, exts) = validate_v5_client_request(&buf, buf.len()).unwrap();
        let state = test_server_state();
        let t2 = TimestampFormat::default();

        let response = build_v5_server_response(&request, &state, t2);
        let response_ext = build_v5_response_extensions(&exts, &state);
        let resp_buf = serialize_v5_response(&response, &response_ext, 228).unwrap();

        // T3 should be non-zero (patched).
        let t3_seconds =
            u32::from_be_bytes([resp_buf[40], resp_buf[41], resp_buf[42], resp_buf[43]]);
        assert_ne!(t3_seconds, 0);
    }

    #[test]
    fn test_serialize_returns_none_if_too_small() {
        let buf = make_v5_client_buf();
        let (request, exts) = validate_v5_client_request(&buf, buf.len()).unwrap();
        let state = test_server_state();
        let t2 = TimestampFormat::default();

        let response = build_v5_server_response(&request, &state, t2);
        let response_ext = build_v5_response_extensions(&exts, &state);

        // Target length 48: no room for required extensions.
        let result = serialize_v5_response(&response, &response_ext, 48);
        assert!(result.is_none());
    }

    // ── handle_v5_request (full pipeline) ─────────────────────────

    #[test]
    fn test_handle_v5_basic_response() {
        let buf = make_v5_client_buf();
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_v5_request(
            &buf,
            buf.len(),
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
        );

        match result {
            HandleResult::V5Response(resp_buf) => {
                assert_eq!(resp_buf.len(), 228); // Matches request length
                let (response, _) = PacketV5::from_bytes(&resp_buf[..48]).unwrap();
                assert_eq!(response.version, Version::V5);
                assert_eq!(response.mode, Mode::Server);
                assert_eq!(response.client_cookie, 0xDEAD_BEEF_CAFE_BABE);
                assert!(response.flags.is_synchronized());
                assert_ne!(response.transmit_timestamp.seconds, 0);
            }
            _ => panic!("expected V5Response"),
        }
    }

    #[test]
    fn test_handle_v5_drops_invalid() {
        let buf = [0u8; 48]; // All zeros → fails validation
        let state = test_server_state();
        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_v5_request(
            &buf,
            buf.len(),
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
        );
        assert!(matches!(result, HandleResult::Drop));
    }

    #[test]
    fn test_handle_v5_with_refids_request() {
        let refids_req = RefIdsRequest { offset: 0 }.to_extension_field();
        let buf = make_v5_client_buf_with_exts(&[refids_req]);

        let mut state = test_server_state();
        // Insert a reference ID into the bloom filter.
        let ref_id = [0xAA; 15];
        state.bloom_filter.insert(&ref_id);

        let ac = AccessControl::default();
        let mut table = ClientTable::new(100);

        let result = handle_v5_request(
            &buf,
            buf.len(),
            "127.0.0.1".parse().unwrap(),
            &state,
            &ac,
            None,
            &mut table,
        );

        match result {
            HandleResult::V5Response(resp_buf) => {
                assert_eq!(resp_buf.len(), 228);
                // Parse response extension fields.
                let resp_exts = parse_extension_fields(&resp_buf[48..]).unwrap();
                // Should contain a RefIds Response.
                assert!(
                    resp_exts
                        .iter()
                        .any(|ef| RefIdsResponse::from_extension_field(ef).is_some())
                );
            }
            _ => panic!("expected V5Response"),
        }
    }
}
