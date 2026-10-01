// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTS (RFC 8915) handling inside the NTP request pipeline.
//!
//! A request that carries NTS extension fields is authenticated with the
//! shared master key store. On success the response is built by
//! [`build_nts_response`]; on any NTS failure the server answers with an
//! `NTSN` Kiss-o'-Death that echoes the Unique Identifier (RFC 8915 §5.7) so
//! the client knows to discard its cookies and re-run NTS-KE.

use std::net::IpAddr;
use std::sync::RwLock;

use tracing::debug;

use crate::nts_server_common::{MasterKeyStore, build_nts_response, process_nts_extensions};
use crate::protocol::{self, ConstPackedSizeBytes};
use crate::unix_time;
use ntp_proto::extension::{self, UNIQUE_IDENTIFIER, UniqueIdentifier, parse_extension_fields};

use super::{
    HandleResult, ServerMetrics, ServerSystemState, build_kod_response, build_server_response,
    serialize_response_with_t3,
};

/// Handle an NTS request if `recv_buf` carries NTS extension fields.
///
/// Returns `None` when the request is not an NTS request, so the caller
/// continues with the ordinary NTPv4 path.
pub(crate) fn try_handle_nts(
    recv_buf: &[u8],
    recv_len: usize,
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    key_store: Option<&RwLock<MasterKeyStore>>,
    src_ip: IpAddr,
    metrics: Option<&ServerMetrics>,
) -> Option<HandleResult> {
    if recv_len <= protocol::Packet::PACKED_SIZE_BYTES {
        return None;
    }
    let ext_data = &recv_buf[protocol::Packet::PACKED_SIZE_BYTES..recv_len];
    // Unparseable extension data is left to the ordinary path (which ignores
    // extension fields), preserving existing behaviour for non-NTS clients.
    let ext_fields = parse_extension_fields(ext_data).ok()?;

    let is_nts = ext_fields.iter().any(|ef| {
        matches!(
            ef.field_type,
            UNIQUE_IDENTIFIER | extension::NTS_COOKIE | extension::NTS_AUTHENTICATOR
        )
    });
    if !is_nts {
        return None;
    }

    // The Unique Identifier must be echoed in every NTS reply, including NAKs;
    // without it there is nothing a client could safely match, so drop.
    let uid = ext_fields
        .iter()
        .find(|ef| ef.field_type == UNIQUE_IDENTIFIER)
        .map(|ef| ef.value.clone());
    let Some(uid) = uid else {
        debug!(client = %src_ip, "NTS request without Unique Identifier; dropping");
        return Some(HandleResult::Drop);
    };

    let Some(key_store) = key_store else {
        debug!(client = %src_ip, "NTS request but no NTS key store configured; dropping");
        return Some(HandleResult::Drop);
    };
    let Ok(store) = key_store.read() else {
        debug!(client = %src_ip, "NTS key store lock poisoned; dropping");
        return Some(HandleResult::Drop);
    };

    match process_nts_extensions(recv_buf, recv_len, &store) {
        Ok(ctx) => {
            let t2: protocol::TimestampFormat = unix_time::Instant::now().into();
            let mut response = build_server_response(request, server_state, t2);
            // The authenticator covers T3, so it must be set before encrypting.
            response.transmit_timestamp = unix_time::Instant::now().into();
            match build_nts_response(&response, &ctx) {
                Ok(buf) => {
                    if let Some(m) = metrics {
                        m.inc_responses_sent();
                    }
                    Some(HandleResult::NtsResponse(buf))
                }
                Err(e) => {
                    debug!(client = %src_ip, error = %e, "failed to build NTS response");
                    Some(HandleResult::Drop)
                }
            }
        }
        Err(e) => {
            // RFC 8915 §5.7: respond with NTSN, echo the Unique Identifier, and
            // include no authenticator or cookies. The reply (48 bytes + UID
            // field) is never larger than the request, which carried the UID
            // plus at least a cookie and an authenticator.
            debug!(client = %src_ip, error = %e, "NTS authentication failed; sending NTSN");
            let kod = build_kod_response(request, protocol::KissOfDeath::Ntsn);
            let header = serialize_response_with_t3(&kod).ok()?;
            let uid_bytes = extension::write_extension_fields(&[
                UniqueIdentifier::new(uid).to_extension_field()
            ])
            .ok()?;
            let mut buf = Vec::with_capacity(header.len() + uid_bytes.len());
            buf.extend_from_slice(&header);
            buf.extend_from_slice(&uid_bytes);
            Some(HandleResult::NtsResponse(buf))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ReadBytes, WriteBytes};
    use ntp_proto::extension::ExtensionField;
    use std::time::Duration;

    fn client_request() -> protocol::Packet {
        protocol::Packet {
            mode: protocol::Mode::Client,
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_900_000_000,
                fraction: 42,
            },
            ..protocol::Packet::default()
        }
    }

    fn request_bytes(fields: &[ExtensionField]) -> Vec<u8> {
        let mut buf = vec![0u8; protocol::Packet::PACKED_SIZE_BYTES];
        (&mut buf[..]).write_bytes(client_request()).unwrap();
        buf.extend_from_slice(&extension::write_extension_fields(fields).unwrap());
        buf
    }

    fn nts_fields(uid: &[u8]) -> Vec<ExtensionField> {
        vec![
            ExtensionField {
                field_type: UNIQUE_IDENTIFIER,
                value: uid.to_vec(),
            },
            ExtensionField {
                field_type: extension::NTS_COOKIE,
                value: vec![0xAB; 100],
            },
            ExtensionField {
                field_type: extension::NTS_AUTHENTICATOR,
                value: vec![0u8; 36],
            },
        ]
    }

    #[test]
    fn plain_request_is_not_nts() {
        let buf = request_bytes(&[]);
        let state = ServerSystemState::default();
        let r = try_handle_nts(
            &buf,
            buf.len(),
            &client_request(),
            &state,
            None,
            "127.0.0.1".parse().unwrap(),
            None,
        );
        assert!(r.is_none());
    }

    #[test]
    fn nts_request_without_key_store_is_dropped() {
        let buf = request_bytes(&nts_fields(&[1u8; 32]));
        let state = ServerSystemState::default();
        let r = try_handle_nts(
            &buf,
            buf.len(),
            &client_request(),
            &state,
            None,
            "127.0.0.1".parse().unwrap(),
            None,
        );
        assert!(matches!(r, Some(HandleResult::Drop)));
    }

    #[test]
    fn bad_cookie_yields_ntsn_with_echoed_uid_and_no_amplification() {
        let uid = [7u8; 32];
        let buf = request_bytes(&nts_fields(&uid));
        let store = RwLock::new(MasterKeyStore::new(Duration::from_secs(3600)));
        let state = ServerSystemState::default();
        let r = try_handle_nts(
            &buf,
            buf.len(),
            &client_request(),
            &state,
            Some(&store),
            "127.0.0.1".parse().unwrap(),
            None,
        );
        let Some(HandleResult::NtsResponse(resp)) = r else {
            panic!("expected NTSN response");
        };
        assert!(resp.len() <= buf.len(), "NAK must not amplify");
        let hdr: protocol::Packet = (&resp[..48]).read_bytes().unwrap();
        assert_eq!(
            hdr.reference_id,
            protocol::ReferenceIdentifier::KissOfDeath(protocol::KissOfDeath::Ntsn)
        );
        assert_eq!(hdr.origin_timestamp, client_request().transmit_timestamp);
        let efs = parse_extension_fields(&resp[48..]).unwrap();
        assert_eq!(efs.len(), 1);
        assert_eq!(efs[0].field_type, UNIQUE_IDENTIFIER);
        assert_eq!(efs[0].value, uid);
    }

    #[test]
    fn nts_request_without_uid_is_dropped() {
        let fields: Vec<_> = nts_fields(&[1u8; 32]).into_iter().skip(1).collect();
        let buf = request_bytes(&fields);
        let store = RwLock::new(MasterKeyStore::new(Duration::from_secs(3600)));
        let state = ServerSystemState::default();
        let r = try_handle_nts(
            &buf,
            buf.len(),
            &client_request(),
            &state,
            Some(&store),
            "127.0.0.1".parse().unwrap(),
            None,
        );
        assert!(matches!(r, Some(HandleResult::Drop)));
    }
}
