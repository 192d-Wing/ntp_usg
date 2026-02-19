// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared NTS-KE (Key Establishment) client logic used by both the
//! tokio-based [`crate::nts`] and smol-based [`crate::smol_nts`] modules.
//!
//! Extracts protocol processing from async I/O so that each runtime module
//! only handles TLS connection setup, record reading/writing, and shutdown.

use std::io;

use tracing::debug;

use crate::nts_common::*;

/// Parse an NTS-KE server address into (hostname, port).
///
/// Default port is [`NTS_KE_DEFAULT_PORT`] (4460) if not specified.
pub(crate) fn parse_nts_ke_server_addr(server: &str) -> (&str, u16) {
    if let Some(idx) = server.rfind(':') {
        if let Ok(p) = server[idx + 1..].parse::<u16>() {
            (&server[..idx], p)
        } else {
            (server, NTS_KE_DEFAULT_PORT)
        }
    } else {
        (server, NTS_KE_DEFAULT_PORT)
    }
}

/// Build the NTS-KE client request records.
///
/// Returns a buffer containing:
/// 1. Next Protocol: NTPv4 (critical)
/// 2. AEAD Algorithms: prefer CMAC-512, also accept CMAC-256 (critical)
/// 3. End of Message (critical)
pub(crate) fn build_nts_ke_request() -> Vec<u8> {
    let mut buf = Vec::new();
    write_ke_record(
        &mut buf,
        true,
        NTS_KE_NEXT_PROTOCOL,
        &NTS_PROTOCOL_NTPV4.to_be_bytes(),
    );
    write_ke_record(
        &mut buf,
        true,
        NTS_KE_AEAD_ALGORITHM,
        &AEAD_AES_SIV_CMAC_512.to_be_bytes(),
    );
    write_ke_record(
        &mut buf,
        true,
        NTS_KE_AEAD_ALGORITHM,
        &AEAD_AES_SIV_CMAC_256.to_be_bytes(),
    );
    write_ke_record(&mut buf, true, NTS_KE_END_OF_MESSAGE, &[]);
    buf
}

/// Process NTS-KE response records and export TLS keys.
///
/// Takes already-parsed NTS-KE records (read from the TLS stream by the
/// runtime-specific caller) and a reference to the underlying
/// `rustls::ClientConnection` (same type from both `tokio-rustls` and
/// `futures-rustls`) for key export.
///
/// Returns an [`NtsKeResult`] with negotiated keys, cookies, and server info.
pub(crate) fn process_nts_ke_records(
    records: &[NtsKeRecord],
    tls_conn: &rustls::ClientConnection,
    default_hostname: &str,
) -> io::Result<NtsKeResult> {
    let mut next_protocol: Option<u16> = None;
    let mut aead_algorithm = AEAD_AES_SIV_CMAC_512;
    let mut cookies = Vec::new();
    let mut ntp_server = default_hostname.to_string();
    let mut ntp_port: u16 = 123;

    for record in records {
        match record.record_type {
            NTS_KE_END_OF_MESSAGE => {
                debug!("NTS-KE: end of message");
                break;
            }
            NTS_KE_NEXT_PROTOCOL => {
                if record.body.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NTS-KE: next protocol record too short",
                    ));
                }
                let proto = read_be_u16(&record.body[..2]);
                let supported = proto == NTS_PROTOCOL_NTPV4;
                #[cfg(feature = "ntpv5")]
                let supported = supported || proto == NTS_PROTOCOL_NTPV5;
                if !supported {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("NTS-KE: unsupported protocol: {}", proto),
                    ));
                }
                next_protocol = Some(proto);
                debug!(
                    protocol = format_args!("0x{:04X}", proto),
                    "NTS-KE: next protocol negotiated"
                );
            }
            NTS_KE_AEAD_ALGORITHM => {
                if record.body.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NTS-KE: AEAD algorithm record too short",
                    ));
                }
                aead_algorithm = read_be_u16(&record.body[..2]);
                debug!(aead_algorithm, "NTS-KE: AEAD algorithm negotiated");
            }
            NTS_KE_ERROR => {
                let code = if record.body.len() >= 2 {
                    read_be_u16(&record.body[..2])
                } else {
                    0
                };
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("NTS-KE server error: code {}", code),
                ));
            }
            NTS_KE_WARNING => {
                let code = if record.body.len() >= 2 {
                    read_be_u16(&record.body[..2])
                } else {
                    0
                };
                debug!("NTS-KE warning: code {}", code);
            }
            NTS_KE_NEW_COOKIE => {
                debug!(cookie_len = record.body.len(), "NTS-KE: received cookie");
                cookies.push(record.body.clone());
            }
            NTS_KE_SERVER => {
                ntp_server = String::from_utf8(record.body.clone()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "NTS-KE: invalid server name")
                })?;
                debug!("NTS-KE: NTP server = {}", ntp_server);
            }
            NTS_KE_PORT => {
                if record.body.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NTS-KE: port record too short",
                    ));
                }
                ntp_port = read_be_u16(&record.body[..2]);
                debug!("NTS-KE: NTP port = {}", ntp_port);
            }
            _ => {
                if record.critical {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "NTS-KE: unrecognized critical record type {}",
                            record.record_type
                        ),
                    ));
                }
                debug!(
                    "NTS-KE: ignoring non-critical record type {}",
                    record.record_type
                );
            }
        }
    }

    let next_protocol = next_protocol.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "NTS-KE: server did not send Next Protocol record",
        )
    })?;

    if cookies.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTS-KE: server did not provide any cookies",
        ));
    }

    // Export keys from TLS session (RFC 8915 Section 4.2).
    let key_len = aead_key_length(aead_algorithm)?;

    let mut c2s_key = vec![0u8; key_len];
    tls_conn
        .export_keying_material(
            &mut c2s_key,
            NTS_EXPORTER_LABEL.as_bytes(),
            Some(&[0x00, 0x00]),
        )
        .map_err(|e| io::Error::other(format!("TLS key export failed: {}", e)))?;

    let mut s2c_key = vec![0u8; key_len];
    tls_conn
        .export_keying_material(
            &mut s2c_key,
            NTS_EXPORTER_LABEL.as_bytes(),
            Some(&[0x00, 0x01]),
        )
        .map_err(|e| io::Error::other(format!("TLS key export failed: {}", e)))?;

    debug!(
        "NTS-KE complete: {} cookies, AEAD={}, server={}:{}",
        cookies.len(),
        aead_algorithm,
        ntp_server,
        ntp_port
    );

    Ok(NtsKeResult {
        c2s_key,
        s2c_key,
        cookies,
        aead_algorithm,
        ntp_server,
        ntp_port,
        next_protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_server_default_port() {
        let (host, port) = parse_nts_ke_server_addr("example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, NTS_KE_DEFAULT_PORT);
    }

    #[test]
    fn test_parse_server_custom_port() {
        let (host, port) = parse_nts_ke_server_addr("example.com:5555");
        assert_eq!(host, "example.com");
        assert_eq!(port, 5555);
    }

    #[test]
    fn test_parse_server_invalid_port_uses_default() {
        let (host, port) = parse_nts_ke_server_addr("example.com:notaport");
        assert_eq!(host, "example.com:notaport");
        assert_eq!(port, NTS_KE_DEFAULT_PORT);
    }

    #[test]
    fn test_parse_server_ipv4_with_port() {
        let (host, port) = parse_nts_ke_server_addr("192.168.1.1:4461");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 4461);
    }

    #[test]
    fn test_parse_server_hostname_only() {
        let (host, port) = parse_nts_ke_server_addr("time.cloudflare.com");
        assert_eq!(host, "time.cloudflare.com");
        assert_eq!(port, 4460);
    }

    #[test]
    fn test_build_nts_ke_request_not_empty() {
        let buf = build_nts_ke_request();
        // At minimum: 3 records × 4-byte header + bodies + EoM
        assert!(buf.len() >= 16);
    }

    #[test]
    fn test_build_nts_ke_request_ends_with_eom() {
        let buf = build_nts_ke_request();
        // The last record should be End of Message (type 0 | critical bit, length 0).
        let len = buf.len();
        assert!(len >= 4);
        let last_record_type = u16::from_be_bytes([buf[len - 4], buf[len - 3]]);
        let last_record_len = u16::from_be_bytes([buf[len - 2], buf[len - 1]]);
        assert_eq!(last_record_type & 0x7FFF, NTS_KE_END_OF_MESSAGE);
        assert_eq!(last_record_len, 0);
    }
}
