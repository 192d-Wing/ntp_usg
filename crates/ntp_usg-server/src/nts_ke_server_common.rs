// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared NTS-KE (Key Establishment) server logic.
//!
//! Provides [`NtsKeServerConfig`] and [`process_nts_ke_records`] used by both
//! the tokio-based [`crate::nts_ke_server`] and smol-based
//! [`crate::smol_nts_ke_server`] modules.

use std::io;
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use tracing::debug;

use crate::default_listen_addr;
use crate::nts_common::*;
use crate::nts_server_common::{CookieContents, MasterKeyStore};

/// Configuration for an NTS-KE server.
pub struct NtsKeServerConfig {
    /// TLS certificate chain (DER encoded).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Private key corresponding to the certificate (DER encoded).
    pub private_key: PrivateKeyDer<'static>,
    /// Listen address (default: `"[::]:4460"`, or `"0.0.0.0:4460"` with `ipv4` feature).
    pub listen_addr: String,
    /// NTP server hostname to advertise to clients via the Server record.
    /// If `None`, clients use the NTS-KE server hostname.
    pub ntp_server: Option<String>,
    /// NTP port to advertise to clients via the Port record.
    /// If `None`, clients use the default port 123.
    pub ntp_port: Option<u16>,
    /// Number of cookies to issue per NTS-KE session (default: 8).
    pub cookie_count: usize,
}

impl NtsKeServerConfig {
    /// Create a config from PEM-encoded certificate and private key bytes.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Self> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let key = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(NtsKeServerConfig {
            cert_chain: certs,
            private_key: key,
            listen_addr: default_listen_addr(4460),
            ntp_server: None,
            ntp_port: None,
            cookie_count: 8,
        })
    }
}

/// Process NTS-KE client records and produce the response bytes to send.
///
/// Takes the parsed client records (collected until End of Message) and a
/// reference to the underlying `rustls::ServerConnection` for TLS key export.
/// Returns the complete NTS-KE response bytes ready to write to the TLS stream.
///
/// Both error responses (unrecognized critical record, missing protocol) and
/// success responses (cookies + negotiated parameters) are returned as `Ok`.
pub(crate) fn process_nts_ke_records(
    client_records: &[NtsKeRecord],
    tls_conn: &rustls::ServerConnection,
    key_store: &Arc<RwLock<MasterKeyStore>>,
    ntp_server: Option<&str>,
    ntp_port: Option<u16>,
    cookie_count: usize,
) -> io::Result<Vec<u8>> {
    // 1. Parse client NTS-KE records.
    let mut client_next_protocol: Option<u16> = None;
    let mut client_aead_algorithms = Vec::new();

    for record in client_records {
        match record.record_type {
            NTS_KE_END_OF_MESSAGE => break,
            NTS_KE_NEXT_PROTOCOL => {
                if record.body.len() >= 2 {
                    let proto = read_be_u16(&record.body[..2]);
                    if proto == NTS_PROTOCOL_NTPV4 {
                        client_next_protocol = Some(proto);
                    }
                    #[cfg(feature = "ntpv5")]
                    if proto == NTS_PROTOCOL_NTPV5 {
                        client_next_protocol = Some(proto);
                    }
                }
            }
            NTS_KE_AEAD_ALGORITHM => {
                if record.body.len() >= 2 {
                    client_aead_algorithms.push(read_be_u16(&record.body[..2]));
                }
            }
            _ => {
                if record.critical {
                    // Unrecognized critical record — send error.
                    let mut resp = Vec::new();
                    write_ke_record(&mut resp, true, NTS_KE_ERROR, &0u16.to_be_bytes());
                    write_ke_record(&mut resp, true, NTS_KE_END_OF_MESSAGE, &[]);
                    return Ok(resp);
                }
                // Ignore non-critical unknown records.
            }
        }
    }

    // 2. Validate client request.
    let negotiated_protocol = match client_next_protocol {
        Some(proto) => proto,
        None => {
            let mut resp = Vec::new();
            write_ke_record(&mut resp, true, NTS_KE_ERROR, &1u16.to_be_bytes());
            write_ke_record(&mut resp, true, NTS_KE_END_OF_MESSAGE, &[]);
            return Ok(resp);
        }
    };

    // 3. Negotiate AEAD algorithm (prefer CMAC-512, fall back to CMAC-256).
    let supported = [AEAD_AES_SIV_CMAC_512, AEAD_AES_SIV_CMAC_256];
    let aead_algorithm = supported
        .iter()
        .find(|a| client_aead_algorithms.contains(a))
        .copied()
        .unwrap_or(AEAD_AES_SIV_CMAC_512);

    // 4. Export TLS keying material (RFC 8915 Section 4.2).
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

    // 5. Generate cookies.
    let cookie_contents = CookieContents {
        aead_algorithm,
        c2s_key,
        s2c_key,
    };
    let cookies: Vec<Vec<u8>> = {
        let store = key_store
            .read()
            .map_err(|_| io::Error::other("master key store lock poisoned"))?;
        (0..cookie_count)
            .map(|_| store.encrypt_cookie(&cookie_contents))
            .collect::<io::Result<Vec<_>>>()?
    };

    // 6. Build response.
    let mut resp = Vec::new();

    // Next Protocol (critical).
    write_ke_record(
        &mut resp,
        true,
        NTS_KE_NEXT_PROTOCOL,
        &negotiated_protocol.to_be_bytes(),
    );

    // AEAD Algorithm (critical).
    write_ke_record(
        &mut resp,
        true,
        NTS_KE_AEAD_ALGORITHM,
        &aead_algorithm.to_be_bytes(),
    );

    // Server record (optional).
    if let Some(server) = ntp_server {
        write_ke_record(&mut resp, false, NTS_KE_SERVER, server.as_bytes());
    }

    // Port record (optional).
    if let Some(port) = ntp_port {
        write_ke_record(&mut resp, false, NTS_KE_PORT, &port.to_be_bytes());
    }

    // Cookies.
    for cookie in &cookies {
        write_ke_record(&mut resp, false, NTS_KE_NEW_COOKIE, cookie);
    }

    // End of Message (critical).
    write_ke_record(&mut resp, true, NTS_KE_END_OF_MESSAGE, &[]);

    debug!(
        "NTS-KE: sent {} cookies, AEAD={}",
        cookies.len(),
        aead_algorithm
    );

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed PEM cert + key pair for testing.
    fn generate_test_pem() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.key_pair.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    #[test]
    fn test_from_pem_valid() {
        let (cert_pem, key_pem) = generate_test_pem();
        let config = NtsKeServerConfig::from_pem(&cert_pem, &key_pem).unwrap();
        assert!(!config.cert_chain.is_empty());
        assert!(config.ntp_server.is_none());
        assert!(config.ntp_port.is_none());
        assert_eq!(config.cookie_count, 8);
        assert_eq!(config.listen_addr, default_listen_addr(4460));
    }

    #[test]
    fn test_from_pem_garbage_cert_yields_empty_chain() {
        // PEM iter skips non-PEM content, producing an empty cert chain.
        let (_, key_pem) = generate_test_pem();
        let config = NtsKeServerConfig::from_pem(b"not-a-cert", &key_pem).unwrap();
        assert!(config.cert_chain.is_empty());
    }

    #[test]
    fn test_from_pem_invalid_key() {
        let (cert_pem, _) = generate_test_pem();
        let result = NtsKeServerConfig::from_pem(&cert_pem, b"not-a-key");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_pem_empty_cert_yields_empty_chain() {
        // Empty input yields an empty cert chain (no PEM blocks found).
        let (_, key_pem) = generate_test_pem();
        let config = NtsKeServerConfig::from_pem(b"", &key_pem).unwrap();
        assert!(config.cert_chain.is_empty());
    }

    #[test]
    fn test_config_fields() {
        let (cert_pem, key_pem) = generate_test_pem();
        let mut config = NtsKeServerConfig::from_pem(&cert_pem, &key_pem).unwrap();
        config.ntp_server = Some("ntp.example.com".to_string());
        config.ntp_port = Some(1234);
        config.cookie_count = 4;
        config.listen_addr = "127.0.0.1:4460".to_string();

        assert_eq!(config.ntp_server.as_deref(), Some("ntp.example.com"));
        assert_eq!(config.ntp_port, Some(1234));
        assert_eq!(config.cookie_count, 4);
        assert_eq!(config.listen_addr, "127.0.0.1:4460");
    }
}
