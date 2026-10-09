// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared NTS-KE (Key Establishment) server logic.
//!
//! Provides [`NtsKeServerConfig`] and [`process_nts_ke_records`] used by both
//! the tokio-based [`crate::nts_ke_server`] and smol-based
//! [`crate::smol_nts_ke_server`] modules.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::error::{ConfigError, NtpServerError, NtsError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use tracing::debug;

use crate::default_listen_addr;
use crate::nts_common::*;
use crate::nts_server_common::{CookieContents, MasterKeyStore};

/// Maximum number of NTS-KE records a server reads from one connection before
/// giving up. A legitimate client request contains only a handful; the cap
/// bounds memory/CPU against a peer that never sends End-of-Message. Shared by
/// the tokio and smol NTS-KE servers.
pub(crate) const MAX_KE_RECORDS: usize = 32;

/// Default wall-clock budget for one NTS-KE connection: TCP accept to response
/// flushed, including the TLS handshake. A real exchange takes one round trip
/// plus a handshake; anything still open after this is a stalled or hostile
/// peer holding a task and a file descriptor.
pub const DEFAULT_KE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cap on NTS-KE connections being served at once.
pub const DEFAULT_KE_MAX_CONNECTIONS: usize = 256;

/// Default cap on in-flight NTS-KE connections from a single IP address.
pub const DEFAULT_KE_MAX_CONNECTIONS_PER_IP: usize = 8;

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
    /// Maximum time one connection may take from accept to response flushed,
    /// TLS handshake included (default: [`DEFAULT_KE_CONNECTION_TIMEOUT`]).
    /// Bounds how long a slow or stalled peer can hold a task and a socket.
    pub connection_timeout: Duration,
    /// Maximum NTS-KE connections handled concurrently (default:
    /// [`DEFAULT_KE_MAX_CONNECTIONS`]). Connections beyond the cap are closed
    /// immediately after accept without a TLS handshake.
    pub max_connections: usize,
    /// Maximum concurrent NTS-KE connections from one client IP (default:
    /// [`DEFAULT_KE_MAX_CONNECTIONS_PER_IP`]). Stops a single source from
    /// consuming the whole `max_connections` budget. `0` disables the per-IP
    /// cap.
    pub max_connections_per_ip: usize,
}

impl NtsKeServerConfig {
    /// Create a config from PEM-encoded certificate and private key bytes.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Self> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| -> io::Error {
                NtpServerError::Config(ConfigError::InvalidTlsCredentials {
                    detail: e.to_string(),
                })
                .into()
            })?;

        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| -> io::Error {
            NtpServerError::Config(ConfigError::InvalidTlsCredentials {
                detail: e.to_string(),
            })
            .into()
        })?;

        Ok(NtsKeServerConfig {
            cert_chain: certs,
            private_key: key,
            listen_addr: default_listen_addr(4460),
            ntp_server: None,
            ntp_port: None,
            cookie_count: 8,
            connection_timeout: DEFAULT_KE_CONNECTION_TIMEOUT,
            max_connections: DEFAULT_KE_MAX_CONNECTIONS,
            max_connections_per_ip: DEFAULT_KE_MAX_CONNECTIONS_PER_IP,
        })
    }
}

/// Admission control for NTS-KE connections: a global cap and a per-IP cap.
///
/// Runtime-agnostic (plain `Mutex`, never held across an await). A connection
/// that is admitted holds a [`KeConnectionPermit`]; dropping the permit frees
/// the slots, so cancellation (e.g. by a timeout) releases them too.
pub(crate) struct KeConnectionLimiter {
    max_total: usize,
    max_per_ip: usize,
    inner: Mutex<LimiterState>,
}

#[derive(Default)]
struct LimiterState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl KeConnectionLimiter {
    pub(crate) fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(KeConnectionLimiter {
            max_total,
            max_per_ip,
            inner: Mutex::new(LimiterState::default()),
        })
    }

    /// Try to admit a connection from `ip`. Returns `None` when either cap is
    /// reached; the caller should close the socket without handshaking.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<KeConnectionPermit> {
        // IPv4 clients on a dual-stack socket arrive as `::ffff:a.b.c.d`.
        let ip = ip.to_canonical();
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if st.total >= self.max_total {
            return None;
        }
        let per_ip = st.per_ip.entry(ip).or_insert(0);
        if self.max_per_ip != 0 && *per_ip >= self.max_per_ip {
            if *per_ip == 0 {
                st.per_ip.remove(&ip);
            }
            return None;
        }
        *per_ip += 1;
        st.total += 1;
        Some(KeConnectionPermit {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Number of connections currently admitted.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).total
    }
}

/// RAII token for an admitted NTS-KE connection; see [`KeConnectionLimiter`].
pub(crate) struct KeConnectionPermit {
    limiter: Arc<KeConnectionLimiter>,
    ip: IpAddr,
}

impl Drop for KeConnectionPermit {
    fn drop(&mut self) {
        let mut st = self.limiter.inner.lock().unwrap_or_else(|e| e.into_inner());
        st.total = st.total.saturating_sub(1);
        if let Some(n) = st.per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                st.per_ip.remove(&self.ip);
            }
        }
    }
}

/// Map a timed-out NTS-KE connection to an `io::Error`.
pub(crate) fn ke_timeout_error(budget: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("NTS-KE connection exceeded {budget:?} budget"),
    )
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
    // RFC 8915 §4.1.5: the server must select an algorithm the client offered.
    // If the client offers none we support, reject with a Bad Request error
    // rather than silently picking one the client cannot use.
    let supported = [AEAD_AES_SIV_CMAC_512, AEAD_AES_SIV_CMAC_256];
    let aead_algorithm = match supported
        .iter()
        .find(|a| client_aead_algorithms.contains(a))
        .copied()
    {
        Some(a) => a,
        None => {
            let mut resp = Vec::new();
            write_ke_record(&mut resp, true, NTS_KE_ERROR, &1u16.to_be_bytes());
            write_ke_record(&mut resp, true, NTS_KE_END_OF_MESSAGE, &[]);
            return Ok(resp);
        }
    };

    // 4. Export TLS keying material (RFC 8915 Section 4.2).
    let key_len = aead_key_length(aead_algorithm)?;

    let mut c2s_key = vec![0u8; key_len];
    tls_conn
        .export_keying_material(
            &mut c2s_key,
            NTS_EXPORTER_LABEL.as_bytes(),
            Some(&exporter_context(
                negotiated_protocol,
                aead_algorithm,
                false,
            )),
        )
        .map_err(|e| -> io::Error {
            NtpServerError::Nts(NtsError::KeyExportFailed {
                detail: e.to_string(),
            })
            .into()
        })?;

    let mut s2c_key = vec![0u8; key_len];
    tls_conn
        .export_keying_material(
            &mut s2c_key,
            NTS_EXPORTER_LABEL.as_bytes(),
            Some(&exporter_context(negotiated_protocol, aead_algorithm, true)),
        )
        .map_err(|e| -> io::Error {
            NtpServerError::Nts(NtsError::KeyExportFailed {
                detail: e.to_string(),
            })
            .into()
        })?;

    // 5. Generate cookies.
    let cookie_contents = CookieContents {
        aead_algorithm,
        c2s_key,
        s2c_key,
    };
    let cookies: Vec<Vec<u8>> = {
        let store = key_store
            .read()
            .map_err(|_| -> io::Error { NtpServerError::Nts(NtsError::KeyStorePoisoned).into() })?;
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
        let key_pem = cert.signing_key.serialize_pem().into_bytes();
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

    // ── KeConnectionLimiter ──────────────────────────────────────

    #[test]
    fn limiter_enforces_global_cap_and_releases_on_drop() {
        let lim = KeConnectionLimiter::new(2, 0);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "10.0.0.3".parse().unwrap();

        let p1 = lim.try_acquire(a).expect("first admitted");
        let p2 = lim.try_acquire(b).expect("second admitted");
        assert!(lim.try_acquire(c).is_none(), "third must be refused");
        assert_eq!(lim.in_flight(), 2);

        drop(p1);
        assert_eq!(lim.in_flight(), 1);
        let _p3 = lim.try_acquire(c).expect("slot freed by drop");
        drop(p2);
        assert_eq!(lim.in_flight(), 1);
    }

    #[test]
    fn limiter_enforces_per_ip_cap_independently() {
        let lim = KeConnectionLimiter::new(100, 2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();

        let _a1 = lim.try_acquire(a).unwrap();
        let a2 = lim.try_acquire(a).unwrap();
        assert!(lim.try_acquire(a).is_none(), "third from same IP refused");
        // Other IPs are unaffected.
        let _b1 = lim.try_acquire(b).unwrap();
        // Releasing one frees a per-IP slot.
        drop(a2);
        let _a3 = lim.try_acquire(a).unwrap();
        assert_eq!(lim.in_flight(), 3);
    }

    #[test]
    fn limiter_treats_v4_mapped_as_v4() {
        let lim = KeConnectionLimiter::new(100, 1);
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let _p = lim.try_acquire(v4).unwrap();
        assert!(lim.try_acquire(mapped).is_none());
    }

    #[test]
    fn limiter_per_ip_zero_disables_cap() {
        let lim = KeConnectionLimiter::new(10, 0);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let permits: Vec<_> = (0..10).map(|_| lim.try_acquire(a).unwrap()).collect();
        assert!(lim.try_acquire(a).is_none(), "global cap still applies");
        drop(permits);
        assert_eq!(lim.in_flight(), 0);
    }
}
