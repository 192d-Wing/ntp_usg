// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Network Time Security (NTS) client using the smol runtime (RFC 8915).
//!
//! NTS provides authenticated NTP using TLS 1.3 for key establishment and
//! AEAD (AES-SIV-CMAC-256) for per-packet authentication.
//!
//! This module provides the same NTS functionality as [`crate::nts`] but using
//! smol and futures-rustls instead of tokio and tokio-rustls.
//!
//! # Protocol Overview
//!
//! 1. **NTS-KE (Key Establishment)**: TLS 1.3 handshake with the NTS-KE server
//!    (default port 4460). Negotiates AEAD algorithm, exports C2S/S2C keys,
//!    and receives cookies for NTP requests.
//!
//! 2. **NTS-Protected NTP**: Standard NTP packets augmented with extension fields:
//!    - Unique Identifier (replay protection)
//!    - NTS Cookie (opaque server state)
//!    - Cookie Placeholders (request additional cookies)
//!    - NTS Authenticator (AEAD ciphertext + tag)
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! use ntp::smol_nts::NtsSession;
//!
//! let mut session = NtsSession::from_ke("time.cloudflare.com").await?;
//! let result = session.request().await?;
//! println!("NTS offset: {:.6}s", result.offset_seconds);
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use futures_rustls::TlsConnector;
use log::debug;
use rustls::pki_types::ServerName;
use smol::net::{TcpStream, UdpSocket};

pub use crate::nts_common::NtsKeResult;
use crate::nts_common::*;
use crate::{
    NtpResult, bind_addr_for, compute_offset_delay, parse_and_validate_response, unix_time,
};

/// Read a single NTS-KE record from the TLS stream.
async fn read_ke_record(
    reader: &mut futures_rustls::client::TlsStream<TcpStream>,
) -> io::Result<NtsKeRecord> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr).await?;
    let raw_type = u16::from_be_bytes([hdr[0], hdr[1]]);
    let body_length = u16::from_be_bytes([hdr[2], hdr[3]]);

    let critical = (raw_type & 0x8000) != 0;
    let record_type = raw_type & 0x7FFF;

    let mut body = vec![0u8; body_length as usize];
    reader.read_exact(&mut body).await?;

    Ok(NtsKeRecord {
        critical,
        record_type,
        body,
    })
}

/// Perform NTS Key Establishment with the given server.
///
/// Connects to the NTS-KE server via TLS 1.3, negotiates NTPv4 + AEAD algorithm,
/// exports C2S/S2C keys, and receives cookies.
///
/// # Arguments
///
/// * `server` - NTS-KE server hostname (port 4460 is used by default, or specify `host:port`)
pub async fn nts_ke(server: &str) -> io::Result<NtsKeResult> {
    let (hostname, port) = if let Some(idx) = server.rfind(':') {
        if let Ok(p) = server[idx + 1..].parse::<u16>() {
            (&server[..idx], p)
        } else {
            (server, NTS_KE_DEFAULT_PORT)
        }
    } else {
        (server, NTS_KE_DEFAULT_PORT)
    };

    let addr = format!("{}:{}", hostname, port);
    debug!("NTS-KE connecting to {}", addr);

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp_stream = TcpStream::connect(&addr).await?;
    let server_name = ServerName::try_from(hostname.to_string()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid server name: {}", e),
        )
    })?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Build NTS-KE request.
    let mut request_buf = Vec::new();
    write_ke_record(
        &mut request_buf,
        true,
        NTS_KE_NEXT_PROTOCOL,
        &NTS_PROTOCOL_NTPV4.to_be_bytes(),
    );
    write_ke_record(
        &mut request_buf,
        true,
        NTS_KE_AEAD_ALGORITHM,
        &AEAD_AES_SIV_CMAC_256.to_be_bytes(),
    );
    write_ke_record(&mut request_buf, true, NTS_KE_END_OF_MESSAGE, &[]);

    tls_stream.write_all(&request_buf).await?;
    tls_stream.flush().await?;

    // Parse NTS-KE response.
    let mut got_next_protocol = false;
    let mut aead_algorithm = AEAD_AES_SIV_CMAC_256;
    let mut cookies = Vec::new();
    let mut ntp_server = hostname.to_string();
    let mut ntp_port: u16 = 123;

    loop {
        let record = read_ke_record(&mut tls_stream).await?;

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
                if proto != NTS_PROTOCOL_NTPV4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("NTS-KE: unsupported protocol: {}", proto),
                    ));
                }
                got_next_protocol = true;
                debug!("NTS-KE: next protocol = NTPv4");
            }
            NTS_KE_AEAD_ALGORITHM => {
                if record.body.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NTS-KE: AEAD algorithm record too short",
                    ));
                }
                aead_algorithm = read_be_u16(&record.body[..2]);
                debug!("NTS-KE: AEAD algorithm = {}", aead_algorithm);
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
                debug!("NTS-KE: received cookie ({} bytes)", record.body.len());
                cookies.push(record.body);
            }
            NTS_KE_SERVER => {
                ntp_server = String::from_utf8(record.body).map_err(|_| {
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

    if !got_next_protocol {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTS-KE: server did not send Next Protocol record",
        ));
    }

    if cookies.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTS-KE: server did not provide any cookies",
        ));
    }

    // Export keys from TLS session.
    let key_len = aead_key_length(aead_algorithm)?;
    let (_, tls_conn) = tls_stream.get_ref();

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

    // Gracefully close TLS.
    let _ = tls_stream.close().await;

    Ok(NtsKeResult {
        c2s_key,
        s2c_key,
        cookies,
        aead_algorithm,
        ntp_server,
        ntp_port,
    })
}

/// An NTS session for sending authenticated NTP requests using smol.
///
/// Created via [`NtsSession::from_ke`], which performs NTS Key Establishment.
/// Each call to [`request`](NtsSession::request) consumes one cookie and
/// replenishes cookies from the server's response.
pub struct NtsSession {
    c2s_key: Vec<u8>,
    s2c_key: Vec<u8>,
    cookies: Vec<Vec<u8>>,
    aead_algorithm: u16,
    ntp_addr: SocketAddr,
    resolved_addrs: Vec<SocketAddr>,
}

impl NtsSession {
    /// Create an NTS session by performing key establishment with the given server.
    pub async fn from_ke(server: &str) -> io::Result<Self> {
        let ke = nts_ke(server).await?;
        Self::from_ke_result(ke).await
    }

    /// Create an NTS session from a previously obtained [`NtsKeResult`].
    pub async fn from_ke_result(ke: NtsKeResult) -> io::Result<Self> {
        let addr_str = format!("{}:{}", ke.ntp_server, ke.ntp_port);
        let resolved_addrs: Vec<SocketAddr> = smol::net::resolve(&addr_str).await?;
        if resolved_addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NTP server address resolved to no addresses",
            ));
        }
        let ntp_addr = resolved_addrs[0];

        Ok(NtsSession {
            c2s_key: ke.c2s_key,
            s2c_key: ke.s2c_key,
            cookies: ke.cookies,
            aead_algorithm: ke.aead_algorithm,
            ntp_addr,
            resolved_addrs,
        })
    }

    /// Returns the number of remaining cookies.
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Send an NTS-protected NTP request with a 5 second timeout.
    pub async fn request(&mut self) -> io::Result<NtpResult> {
        self.request_with_timeout(Duration::from_secs(5)).await
    }

    /// Send an NTS-protected NTP request with the given timeout.
    pub async fn request_with_timeout(&mut self, timeout: Duration) -> io::Result<NtpResult> {
        futures_lite::future::or(self.request_inner(), async {
            smol::Timer::after(timeout).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "NTS request timed out",
            ))
        })
        .await
    }

    async fn request_inner(&mut self) -> io::Result<NtpResult> {
        let cookie = self
            .cookies
            .pop()
            .ok_or_else(|| io::Error::other("no NTS cookies remaining"))?;

        let (send_buf, t1, uid_data) =
            build_nts_request(&self.c2s_key, self.aead_algorithm, cookie)?;

        let sock = UdpSocket::bind(bind_addr_for(&self.ntp_addr)).await?;
        sock.send_to(&send_buf, self.ntp_addr).await?;

        let mut recv_buf = [0u8; 2048];
        let (recv_len, src_addr) = sock.recv_from(&mut recv_buf).await?;

        let (response, t4) =
            parse_and_validate_response(&recv_buf, recv_len, src_addr, &self.resolved_addrs)?;

        if response.origin_timestamp != t1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS: origin timestamp mismatch",
            ));
        }

        let new_cookies = validate_nts_response(
            &self.s2c_key,
            self.aead_algorithm,
            &uid_data,
            &recv_buf,
            recv_len,
        )?;
        self.cookies.extend(new_cookies);

        debug!(
            "NTS request successful, {} cookies remaining",
            self.cookies.len()
        );

        let t4_instant = unix_time::Instant::from(t4);
        let t1_instant = unix_time::timestamp_to_instant(t1, &t4_instant);
        let t2_instant = unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
        let t3_instant = unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);

        let (offset_seconds, delay_seconds) =
            compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);

        Ok(NtpResult {
            packet: response,
            destination_timestamp: t4,
            offset_seconds,
            delay_seconds,
        })
    }
}
