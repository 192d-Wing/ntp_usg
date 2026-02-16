// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Network Time Security (NTS) client implementation (RFC 8915).
//!
//! NTS provides authenticated NTP using TLS 1.3 for key establishment and
//! AEAD (AES-SIV-CMAC-256) for per-packet authentication.
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
//! use ntp::nts::NtsSession;
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

use aes_siv::aead::Aead;
use aes_siv::aead::KeyInit;
use aes_siv::{Aes128SivAead, Aes256SivAead};
use log::debug;
use rustls::pki_types::ServerName;
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

use crate::extension::{
    self, ExtensionField, NtsAuthenticator, NtsCookie, NtsCookiePlaceholder, UniqueIdentifier,
    UNIQUE_IDENTIFIER,
};
use crate::protocol::{self, ConstPackedSizeBytes, WriteBytes};
use crate::{NtpResult, bind_addr_for, compute_offset_delay, parse_and_validate_response, unix_time};

// NTS-KE record types (RFC 8915 Section 4).

/// End of Message NTS-KE record type.
const NTS_KE_END_OF_MESSAGE: u16 = 0;
/// NTS Next Protocol Negotiation record type.
const NTS_KE_NEXT_PROTOCOL: u16 = 1;
/// Error record type.
const NTS_KE_ERROR: u16 = 2;
/// Warning record type.
const NTS_KE_WARNING: u16 = 3;
/// AEAD Algorithm Negotiation record type.
const NTS_KE_AEAD_ALGORITHM: u16 = 4;
/// New Cookie for NTPv4 record type.
const NTS_KE_NEW_COOKIE: u16 = 5;
/// NTPv4 Server Negotiation record type.
const NTS_KE_SERVER: u16 = 6;
/// NTPv4 Port Negotiation record type.
const NTS_KE_PORT: u16 = 7;

/// NTPv4 protocol ID for NTS Next Protocol Negotiation.
const NTS_PROTOCOL_NTPV4: u16 = 0;

/// Default NTS-KE port (RFC 8915 Section 4).
const NTS_KE_DEFAULT_PORT: u16 = 4460;

/// AEAD_AES_SIV_CMAC_256 algorithm ID (RFC 8915 Section 5.1).
const AEAD_AES_SIV_CMAC_256: u16 = 15;

/// AEAD_AES_SIV_CMAC_512 algorithm ID.
const AEAD_AES_SIV_CMAC_512: u16 = 17;

/// TLS exporter label for NTS (RFC 8915 Section 4.2).
const NTS_EXPORTER_LABEL: &str = "EXPORTER-network-time-security";

/// Number of cookie placeholders to include in NTS requests.
pub(crate) const COOKIE_PLACEHOLDER_COUNT: usize = 7;

/// Cookie count threshold below which re-keying should be attempted.
pub(crate) const COOKIE_REKEY_THRESHOLD: usize = 2;

/// Result of NTS Key Establishment.
#[derive(Clone, Debug)]
pub struct NtsKeResult {
    /// Client-to-server AEAD key.
    pub c2s_key: Vec<u8>,
    /// Server-to-client AEAD key.
    pub s2c_key: Vec<u8>,
    /// Cookies for NTP requests (each used exactly once).
    pub cookies: Vec<Vec<u8>>,
    /// Negotiated AEAD algorithm ID.
    pub aead_algorithm: u16,
    /// NTP server hostname (may differ from NTS-KE server).
    pub ntp_server: String,
    /// NTP server port (default 123).
    pub ntp_port: u16,
}

/// NTS-KE record as read from the TLS stream.
struct NtsKeRecord {
    critical: bool,
    record_type: u16,
    body: Vec<u8>,
}

/// Read a single NTS-KE record from the TLS stream.
async fn read_ke_record(
    reader: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> io::Result<NtsKeRecord> {
    use tokio::io::AsyncReadExt;

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

/// Write a single NTS-KE record to a buffer.
fn write_ke_record(buf: &mut Vec<u8>, critical: bool, record_type: u16, body: &[u8]) {
    let raw_type = if critical {
        record_type | 0x8000
    } else {
        record_type
    };
    buf.extend_from_slice(&raw_type.to_be_bytes());
    buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    buf.extend_from_slice(body);
}

/// Read a big-endian u16 from a byte slice of length >= 2.
fn read_be_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

/// Get the AEAD key length for the given algorithm.
fn aead_key_length(algorithm: u16) -> io::Result<usize> {
    match algorithm {
        AEAD_AES_SIV_CMAC_256 => Ok(32),
        AEAD_AES_SIV_CMAC_512 => Ok(64),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported AEAD algorithm: {}", algorithm),
        )),
    }
}

/// Perform NTS Key Establishment with the given server.
///
/// Connects to the NTS-KE server via TLS 1.3, negotiates NTPv4 + AEAD algorithm,
/// exports C2S/S2C keys, and receives cookies.
///
/// # Arguments
///
/// * `server` - NTS-KE server hostname (port 4460 is used by default, or specify `host:port`)
///
/// # Example
///
/// ```no_run
/// # async fn example() -> std::io::Result<()> {
/// let ke_result = ntp::nts::nts_ke("time.cloudflare.com").await?;
/// println!("Got {} cookies", ke_result.cookies.len());
/// # Ok(())
/// # }
/// ```
pub async fn nts_ke(server: &str) -> io::Result<NtsKeResult> {
    use tokio::io::AsyncWriteExt;

    // Parse server address — default port 4460.
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

    // Configure TLS 1.3 client.
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    // Connect TCP + TLS.
    let tcp_stream = TcpStream::connect(&addr).await?;
    let server_name = ServerName::try_from(hostname.to_string()).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid server name: {}", e))
    })?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Build NTS-KE request:
    // 1. Next Protocol: NTPv4 (critical)
    // 2. AEAD Algorithm: AES-SIV-CMAC-256 (critical)
    // 3. End of Message (critical)
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
                ntp_server =
                    String::from_utf8(record.body).map_err(|_| {
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

    // Export keys from TLS session (RFC 8915 Section 4.2).
    let key_len = aead_key_length(aead_algorithm)?;
    let (_, tls_conn) = tls_stream.get_ref();

    let mut c2s_key = vec![0u8; key_len];
    tls_conn
        .export_keying_material(&mut c2s_key, NTS_EXPORTER_LABEL.as_bytes(), Some(&[0x00, 0x00]))
        .map_err(|e| io::Error::other(format!("TLS key export failed: {}", e)))?;

    let mut s2c_key = vec![0u8; key_len];
    tls_conn
        .export_keying_material(&mut s2c_key, NTS_EXPORTER_LABEL.as_bytes(), Some(&[0x00, 0x01]))
        .map_err(|e| io::Error::other(format!("TLS key export failed: {}", e)))?;

    debug!(
        "NTS-KE complete: {} cookies, AEAD={}, server={}:{}",
        cookies.len(),
        aead_algorithm,
        ntp_server,
        ntp_port
    );

    // Gracefully close TLS.
    let _ = tls_stream.shutdown().await;

    Ok(NtsKeResult {
        c2s_key,
        s2c_key,
        cookies,
        aead_algorithm,
        ntp_server,
        ntp_port,
    })
}

/// An NTS session for sending authenticated NTP requests.
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
    /// Resolved addresses for source validation.
    resolved_addrs: Vec<SocketAddr>,
}

impl NtsSession {
    /// Create an NTS session by performing key establishment with the given server.
    ///
    /// Connects to the NTS-KE server, negotiates keys and cookies, then resolves
    /// the NTP server address for subsequent requests.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> std::io::Result<()> {
    /// let mut session = ntp::nts::NtsSession::from_ke("time.cloudflare.com").await?;
    /// let result = session.request().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_ke(server: &str) -> io::Result<Self> {
        let ke = nts_ke(server).await?;
        Self::from_ke_result(ke).await
    }

    /// Create an NTS session from a previously obtained [`NtsKeResult`].
    pub async fn from_ke_result(ke: NtsKeResult) -> io::Result<Self> {
        let addr_str = format!("{}:{}", ke.ntp_server, ke.ntp_port);
        let resolved_addrs: Vec<SocketAddr> =
            tokio::net::lookup_host(&addr_str).await?.collect();
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
    ///
    /// Constructs an NTP packet with NTS extension fields, authenticates it
    /// with AEAD, sends it, and validates the authenticated response.
    ///
    /// Each call consumes one cookie. New cookies provided in the server's
    /// response are automatically added to the session.
    pub async fn request_with_timeout(&mut self, timeout: Duration) -> io::Result<NtpResult> {
        tokio::time::timeout(timeout, self.request_inner())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTS request timed out"))?
    }

    async fn request_inner(&mut self) -> io::Result<NtpResult> {
        // Pop a cookie.
        let cookie = self.cookies.pop().ok_or_else(|| {
            io::Error::other("no NTS cookies remaining")
        })?;

        // Build the NTS-authenticated request packet.
        let (send_buf, t1, uid_data) =
            build_nts_request(&self.c2s_key, self.aead_algorithm, cookie)?;

        // Send the packet.
        let sock = UdpSocket::bind(bind_addr_for(&self.ntp_addr)).await?;
        sock.send_to(&send_buf, self.ntp_addr).await?;

        // Receive the response.
        let mut recv_buf = [0u8; 2048];
        let (recv_len, src_addr) = sock.recv_from(&mut recv_buf).await?;

        // Validate the NTP header (shared validation).
        let (response, t4) =
            parse_and_validate_response(&recv_buf, recv_len, src_addr, &self.resolved_addrs)?;

        // Validate origin timestamp matches our request.
        if response.origin_timestamp != t1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS: origin timestamp mismatch",
            ));
        }

        // Validate NTS extension fields and extract new cookies.
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

        // Compute offset and delay.
        let t4_instant = unix_time::Instant::from(t4);
        let t1_instant = unix_time::timestamp_to_instant(t1, &t4_instant);
        let t2_instant =
            unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
        let t3_instant =
            unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);

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

/// Build an NTS-authenticated NTP request packet.
///
/// Constructs the NTP header with extension fields (Unique Identifier, NTS Cookie,
/// cookie placeholders) and an AEAD authenticator.
///
/// Returns `(send_buf, t1, uid_data)` where:
/// - `send_buf` is the complete serialized packet ready to send
/// - `t1` is the origin timestamp
/// - `uid_data` is the Unique Identifier bytes for response validation
pub(crate) fn build_nts_request(
    c2s_key: &[u8],
    aead_algorithm: u16,
    cookie: Vec<u8>,
) -> io::Result<(Vec<u8>, protocol::TimestampFormat, Vec<u8>)> {
    let cookie_len = cookie.len();

    // Build the NTP header.
    let packet = protocol::Packet {
        leap_indicator: protocol::LeapIndicator::default(),
        version: protocol::Version::V4,
        mode: protocol::Mode::Client,
        stratum: protocol::Stratum::UNSPECIFIED,
        poll: 0,
        precision: 0,
        root_delay: protocol::ShortFormat::default(),
        root_dispersion: protocol::ShortFormat::default(),
        reference_id: protocol::ReferenceIdentifier::PrimarySource(
            protocol::PrimarySource::Null,
        ),
        reference_timestamp: protocol::TimestampFormat::default(),
        origin_timestamp: protocol::TimestampFormat::default(),
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: unix_time::Instant::now().into(),
    };
    let t1 = packet.transmit_timestamp;

    let mut header_buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut header_buf[..]).write_bytes(packet)?;

    // Build extension fields (unencrypted).
    let mut uid_data = vec![0u8; 32];
    rand::fill(&mut uid_data[..]);
    let uid = UniqueIdentifier::new(uid_data.clone());
    let nts_cookie = NtsCookie::new(cookie);

    // Build extension fields before the authenticator (these are AAD).
    let mut pre_auth_fields = vec![uid.to_extension_field(), nts_cookie.to_extension_field()];

    // Add cookie placeholders so the server sends replacement cookies.
    for _ in 0..COOKIE_PLACEHOLDER_COUNT {
        let placeholder = NtsCookiePlaceholder::new(cookie_len);
        pre_auth_fields.push(placeholder.to_extension_field());
    }

    let pre_auth_bytes = extension::write_extension_fields(&pre_auth_fields)?;

    // Build AAD = NTP header + all extension fields before authenticator.
    let mut aad = Vec::with_capacity(header_buf.len() + pre_auth_bytes.len());
    aad.extend_from_slice(&header_buf);
    aad.extend_from_slice(&pre_auth_bytes);

    // AEAD encrypt (plaintext is empty for basic NTS client — no encrypted extensions).
    let (nonce, ciphertext) = aead_encrypt(aead_algorithm, c2s_key, &aad, &[])?;

    // Build the NTS Authenticator extension field.
    let authenticator = NtsAuthenticator::new(nonce, ciphertext);
    let auth_ef = authenticator.to_extension_field();
    let auth_bytes = extension::write_extension_fields(&[auth_ef])?;

    // Assemble the complete packet.
    let mut send_buf = Vec::with_capacity(aad.len() + auth_bytes.len());
    send_buf.extend_from_slice(&aad);
    send_buf.extend_from_slice(&auth_bytes);

    Ok((send_buf, t1, uid_data))
}

/// Validate NTS extension fields in an NTP response.
///
/// Verifies the Unique Identifier matches, authenticates the response via AEAD,
/// and extracts new cookies from the server.
///
/// Returns the list of new cookies provided by the server.
pub(crate) fn validate_nts_response(
    s2c_key: &[u8],
    aead_algorithm: u16,
    uid_data: &[u8],
    recv_buf: &[u8],
    recv_len: usize,
) -> io::Result<Vec<Vec<u8>>> {
    // Parse extension fields from the response.
    if recv_len <= protocol::Packet::PACKED_SIZE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTS: response has no extension fields",
        ));
    }
    let ext_data = &recv_buf[protocol::Packet::PACKED_SIZE_BYTES..recv_len];
    let ext_fields = extension::parse_extension_fields(ext_data)?;

    // Find the Unique Identifier and verify it matches.
    let resp_uid = ext_fields
        .iter()
        .find(|ef| ef.field_type == UNIQUE_IDENTIFIER)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS: response missing Unique Identifier",
            )
        })?;
    if resp_uid.value != uid_data {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTS: Unique Identifier mismatch",
        ));
    }

    // Find the NTS Authenticator.
    let auth_ef = ext_fields
        .iter()
        .find(|ef| ef.field_type == extension::NTS_AUTHENTICATOR)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS: response missing NTS Authenticator",
            )
        })?;
    let resp_auth = NtsAuthenticator::from_extension_field(auth_ef)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "NTS: failed to parse NTS Authenticator",
            )
        })?;

    // Build AAD for response verification: NTP header + extension fields before authenticator.
    let auth_ef_start = find_authenticator_offset(ext_data, &ext_fields)?;
    let mut resp_aad = Vec::new();
    resp_aad.extend_from_slice(&recv_buf[..protocol::Packet::PACKED_SIZE_BYTES]);
    resp_aad.extend_from_slice(&ext_data[..auth_ef_start]);

    // AEAD decrypt/verify.
    let _plaintext = aead_decrypt(
        aead_algorithm,
        s2c_key,
        &resp_aad,
        &resp_auth.nonce,
        &resp_auth.ciphertext,
    )?;

    // Extract new cookies from the response.
    let mut new_cookies = Vec::new();
    for ef in &ext_fields {
        if let Some(cookie) = NtsCookie::from_extension_field(ef) {
            new_cookies.push(cookie.0);
        }
    }

    Ok(new_cookies)
}

/// Find the byte offset of the NTS Authenticator extension field within the
/// extension data (relative to the start of the extension data, not the packet).
fn find_authenticator_offset(
    ext_data: &[u8],
    ext_fields: &[ExtensionField],
) -> io::Result<usize> {
    let mut offset = 0usize;
    for ef in ext_fields {
        if ef.field_type == extension::NTS_AUTHENTICATOR {
            return Ok(offset);
        }
        let field_length = 4 + ef.value.len();
        let padded = (field_length + 3) & !3;
        offset += padded;
        if offset > ext_data.len() {
            break;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "NTS: could not locate authenticator offset",
    ))
}

/// AEAD encrypt using the negotiated algorithm.
///
/// Returns `(nonce, ciphertext)`.
fn aead_encrypt(
    algorithm: u16,
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    match algorithm {
        AEAD_AES_SIV_CMAC_256 => {
            let cipher = Aes128SivAead::new_from_slice(key).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("AES-SIV key error: {}", e))
            })?;
            // AES-SIV uses a synthetic nonce (SIV mode), so we provide an empty nonce.
            // The actual "nonce" for NTS is random data included as AAD.
            let mut nonce_bytes = [0u8; 16];
            rand::fill(&mut nonce_bytes);

            // AES-SIV-CMAC uses a fixed nonce internally (part of SIV construction).
            // For NTS, we use the nonce as additional data.
            let payload = aes_siv::aead::Payload {
                msg: plaintext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
                io::Error::other(format!("AEAD encrypt failed: {}", e))
            })?;

            Ok((nonce_bytes.to_vec(), ciphertext))
        }
        AEAD_AES_SIV_CMAC_512 => {
            let cipher = Aes256SivAead::new_from_slice(key).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("AES-SIV key error: {}", e))
            })?;
            let mut nonce_bytes = [0u8; 16];
            rand::fill(&mut nonce_bytes);

            let payload = aes_siv::aead::Payload {
                msg: plaintext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
                io::Error::other(format!("AEAD encrypt failed: {}", e))
            })?;

            Ok((nonce_bytes.to_vec(), ciphertext))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported AEAD algorithm: {}", algorithm),
        )),
    }
}

/// AEAD decrypt using the negotiated algorithm.
fn aead_decrypt(
    algorithm: u16,
    key: &[u8],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    match algorithm {
        AEAD_AES_SIV_CMAC_256 => {
            let cipher = Aes128SivAead::new_from_slice(key).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("AES-SIV key error: {}", e))
            })?;
            let payload = aes_siv::aead::Payload {
                msg: ciphertext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(nonce);
            cipher.decrypt(nonce, payload).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NTS: AEAD authentication failed — response may be tampered",
                )
            })
        }
        AEAD_AES_SIV_CMAC_512 => {
            let cipher = Aes256SivAead::new_from_slice(key).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("AES-SIV key error: {}", e))
            })?;
            let payload = aes_siv::aead::Payload {
                msg: ciphertext,
                aad,
            };
            let nonce = aes_siv::Nonce::from_slice(nonce);
            cipher.decrypt(nonce, payload).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NTS: AEAD authentication failed — response may be tampered",
                )
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported AEAD algorithm: {}", algorithm),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_key_length() {
        assert_eq!(aead_key_length(AEAD_AES_SIV_CMAC_256).unwrap(), 32);
        assert_eq!(aead_key_length(AEAD_AES_SIV_CMAC_512).unwrap(), 64);
        assert!(aead_key_length(99).is_err());
    }

    #[test]
    fn test_aead_roundtrip_256() {
        let key = vec![0x42u8; 32];
        let aad = b"test associated data";
        let plaintext = b"hello NTS";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, plaintext).unwrap();
        let decrypted =
            aead_decrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_roundtrip_512() {
        let key = vec![0x42u8; 64];
        let aad = b"test associated data";
        let plaintext = b"hello NTS 512";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_512, &key, aad, plaintext).unwrap();
        let decrypted =
            aead_decrypt(AEAD_AES_SIV_CMAC_512, &key, aad, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_tampered_ciphertext() {
        let key = vec![0x42u8; 32];
        let aad = b"test aad";
        let plaintext = b"secret";

        let (nonce, mut ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, plaintext).unwrap();
        // Tamper with the ciphertext.
        if let Some(b) = ciphertext.first_mut() {
            *b ^= 0xFF;
        }
        let result = aead_decrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_wrong_aad() {
        let key = vec![0x42u8; 32];
        let aad = b"correct aad";
        let plaintext = b"secret";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, plaintext).unwrap();
        let result =
            aead_decrypt(AEAD_AES_SIV_CMAC_256, &key, b"wrong aad", &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_ke_record() {
        let mut buf = Vec::new();
        write_ke_record(&mut buf, true, NTS_KE_NEXT_PROTOCOL, &[0x00, 0x00]);
        // Critical bit set: 0x8001, body length 2.
        assert_eq!(buf, [0x80, 0x01, 0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn test_write_ke_record_non_critical() {
        let mut buf = Vec::new();
        write_ke_record(&mut buf, false, NTS_KE_AEAD_ALGORITHM, &[0x00, 0x0F]);
        // No critical bit: 0x0004, body length 2.
        assert_eq!(buf, [0x00, 0x04, 0x00, 0x02, 0x00, 0x0F]);
    }

    #[test]
    fn test_find_authenticator_offset() {
        let fields = vec![
            ExtensionField {
                field_type: UNIQUE_IDENTIFIER,
                value: vec![0u8; 32],
            },
            ExtensionField {
                field_type: extension::NTS_COOKIE,
                value: vec![0u8; 100],
            },
            ExtensionField {
                field_type: extension::NTS_AUTHENTICATOR,
                value: vec![0u8; 48],
            },
        ];
        let ext_data = extension::write_extension_fields(&fields).unwrap();
        let offset = find_authenticator_offset(&ext_data, &fields).unwrap();
        // First field: 4 + 32 = 36 bytes. Second field: 4 + 100 = 104 bytes.
        assert_eq!(offset, 36 + 104);
    }

    #[test]
    fn test_aead_empty_plaintext() {
        let key = vec![0x42u8; 32];
        let aad = b"NTP header + extension fields";

        let (nonce, ciphertext) =
            aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &[]).unwrap();
        let decrypted =
            aead_decrypt(AEAD_AES_SIV_CMAC_256, &key, aad, &nonce, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }
}
