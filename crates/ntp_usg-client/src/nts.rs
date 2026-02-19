// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Network Time Security (NTS) client implementation (RFC 8915).
//!
//! NTS provides authenticated NTP using TLS 1.3 for key establishment and
//! AEAD (AES-SIV-CMAC-512 preferred, 256 fallback) for per-packet authentication.
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
//! use ntp_client::nts::NtsSession;
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

use rustls::pki_types::ServerName;
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tracing::debug;

pub use crate::nts_common::NtsKeResult;
use crate::nts_common::*;
use crate::nts_ke_exchange;
use crate::request::{bind_addr_for, compute_offset_delay, parse_and_validate_response};
use crate::{NtpResult, unix_time};

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
/// let ke_result = ntp_client::nts::nts_ke("time.cloudflare.com").await?;
/// println!("Got {} cookies", ke_result.cookies.len());
/// # Ok(())
/// # }
/// ```
pub async fn nts_ke(server: &str) -> io::Result<NtsKeResult> {
    use tokio::io::AsyncWriteExt;

    let (hostname, port) = nts_ke_exchange::parse_nts_ke_server_addr(server);
    let addr = format!("{}:{}", hostname, port);
    debug!("NTS-KE connecting to {}", addr);

    // Configure TLS 1.3 client with PQ-NTS or classical crypto provider.
    let tls_config = crate::tls_config::nts_client_config();
    let connector = TlsConnector::from(Arc::new(tls_config));

    // Connect TCP + TLS.
    let tcp_stream = TcpStream::connect(&addr).await?;
    let server_name = ServerName::try_from(hostname.to_string()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid server name: {}", e),
        )
    })?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Send NTS-KE request.
    let request_buf = nts_ke_exchange::build_nts_ke_request();
    tls_stream.write_all(&request_buf).await?;
    tls_stream.flush().await?;

    // Read all NTS-KE response records until End of Message.
    let mut records = Vec::new();
    loop {
        let record = read_ke_record(&mut tls_stream).await?;
        let is_eom = record.record_type == NTS_KE_END_OF_MESSAGE;
        records.push(record);
        if is_eom {
            break;
        }
    }

    // Process records (shared logic: negotiate, export keys).
    let (_, tls_conn) = tls_stream.get_ref();
    let result = nts_ke_exchange::process_nts_ke_records(&records, tls_conn, hostname)?;

    // Gracefully close TLS.
    let _ = tls_stream.shutdown().await;

    Ok(result)
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
    /// let mut session = ntp_client::nts::NtsSession::from_ke("time.cloudflare.com").await?;
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
        let resolved_addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str).await?.collect();
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

    /// Returns the AEAD algorithm negotiated during key establishment.
    pub fn aead_algorithm(&self) -> u16 {
        self.aead_algorithm
    }

    /// Returns the NTP server address used for requests.
    pub fn ntp_addr(&self) -> SocketAddr {
        self.ntp_addr
    }

    async fn request_inner(&mut self) -> io::Result<NtpResult> {
        // Pop a cookie.
        let cookie = self
            .cookies
            .pop()
            .ok_or_else(|| io::Error::other("no NTS cookies remaining"))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    // ── NtsKeResult ──────────────────────────────────────────────

    #[test]
    fn test_nts_ke_result_fields() {
        let ke = NtsKeResult {
            c2s_key: vec![1; 64],
            s2c_key: vec![2; 64],
            cookies: vec![vec![3; 100], vec![4; 100]],
            aead_algorithm: AEAD_AES_SIV_CMAC_512,
            ntp_server: "ntp.example.com".to_string(),
            ntp_port: 123,
            next_protocol: NTS_PROTOCOL_NTPV4,
        };
        assert_eq!(ke.cookies.len(), 2);
        assert_eq!(ke.aead_algorithm, AEAD_AES_SIV_CMAC_512);
        assert_eq!(ke.ntp_server, "ntp.example.com");
        assert_eq!(ke.ntp_port, 123);
        assert_eq!(ke.next_protocol, NTS_PROTOCOL_NTPV4);
    }

    // ── NtsSession (non-network) ─────────────────────────────────

    #[tokio::test]
    async fn test_session_from_ke_result_resolves_localhost() {
        let ke = NtsKeResult {
            c2s_key: vec![0; 64],
            s2c_key: vec![0; 64],
            cookies: vec![vec![0; 100]; 8],
            aead_algorithm: AEAD_AES_SIV_CMAC_512,
            ntp_server: "127.0.0.1".to_string(),
            ntp_port: 123,
            next_protocol: NTS_PROTOCOL_NTPV4,
        };
        let session = NtsSession::from_ke_result(ke).await.unwrap();
        assert_eq!(session.cookie_count(), 8);
        assert_eq!(session.aead_algorithm(), AEAD_AES_SIV_CMAC_512);
        assert_eq!(session.ntp_addr().port(), 123);
    }

    #[tokio::test]
    async fn test_session_cookie_count_decrements() {
        let ke = NtsKeResult {
            c2s_key: vec![0; 64],
            s2c_key: vec![0; 64],
            cookies: vec![vec![0; 100]; 3],
            aead_algorithm: AEAD_AES_SIV_CMAC_512,
            ntp_server: "127.0.0.1".to_string(),
            ntp_port: 123,
            next_protocol: NTS_PROTOCOL_NTPV4,
        };
        let session = NtsSession::from_ke_result(ke).await.unwrap();
        assert_eq!(session.cookie_count(), 3);
    }

    #[tokio::test]
    async fn test_session_request_fails_no_cookies() {
        let ke = NtsKeResult {
            c2s_key: vec![0; 64],
            s2c_key: vec![0; 64],
            cookies: vec![], // No cookies
            aead_algorithm: AEAD_AES_SIV_CMAC_512,
            ntp_server: "127.0.0.1".to_string(),
            ntp_port: 123,
            next_protocol: NTS_PROTOCOL_NTPV4,
        };
        let mut session = NtsSession::from_ke_result(ke).await.unwrap();
        let result = session.request().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no NTS cookies"));
    }

    // ── build_nts_request ────────────────────────────────────────

    #[test]
    fn test_build_request_produces_valid_packet() {
        let c2s_key = vec![0xAA; 64];
        let cookie = vec![0xBB; 100];
        let (buf, t1, uid) = build_nts_request(&c2s_key, AEAD_AES_SIV_CMAC_512, cookie).unwrap();
        // Packet must be at least 48 bytes (NTP header).
        assert!(buf.len() >= 48);
        // T1 should be non-zero.
        assert!(t1.seconds > 0 || t1.fraction > 0);
        // UID should be 32 bytes (our random unique identifier).
        assert_eq!(uid.len(), 32);
    }

    #[test]
    fn test_build_request_different_uids() {
        let c2s_key = vec![0xAA; 64];
        let (_, _, uid1) =
            build_nts_request(&c2s_key, AEAD_AES_SIV_CMAC_512, vec![0; 100]).unwrap();
        let (_, _, uid2) =
            build_nts_request(&c2s_key, AEAD_AES_SIV_CMAC_512, vec![0; 100]).unwrap();
        // UIDs should be different (random).
        assert_ne!(uid1, uid2);
    }
}
