// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Network Time Security (NTS) client using the smol runtime (RFC 8915).
//!
//! NTS provides authenticated NTP using TLS 1.3 for key establishment and
//! AEAD (AES-SIV-CMAC-512 preferred, 256 fallback) for per-packet authentication.
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
//! use ntp_client::smol_nts::NtsSession;
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
use rustls::pki_types::ServerName;
use smol::net::{TcpStream, UdpSocket};
use tracing::{Instrument, debug};

use crate::error::{ConfigError, NtpError, NtsError, ProtocolError, TimeoutError};
pub use crate::nts_common::NtsKeResult;
use crate::nts_common::*;
use crate::nts_ke_exchange;
use crate::request::{bind_addr_for, compute_offset_delay, parse_and_validate_response};
use crate::{NtpResult, unix_time};

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
    let (hostname, port) = nts_ke_exchange::parse_nts_ke_server_addr(server);
    let span = tracing::debug_span!("nts_ke", server = %server, hostname = %hostname);
    async {
        let addr = format!("{}:{}", hostname, port);
        debug!("NTS-KE connecting to {}", addr);

        // Configure TLS 1.3 client with PQ-NTS or classical crypto provider.
        let tls_config = crate::tls_config::nts_client_config();
        let connector = TlsConnector::from(Arc::new(tls_config));

        let tcp_stream = TcpStream::connect(&addr).await?;
        let server_name = ServerName::try_from(hostname.to_string()).map_err(|e| -> io::Error {
            NtpError::Config(ConfigError::InvalidServerName {
                detail: e.to_string(),
            })
            .into()
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
        let _ = tls_stream.close().await;

        Ok(result)
    }
    .instrument(span)
    .await
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
            return Err(NtpError::Config(ConfigError::NoAddresses { address: addr_str }).into());
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
            Err(NtpError::Timeout(TimeoutError::NtsKe).into())
        })
        .await
    }

    async fn request_inner(&mut self) -> io::Result<NtpResult> {
        let cookie = self
            .cookies
            .pop()
            .ok_or_else(|| -> io::Error { NtpError::Nts(NtsError::NoCookies).into() })?;

        let (send_buf, t1, uid_data) =
            build_nts_request(&self.c2s_key, self.aead_algorithm, cookie)?;

        let sock = UdpSocket::bind(bind_addr_for(&self.ntp_addr)).await?;
        sock.send_to(&send_buf, self.ntp_addr).await?;

        let mut recv_buf = [0u8; 2048];
        let (recv_len, src_addr) = sock.recv_from(&mut recv_buf).await?;

        let (response, t4) =
            parse_and_validate_response(&recv_buf, recv_len, src_addr, &self.resolved_addrs)?;

        if response.origin_timestamp != t1 {
            return Err(NtpError::Protocol(ProtocolError::OriginTimestampMismatch).into());
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
