// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTS-KE (Key Establishment) server using the Tokio runtime (RFC 8915).
//!
//! Accepts TLS 1.3 connections from NTS clients, negotiates NTPv4 protocol and
//! AEAD algorithm, exports keying material, generates cookies, and sends them
//! to the client.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! use ntp_server::nts_ke_server::{NtsKeServer, NtsKeServerConfig};
//! use ntp_server::nts_server_common::MasterKeyStore;
//! use std::sync::{Arc, RwLock};
//! use std::time::Duration;
//!
//! let key_store = Arc::new(RwLock::new(MasterKeyStore::new(Duration::from_secs(86400))));
//!
//! // Load your TLS certificate and private key.
//! let cert_pem = std::fs::read("server.crt")?;
//! let key_pem = std::fs::read("server.key")?;
//!
//! let config = NtsKeServerConfig::from_pem(&cert_pem, &key_pem)?;
//!
//! let server = NtsKeServer::new(config, key_store)?;
//! server.run().await
//! # }
//! ```

use std::io;
use std::sync::{Arc, RwLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use crate::nts_common::*;
pub use crate::nts_ke_server_common::NtsKeServerConfig;
use crate::nts_server_common::MasterKeyStore;

/// An NTS-KE server that accepts TLS connections and issues NTS cookies.
pub struct NtsKeServer {
    tls_acceptor: TlsAcceptor,
    key_store: Arc<RwLock<MasterKeyStore>>,
    ntp_server: Option<String>,
    ntp_port: Option<u16>,
    cookie_count: usize,
    listen_addr: String,
}

impl NtsKeServer {
    /// Create a new NTS-KE server from the given configuration and key store.
    pub fn new(
        config: NtsKeServerConfig,
        key_store: Arc<RwLock<MasterKeyStore>>,
    ) -> io::Result<Self> {
        let tls_config =
            crate::tls_config::nts_server_config(config.cert_chain, config.private_key)?;

        Ok(NtsKeServer {
            tls_acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            key_store,
            ntp_server: config.ntp_server,
            ntp_port: config.ntp_port,
            cookie_count: config.cookie_count,
            listen_addr: config.listen_addr,
        })
    }

    /// Run the NTS-KE server, accepting connections indefinitely.
    pub async fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        debug!("NTS-KE server listening on {}", self.listen_addr);

        loop {
            let (tcp_stream, peer_addr) = listener.accept().await?;
            debug!(peer = %peer_addr, "NTS-KE connection accepted");

            let acceptor = self.tls_acceptor.clone();
            let key_store = self.key_store.clone();
            let ntp_server = self.ntp_server.clone();
            let ntp_port = self.ntp_port;
            let cookie_count = self.cookie_count;

            tokio::spawn(async move {
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) = handle_nts_ke_connection(
                            tls_stream,
                            &key_store,
                            ntp_server.as_deref(),
                            ntp_port,
                            cookie_count,
                        )
                        .await
                        {
                            debug!(peer = %peer_addr, error = %e, "NTS-KE connection error");
                        }
                    }
                    Err(e) => {
                        debug!("TLS accept error from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

/// Handle a single NTS-KE client connection.
async fn handle_nts_ke_connection(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    key_store: &Arc<RwLock<MasterKeyStore>>,
    ntp_server: Option<&str>,
    ntp_port: Option<u16>,
    cookie_count: usize,
) -> io::Result<()> {
    // Read all client NTS-KE records until End of Message.
    let mut records = Vec::new();
    loop {
        let record = read_ke_record_server(&mut tls_stream).await?;
        let is_eom = record.record_type == NTS_KE_END_OF_MESSAGE;
        records.push(record);
        if is_eom {
            break;
        }
    }

    // Process records (shared logic: negotiate, export keys, generate cookies).
    let (_, tls_conn) = tls_stream.get_ref();
    let resp = crate::nts_ke_server_common::process_nts_ke_records(
        &records,
        tls_conn,
        key_store,
        ntp_server,
        ntp_port,
        cookie_count,
    )?;

    // Send response and close.
    tls_stream.write_all(&resp).await?;
    tls_stream.flush().await?;
    let _ = tls_stream.shutdown().await;

    Ok(())
}

/// Read a single NTS-KE record from a server-side TLS stream.
async fn read_ke_record_server(
    reader: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
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
