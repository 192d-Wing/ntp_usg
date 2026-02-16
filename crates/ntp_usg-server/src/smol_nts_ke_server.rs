// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTS-KE (Key Establishment) server using the smol runtime (RFC 8915).
//!
//! Provides the same NTS-KE server functionality as [`crate::nts_ke_server`]
//! but using smol and futures-rustls instead of tokio and tokio-rustls.

use std::io;
use std::sync::{Arc, RwLock};

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use log::debug;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;

use crate::nts_common::*;
use crate::nts_server_common::{CookieContents, MasterKeyStore};

/// Configuration for an NTS-KE server (smol runtime).
pub struct NtsKeServerConfig {
    /// TLS certificate chain (DER encoded).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Private key corresponding to the certificate (DER encoded).
    pub private_key: PrivateKeyDer<'static>,
    /// Listen address (default: `"0.0.0.0:4460"`).
    pub listen_addr: String,
    /// NTP server hostname to advertise to clients.
    pub ntp_server: Option<String>,
    /// NTP port to advertise to clients.
    pub ntp_port: Option<u16>,
    /// Number of cookies to issue per session (default: 8).
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
            listen_addr: "0.0.0.0:4460".to_string(),
            ntp_server: None,
            ntp_port: None,
            cookie_count: 8,
        })
    }
}

/// An NTS-KE server using the smol runtime.
pub struct NtsKeServer {
    tls_acceptor: futures_rustls::TlsAcceptor,
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
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(config.cert_chain, config.private_key)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("TLS config error: {}", e),
                    )
                })?;

        Ok(NtsKeServer {
            tls_acceptor: futures_rustls::TlsAcceptor::from(Arc::new(tls_config)),
            key_store,
            ntp_server: config.ntp_server,
            ntp_port: config.ntp_port,
            cookie_count: config.cookie_count,
            listen_addr: config.listen_addr,
        })
    }

    /// Run the NTS-KE server, accepting connections indefinitely.
    pub async fn run(&self) -> io::Result<()> {
        let listener = smol::net::TcpListener::bind(&self.listen_addr).await?;
        debug!("NTS-KE server (smol) listening on {}", self.listen_addr);

        loop {
            let (tcp_stream, peer_addr) = listener.accept().await?;
            debug!("NTS-KE connection from {}", peer_addr);

            let acceptor = self.tls_acceptor.clone();
            let key_store = self.key_store.clone();
            let ntp_server = self.ntp_server.clone();
            let ntp_port = self.ntp_port;
            let cookie_count = self.cookie_count;

            smol::spawn(async move {
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
                            debug!("NTS-KE error from {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => {
                        debug!("TLS accept error from {}: {}", peer_addr, e);
                    }
                }
            })
            .detach();
        }
    }
}

/// Handle a single NTS-KE client connection (smol runtime).
async fn handle_nts_ke_connection(
    mut tls_stream: futures_rustls::server::TlsStream<smol::net::TcpStream>,
    key_store: &Arc<RwLock<MasterKeyStore>>,
    ntp_server: Option<&str>,
    ntp_port: Option<u16>,
    cookie_count: usize,
) -> io::Result<()> {
    // 1. Read client NTS-KE records until End of Message.
    let mut client_next_protocol = false;
    let mut client_aead_algorithms = Vec::new();

    loop {
        let record = read_ke_record_server(&mut tls_stream).await?;
        match record.record_type {
            NTS_KE_END_OF_MESSAGE => break,
            NTS_KE_NEXT_PROTOCOL => {
                if record.body.len() >= 2 {
                    let proto = read_be_u16(&record.body[..2]);
                    if proto == NTS_PROTOCOL_NTPV4 {
                        client_next_protocol = true;
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
                    let mut resp = Vec::new();
                    write_ke_record(&mut resp, true, NTS_KE_ERROR, &0u16.to_be_bytes());
                    write_ke_record(&mut resp, true, NTS_KE_END_OF_MESSAGE, &[]);
                    tls_stream.write_all(&resp).await?;
                    tls_stream.flush().await?;
                    return Ok(());
                }
            }
        }
    }

    // 2. Validate client request.
    if !client_next_protocol {
        let mut resp = Vec::new();
        write_ke_record(&mut resp, true, NTS_KE_ERROR, &1u16.to_be_bytes());
        write_ke_record(&mut resp, true, NTS_KE_END_OF_MESSAGE, &[]);
        tls_stream.write_all(&resp).await?;
        tls_stream.flush().await?;
        return Ok(());
    }

    // 3. Negotiate AEAD algorithm.
    let supported = [AEAD_AES_SIV_CMAC_256, AEAD_AES_SIV_CMAC_512];
    let aead_algorithm = supported
        .iter()
        .find(|a| client_aead_algorithms.contains(a))
        .copied()
        .unwrap_or(AEAD_AES_SIV_CMAC_256);

    // 4. Export TLS keying material.
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

    // 6. Build and send response.
    let mut resp = Vec::new();

    write_ke_record(
        &mut resp,
        true,
        NTS_KE_NEXT_PROTOCOL,
        &NTS_PROTOCOL_NTPV4.to_be_bytes(),
    );
    write_ke_record(
        &mut resp,
        true,
        NTS_KE_AEAD_ALGORITHM,
        &aead_algorithm.to_be_bytes(),
    );
    if let Some(server) = ntp_server {
        write_ke_record(&mut resp, false, NTS_KE_SERVER, server.as_bytes());
    }
    if let Some(port) = ntp_port {
        write_ke_record(&mut resp, false, NTS_KE_PORT, &port.to_be_bytes());
    }
    for cookie in &cookies {
        write_ke_record(&mut resp, false, NTS_KE_NEW_COOKIE, cookie);
    }
    write_ke_record(&mut resp, true, NTS_KE_END_OF_MESSAGE, &[]);

    tls_stream.write_all(&resp).await?;
    tls_stream.flush().await?;

    debug!(
        "NTS-KE (smol): sent {} cookies, AEAD={}",
        cookies.len(),
        aead_algorithm
    );

    let _ = tls_stream.close().await;

    Ok(())
}

/// Read a single NTS-KE record from a server-side TLS stream (smol).
async fn read_ke_record_server(
    reader: &mut futures_rustls::server::TlsStream<smol::net::TcpStream>,
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
