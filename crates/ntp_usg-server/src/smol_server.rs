// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP server using the smol runtime.
//!
//! Provides the same NTP server functionality as [`crate::server`] but using
//! the smol async runtime. See the tokio-based [`crate::server`] module for
//! full documentation.
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> std::io::Result<()> {
//! smol::block_on(async {
//!     use ntp_server::smol_server::NtpServer;
//!
//!     let server = NtpServer::builder()
//!         .listen("[::]:123")
//!         .stratum(ntp_server::protocol::Stratum(2))
//!         .build()
//!         .await?;
//!
//!     server.run().await
//! })
//! # }
//! ```

use log::debug;
use std::io;
use std::sync::{Arc, RwLock};

use crate::server_common::{
    ClientTable, ConfigHandle, HandleResult, ServerMetrics, ServerSystemState, handle_request,
};

// Generate the shared NtpServerBuilder struct and config methods.
crate::server_common::define_server_builder! {
    /// Builder for configuring and creating an [`NtpServer`].
    extra_fields {}
    extra_defaults {}
}

impl NtpServerBuilder {
    /// Build the server. Binds to the configured listen address.
    pub async fn build(self) -> io::Result<NtpServer> {
        let cfg = self.into_config();

        #[cfg(feature = "socket-opts")]
        let sock = {
            let addr: std::net::SocketAddr = cfg.listen_addr.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("socket-opts requires IP:port listen address: {e}"),
                )
            })?;
            let std_sock = cfg.socket_opts.bind_udp(addr)?;
            smol::Async::new(std_sock)?.into()
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = cfg.socket_opts;
            smol::net::UdpSocket::bind(&cfg.listen_addr).await?
        };
        debug!("NTP server listening on {}", cfg.listen_addr);

        Ok(NtpServer {
            sock,
            system_state: Arc::new(RwLock::new(cfg.system_state)),
            config: Arc::new(RwLock::new(cfg.server_config)),
            client_table: ClientTable::new(cfg.max_clients),
            metrics: cfg.metrics,
        })
    }
}

/// An NTP server that responds to client requests using the smol runtime.
///
/// Created via [`NtpServer::builder()`]. Call [`run()`](NtpServer::run) to start
/// serving requests.
pub struct NtpServer {
    sock: smol::net::UdpSocket,
    system_state: Arc<RwLock<ServerSystemState>>,
    config: Arc<RwLock<crate::server_common::ServerConfig>>,
    client_table: ClientTable,
    metrics: Option<Arc<ServerMetrics>>,
}

impl NtpServer {
    /// Create a builder for configuring the server.
    pub fn builder() -> NtpServerBuilder {
        NtpServerBuilder::new()
    }

    /// Get a reference to the server's system state for external updates.
    pub fn system_state(&self) -> &Arc<RwLock<ServerSystemState>> {
        &self.system_state
    }

    /// Get a handle for updating server configuration at runtime.
    ///
    /// The returned [`ConfigHandle`] can be cloned and sent to other tasks.
    /// Updates made through the handle take effect on the next incoming request.
    pub fn config_handle(&self) -> ConfigHandle {
        ConfigHandle::new(self.config.clone())
    }

    /// Get the attached metrics instance, if any.
    pub fn metrics(&self) -> Option<&Arc<ServerMetrics>> {
        self.metrics.as_ref()
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.sock.local_addr()
    }

    /// Run the server, processing incoming NTP requests indefinitely.
    pub async fn run(mut self) -> io::Result<()> {
        let mut recv_buf = [0u8; 2048];

        loop {
            let (recv_len, src_addr) = self.sock.recv_from(&mut recv_buf).await?;

            let server_state = self
                .system_state
                .read()
                .map_err(|_| io::Error::other("system state lock poisoned"))?
                .clone();

            let result = {
                let config = self
                    .config
                    .read()
                    .map_err(|_| io::Error::other("config lock poisoned"))?;
                handle_request(
                    &recv_buf,
                    recv_len,
                    src_addr.ip(),
                    &server_state,
                    &config.access_control,
                    config.rate_limit.as_ref(),
                    &mut self.client_table,
                    config.enable_interleaved,
                    self.metrics.as_deref(),
                )
            };

            if let Some(m) = &self.metrics {
                m.set_active_clients(self.client_table.len() as u64);
            }

            match result {
                HandleResult::Response(resp_buf) => {
                    let _ = self.sock.send_to(&resp_buf, src_addr).await;
                }
                #[cfg(feature = "ntpv5")]
                HandleResult::V5Response(resp_buf) => {
                    let _ = self.sock.send_to(&resp_buf, src_addr).await;
                }
                HandleResult::Drop => {
                    debug!("dropped packet from {}", src_addr);
                }
            }
        }
    }
}
