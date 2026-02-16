// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTP server using the Tokio runtime.
//!
//! Provides a configurable NTPv4 server that responds to client requests with
//! accurate timestamps per RFC 5905. Supports rate limiting (RFC 8633),
//! IP-based access control, and interleaved mode (RFC 9769).
//!
//! # Architecture
//!
//! The server uses a builder pattern for configuration and processes incoming
//! UDP datagrams on a single async task (suitable for most deployments).
//!
//! # Examples
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! use ntp_server::server::NtpServer;
//!
//! let server = NtpServer::builder()
//!     .listen("0.0.0.0:123")
//!     .stratum(ntp_server::protocol::Stratum(2))
//!     .build()
//!     .await?;
//!
//! server.run().await
//! # }
//! ```

use log::debug;
use std::io;
use std::sync::{Arc, RwLock};
use tokio::net::UdpSocket;

use crate::protocol;
use crate::server_common::{
    AccessControl, ClientTable, HandleResult, IpNet, RateLimitConfig, ServerSystemState,
    handle_request,
};

/// Builder for configuring and creating an [`NtpServer`].
pub struct NtpServerBuilder {
    listen_addr: String,
    system_state: ServerSystemState,
    allow_list: Option<Vec<IpNet>>,
    deny_list: Option<Vec<IpNet>>,
    rate_limit: Option<RateLimitConfig>,
    enable_interleaved: bool,
    max_clients: usize,
}

impl NtpServerBuilder {
    fn new() -> Self {
        NtpServerBuilder {
            listen_addr: "0.0.0.0:123".to_string(),
            system_state: ServerSystemState::default(),
            allow_list: None,
            deny_list: None,
            rate_limit: None,
            enable_interleaved: false,
            max_clients: 100_000,
        }
    }

    /// Set the listen address (default: `"0.0.0.0:123"`).
    pub fn listen(mut self, addr: impl Into<String>) -> Self {
        self.listen_addr = addr.into();
        self
    }

    /// Set the server's stratum level.
    pub fn stratum(mut self, stratum: protocol::Stratum) -> Self {
        self.system_state.stratum = stratum;
        self
    }

    /// Set the server's reference identifier.
    pub fn reference_id(mut self, id: protocol::ReferenceIdentifier) -> Self {
        self.system_state.reference_id = id;
        self
    }

    /// Set the server's clock precision in log2 seconds (e.g., -20 ≈ 1μs).
    pub fn precision(mut self, precision: i8) -> Self {
        self.system_state.precision = precision;
        self
    }

    /// Set the server's leap indicator.
    pub fn leap_indicator(mut self, li: protocol::LeapIndicator) -> Self {
        self.system_state.leap_indicator = li;
        self
    }

    /// Set the server's root delay.
    pub fn root_delay(mut self, delay: protocol::ShortFormat) -> Self {
        self.system_state.root_delay = delay;
        self
    }

    /// Set the server's root dispersion.
    pub fn root_dispersion(mut self, disp: protocol::ShortFormat) -> Self {
        self.system_state.root_dispersion = disp;
        self
    }

    /// Add an IP network to the allow list.
    ///
    /// If any allow entries are configured, only matching clients are served.
    /// Non-matching clients receive a KoD RSTR response.
    pub fn allow(mut self, network: IpNet) -> Self {
        self.allow_list.get_or_insert_with(Vec::new).push(network);
        self
    }

    /// Add an IP network to the deny list.
    ///
    /// Matching clients receive a KoD DENY response.
    pub fn deny(mut self, network: IpNet) -> Self {
        self.deny_list.get_or_insert_with(Vec::new).push(network);
        self
    }

    /// Enable per-client rate limiting with the given configuration.
    ///
    /// Clients exceeding the rate limit receive a KoD RATE response.
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Enable interleaved mode (RFC 9769) for improved timestamp accuracy.
    pub fn enable_interleaved(mut self, enable: bool) -> Self {
        self.enable_interleaved = enable;
        self
    }

    /// Set the maximum number of client entries tracked (default: 100,000).
    pub fn max_clients(mut self, max: usize) -> Self {
        self.max_clients = max;
        self
    }

    /// Build the server. Binds to the configured listen address.
    pub async fn build(self) -> io::Result<NtpServer> {
        let sock = UdpSocket::bind(&self.listen_addr).await?;
        debug!("NTP server listening on {}", self.listen_addr);

        Ok(NtpServer {
            sock,
            system_state: Arc::new(RwLock::new(self.system_state)),
            access_control: AccessControl::new(self.allow_list, self.deny_list),
            rate_limit: self.rate_limit,
            client_table: ClientTable::new(self.max_clients),
            enable_interleaved: self.enable_interleaved,
        })
    }
}

/// An NTP server that responds to client requests.
///
/// Created via [`NtpServer::builder()`]. Call [`run()`](NtpServer::run) to start
/// serving requests.
pub struct NtpServer {
    sock: UdpSocket,
    system_state: Arc<RwLock<ServerSystemState>>,
    access_control: AccessControl,
    rate_limit: Option<RateLimitConfig>,
    client_table: ClientTable,
    enable_interleaved: bool,
}

impl NtpServer {
    /// Create a builder for configuring the server.
    pub fn builder() -> NtpServerBuilder {
        NtpServerBuilder::new()
    }

    /// Get a reference to the server's system state for external updates.
    ///
    /// Use this to update the server's stratum, reference ID, leap indicator,
    /// etc. when the upstream reference changes.
    pub fn system_state(&self) -> &Arc<RwLock<ServerSystemState>> {
        &self.system_state
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.sock.local_addr()
    }

    /// Run the server, processing incoming NTP requests indefinitely.
    ///
    /// This future runs until an I/O error occurs on the socket.
    pub async fn run(mut self) -> io::Result<()> {
        let mut recv_buf = [0u8; 2048];

        loop {
            let (recv_len, src_addr) = self.sock.recv_from(&mut recv_buf).await?;

            let server_state = self
                .system_state
                .read()
                .map_err(|_| io::Error::other("system state lock poisoned"))?
                .clone();

            let result = handle_request(
                &recv_buf,
                recv_len,
                src_addr.ip(),
                &server_state,
                &self.access_control,
                self.rate_limit.as_ref(),
                &mut self.client_table,
                self.enable_interleaved,
            );

            match result {
                HandleResult::Response(resp_buf) => {
                    let _ = self.sock.send_to(&resp_buf, src_addr).await;
                }
                HandleResult::Drop => {
                    debug!("dropped packet from {}", src_addr);
                }
            }
        }
    }
}
