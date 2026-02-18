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

use crate::default_listen_addr;
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
    socket_opts: crate::socket_opts::SocketOptions,
}

impl NtpServerBuilder {
    fn new() -> Self {
        NtpServerBuilder {
            listen_addr: default_listen_addr(123),
            system_state: ServerSystemState::default(),
            allow_list: None,
            deny_list: None,
            rate_limit: None,
            enable_interleaved: false,
            max_clients: 100_000,
            socket_opts: crate::socket_opts::SocketOptions::default(),
        }
    }

    /// Set the listen address (default: `"[::]:123"`, or `"0.0.0.0:123"` with `ipv4` feature).
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
    pub fn allow(mut self, network: IpNet) -> Self {
        self.allow_list.get_or_insert_with(Vec::new).push(network);
        self
    }

    /// Add an IP network to the deny list.
    pub fn deny(mut self, network: IpNet) -> Self {
        self.deny_list.get_or_insert_with(Vec::new).push(network);
        self
    }

    /// Enable per-client rate limiting with the given configuration.
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Enable interleaved mode (RFC 9769).
    pub fn enable_interleaved(mut self, enable: bool) -> Self {
        self.enable_interleaved = enable;
        self
    }

    /// Set the NTPv5 timescale for this server.
    #[cfg(feature = "ntpv5")]
    pub fn timescale(mut self, ts: ntp_proto::protocol::ntpv5::Timescale) -> Self {
        self.system_state.timescale = ts;
        self
    }

    /// Set the NTPv5 120-bit reference ID for this server.
    ///
    /// This ID is inserted into the server's Bloom filter for loop detection.
    #[cfg(feature = "ntpv5")]
    pub fn v5_reference_id(mut self, id: [u8; 15]) -> Self {
        self.system_state.bloom_filter.insert(&id);
        self.system_state.v5_reference_id = id;
        self
    }

    /// Set the NTPv5 Bloom filter for loop detection.
    ///
    /// The filter should contain the reference IDs of all upstream time sources.
    #[cfg(feature = "ntpv5")]
    pub fn v5_bloom_filter(mut self, filter: ntp_proto::protocol::bloom::BloomFilter) -> Self {
        self.system_state.bloom_filter = filter;
        self
    }

    /// Set the maximum number of client entries tracked (default: 100,000).
    pub fn max_clients(mut self, max: usize) -> Self {
        self.max_clients = max;
        self
    }

    /// Restrict IPv6 sockets to IPv6-only traffic (no IPv4-mapped addresses).
    ///
    /// Only applies to IPv6 listen addresses; ignored for IPv4.
    /// Requires the `socket-opts` feature.
    #[cfg(feature = "socket-opts")]
    pub fn v6only(mut self, enabled: bool) -> Self {
        self.socket_opts.v6only = Some(enabled);
        self
    }

    /// Set the DSCP (Differentiated Services Code Point) for outgoing packets.
    ///
    /// The DSCP value (0-63) is placed in the upper 6 bits of the IP TOS /
    /// IPv6 Traffic Class byte. Requires the `socket-opts` feature.
    #[cfg(feature = "socket-opts")]
    pub fn dscp(mut self, value: u8) -> Self {
        self.socket_opts.dscp = Some(value);
        self
    }

    /// Build the server. Binds to the configured listen address.
    pub async fn build(self) -> io::Result<NtpServer> {
        #[cfg(feature = "socket-opts")]
        let sock = {
            let addr: std::net::SocketAddr = self.listen_addr.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("socket-opts requires IP:port listen address: {e}"),
                )
            })?;
            let std_sock = self.socket_opts.bind_udp(addr)?;
            smol::Async::new(std_sock)?.into()
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = self.socket_opts;
            smol::net::UdpSocket::bind(&self.listen_addr).await?
        };
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

/// An NTP server that responds to client requests using the smol runtime.
///
/// Created via [`NtpServer::builder()`]. Call [`run()`](NtpServer::run) to start
/// serving requests.
pub struct NtpServer {
    sock: smol::net::UdpSocket,
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
    pub fn system_state(&self) -> &Arc<RwLock<ServerSystemState>> {
        &self.system_state
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
