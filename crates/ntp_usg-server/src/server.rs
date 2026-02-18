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
//!     .listen("[::]:123")
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

use crate::default_listen_addr;
use crate::protocol;
use crate::server_common::{
    AccessControl, ClientTable, ConfigHandle, HandleResult, IpNet, RateLimitConfig, ServerConfig,
    ServerMetrics, ServerSystemState, handle_request,
};

#[cfg(feature = "refclock")]
use ntp_client::refclock::RefClock;
#[cfg(feature = "refclock")]
use tokio::task::JoinHandle;

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
    metrics: Option<Arc<ServerMetrics>>,
    #[cfg(feature = "refclock")]
    reference_clock: Option<Box<dyn RefClock>>,
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
            metrics: None,
            #[cfg(feature = "refclock")]
            reference_clock: None,
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

    /// Attach a shared metrics instance for runtime counter tracking.
    ///
    /// The server will increment atomic counters on every request. Pass the
    /// same `Arc<ServerMetrics>` to other tasks to read snapshots via
    /// [`ServerMetrics::snapshot()`].
    pub fn metrics(mut self, metrics: Arc<ServerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Restrict IPv6 sockets to IPv6-only traffic (no IPv4-mapped addresses).
    ///
    /// When `true`, the socket will only accept IPv6 connections. When `false`,
    /// the socket accepts both IPv4 and IPv6 (dual-stack). Default: OS default
    /// (typically dual-stack on most platforms).
    ///
    /// Only applies to IPv6 listen addresses; ignored for IPv4.
    ///
    /// Requires the `socket-opts` feature.
    #[cfg(feature = "socket-opts")]
    pub fn v6only(mut self, enabled: bool) -> Self {
        self.socket_opts.v6only = Some(enabled);
        self
    }

    /// Set the DSCP (Differentiated Services Code Point) for outgoing packets.
    ///
    /// The DSCP value (0-63) is placed in the upper 6 bits of the IP TOS /
    /// IPv6 Traffic Class byte. Common values:
    /// - 46 (EF) — Expedited Forwarding, recommended for NTP
    /// - 0 — Best effort (default)
    ///
    /// Requires the `socket-opts` feature.
    #[cfg(feature = "socket-opts")]
    pub fn dscp(mut self, value: u8) -> Self {
        self.socket_opts.dscp = Some(value);
        self
    }

    /// Set a reference clock for Stratum 1 operation.
    ///
    /// When a reference clock is provided, the server will:
    /// - Automatically set stratum to the clock's stratum value
    /// - Use the clock's reference ID
    /// - Periodically update system state from the clock
    /// - Update root delay/dispersion based on clock samples
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "refclock")]
    /// # async fn example() -> std::io::Result<()> {
    /// use ntp_server::server::NtpServer;
    /// use ntp_client::refclock::LocalClock;
    ///
    /// let clock = LocalClock::new(0.001);
    ///
    /// let server = NtpServer::builder()
    ///     .listen("[::]:123")
    ///     .reference_clock(clock)  // Auto-sets stratum and ref ID
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "refclock")]
    pub fn reference_clock(mut self, clock: impl RefClock + 'static) -> Self {
        // Get stratum and reference ID from the clock
        let stratum = protocol::Stratum(clock.stratum());
        let ref_id_bytes = clock.reference_id();

        // Convert reference ID bytes to appropriate type based on stratum
        let reference_id = if stratum == protocol::Stratum::PRIMARY {
            // Stratum 1: interpret as primary source (GPS, PPS, etc.)
            // Map common reference IDs to PrimarySource variants
            match &ref_id_bytes {
                b"GPS\0" => {
                    protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Gps)
                }
                b"PPS\0" => {
                    protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Pps)
                }
                b"IRIG" => {
                    protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Irig)
                }
                b"NIST" => {
                    protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Nist)
                }
                b"LOCL" => {
                    protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Locl)
                }
                _ => {
                    // Unknown primary source - use as-is
                    protocol::ReferenceIdentifier::SecondaryOrClient(ref_id_bytes)
                }
            }
        } else {
            // Stratum 2+: treat as opaque bytes
            protocol::ReferenceIdentifier::SecondaryOrClient(ref_id_bytes)
        };

        self.system_state.stratum = stratum;
        self.system_state.reference_id = reference_id;
        self.reference_clock = Some(Box::new(clock));
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
            UdpSocket::from_std(std_sock)?
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = self.socket_opts;
            UdpSocket::bind(&self.listen_addr).await?
        };
        debug!("NTP server listening on {}", self.listen_addr);

        #[cfg(feature = "refclock")]
        let refclock_task = if let Some(mut clock) = self.reference_clock {
            let system_state = Arc::new(RwLock::new(self.system_state.clone()));
            let state_clone = system_state.clone();

            // Spawn background task to update system state from reference clock
            Some(tokio::spawn(async move {
                loop {
                    match clock.read_sample().await {
                        Ok(sample) => {
                            if let Ok(mut state) = state_clone.write() {
                                // Update reference timestamp
                                state.reference_timestamp = sample.timestamp.into();

                                // Update root dispersion from clock sample
                                // ShortFormat represents seconds in 16.16 fixed point
                                let disp_fixed = (sample.dispersion * 65536.0) as u32;
                                state.root_dispersion = protocol::ShortFormat {
                                    seconds: (disp_fixed >> 16) as u16,
                                    fraction: (disp_fixed & 0xFFFF) as u16,
                                };

                                debug!(
                                    "RefClock update: offset={:.9}s, dispersion={:.9}s, quality={}",
                                    sample.offset, sample.dispersion, sample.quality
                                );
                            }
                        }
                        Err(e) => {
                            debug!("RefClock read error: {}", e);
                        }
                    }

                    // Wait for next poll interval
                    tokio::time::sleep(clock.poll_interval()).await;
                }
            }))
        } else {
            None
        };

        #[cfg(feature = "refclock")]
        let system_state = Arc::new(RwLock::new(self.system_state));

        #[cfg(not(feature = "refclock"))]
        let system_state = Arc::new(RwLock::new(self.system_state));

        let config = Arc::new(RwLock::new(ServerConfig {
            access_control: AccessControl::new(self.allow_list, self.deny_list),
            rate_limit: self.rate_limit,
            enable_interleaved: self.enable_interleaved,
        }));

        Ok(NtpServer {
            sock,
            system_state,
            config,
            client_table: ClientTable::new(self.max_clients),
            metrics: self.metrics,
            #[cfg(feature = "refclock")]
            _refclock_task: refclock_task,
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
    config: Arc<RwLock<ServerConfig>>,
    client_table: ClientTable,
    metrics: Option<Arc<ServerMetrics>>,
    #[cfg(feature = "refclock")]
    _refclock_task: Option<JoinHandle<()>>,
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
