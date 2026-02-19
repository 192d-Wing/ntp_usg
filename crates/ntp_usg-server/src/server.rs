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

use std::io;
use std::sync::{Arc, RwLock};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::protocol;
use crate::server_common::{
    ClientTable, ConfigHandle, HandleResult, ServerMetrics, ServerSystemState, handle_request,
};

#[cfg(feature = "refclock")]
use ntp_client::refclock::RefClock;
#[cfg(feature = "refclock")]
use tokio::task::JoinHandle;

// Generate the shared NtpServerBuilder struct and config methods.
crate::server_common::define_server_builder! {
    /// Builder for configuring and creating an [`NtpServer`].
    extra_fields {
        #[cfg(feature = "refclock")]
        reference_clock: Option<Box<dyn RefClock>>,
    }
    extra_defaults {
        #[cfg(feature = "refclock")]
        reference_clock: None,
    }
}

impl NtpServerBuilder {
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
    #[allow(unused_mut)] // `mut` needed only with `refclock` feature
    pub async fn build(mut self) -> io::Result<NtpServer> {
        #[cfg(feature = "refclock")]
        let reference_clock = self.reference_clock.take();

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
            UdpSocket::from_std(std_sock)?
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = cfg.socket_opts;
            UdpSocket::bind(&cfg.listen_addr).await?
        };
        debug!("NTP server listening on {}", cfg.listen_addr);

        let system_state = Arc::new(RwLock::new(cfg.system_state));

        #[cfg(feature = "refclock")]
        let refclock_task = if let Some(mut clock) = reference_clock {
            let state_clone = system_state.clone();

            Some(tokio::spawn(async move {
                loop {
                    match clock.read_sample().await {
                        Ok(sample) => {
                            if let Ok(mut state) = state_clone.write() {
                                state.reference_timestamp = sample.timestamp.into();
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
                    tokio::time::sleep(clock.poll_interval()).await;
                }
            }))
        } else {
            None
        };

        Ok(NtpServer {
            sock,
            system_state,
            config: Arc::new(RwLock::new(cfg.server_config)),
            client_table: ClientTable::new(cfg.max_clients),
            metrics: cfg.metrics,
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
    config: Arc<RwLock<crate::server_common::ServerConfig>>,
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
    /// This future runs until an I/O error occurs on the socket. Use
    /// `tokio::select!` or a shutdown signal to stop the server gracefully.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_common::{IpNet, RateLimitConfig};
    use std::sync::Arc;

    #[test]
    fn test_builder_defaults() {
        let builder = NtpServer::builder();
        assert!(!builder.enable_interleaved);
        assert_eq!(builder.max_clients, 100_000);
        assert!(builder.allow_list.is_none());
        assert!(builder.deny_list.is_none());
        assert!(builder.rate_limit.is_none());
        assert!(builder.metrics.is_none());
        assert_eq!(builder.system_state.stratum, protocol::Stratum::PRIMARY);
        assert_eq!(builder.system_state.precision, -20);
    }

    #[test]
    fn test_builder_listen() {
        let builder = NtpServer::builder().listen("0.0.0.0:1234");
        assert_eq!(builder.listen_addr, "0.0.0.0:1234");
    }

    #[test]
    fn test_builder_stratum() {
        let builder = NtpServer::builder().stratum(protocol::Stratum(2));
        assert_eq!(builder.system_state.stratum, protocol::Stratum(2));
    }

    #[test]
    fn test_builder_precision() {
        let builder = NtpServer::builder().precision(-24);
        assert_eq!(builder.system_state.precision, -24);
    }

    #[test]
    fn test_builder_leap_indicator() {
        let builder = NtpServer::builder().leap_indicator(protocol::LeapIndicator::AddOne);
        assert_eq!(
            builder.system_state.leap_indicator,
            protocol::LeapIndicator::AddOne
        );
    }

    #[test]
    fn test_builder_reference_id() {
        let ref_id = protocol::ReferenceIdentifier::PrimarySource(protocol::PrimarySource::Gps);
        let builder = NtpServer::builder().reference_id(ref_id);
        assert_eq!(builder.system_state.reference_id, ref_id);
    }

    #[test]
    fn test_builder_root_delay() {
        let delay = protocol::ShortFormat {
            seconds: 1,
            fraction: 500,
        };
        let builder = NtpServer::builder().root_delay(delay);
        assert_eq!(builder.system_state.root_delay, delay);
    }

    #[test]
    fn test_builder_root_dispersion() {
        let disp = protocol::ShortFormat {
            seconds: 0,
            fraction: 1000,
        };
        let builder = NtpServer::builder().root_dispersion(disp);
        assert_eq!(builder.system_state.root_dispersion, disp);
    }

    #[test]
    fn test_builder_enable_interleaved() {
        let builder = NtpServer::builder().enable_interleaved(true);
        assert!(builder.enable_interleaved);
    }

    #[test]
    fn test_builder_max_clients() {
        let builder = NtpServer::builder().max_clients(500);
        assert_eq!(builder.max_clients, 500);
    }

    #[test]
    fn test_builder_allow() {
        let net = IpNet::new("192.168.0.0".parse().unwrap(), 24);
        let builder = NtpServer::builder().allow(net);
        assert_eq!(builder.allow_list.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_builder_deny() {
        let net = IpNet::new("10.0.0.0".parse().unwrap(), 8);
        let builder = NtpServer::builder().deny(net);
        assert_eq!(builder.deny_list.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_builder_rate_limit() {
        let config = RateLimitConfig::default();
        let builder = NtpServer::builder().rate_limit(config);
        assert!(builder.rate_limit.is_some());
        let rl = builder.rate_limit.unwrap();
        assert!(rl.max_requests_per_window > 0);
    }

    #[test]
    fn test_builder_metrics() {
        let metrics = Arc::new(ServerMetrics::new());
        let builder = NtpServer::builder().metrics(metrics.clone());
        assert!(builder.metrics.is_some());
    }

    #[test]
    fn test_builder_chaining() {
        let builder = NtpServer::builder()
            .listen("[::]:8123")
            .stratum(protocol::Stratum(3))
            .precision(-18)
            .enable_interleaved(true)
            .max_clients(10_000);

        assert_eq!(builder.listen_addr, "[::]:8123");
        assert_eq!(builder.system_state.stratum, protocol::Stratum(3));
        assert_eq!(builder.system_state.precision, -18);
        assert!(builder.enable_interleaved);
        assert_eq!(builder.max_clients, 10_000);
    }

    #[tokio::test]
    async fn test_builder_build_binds_socket() {
        let server = NtpServer::builder()
            .listen("127.0.0.1:0")
            .build()
            .await
            .expect("should bind to ephemeral port");

        let addr = server.local_addr().unwrap();
        assert!(addr.port() > 0);
        assert!(server.metrics().is_none());
    }

    #[tokio::test]
    async fn test_builder_build_with_metrics() {
        let metrics = Arc::new(ServerMetrics::new());
        let server = NtpServer::builder()
            .listen("127.0.0.1:0")
            .metrics(metrics.clone())
            .build()
            .await
            .unwrap();

        assert!(server.metrics().is_some());
    }

    #[tokio::test]
    async fn test_server_system_state_access() {
        let server = NtpServer::builder()
            .listen("127.0.0.1:0")
            .stratum(protocol::Stratum(2))
            .build()
            .await
            .unwrap();

        let state = server.system_state().read().unwrap();
        assert_eq!(state.stratum, protocol::Stratum(2));
    }

    #[tokio::test]
    async fn test_server_config_handle() {
        let server = NtpServer::builder()
            .listen("127.0.0.1:0")
            .build()
            .await
            .unwrap();

        // config_handle should be obtainable
        let _handle = server.config_handle();
    }
}
