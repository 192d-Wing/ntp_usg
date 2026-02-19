// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared NTP server builder infrastructure.
//!
//! Provides the [`define_server_builder!`] macro and [`ServerBuildConfig`]
//! struct used by both the tokio and smol server implementations.

use std::sync::Arc;

use super::{ServerConfig, ServerMetrics, ServerSystemState};

/// Runtime-independent configuration produced by `NtpServerBuilder::into_config`.
///
/// Contains everything needed to create an NTP server except the
/// runtime-specific socket binding.
pub(crate) struct ServerBuildConfig {
    pub(crate) system_state: ServerSystemState,
    pub(crate) server_config: ServerConfig,
    pub(crate) max_clients: usize,
    pub(crate) metrics: Option<Arc<ServerMetrics>>,
    pub(crate) listen_addr: String,
    pub(crate) socket_opts: crate::socket_opts::SocketOptions,
}

/// Define an `NtpServerBuilder` struct with shared NTP server configuration methods.
///
/// Both the tokio [`crate::server`] and smol [`crate::smol_server`] modules
/// invoke this macro to generate their own `NtpServerBuilder` type with
/// identical configuration methods. Each module then adds a runtime-specific
/// `build()` method.
///
/// # Parameters
///
/// - `extra_fields { ... }` — Additional struct fields (e.g., for reference clocks)
/// - `extra_defaults { ... }` — Default values for the extra fields in `new()`
macro_rules! define_server_builder {
    (
        $(#[$struct_meta:meta])*
        extra_fields { $($extra_field:tt)* }
        extra_defaults { $($extra_default:tt)* }
    ) => {
        $(#[$struct_meta])*
        pub struct NtpServerBuilder {
            listen_addr: String,
            system_state: $crate::server_common::ServerSystemState,
            allow_list: Option<Vec<$crate::server_common::IpNet>>,
            deny_list: Option<Vec<$crate::server_common::IpNet>>,
            rate_limit: Option<$crate::server_common::RateLimitConfig>,
            enable_interleaved: bool,
            max_clients: usize,
            socket_opts: $crate::socket_opts::SocketOptions,
            metrics: Option<::std::sync::Arc<$crate::server_common::ServerMetrics>>,
            $($extra_field)*
        }

        impl NtpServerBuilder {
            fn new() -> Self {
                NtpServerBuilder {
                    listen_addr: $crate::default_listen_addr(123),
                    system_state: <$crate::server_common::ServerSystemState
                        as ::std::default::Default>::default(),
                    allow_list: None,
                    deny_list: None,
                    rate_limit: None,
                    enable_interleaved: false,
                    max_clients: 100_000,
                    socket_opts: <$crate::socket_opts::SocketOptions
                        as ::std::default::Default>::default(),
                    metrics: None,
                    $($extra_default)*
                }
            }

            /// Set the listen address (default: `"[::]:123"`, or `"0.0.0.0:123"`
            /// with `ipv4` feature).
            pub fn listen(mut self, addr: impl Into<String>) -> Self {
                self.listen_addr = addr.into();
                self
            }

            /// Set the server's stratum level.
            pub fn stratum(mut self, stratum: $crate::protocol::Stratum) -> Self {
                self.system_state.stratum = stratum;
                self
            }

            /// Set the server's reference identifier.
            pub fn reference_id(
                mut self,
                id: $crate::protocol::ReferenceIdentifier,
            ) -> Self {
                self.system_state.reference_id = id;
                self
            }

            /// Set the server's clock precision in log2 seconds (e.g., -20 ≈ 1μs).
            pub fn precision(mut self, precision: i8) -> Self {
                self.system_state.precision = precision;
                self
            }

            /// Set the server's leap indicator.
            pub fn leap_indicator(
                mut self,
                li: $crate::protocol::LeapIndicator,
            ) -> Self {
                self.system_state.leap_indicator = li;
                self
            }

            /// Set the server's root delay.
            pub fn root_delay(
                mut self,
                delay: $crate::protocol::ShortFormat,
            ) -> Self {
                self.system_state.root_delay = delay;
                self
            }

            /// Set the server's root dispersion.
            pub fn root_dispersion(
                mut self,
                disp: $crate::protocol::ShortFormat,
            ) -> Self {
                self.system_state.root_dispersion = disp;
                self
            }

            /// Add an IP network to the allow list.
            ///
            /// If any allow entries are configured, only matching clients are served.
            /// Non-matching clients receive a KoD RSTR response.
            pub fn allow(mut self, network: $crate::server_common::IpNet) -> Self {
                self.allow_list
                    .get_or_insert_with(::std::vec::Vec::new)
                    .push(network);
                self
            }

            /// Add an IP network to the deny list.
            ///
            /// Matching clients receive a KoD DENY response.
            pub fn deny(mut self, network: $crate::server_common::IpNet) -> Self {
                self.deny_list
                    .get_or_insert_with(::std::vec::Vec::new)
                    .push(network);
                self
            }

            /// Enable per-client rate limiting with the given configuration.
            ///
            /// Clients exceeding the rate limit receive a KoD RATE response.
            pub fn rate_limit(
                mut self,
                config: $crate::server_common::RateLimitConfig,
            ) -> Self {
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

            /// Attach a shared metrics instance for runtime counter tracking.
            ///
            /// The server will increment atomic counters on every request. Pass the
            /// same `Arc<ServerMetrics>` to other tasks to read snapshots via
            /// [`ServerMetrics::snapshot()`].
            pub fn metrics(
                mut self,
                metrics: ::std::sync::Arc<$crate::server_common::ServerMetrics>,
            ) -> Self {
                self.metrics = Some(metrics);
                self
            }

            /// Set the NTPv5 timescale for this server.
            #[cfg(feature = "ntpv5")]
            pub fn timescale(
                mut self,
                ts: $crate::protocol::ntpv5::Timescale,
            ) -> Self {
                self.system_state.timescale = ts;
                self
            }

            /// Set the NTPv5 120-bit reference ID for this server.
            ///
            /// This ID is inserted into the server's Bloom filter for loop
            /// detection.
            #[cfg(feature = "ntpv5")]
            pub fn v5_reference_id(mut self, id: [u8; 15]) -> Self {
                self.system_state.bloom_filter.insert(&id);
                self.system_state.v5_reference_id = id;
                self
            }

            /// Set the NTPv5 Bloom filter for loop detection.
            ///
            /// The filter should contain the reference IDs of all upstream time
            /// sources.
            #[cfg(feature = "ntpv5")]
            pub fn v5_bloom_filter(
                mut self,
                filter: $crate::protocol::bloom::BloomFilter,
            ) -> Self {
                self.system_state.bloom_filter = filter;
                self
            }

            /// Restrict IPv6 sockets to IPv6-only traffic (no IPv4-mapped
            /// addresses).
            ///
            /// When `true`, the socket will only accept IPv6 connections. When
            /// `false`, the socket accepts both IPv4 and IPv6 (dual-stack).
            /// Default: OS default (typically dual-stack on most platforms).
            ///
            /// Only applies to IPv6 listen addresses; ignored for IPv4.
            ///
            /// Requires the `socket-opts` feature.
            #[cfg(feature = "socket-opts")]
            pub fn v6only(mut self, enabled: bool) -> Self {
                self.socket_opts.v6only = Some(enabled);
                self
            }

            /// Set the DSCP (Differentiated Services Code Point) for outgoing
            /// packets.
            ///
            /// The DSCP value (0-63) is placed in the upper 6 bits of the IP
            /// TOS / IPv6 Traffic Class byte. Common values:
            /// - 46 (EF) — Expedited Forwarding, recommended for NTP
            /// - 0 — Best effort (default)
            ///
            /// Requires the `socket-opts` feature.
            #[cfg(feature = "socket-opts")]
            pub fn dscp(mut self, value: u8) -> Self {
                self.socket_opts.dscp = Some(value);
                self
            }

            /// Convert this builder into a runtime-independent build
            /// configuration.
            pub(crate) fn into_config(
                self,
            ) -> $crate::server_common::ServerBuildConfig {
                $crate::server_common::ServerBuildConfig {
                    system_state: self.system_state,
                    server_config: $crate::server_common::ServerConfig {
                        access_control: $crate::server_common::AccessControl::new(
                            self.allow_list,
                            self.deny_list,
                        ),
                        rate_limit: self.rate_limit,
                        enable_interleaved: self.enable_interleaved,
                    },
                    max_clients: self.max_clients,
                    metrics: self.metrics,
                    listen_addr: self.listen_addr,
                    socket_opts: self.socket_opts,
                }
            }
        }
    };
}
pub(crate) use define_server_builder;

#[cfg(test)]
#[allow(unreachable_pub, dead_code)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    // Invoke the macro with empty extras so we have a testable NtpServerBuilder.
    define_server_builder! {
        /// Test-only builder.
        extra_fields {}
        extra_defaults {}
    }

    #[test]
    fn test_into_config_defaults() {
        let cfg = NtpServerBuilder::new().into_config();
        assert_eq!(cfg.max_clients, 100_000);
        assert_eq!(cfg.listen_addr, crate::default_listen_addr(123));
        assert!(cfg.metrics.is_none());
        assert!(cfg.server_config.rate_limit.is_none());
        assert!(!cfg.server_config.enable_interleaved);
    }

    #[test]
    fn test_into_config_listen_addr() {
        let cfg = NtpServerBuilder::new()
            .listen("127.0.0.1:9999")
            .into_config();
        assert_eq!(cfg.listen_addr, "127.0.0.1:9999");
    }

    #[test]
    fn test_into_config_stratum_precision() {
        use crate::protocol::{PrimarySource, ReferenceIdentifier, Stratum};

        let cfg = NtpServerBuilder::new()
            .stratum(Stratum::SECONDARY_MIN)
            .precision(-24)
            .reference_id(ReferenceIdentifier::PrimarySource(PrimarySource::Gps))
            .into_config();
        assert_eq!(cfg.system_state.stratum, Stratum::SECONDARY_MIN);
        assert_eq!(cfg.system_state.precision, -24);
        assert_eq!(
            cfg.system_state.reference_id,
            ReferenceIdentifier::PrimarySource(PrimarySource::Gps)
        );
    }

    #[test]
    fn test_into_config_allow_deny() {
        use crate::server_common::IpNet;
        use std::net::IpAddr;

        let cfg = NtpServerBuilder::new()
            .allow(IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8))
            .deny(IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16))
            .into_config();
        // AccessControl was constructed — verify it exists by checking the type.
        // The AccessControl::new() receives Some(vec![...]) for both lists.
        let _ac = &cfg.server_config.access_control;
    }

    #[test]
    fn test_into_config_multiple_allow_entries() {
        use crate::server_common::IpNet;
        use std::net::IpAddr;

        let cfg = NtpServerBuilder::new()
            .allow(IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8))
            .allow(IpNet::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12))
            .allow(IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16))
            .into_config();
        let _ac = &cfg.server_config.access_control;
    }

    #[test]
    fn test_into_config_rate_limit() {
        use crate::server_common::RateLimitConfig;

        let rl = RateLimitConfig {
            max_requests_per_window: 10,
            window_duration: Duration::from_secs(60),
            min_interval: Duration::from_secs(2),
        };
        let cfg = NtpServerBuilder::new().rate_limit(rl).into_config();
        let rl_cfg = cfg.server_config.rate_limit.unwrap();
        assert_eq!(rl_cfg.max_requests_per_window, 10);
        assert_eq!(rl_cfg.window_duration, Duration::from_secs(60));
        assert_eq!(rl_cfg.min_interval, Duration::from_secs(2));
    }

    #[test]
    fn test_into_config_interleaved_max_clients() {
        let cfg = NtpServerBuilder::new()
            .enable_interleaved(true)
            .max_clients(500)
            .into_config();
        assert!(cfg.server_config.enable_interleaved);
        assert_eq!(cfg.max_clients, 500);
    }

    #[test]
    fn test_into_config_metrics() {
        let metrics = Arc::new(ServerMetrics::default());
        let cfg = NtpServerBuilder::new()
            .metrics(metrics.clone())
            .into_config();
        assert!(cfg.metrics.is_some());
    }
}
