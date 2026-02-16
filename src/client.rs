// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Continuous NTP client with adaptive poll interval management and interleaved mode.
//!
//! This module provides a long-lived NTP client that maintains associations with
//! one or more NTP servers, polling them at adaptive intervals per RFC 5905
//! Section 7.3 and supporting interleaved mode per RFC 9769 for improved accuracy.
//!
//! # Architecture
//!
//! The client uses a builder pattern for configuration and a `tokio::sync::watch`
//! channel for publishing the current synchronization state to consumers.
//!
//! # Examples
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! let (client, state_rx) = ntp::client::NtpClient::builder()
//!     .server("pool.ntp.org:123")
//!     .server("time.google.com:123")
//!     .min_poll(4)
//!     .max_poll(10)
//!     .build()
//!     .await?;
//!
//! // Spawn the poll loop.
//! tokio::spawn(client.run());
//!
//! // Read the latest sync state at any time.
//! let state = state_rx.borrow();
//! println!("Offset: {:.6}s, Jitter: {:.6}s", state.offset, state.jitter);
//! # Ok(())
//! # }
//! ```

use log::{debug, warn};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::filter::{ClockSample, SampleFilter};
use crate::{
    build_request_packet, compute_offset_delay, parse_and_validate_response, protocol, unix_time,
    KissOfDeathError,
};

/// The current synchronization state, available to consumers via
/// `tokio::sync::watch::Receiver<NtpSyncState>`.
#[derive(Clone, Debug)]
pub struct NtpSyncState {
    /// Best estimated clock offset in seconds (positive = local clock behind server).
    pub offset: f64,
    /// Best estimated round-trip delay in seconds.
    pub delay: f64,
    /// RMS jitter of recent samples in seconds.
    pub jitter: f64,
    /// Stratum of the best peer.
    pub stratum: u8,
    /// Whether interleaved mode is active for the best peer.
    pub interleaved: bool,
    /// When this state was last updated.
    pub last_update: std::time::Instant,
    /// Number of successful responses received across all peers.
    pub total_responses: u64,
}

impl Default for NtpSyncState {
    fn default() -> Self {
        NtpSyncState {
            offset: 0.0,
            delay: 0.0,
            jitter: 0.0,
            stratum: protocol::MAXSTRAT,
            interleaved: false,
            last_update: std::time::Instant::now(),
            total_responses: 0,
        }
    }
}

/// Result of polling a single peer.
enum PollResult {
    /// Successful basic-mode exchange.
    Sample(ClockSample, bool /* interleaved */),
    /// Server sent RATE kiss code.
    RateKissCode,
    /// Server sent DENY or RSTR kiss code.
    DenyKissCode,
}

/// State maintained for a single NTP server peer.
struct PeerState {
    /// Resolved socket address of this peer.
    addr: SocketAddr,
    /// Current poll exponent (log2 seconds). Bounded by [min_poll, max_poll].
    poll_exponent: u8,
    /// 8-bit shift register for reachability (RFC 5905 Section 9.1).
    reachability: u8,
    /// Clock filter for this peer.
    filter: SampleFilter,
    /// Last stratum received from this peer.
    stratum: Option<protocol::Stratum>,
    /// Our transmit timestamp (T1) from the previous exchange (for interleaved mode).
    prev_t1: Option<protocol::TimestampFormat>,
    /// Our receive timestamp (T4) from the previous exchange (for interleaved mode).
    prev_t4: Option<protocol::TimestampFormat>,
    /// Our transmit timestamp (T1) from the current (most recent sent) exchange.
    current_t1: Option<protocol::TimestampFormat>,
    /// Whether interleaved mode has been detected for this peer.
    interleaved: bool,
    /// If true, we have received DENY or RSTR and must stop polling.
    demobilized: bool,
}

impl PeerState {
    fn new(addr: SocketAddr, initial_poll: u8) -> Self {
        PeerState {
            addr,
            poll_exponent: initial_poll,
            reachability: 0,
            filter: SampleFilter::new(),
            stratum: None,
            prev_t1: None,
            prev_t4: None,
            current_t1: None,
            interleaved: false,
            demobilized: false,
        }
    }

    /// Get the current poll interval as a Duration.
    fn poll_interval(&self) -> Duration {
        Duration::from_secs(1u64 << self.poll_exponent)
    }

    /// Shift a 1 into the reachability register (successful response).
    fn reach_success(&mut self) {
        self.reachability = (self.reachability << 1) | 1;
    }

    /// Shift a 0 into the reachability register (timeout/failure).
    fn reach_failure(&mut self) {
        self.reachability <<= 1;
    }

    /// Increase poll interval. Clamps at max_poll.
    fn increase_poll(&mut self, max_poll: u8) {
        if self.poll_exponent < max_poll {
            self.poll_exponent += 1;
        }
    }

    /// Decrease poll interval. Clamps at min_poll.
    fn decrease_poll(&mut self, min_poll: u8) {
        if self.poll_exponent > min_poll {
            self.poll_exponent -= 1;
        }
    }

    /// Adjust poll interval based on current jitter and offset.
    fn adjust_poll(&mut self, min_poll: u8, max_poll: u8) {
        let jitter = self.filter.jitter();
        if let Some(best) = self.filter.best_sample() {
            // If offset is large or jitter is high, decrease poll interval.
            if best.offset.abs() > 0.128 || (best.delay > 0.0 && jitter > best.delay * 4.0) {
                self.decrease_poll(min_poll);
            } else if self.filter.len() >= 4 {
                // Conditions are stable and we have enough samples.
                self.increase_poll(max_poll);
            }
        }
    }

    /// Compute synchronization distance (used to select best peer).
    /// Lower is better.
    fn sync_distance(&self) -> f64 {
        match self.filter.best_sample() {
            Some(s) => s.delay.abs() / 2.0 + self.filter.jitter(),
            None => f64::MAX,
        }
    }
}

/// Classify a response as basic or interleaved mode and compute the clock sample.
///
/// This is a pure function (no I/O) for testability.
fn classify_and_compute(
    response: &protocol::Packet,
    t4: protocol::TimestampFormat,
    current_t1: protocol::TimestampFormat,
    prev_t1: Option<protocol::TimestampFormat>,
    prev_t4: Option<protocol::TimestampFormat>,
) -> io::Result<(ClockSample, bool)> {
    if response.origin_timestamp == current_t1 {
        // Basic mode: all timestamps from the same exchange.
        let t4_instant = unix_time::Instant::from(t4);
        let t1_instant = unix_time::timestamp_to_instant(current_t1, &t4_instant);
        let t2_instant =
            unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
        let t3_instant =
            unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);
        let (offset, delay) =
            compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);
        Ok((
            ClockSample {
                offset,
                delay,
                age: 0.0,
            },
            false,
        ))
    } else if let (Some(pt1), Some(pt4)) = (prev_t1, prev_t4) {
        if response.origin_timestamp == pt1 {
            // Interleaved mode: server returned more accurate timestamps
            // for the previous exchange.
            let t4_instant = unix_time::Instant::from(pt4);
            let t1_instant = unix_time::timestamp_to_instant(pt1, &t4_instant);
            let t2_instant =
                unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
            let t3_instant =
                unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);
            let (offset, delay) =
                compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);
            Ok((
                ClockSample {
                    offset,
                    delay,
                    age: 0.0,
                },
                true,
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "origin timestamp mismatch: neither basic nor interleaved",
            ))
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "origin timestamp mismatch: response does not match our request",
        ))
    }
}

/// Builder for configuring and creating an [`NtpClient`].
pub struct NtpClientBuilder {
    servers: Vec<String>,
    min_poll: u8,
    max_poll: u8,
    initial_poll: Option<u8>,
}

impl NtpClientBuilder {
    fn new() -> Self {
        NtpClientBuilder {
            servers: Vec::new(),
            min_poll: protocol::MINPOLL,
            max_poll: protocol::MAXPOLL,
            initial_poll: None,
        }
    }

    /// Add an NTP server address (hostname:port or ip:port).
    pub fn server(mut self, addr: impl Into<String>) -> Self {
        self.servers.push(addr.into());
        self
    }

    /// Set minimum poll exponent (default: MINPOLL=4, i.e. 16s).
    pub fn min_poll(mut self, exponent: u8) -> Self {
        self.min_poll = exponent.clamp(protocol::MINPOLL, protocol::MAXPOLL);
        self
    }

    /// Set maximum poll exponent (default: MAXPOLL=17, i.e. ~36h).
    pub fn max_poll(mut self, exponent: u8) -> Self {
        self.max_poll = exponent.clamp(protocol::MINPOLL, protocol::MAXPOLL);
        self
    }

    /// Set initial poll exponent. Defaults to min_poll.
    pub fn initial_poll(mut self, exponent: u8) -> Self {
        self.initial_poll = Some(exponent);
        self
    }

    /// Build the client. Performs async DNS resolution for all servers.
    ///
    /// Returns the client (to be spawned) and a watch receiver for state updates.
    pub async fn build(
        self,
    ) -> io::Result<(
        NtpClient,
        tokio::sync::watch::Receiver<NtpSyncState>,
    )> {
        if self.servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one server address is required",
            ));
        }

        let min_poll = self.min_poll;
        let max_poll = if self.max_poll >= self.min_poll {
            self.max_poll
        } else {
            self.min_poll
        };
        let initial_poll = self
            .initial_poll
            .unwrap_or(min_poll)
            .clamp(min_poll, max_poll);

        let mut peers = Vec::new();
        for server in &self.servers {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host(server.as_str()).await?.collect();
            if let Some(&addr) = addrs.first() {
                peers.push(PeerState::new(addr, initial_poll));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("address resolved to no socket addresses: {server}"),
                ));
            }
        }

        let (state_tx, state_rx) = tokio::sync::watch::channel(NtpSyncState::default());

        Ok((
            NtpClient {
                peers,
                state_tx,
                min_poll,
                max_poll,
                total_responses: 0,
            },
            state_rx,
        ))
    }
}

/// A continuous NTP client that polls servers at adaptive intervals.
///
/// Created via [`NtpClient::builder()`]. Call [`run()`](NtpClient::run) to start
/// the poll loop (typically via `tokio::spawn`).
pub struct NtpClient {
    peers: Vec<PeerState>,
    state_tx: tokio::sync::watch::Sender<NtpSyncState>,
    min_poll: u8,
    max_poll: u8,
    total_responses: u64,
}

impl NtpClient {
    /// Create a builder for configuring the client.
    pub fn builder() -> NtpClientBuilder {
        NtpClientBuilder::new()
    }

    /// Run the continuous poll loop. This future runs indefinitely.
    ///
    /// Each peer is polled independently at its own adaptive interval.
    /// The best peer's offset is published to the watch channel after
    /// each successful response.
    pub async fn run(mut self) {
        // Initialize all peers to poll immediately.
        let mut next_poll: Vec<tokio::time::Instant> = self
            .peers
            .iter()
            .map(|_| tokio::time::Instant::now())
            .collect();

        loop {
            // Find the peer with the earliest next poll time that isn't demobilized.
            let next = next_poll
                .iter()
                .enumerate()
                .filter(|(i, _)| !self.peers[*i].demobilized)
                .min_by_key(|(_, t)| *t);

            let (idx, &deadline) = match next {
                Some(n) => n,
                None => {
                    warn!("all peers demobilized, stopping poll loop");
                    return;
                }
            };

            // Sleep until the deadline.
            tokio::time::sleep_until(deadline).await;

            debug!(
                "polling peer {} (poll interval: {}s)",
                self.peers[idx].addr,
                1u64 << self.peers[idx].poll_exponent
            );

            // Poll the peer with a 5-second timeout.
            let result = Self::poll_peer(&mut self.peers[idx]).await;

            match result {
                Ok(PollResult::Sample(sample, interleaved)) => {
                    let peer = &mut self.peers[idx];
                    peer.reach_success();
                    peer.filter.add(sample.offset, sample.delay);
                    peer.interleaved = interleaved;
                    peer.adjust_poll(self.min_poll, self.max_poll);
                    self.total_responses += 1;
                    self.publish_best_state();
                    debug!(
                        "peer {}: offset={:.6}s delay={:.6}s interleaved={}",
                        self.peers[idx].addr, sample.offset, sample.delay, interleaved
                    );
                }
                Ok(PollResult::RateKissCode) => {
                    self.peers[idx].reach_success();
                    self.peers[idx].decrease_poll(self.min_poll);
                    warn!(
                        "peer {} sent RATE, reducing poll interval",
                        self.peers[idx].addr
                    );
                }
                Ok(PollResult::DenyKissCode) => {
                    self.peers[idx].demobilized = true;
                    warn!(
                        "peer {} sent DENY/RSTR, demobilizing",
                        self.peers[idx].addr
                    );
                }
                Err(e) => {
                    self.peers[idx].reach_failure();
                    debug!("peer {} poll failed: {}", self.peers[idx].addr, e);
                }
            }

            // Schedule next poll for this peer.
            next_poll[idx] =
                tokio::time::Instant::now() + self.peers[idx].poll_interval();
        }
    }

    /// Poll a single peer and return the result.
    async fn poll_peer(peer: &mut PeerState) -> io::Result<PollResult> {
        let bind_addr = crate::bind_addr_for(&peer.addr);
        let sock = UdpSocket::bind(bind_addr).await?;

        // Build request packet. Record T1.
        let (send_buf, t1) = build_request_packet()?;
        peer.current_t1 = Some(t1);

        let timeout = Duration::from_secs(5);

        // Send with timeout.
        tokio::time::timeout(timeout, sock.send_to(&send_buf, peer.addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP send timed out"))??;

        // Receive with timeout.
        let mut recv_buf = [0u8; 1024];
        let (recv_len, src_addr) =
            tokio::time::timeout(timeout, sock.recv_from(&mut recv_buf))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "NTP recv timed out")
                })??;

        // Parse and validate (without origin timestamp check).
        let parse_result =
            parse_and_validate_response(&recv_buf, recv_len, src_addr, &[peer.addr]);

        match parse_result {
            Err(e) => {
                // Check if this is a KoD error.
                if let Some(kod) = e
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<KissOfDeathError>())
                {
                    return match kod.code {
                        protocol::KissOfDeath::Rate => Ok(PollResult::RateKissCode),
                        protocol::KissOfDeath::Deny | protocol::KissOfDeath::Rstr => {
                            Ok(PollResult::DenyKissCode)
                        }
                    };
                }
                Err(e)
            }
            Ok((response, t4)) => {
                // Update stratum from response.
                peer.stratum = Some(response.stratum);

                // Classify as basic or interleaved and compute sample.
                let (sample, interleaved) = classify_and_compute(
                    &response,
                    t4,
                    t1,
                    peer.prev_t1,
                    peer.prev_t4,
                )?;

                // Rotate timestamps for next exchange.
                peer.prev_t1 = peer.current_t1;
                peer.prev_t4 = Some(t4);

                Ok(PollResult::Sample(sample, interleaved))
            }
        }
    }

    /// Select the best peer and publish its state to the watch channel.
    fn publish_best_state(&self) {
        let best = self
            .peers
            .iter()
            .filter(|p| !p.demobilized && p.filter.best_sample().is_some())
            .min_by(|a, b| {
                a.sync_distance()
                    .partial_cmp(&b.sync_distance())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        if let Some(peer) = best
            && let Some(sample) = peer.filter.best_sample()
        {
            let state = NtpSyncState {
                offset: sample.offset,
                delay: sample.delay,
                jitter: peer.filter.jitter(),
                stratum: peer.stratum.map_or(protocol::MAXSTRAT, |s| s.0),
                interleaved: peer.interleaved,
                last_update: std::time::Instant::now(),
                total_responses: self.total_responses,
            };
            // Ignore send errors (no receivers).
            let _ = self.state_tx.send(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_state_poll_interval() {
        let peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        assert_eq!(peer.poll_interval(), Duration::from_secs(16));
    }

    #[test]
    fn test_peer_state_increase_poll() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MAXPOLL);
        peer.increase_poll(protocol::MAXPOLL);
        assert_eq!(peer.poll_exponent, protocol::MAXPOLL);
    }

    #[test]
    fn test_peer_state_decrease_poll() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        peer.decrease_poll(protocol::MINPOLL);
        assert_eq!(peer.poll_exponent, protocol::MINPOLL);
    }

    #[test]
    fn test_reachability_register() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        assert_eq!(peer.reachability, 0);

        peer.reach_success();
        assert_eq!(peer.reachability, 0b0000_0001);

        peer.reach_success();
        assert_eq!(peer.reachability, 0b0000_0011);

        peer.reach_failure();
        assert_eq!(peer.reachability, 0b0000_0110);

        // After 8 failures, register should be zero.
        for _ in 0..8 {
            peer.reach_failure();
        }
        assert_eq!(peer.reachability, 0);
    }

    #[test]
    fn test_classify_basic_mode() {
        let t1 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = protocol::Packet {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            version: protocol::Version::V4,
            mode: protocol::Mode::Server,
            stratum: protocol::Stratum(2),
            poll: 6,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: t1, // Matches current T1 = basic mode
            receive_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 500_000_000,
            },
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 500_000_001,
            },
        };

        let (sample, interleaved) =
            classify_and_compute(&response, t4, t1, None, None).unwrap();
        assert!(!interleaved);
        // Offset and delay should be finite values.
        assert!(sample.offset.is_finite());
        assert!(sample.delay.is_finite());
    }

    #[test]
    fn test_classify_interleaved_mode() {
        let prev_t1 = protocol::TimestampFormat {
            seconds: 3_913_055_990,
            fraction: 0,
        };
        let prev_t4 = protocol::TimestampFormat {
            seconds: 3_913_055_991,
            fraction: 0,
        };
        let current_t1 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = protocol::Packet {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            version: protocol::Version::V4,
            mode: protocol::Mode::Server,
            stratum: protocol::Stratum(2),
            poll: 6,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: prev_t1, // Matches previous T1 = interleaved mode
            receive_timestamp: protocol::TimestampFormat {
                seconds: 3_913_055_990,
                fraction: 500_000_000,
            },
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 3_913_055_990,
                fraction: 500_000_001,
            },
        };

        let (sample, interleaved) = classify_and_compute(
            &response,
            t4,
            current_t1,
            Some(prev_t1),
            Some(prev_t4),
        )
        .unwrap();
        assert!(interleaved);
        assert!(sample.offset.is_finite());
        assert!(sample.delay.is_finite());
    }

    #[test]
    fn test_classify_mismatch_rejected() {
        let t1 = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0,
        };
        let response = protocol::Packet {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            version: protocol::Version::V4,
            mode: protocol::Mode::Server,
            stratum: protocol::Stratum(2),
            poll: 6,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::SecondaryOrClient([127, 0, 0, 1]),
            reference_timestamp: protocol::TimestampFormat::default(),
            origin_timestamp: protocol::TimestampFormat {
                seconds: 999_999_999, // Matches nothing
                fraction: 0,
            },
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 1,
                fraction: 0,
            },
        };

        let result = classify_and_compute(&response, t4, t1, None, None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_rejects_empty_servers() {
        let result = NtpClient::builder().build().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_adjust_poll_large_offset() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), 10);
        // Add samples with large offset.
        peer.filter.add(0.5, 0.050); // 500ms offset >> 128ms threshold
        peer.filter.add(0.5, 0.060);
        peer.filter.add(0.5, 0.070);
        peer.filter.add(0.5, 0.080);
        peer.adjust_poll(protocol::MINPOLL, protocol::MAXPOLL);
        assert!(peer.poll_exponent < 10); // Should have decreased
    }

    #[test]
    fn test_adjust_poll_stable() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), 6);
        // Add samples with small, stable offset.
        for i in 0..4 {
            peer.filter.add(0.001 + i as f64 * 0.0001, 0.050);
        }
        peer.adjust_poll(protocol::MINPOLL, protocol::MAXPOLL);
        assert!(peer.poll_exponent > 6); // Should have increased
    }
}
