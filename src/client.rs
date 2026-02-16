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
//!     .server("time.nist.gov:123")
//!     .server("time-a-g.nist.gov:123")
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

pub use crate::client_common::NtpSyncState;
use crate::client_common::classify_and_compute;
use crate::filter::{ClockSample, SampleFilter};
use crate::{KissOfDeathError, build_request_packet, parse_and_validate_response, protocol};

#[cfg(feature = "nts")]
use crate::nts;
#[cfg(feature = "nts")]
use crate::nts_common;

/// Result of polling a single peer.
enum PollResult {
    /// Successful basic-mode exchange.
    Sample(ClockSample, bool /* interleaved */),
    /// Server sent RATE kiss code.
    RateKissCode,
    /// Server sent DENY or RSTR kiss code.
    DenyKissCode,
}

/// NTS-specific state for a peer, separated to avoid borrow checker issues.
#[cfg(feature = "nts")]
struct NtsPeerState {
    /// Client-to-server AEAD key.
    c2s_key: Vec<u8>,
    /// Server-to-client AEAD key.
    s2c_key: Vec<u8>,
    /// Cookies for NTP requests (each used exactly once).
    cookies: Vec<Vec<u8>>,
    /// Negotiated AEAD algorithm ID.
    aead_algorithm: u16,
    /// NTS-KE server hostname for re-keying when cookies run low.
    nts_ke_server: String,
    /// Cookie length from initial NTS-KE (for placeholder sizing).
    cookie_len: usize,
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
    /// NTS state, present only for NTS-authenticated peers.
    #[cfg(feature = "nts")]
    nts_state: Option<NtsPeerState>,
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
            #[cfg(feature = "nts")]
            nts_state: None,
        }
    }

    /// Create a peer with NTS state from a completed NTS-KE exchange.
    #[cfg(feature = "nts")]
    fn new_nts(
        addr: SocketAddr,
        initial_poll: u8,
        ke: nts::NtsKeResult,
        nts_ke_server: String,
    ) -> Self {
        let cookie_len = ke.cookies.first().map_or(0, |c| c.len());
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
            nts_state: Some(NtsPeerState {
                c2s_key: ke.c2s_key,
                s2c_key: ke.s2c_key,
                cookies: ke.cookies,
                aead_algorithm: ke.aead_algorithm,
                nts_ke_server,
                cookie_len,
            }),
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
/// Builder for configuring and creating an [`NtpClient`].
pub struct NtpClientBuilder {
    servers: Vec<String>,
    #[cfg(feature = "nts")]
    nts_servers: Vec<String>,
    min_poll: u8,
    max_poll: u8,
    initial_poll: Option<u8>,
}

impl NtpClientBuilder {
    fn new() -> Self {
        NtpClientBuilder {
            servers: Vec::new(),
            #[cfg(feature = "nts")]
            nts_servers: Vec::new(),
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

    /// Add an NTS server hostname.
    ///
    /// Performs NTS Key Establishment during [`build()`](NtpClientBuilder::build)
    /// and uses authenticated NTP requests for this peer.
    #[cfg(feature = "nts")]
    pub fn nts_server(mut self, hostname: impl Into<String>) -> Self {
        self.nts_servers.push(hostname.into());
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
    ) -> io::Result<(NtpClient, tokio::sync::watch::Receiver<NtpSyncState>)> {
        #[cfg(feature = "nts")]
        let has_nts = !self.nts_servers.is_empty();
        #[cfg(not(feature = "nts"))]
        let has_nts = false;

        if self.servers.is_empty() && !has_nts {
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
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(server.as_str()).await?.collect();
            if let Some(&addr) = addrs.first() {
                peers.push(PeerState::new(addr, initial_poll));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("address resolved to no socket addresses: {server}"),
                ));
            }
        }

        // Perform NTS-KE for each NTS server and create NTS peers.
        #[cfg(feature = "nts")]
        for nts_server in &self.nts_servers {
            let ke = nts::nts_ke(nts_server).await?;
            let addr_str = format!("{}:{}", ke.ntp_server, ke.ntp_port);
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host(addr_str.as_str()).await?.collect();
            if let Some(&addr) = addrs.first() {
                peers.push(PeerState::new_nts(
                    addr,
                    initial_poll,
                    ke,
                    nts_server.clone(),
                ));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "NTS NTP server resolved to no socket addresses: {}",
                        nts_server
                    ),
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
                    warn!("peer {} sent DENY/RSTR, demobilizing", self.peers[idx].addr);
                }
                Err(e) => {
                    self.peers[idx].reach_failure();
                    debug!("peer {} poll failed: {}", self.peers[idx].addr, e);
                }
            }

            // Schedule next poll for this peer.
            next_poll[idx] = tokio::time::Instant::now() + self.peers[idx].poll_interval();
        }
    }

    /// Poll a single peer and return the result.
    async fn poll_peer(peer: &mut PeerState) -> io::Result<PollResult> {
        // Dispatch to NTS poll path if this peer has NTS state.
        #[cfg(feature = "nts")]
        if peer.nts_state.is_some() {
            let mut nts = peer.nts_state.take().unwrap();
            let result = Self::poll_peer_nts(peer, &mut nts).await;
            peer.nts_state = Some(nts);
            return result;
        }

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
        let (recv_len, src_addr) = tokio::time::timeout(timeout, sock.recv_from(&mut recv_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP recv timed out"))??;

        // Parse and validate (without origin timestamp check).
        let parse_result = parse_and_validate_response(&recv_buf, recv_len, src_addr, &[peer.addr]);

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
                let (sample, interleaved) =
                    classify_and_compute(&response, t4, t1, peer.prev_t1, peer.prev_t4)?;

                // Rotate timestamps for next exchange.
                peer.prev_t1 = peer.current_t1;
                peer.prev_t4 = Some(t4);

                Ok(PollResult::Sample(sample, interleaved))
            }
        }
    }

    /// Poll a single NTS-authenticated peer and return the result.
    #[cfg(feature = "nts")]
    async fn poll_peer_nts(
        peer: &mut PeerState,
        nts_state: &mut NtsPeerState,
    ) -> io::Result<PollResult> {
        // Replenish cookies if running low.
        if nts_state.cookies.len() <= nts_common::COOKIE_REKEY_THRESHOLD {
            debug!(
                "peer {}: {} cookies remaining, attempting NTS-KE re-key",
                peer.addr,
                nts_state.cookies.len()
            );
            match nts::nts_ke(&nts_state.nts_ke_server).await {
                Ok(ke) => {
                    nts_state.c2s_key = ke.c2s_key;
                    nts_state.s2c_key = ke.s2c_key;
                    nts_state.cookies = ke.cookies;
                    nts_state.aead_algorithm = ke.aead_algorithm;
                    nts_state.cookie_len = nts_state.cookies.first().map_or(0, |c| c.len());
                    debug!(
                        "peer {}: NTS-KE re-key successful, {} cookies",
                        peer.addr,
                        nts_state.cookies.len()
                    );
                }
                Err(e) => {
                    warn!("peer {}: NTS-KE re-key failed: {}", peer.addr, e);
                    // Continue with remaining cookies; will error at zero.
                }
            }
        }

        // Pop a cookie.
        let cookie = nts_state
            .cookies
            .pop()
            .ok_or_else(|| io::Error::other("no NTS cookies remaining"))?;

        // Build NTS-authenticated request packet.
        let (send_buf, t1, uid_data) =
            nts_common::build_nts_request(&nts_state.c2s_key, nts_state.aead_algorithm, cookie)?;
        peer.current_t1 = Some(t1);

        let bind_addr = crate::bind_addr_for(&peer.addr);
        let sock = UdpSocket::bind(bind_addr).await?;
        let timeout = Duration::from_secs(5);

        // Send with timeout.
        tokio::time::timeout(timeout, sock.send_to(&send_buf, peer.addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP send timed out"))??;

        // Receive with timeout (larger buffer for NTS extension fields).
        let mut recv_buf = [0u8; 2048];
        let (recv_len, src_addr) = tokio::time::timeout(timeout, sock.recv_from(&mut recv_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP recv timed out"))??;

        // Parse and validate the NTP header.
        let parse_result = parse_and_validate_response(&recv_buf, recv_len, src_addr, &[peer.addr]);

        match parse_result {
            Err(e) => {
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
                // Validate NTS extension fields and extract new cookies.
                let new_cookies = nts_common::validate_nts_response(
                    &nts_state.s2c_key,
                    nts_state.aead_algorithm,
                    &uid_data,
                    &recv_buf,
                    recv_len,
                )?;
                nts_state.cookies.extend(new_cookies);

                // Update stratum.
                peer.stratum = Some(response.stratum);

                // Classify as basic or interleaved and compute sample.
                let (sample, interleaved) =
                    classify_and_compute(&response, t4, t1, peer.prev_t1, peer.prev_t4)?;

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
            #[cfg(feature = "nts")]
            let nts_authenticated = peer.nts_state.is_some();
            #[cfg(not(feature = "nts"))]
            let nts_authenticated = false;

            let state = NtpSyncState {
                offset: sample.offset,
                delay: sample.delay,
                jitter: peer.filter.jitter(),
                stratum: peer.stratum.map_or(protocol::MAXSTRAT, |s| s.0),
                interleaved: peer.interleaved,
                last_update: std::time::Instant::now(),
                total_responses: self.total_responses,
                nts_authenticated,
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

    #[tokio::test]
    async fn test_builder_rejects_empty_servers() {
        let result = NtpClient::builder().build().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_reachability_max_then_overflow() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        for _ in 0..8 {
            peer.reach_success();
        }
        assert_eq!(peer.reachability, 0xFF);
        peer.reach_success();
        assert_eq!(peer.reachability, 0xFF); // Still all 1s
    }

    #[test]
    fn test_reachability_alternating() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        peer.reach_success(); // 0b0000_0001
        peer.reach_failure(); // 0b0000_0010
        peer.reach_success(); // 0b0000_0101
        peer.reach_failure(); // 0b0000_1010
        assert_eq!(peer.reachability, 0b0000_1010);
    }

    #[test]
    fn test_increase_poll_normal() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), 8);
        peer.increase_poll(protocol::MAXPOLL);
        assert_eq!(peer.poll_exponent, 9);
    }

    #[test]
    fn test_decrease_poll_normal() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), 8);
        peer.decrease_poll(protocol::MINPOLL);
        assert_eq!(peer.poll_exponent, 7);
    }

    #[test]
    fn test_sync_distance_no_samples() {
        let peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        assert_eq!(peer.sync_distance(), f64::MAX);
    }

    #[test]
    fn test_sync_distance_with_samples() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        peer.filter.add(0.001, 0.100);
        let dist = peer.sync_distance();
        assert!(dist > 0.0);
        assert!(dist < f64::MAX);
    }

    #[test]
    fn test_poll_interval_various_exponents() {
        for exp in protocol::MINPOLL..=protocol::MAXPOLL {
            let peer = PeerState::new("127.0.0.1:123".parse().unwrap(), exp);
            let expected = Duration::from_secs(1u64 << exp);
            assert_eq!(peer.poll_interval(), expected);
        }
    }

    #[test]
    fn test_adjust_poll_no_samples() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), 6);
        let original = peer.poll_exponent;
        peer.adjust_poll(protocol::MINPOLL, protocol::MAXPOLL);
        assert_eq!(peer.poll_exponent, original);
    }

    #[test]
    fn test_adjust_poll_large_offset() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), 10);
        peer.filter.add(0.5, 0.050);
        peer.filter.add(0.5, 0.060);
        peer.filter.add(0.5, 0.070);
        peer.filter.add(0.5, 0.080);
        peer.adjust_poll(protocol::MINPOLL, protocol::MAXPOLL);
        assert!(peer.poll_exponent < 10);
    }

    #[test]
    fn test_adjust_poll_stable() {
        let mut peer = PeerState::new("127.0.0.1:123".parse().unwrap(), 6);
        for i in 0..4 {
            peer.filter.add(0.001 + i as f64 * 0.0001, 0.050);
        }
        peer.adjust_poll(protocol::MINPOLL, protocol::MAXPOLL);
        assert!(peer.poll_exponent > 6);
    }
}
