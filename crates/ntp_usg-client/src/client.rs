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
//! let (client, state_rx) = ntp_client::client::NtpClient::builder()
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

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

pub use crate::client_common::NtpSyncState;
use crate::client_common::{PeerState, PollResult, check_kod, select_and_build_state};
use crate::request::{bind_addr_for, build_request_packet, parse_and_validate_response};

#[cfg(feature = "nts")]
use crate::client_common::NtsPeerState;
#[cfg(feature = "nts")]
use crate::nts;
#[cfg(feature = "nts")]
use crate::nts_common;

#[cfg(feature = "ntpv5")]
use crate::client_common::NtpV5PeerState;

// Generate the shared NtpClientBuilder struct and config methods.
crate::client_common::define_client_builder! {
    /// Builder for configuring and creating an [`NtpClient`].
    extra_fields {
        #[cfg(feature = "nts")]
        nts_servers: Vec<String>,
    }
    extra_defaults {
        #[cfg(feature = "nts")]
        nts_servers: Vec::new(),
    }
}

impl NtpClientBuilder {
    /// Add an NTS server hostname.
    ///
    /// Performs NTS Key Establishment during [`build()`](NtpClientBuilder::build)
    /// and uses authenticated NTP requests for this peer.
    #[cfg(feature = "nts")]
    pub fn nts_server(mut self, hostname: impl Into<String>) -> Self {
        self.nts_servers.push(hostname.into());
        self
    }

    /// Build the client. Performs async DNS resolution for all servers.
    ///
    /// Returns the client (to be spawned) and a watch receiver for state updates.
    pub async fn build(
        self,
    ) -> io::Result<(NtpClient, tokio::sync::watch::Receiver<NtpSyncState>)> {
        #[cfg(feature = "nts")]
        let nts_servers = self.nts_servers.clone();
        #[cfg(feature = "nts")]
        let has_nts = !nts_servers.is_empty();
        #[cfg(not(feature = "nts"))]
        let has_nts = false;

        let cfg = self.into_config();

        if cfg.servers.is_empty() && !has_nts {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one server address is required",
            ));
        }

        let mut peers = Vec::new();
        for server in &cfg.servers {
            let addrs: Vec<SocketAddr> = crate::request::prefer_addresses(
                tokio::net::lookup_host(server.as_str()).await?.collect(),
            );
            if let Some(&addr) = addrs.first() {
                #[cfg(feature = "ntpv5")]
                let peer = if cfg.enable_ntpv5 {
                    PeerState::new_v5(addr, cfg.initial_poll)
                } else {
                    PeerState::new(addr, cfg.initial_poll)
                };
                #[cfg(not(feature = "ntpv5"))]
                let peer = PeerState::new(addr, cfg.initial_poll);
                peers.push(peer);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("address resolved to no socket addresses: {server}"),
                ));
            }
        }

        // Perform NTS-KE for each NTS server and create NTS peers.
        #[cfg(feature = "nts")]
        for nts_server in &nts_servers {
            let ke = nts::nts_ke(nts_server).await?;
            let addr_str = format!("{}:{}", ke.ntp_server, ke.ntp_port);
            let addrs: Vec<SocketAddr> = crate::request::prefer_addresses(
                tokio::net::lookup_host(addr_str.as_str()).await?.collect(),
            );
            if let Some(&addr) = addrs.first() {
                peers.push(PeerState::new_nts(
                    addr,
                    cfg.initial_poll,
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
                min_poll: cfg.min_poll,
                max_poll: cfg.max_poll,
                total_responses: 0,
                socket_opts: cfg.socket_opts,
                #[cfg(feature = "discipline")]
                discipline: if cfg.enable_discipline {
                    Some(crate::discipline::ClockDiscipline::new())
                } else {
                    None
                },
                #[cfg(feature = "discipline")]
                adjuster: if cfg.enable_discipline {
                    Some(crate::clock_adjust::ClockAdjuster::new())
                } else {
                    None
                },
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
    socket_opts: crate::socket_opts::SocketOptions,
    /// Clock discipline loop (PLL/FLL) per RFC 5905 Section 11.3.
    #[cfg(feature = "discipline")]
    discipline: Option<crate::discipline::ClockDiscipline>,
    /// Periodic clock adjuster per RFC 5905 Section 12.
    #[cfg(feature = "discipline")]
    adjuster: Option<crate::clock_adjust::ClockAdjuster>,
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
        debug!("NTP client starting with {} peers", self.peers.len());
        // Initialize all peers to poll immediately.
        let mut next_poll: Vec<tokio::time::Instant> = self
            .peers
            .iter()
            .map(|_| tokio::time::Instant::now())
            .collect();

        // Monotonic epoch for the discipline loop.
        #[cfg(feature = "discipline")]
        let discipline_epoch = std::time::Instant::now();

        // Track time for the 1-second adjuster tick.
        #[cfg(feature = "discipline")]
        let mut last_adjust_tick = std::time::Instant::now();

        loop {
            // Run any pending adjuster ticks before the next poll.
            #[cfg(feature = "discipline")]
            if let Some(adjuster) = &mut self.adjuster {
                let now = std::time::Instant::now();
                while now.duration_since(last_adjust_tick) >= Duration::from_secs(1) {
                    last_adjust_tick += Duration::from_secs(1);
                    let adj = adjuster.tick();
                    if adj.abs() > 1e-15
                        && let Err(e) = crate::clock::slew_clock(adj)
                    {
                        debug!("adjuster: slew_clock failed: {}", e);
                    }
                }
            }

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

            // Sleep until the next poll deadline, but wake up for adjuster ticks.
            #[cfg(feature = "discipline")]
            {
                let sleep_until = if self.adjuster.is_some() {
                    // Wake up at most 1 second from the last tick.
                    let next_tick = last_adjust_tick + Duration::from_secs(1);
                    let next_tick_tokio = tokio::time::Instant::now()
                        + next_tick.saturating_duration_since(std::time::Instant::now());
                    deadline.min(next_tick_tokio)
                } else {
                    deadline
                };
                tokio::time::sleep_until(sleep_until).await;
                // If we woke for the adjuster tick but not the poll, loop back.
                if tokio::time::Instant::now() < deadline {
                    continue;
                }
            }

            #[cfg(not(feature = "discipline"))]
            tokio::time::sleep_until(deadline).await;

            debug!(
                peer = %self.peers[idx].addr,
                poll_interval_s = 1u64 << self.peers[idx].poll_exponent,
                "polling peer"
            );

            // Poll the peer with a 5-second timeout.
            let result = Self::poll_peer(&mut self.peers[idx], &self.socket_opts).await;

            match result {
                Ok(PollResult::Sample(sample, interleaved)) => {
                    let peer = &mut self.peers[idx];
                    peer.reach_success();
                    peer.filter.add(sample.offset, sample.delay);
                    peer.interleaved = interleaved;
                    peer.adjust_poll(self.min_poll, self.max_poll);
                    self.total_responses += 1;

                    let _estimate = self.publish_best_state();

                    // Feed the discipline loop if enabled.
                    #[cfg(feature = "discipline")]
                    if let (Some(discipline), Some(adjuster), Some((offset, jitter))) =
                        (&mut self.discipline, &mut self.adjuster, _estimate)
                    {
                        let now = std::time::Instant::now()
                            .duration_since(discipline_epoch)
                            .as_secs_f64();
                        if let Some(output) =
                            discipline.update(offset, jitter, now, self.peers[idx].poll_exponent)
                        {
                            if output.step {
                                debug!(
                                    "discipline: stepping clock by {:.6}s",
                                    output.phase_correction
                                );
                                if let Err(e) = crate::clock::step_clock(output.phase_correction) {
                                    warn!("discipline: step_clock failed: {}", e);
                                }
                            } else {
                                adjuster.set_correction(
                                    output.phase_correction,
                                    output.frequency_correction,
                                );
                            }
                        }
                    }

                    debug!(
                        peer = %self.peers[idx].addr,
                        offset = sample.offset,
                        delay = sample.delay,
                        interleaved,
                        "peer sample received"
                    );
                }
                Ok(PollResult::RateKissCode) => {
                    self.peers[idx].reach_success();
                    self.peers[idx].decrease_poll(self.min_poll);
                    warn!(peer = %self.peers[idx].addr, "peer sent RATE, reducing poll interval");
                }
                Ok(PollResult::DenyKissCode) => {
                    self.peers[idx].demobilized = true;
                    warn!(peer = %self.peers[idx].addr, "peer sent DENY/RSTR, demobilizing");
                }
                Err(e) => {
                    self.peers[idx].reach_failure();
                    debug!(peer = %self.peers[idx].addr, error = %e, "peer poll failed");
                }
            }

            // Schedule next poll for this peer.
            next_poll[idx] = tokio::time::Instant::now() + self.peers[idx].poll_interval();
        }
    }

    /// Poll a single peer and return the result.
    async fn poll_peer(
        peer: &mut PeerState,
        socket_opts: &crate::socket_opts::SocketOptions,
    ) -> io::Result<PollResult> {
        // Dispatch to NTS poll path if this peer has NTS state.
        #[cfg(feature = "nts")]
        if peer.nts_state.is_some() {
            let mut nts = peer.nts_state.take().unwrap();
            let result = Self::poll_peer_nts(peer, &mut nts, socket_opts).await;
            peer.nts_state = Some(nts);
            return result;
        }

        // Dispatch to NTPv5 poll path if this peer has V5 state.
        #[cfg(feature = "ntpv5")]
        if peer.v5_state.is_some() {
            let mut v5 = peer.v5_state.take().unwrap();
            let result = Self::poll_peer_v5(peer, &mut v5, socket_opts).await;
            peer.v5_state = Some(v5);
            return result;
        }

        #[cfg(feature = "socket-opts")]
        let sock = {
            let bind_addr = bind_addr_for(&peer.addr);
            let std_sock = socket_opts.bind_udp(bind_addr)?;
            UdpSocket::from_std(std_sock)?
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = socket_opts;
            UdpSocket::bind(bind_addr_for(&peer.addr)).await?
        };

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
            Err(e) => match check_kod(&e) {
                Some(poll_result) => Ok(poll_result),
                None => Err(e),
            },
            Ok((response, t4)) => peer.process_response(&response, t4, t1),
        }
    }

    /// Poll a single NTS-authenticated peer and return the result.
    #[cfg(feature = "nts")]
    async fn poll_peer_nts(
        peer: &mut PeerState,
        nts_state: &mut NtsPeerState,
        socket_opts: &crate::socket_opts::SocketOptions,
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

        #[cfg(feature = "socket-opts")]
        let sock = {
            let bind_addr = bind_addr_for(&peer.addr);
            let std_sock = socket_opts.bind_udp(bind_addr)?;
            UdpSocket::from_std(std_sock)?
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = socket_opts;
            UdpSocket::bind(bind_addr_for(&peer.addr)).await?
        };
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
            Err(e) => match check_kod(&e) {
                Some(poll_result) => Ok(poll_result),
                None => Err(e),
            },
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

                peer.process_response(&response, t4, t1)
            }
        }
    }

    /// Poll a single NTPv5 peer through the version negotiation state machine.
    #[cfg(feature = "ntpv5")]
    async fn poll_peer_v5(
        peer: &mut PeerState,
        v5_state: &mut NtpV5PeerState,
        socket_opts: &crate::socket_opts::SocketOptions,
    ) -> io::Result<PollResult> {
        use crate::request::{
            build_v4_negotiation_packet, build_v5_request_packet, parse_and_validate_v5_response,
            response_has_negotiation_magic,
        };
        use ntp_proto::ntpv5_ext::RefIdsResponse;
        use ntp_proto::protocol::bloom::BloomFilter;
        use ntp_proto::protocol::ntpv5::Timescale;

        match v5_state {
            NtpV5PeerState::Negotiating { attempts } => {
                // Send V4 packet with negotiation magic.
                let (send_buf, t1) = build_v4_negotiation_packet()?;
                peer.current_t1 = Some(t1);
                *attempts += 1;

                #[cfg(feature = "socket-opts")]
                let sock = {
                    let bind_addr = bind_addr_for(&peer.addr);
                    let std_sock = socket_opts.bind_udp(bind_addr)?;
                    UdpSocket::from_std(std_sock)?
                };
                #[cfg(not(feature = "socket-opts"))]
                let sock = {
                    let _ = socket_opts;
                    UdpSocket::bind(bind_addr_for(&peer.addr)).await?
                };

                let timeout = Duration::from_secs(5);
                tokio::time::timeout(timeout, sock.send_to(&send_buf, peer.addr))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP send timed out"))??;

                let mut recv_buf = [0u8; 1024];
                let (recv_len, src_addr) =
                    tokio::time::timeout(timeout, sock.recv_from(&mut recv_buf))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "NTP recv timed out")
                        })??;

                let parse_result =
                    parse_and_validate_response(&recv_buf, recv_len, src_addr, &[peer.addr]);

                match parse_result {
                    Err(e) => match check_kod(&e) {
                        Some(poll_result) => Ok(poll_result),
                        None => {
                            // After 3 failed attempts, fall back to V4.
                            if *attempts >= 3 {
                                debug!(
                                    "peer {}: V5 negotiation failed after {} attempts, falling back to V4",
                                    peer.addr, attempts
                                );
                                *v5_state = NtpV5PeerState::V4Only {
                                    exchanges_since_probe: 0,
                                };
                            }
                            Err(e)
                        }
                    },
                    Ok((response, t4)) => {
                        if response_has_negotiation_magic(&response) {
                            debug!(
                                "peer {}: server echoed V5 negotiation magic, transitioning to V5",
                                peer.addr
                            );
                            *v5_state = NtpV5PeerState::V5Active {
                                bloom_filter: Box::new(BloomFilter::new()),
                                bloom_complete: false,
                                bloom_offset: 0,
                                server_cookie: 0,
                                current_client_cookie: 0,
                                prev_client_cookie: 0,
                                timescale: Timescale::Utc,
                            };
                        } else if *attempts >= 3 {
                            debug!(
                                "peer {}: no V5 magic after {} attempts, staying on V4",
                                peer.addr, attempts
                            );
                            *v5_state = NtpV5PeerState::V4Only {
                                exchanges_since_probe: 0,
                            };
                        }
                        // Process the V4 response normally.
                        peer.process_response(&response, t4, t1)
                    }
                }
            }

            NtpV5PeerState::V5Active {
                bloom_filter,
                bloom_complete,
                bloom_offset,
                server_cookie,
                current_client_cookie,
                prev_client_cookie,
                timescale,
            } => {
                // Build V5 request.
                let bloom_req = if !*bloom_complete {
                    Some(*bloom_offset)
                } else {
                    None
                };
                let (send_buf, client_cookie) =
                    build_v5_request_packet(*timescale, *server_cookie, bloom_req)?;

                // Record T1 for offset computation.
                peer.current_t1 = Some(crate::unix_time::Instant::now().into());
                *prev_client_cookie = *current_client_cookie;
                *current_client_cookie = client_cookie;

                #[cfg(feature = "socket-opts")]
                let sock = {
                    let bind_addr = bind_addr_for(&peer.addr);
                    let std_sock = socket_opts.bind_udp(bind_addr)?;
                    UdpSocket::from_std(std_sock)?
                };
                #[cfg(not(feature = "socket-opts"))]
                let sock = {
                    let _ = socket_opts;
                    UdpSocket::bind(bind_addr_for(&peer.addr)).await?
                };

                let timeout = Duration::from_secs(5);
                tokio::time::timeout(timeout, sock.send_to(&send_buf, peer.addr))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP send timed out"))??;

                let mut recv_buf = [0u8; 2048];
                let (recv_len, src_addr) =
                    tokio::time::timeout(timeout, sock.recv_from(&mut recv_buf))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "NTP recv timed out")
                        })??;

                let (response, t4, ext_fields) = parse_and_validate_v5_response(
                    &recv_buf,
                    recv_len,
                    src_addr,
                    &[peer.addr],
                    client_cookie,
                )?;

                // Process Bloom filter chunks from extension fields.
                for ef in &ext_fields {
                    if let Some(resp) = RefIdsResponse::from_extension_field(ef) {
                        bloom_filter.set_chunk(*bloom_offset, &resp.data);
                        *bloom_offset += resp.data.len() as u16;
                        if *bloom_offset >= 512 {
                            *bloom_complete = true;
                        }
                    }
                }

                // Update server cookie.
                *server_cookie = response.server_cookie;

                peer.process_response_v5(&response, t4, client_cookie)
            }

            NtpV5PeerState::V4Only {
                exchanges_since_probe,
            } => {
                // Normal V4 path.
                #[cfg(feature = "socket-opts")]
                let sock = {
                    let bind_addr = bind_addr_for(&peer.addr);
                    let std_sock = socket_opts.bind_udp(bind_addr)?;
                    UdpSocket::from_std(std_sock)?
                };
                #[cfg(not(feature = "socket-opts"))]
                let sock = {
                    let _ = socket_opts;
                    UdpSocket::bind(bind_addr_for(&peer.addr)).await?
                };

                let (send_buf, t1) = build_request_packet()?;
                peer.current_t1 = Some(t1);

                let timeout = Duration::from_secs(5);
                tokio::time::timeout(timeout, sock.send_to(&send_buf, peer.addr))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "NTP send timed out"))??;

                let mut recv_buf = [0u8; 1024];
                let (recv_len, src_addr) =
                    tokio::time::timeout(timeout, sock.recv_from(&mut recv_buf))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "NTP recv timed out")
                        })??;

                let parse_result =
                    parse_and_validate_response(&recv_buf, recv_len, src_addr, &[peer.addr]);

                *exchanges_since_probe += 1;

                // Re-probe for V5 every 256 exchanges.
                if *exchanges_since_probe >= 256 {
                    debug!(
                        "peer {}: re-probing for V5 after {} V4 exchanges",
                        peer.addr, exchanges_since_probe
                    );
                    *v5_state = NtpV5PeerState::Negotiating { attempts: 0 };
                }

                match parse_result {
                    Err(e) => match check_kod(&e) {
                        Some(poll_result) => Ok(poll_result),
                        None => Err(e),
                    },
                    Ok((response, t4)) => peer.process_response(&response, t4, t1),
                }
            }
        }
    }

    /// Select the best peer(s) using the RFC 5905 Section 11.2 selection,
    /// clustering, and combining pipeline, then publish the system state.
    ///
    /// Returns `Some((offset, jitter))` if a valid system estimate was
    /// produced, for feeding to the clock discipline loop.
    fn publish_best_state(&mut self) -> Option<(f64, f64)> {
        #[cfg(feature = "discipline")]
        let (frequency, discipline_state) = match &self.discipline {
            Some(d) => (d.frequency(), Some(d.state())),
            None => (0.0, None),
        };
        #[cfg(not(feature = "discipline"))]
        let (frequency, discipline_state) = (0.0, None);

        let result = select_and_build_state(
            &mut self.peers,
            self.total_responses,
            frequency,
            discipline_state,
        )?;

        // Ignore send errors (no receivers).
        let _ = self.state_tx.send(result.state);
        Some((result.offset, result.jitter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_builder_rejects_empty_servers() {
        let result = NtpClient::builder().build().await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected error for empty servers"),
        };
        assert!(err.to_string().contains("at least one server"));
    }

    #[test]
    fn test_builder_defaults() {
        let builder = NtpClient::builder();
        assert!(builder.servers.is_empty());
        assert_eq!(builder.min_poll, crate::protocol::MINPOLL);
        assert_eq!(builder.max_poll, crate::protocol::MAXPOLL);
        assert!(builder.initial_poll.is_none());
    }

    #[test]
    fn test_builder_min_poll_clamped_high() {
        let builder = NtpClient::builder().min_poll(255);
        assert_eq!(builder.min_poll, crate::protocol::MAXPOLL);
    }

    #[test]
    fn test_builder_min_poll_clamped_low() {
        let builder = NtpClient::builder().min_poll(0);
        assert_eq!(builder.min_poll, crate::protocol::MINPOLL);
    }

    #[test]
    fn test_builder_max_poll_clamped() {
        let builder = NtpClient::builder().max_poll(255);
        assert_eq!(builder.max_poll, crate::protocol::MAXPOLL);
    }

    #[test]
    fn test_builder_server_accumulates() {
        let builder = NtpClient::builder()
            .server("a.example.com:123")
            .server("b.example.com:123");
        assert_eq!(builder.servers.len(), 2);
    }

    #[test]
    fn test_builder_initial_poll() {
        let builder = NtpClient::builder().initial_poll(8);
        assert_eq!(builder.initial_poll, Some(8));
    }

    #[tokio::test]
    async fn test_builder_resolves_localhost() {
        let result = NtpClient::builder()
            .server("127.0.0.1:123")
            .min_poll(4)
            .max_poll(6)
            .build()
            .await;
        let (client, _rx) = result.expect("build should succeed");
        assert_eq!(client.peers.len(), 1);
        assert_eq!(client.min_poll, 4);
        assert_eq!(client.max_poll, 6);
    }

    #[tokio::test]
    async fn test_builder_max_poll_floored_to_min() {
        // If max_poll < min_poll, max_poll is raised to min_poll.
        let (client, _rx) = NtpClient::builder()
            .server("127.0.0.1:123")
            .min_poll(8)
            .max_poll(4) // Less than min_poll
            .build()
            .await
            .expect("build should succeed");
        assert_eq!(client.min_poll, 8);
        assert_eq!(client.max_poll, 8);
    }

    #[tokio::test]
    async fn test_builder_initial_poll_clamped_to_range() {
        let (client, _rx) = NtpClient::builder()
            .server("127.0.0.1:123")
            .min_poll(6)
            .max_poll(10)
            .initial_poll(4) // Below min_poll
            .build()
            .await
            .expect("build should succeed");
        // initial_poll should be clamped to min_poll=6
        assert_eq!(client.peers[0].poll_exponent, 6);
    }
}
