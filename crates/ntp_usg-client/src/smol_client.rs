// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Continuous NTP client using the smol runtime.
//!
//! This module provides the same continuous NTP client functionality as
//! [`crate::client`] but using smol instead of tokio. It maintains
//! associations with one or more NTP servers, polling them at adaptive
//! intervals per RFC 5905 Section 7.3 and supporting interleaved mode per
//! RFC 9769.
//!
//! # Architecture
//!
//! The client uses a builder pattern for configuration. State is shared via
//! `Arc<std::sync::RwLock<NtpSyncState>>` rather than a tokio watch channel.
//!
//! # Examples
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! let (client, state) = ntp_client::smol_client::NtpClient::builder()
//!     .server("time.nist.gov:123")
//!     .server("time-a-g.nist.gov:123")
//!     .min_poll(4)
//!     .max_poll(10)
//!     .build()
//!     .await?;
//!
//! // Spawn the poll loop.
//! smol::spawn(client.run()).detach();
//!
//! // Read the latest sync state at any time.
//! let state = state.read().unwrap();
//! println!("Offset: {:.6}s, Jitter: {:.6}s", state.offset, state.jitter);
//! # Ok(())
//! # }
//! ```

use log::{debug, warn};
use smol::net::UdpSocket;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub use crate::client_common::NtpSyncState;
use crate::client_common::{classify_and_compute, short_format_to_secs};
use crate::filter::{ClockSample, SampleFilter};
use crate::selection::{self, PeerCandidate};
use crate::{KissOfDeathError, build_request_packet, parse_and_validate_response, protocol};

#[cfg(feature = "nts-smol")]
use crate::nts_common;
#[cfg(feature = "nts-smol")]
use crate::smol_nts;

/// Result of polling a single peer.
enum PollResult {
    /// Successful basic-mode exchange.
    Sample(ClockSample, bool /* interleaved */),
    /// Server sent RATE kiss code.
    RateKissCode,
    /// Server sent DENY or RSTR kiss code.
    DenyKissCode,
}

/// NTS-specific state for a peer.
#[cfg(feature = "nts-smol")]
struct NtsPeerState {
    c2s_key: Vec<u8>,
    s2c_key: Vec<u8>,
    cookies: Vec<Vec<u8>>,
    aead_algorithm: u16,
    nts_ke_server: String,
    cookie_len: usize,
}

/// State maintained for a single NTP server peer.
struct PeerState {
    addr: SocketAddr,
    poll_exponent: u8,
    reachability: u8,
    filter: SampleFilter,
    stratum: Option<protocol::Stratum>,
    root_delay_secs: f64,
    root_dispersion_secs: f64,
    prev_t1: Option<protocol::TimestampFormat>,
    prev_t4: Option<protocol::TimestampFormat>,
    current_t1: Option<protocol::TimestampFormat>,
    interleaved: bool,
    demobilized: bool,
    #[cfg(feature = "nts-smol")]
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
            root_delay_secs: 0.0,
            root_dispersion_secs: 0.0,
            prev_t1: None,
            prev_t4: None,
            current_t1: None,
            interleaved: false,
            demobilized: false,
            #[cfg(feature = "nts-smol")]
            nts_state: None,
        }
    }

    #[cfg(feature = "nts-smol")]
    fn new_nts(
        addr: SocketAddr,
        initial_poll: u8,
        ke: smol_nts::NtsKeResult,
        nts_ke_server: String,
    ) -> Self {
        let cookie_len = ke.cookies.first().map_or(0, |c| c.len());
        PeerState {
            addr,
            poll_exponent: initial_poll,
            reachability: 0,
            filter: SampleFilter::new(),
            stratum: None,
            root_delay_secs: 0.0,
            root_dispersion_secs: 0.0,
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

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(1u64 << self.poll_exponent)
    }

    fn reach_success(&mut self) {
        self.reachability = (self.reachability << 1) | 1;
    }

    fn reach_failure(&mut self) {
        self.reachability <<= 1;
    }

    fn increase_poll(&mut self, max_poll: u8) {
        if self.poll_exponent < max_poll {
            self.poll_exponent += 1;
        }
    }

    fn decrease_poll(&mut self, min_poll: u8) {
        if self.poll_exponent > min_poll {
            self.poll_exponent -= 1;
        }
    }

    fn adjust_poll(&mut self, min_poll: u8, max_poll: u8) {
        let jitter = self.filter.jitter();
        if let Some(best) = self.filter.best_sample() {
            if best.offset.abs() > 0.128 || (best.delay > 0.0 && jitter > best.delay * 4.0) {
                self.decrease_poll(min_poll);
            } else if self.filter.len() >= 4 {
                self.increase_poll(max_poll);
            }
        }
    }

}

/// Builder for configuring and creating an [`NtpClient`].
pub struct NtpClientBuilder {
    servers: Vec<String>,
    #[cfg(feature = "nts-smol")]
    nts_servers: Vec<String>,
    min_poll: u8,
    max_poll: u8,
    initial_poll: Option<u8>,
    #[cfg(feature = "discipline")]
    enable_discipline: bool,
}

impl NtpClientBuilder {
    fn new() -> Self {
        NtpClientBuilder {
            servers: Vec::new(),
            #[cfg(feature = "nts-smol")]
            nts_servers: Vec::new(),
            min_poll: protocol::MINPOLL,
            max_poll: protocol::MAXPOLL,
            initial_poll: None,
            #[cfg(feature = "discipline")]
            enable_discipline: false,
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
    #[cfg(feature = "nts-smol")]
    pub fn nts_server(mut self, hostname: impl Into<String>) -> Self {
        self.nts_servers.push(hostname.into());
        self
    }

    /// Set initial poll exponent. Defaults to min_poll.
    pub fn initial_poll(mut self, exponent: u8) -> Self {
        self.initial_poll = Some(exponent);
        self
    }

    /// Enable the clock discipline loop (PLL/FLL) and periodic clock adjustment.
    ///
    /// Requires the `discipline` feature (which implies `clock`).
    /// Clock corrections require elevated privileges (root/admin).
    #[cfg(feature = "discipline")]
    pub fn enable_discipline(mut self, enable: bool) -> Self {
        self.enable_discipline = enable;
        self
    }

    /// Build the client. Performs async DNS resolution for all servers.
    ///
    /// Returns the client (to be spawned) and a shared state handle.
    pub async fn build(self) -> io::Result<(NtpClient, Arc<RwLock<NtpSyncState>>)> {
        #[cfg(feature = "nts-smol")]
        let has_nts = !self.nts_servers.is_empty();
        #[cfg(not(feature = "nts-smol"))]
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
            let addrs: Vec<SocketAddr> = smol::net::resolve(server.as_str()).await?;
            if let Some(&addr) = addrs.first() {
                peers.push(PeerState::new(addr, initial_poll));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("address resolved to no socket addresses: {server}"),
                ));
            }
        }

        #[cfg(feature = "nts-smol")]
        for nts_server in &self.nts_servers {
            let ke = smol_nts::nts_ke(nts_server).await?;
            let addr_str = format!("{}:{}", ke.ntp_server, ke.ntp_port);
            let addrs: Vec<SocketAddr> = smol::net::resolve(addr_str.as_str()).await?;
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

        let state = Arc::new(RwLock::new(NtpSyncState::default()));

        Ok((
            NtpClient {
                peers,
                state: Arc::clone(&state),
                min_poll,
                max_poll,
                total_responses: 0,
                #[cfg(feature = "discipline")]
                discipline: if self.enable_discipline {
                    Some(crate::discipline::ClockDiscipline::new())
                } else {
                    None
                },
                #[cfg(feature = "discipline")]
                adjuster: if self.enable_discipline {
                    Some(crate::clock_adjust::ClockAdjuster::new())
                } else {
                    None
                },
            },
            state,
        ))
    }
}

/// A continuous NTP client using the smol runtime.
///
/// Created via [`NtpClient::builder()`]. Call [`run()`](NtpClient::run) to start
/// the poll loop (typically via `smol::spawn(...).detach()`).
pub struct NtpClient {
    peers: Vec<PeerState>,
    state: Arc<RwLock<NtpSyncState>>,
    min_poll: u8,
    max_poll: u8,
    total_responses: u64,
    #[cfg(feature = "discipline")]
    discipline: Option<crate::discipline::ClockDiscipline>,
    #[cfg(feature = "discipline")]
    adjuster: Option<crate::clock_adjust::ClockAdjuster>,
}

impl NtpClient {
    /// Create a builder for configuring the client.
    pub fn builder() -> NtpClientBuilder {
        NtpClientBuilder::new()
    }

    /// Run the continuous poll loop. This future runs indefinitely.
    pub async fn run(mut self) {
        let mut next_poll: Vec<std::time::Instant> = self
            .peers
            .iter()
            .map(|_| std::time::Instant::now())
            .collect();

        #[cfg(feature = "discipline")]
        let discipline_epoch = std::time::Instant::now();

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

            let now = std::time::Instant::now();

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

            // Sleep until the next poll deadline, waking for adjuster ticks if needed.
            if deadline > now {
                #[cfg(feature = "discipline")]
                {
                    let sleep_dur = if self.adjuster.is_some() {
                        let next_tick = last_adjust_tick + Duration::from_secs(1);
                        let tick_dur = next_tick.saturating_duration_since(now);
                        (deadline - now).min(tick_dur)
                    } else {
                        deadline - now
                    };
                    smol::Timer::after(sleep_dur).await;
                    if std::time::Instant::now() < deadline {
                        continue;
                    }
                }
                #[cfg(not(feature = "discipline"))]
                smol::Timer::after(deadline - now).await;
            }

            debug!(
                "polling peer {} (poll interval: {}s)",
                self.peers[idx].addr,
                1u64 << self.peers[idx].poll_exponent
            );

            let result = Self::poll_peer(&mut self.peers[idx]).await;

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
                        if let Some(output) = discipline.update(
                            offset,
                            jitter,
                            now,
                            self.peers[idx].poll_exponent,
                        ) {
                            if output.step {
                                debug!("discipline: stepping clock by {:.6}s", output.phase_correction);
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
            next_poll[idx] = std::time::Instant::now() + self.peers[idx].poll_interval();
        }
    }

    /// Poll a single peer and return the result.
    async fn poll_peer(peer: &mut PeerState) -> io::Result<PollResult> {
        #[cfg(feature = "nts-smol")]
        if peer.nts_state.is_some() {
            let mut nts = peer.nts_state.take().unwrap();
            let result = Self::poll_peer_nts(peer, &mut nts).await;
            peer.nts_state = Some(nts);
            return result;
        }

        let bind_addr = crate::bind_addr_for(&peer.addr);
        let sock = UdpSocket::bind(bind_addr).await?;

        let (send_buf, t1) = build_request_packet()?;
        peer.current_t1 = Some(t1);

        let timeout = Duration::from_secs(5);

        // Send with timeout.
        futures_lite::future::or(sock.send_to(&send_buf, peer.addr), async {
            smol::Timer::after(timeout).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "NTP send timed out",
            ))
        })
        .await?;

        // Receive with timeout.
        let mut recv_buf = [0u8; 1024];
        let (recv_len, src_addr) = futures_lite::future::or(sock.recv_from(&mut recv_buf), async {
            smol::Timer::after(timeout).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "NTP recv timed out",
            ))
        })
        .await?;

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
                peer.stratum = Some(response.stratum);
                peer.root_delay_secs = short_format_to_secs(&response.root_delay);
                peer.root_dispersion_secs = short_format_to_secs(&response.root_dispersion);

                let (sample, interleaved) =
                    classify_and_compute(&response, t4, t1, peer.prev_t1, peer.prev_t4)?;

                peer.prev_t1 = peer.current_t1;
                peer.prev_t4 = Some(t4);

                Ok(PollResult::Sample(sample, interleaved))
            }
        }
    }

    #[cfg(feature = "nts-smol")]
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
            match smol_nts::nts_ke(&nts_state.nts_ke_server).await {
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
                }
            }
        }

        let cookie = nts_state
            .cookies
            .pop()
            .ok_or_else(|| io::Error::other("no NTS cookies remaining"))?;

        let (send_buf, t1, uid_data) =
            nts_common::build_nts_request(&nts_state.c2s_key, nts_state.aead_algorithm, cookie)?;
        peer.current_t1 = Some(t1);

        let bind_addr = crate::bind_addr_for(&peer.addr);
        let sock = UdpSocket::bind(bind_addr).await?;
        let timeout = Duration::from_secs(5);

        futures_lite::future::or(sock.send_to(&send_buf, peer.addr), async {
            smol::Timer::after(timeout).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "NTP send timed out",
            ))
        })
        .await?;

        let mut recv_buf = [0u8; 2048];
        let (recv_len, src_addr) = futures_lite::future::or(sock.recv_from(&mut recv_buf), async {
            smol::Timer::after(timeout).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "NTP recv timed out",
            ))
        })
        .await?;

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
                let new_cookies = nts_common::validate_nts_response(
                    &nts_state.s2c_key,
                    nts_state.aead_algorithm,
                    &uid_data,
                    &recv_buf,
                    recv_len,
                )?;
                nts_state.cookies.extend(new_cookies);

                peer.stratum = Some(response.stratum);
                peer.root_delay_secs = short_format_to_secs(&response.root_delay);
                peer.root_dispersion_secs = short_format_to_secs(&response.root_dispersion);

                let (sample, interleaved) =
                    classify_and_compute(&response, t4, t1, peer.prev_t1, peer.prev_t4)?;

                peer.prev_t1 = peer.current_t1;
                peer.prev_t4 = Some(t4);

                Ok(PollResult::Sample(sample, interleaved))
            }
        }
    }

    /// Select the best peer(s) using the RFC 5905 Section 11.2 pipeline,
    /// then publish the system state.
    ///
    /// Returns `Some((offset, jitter))` if a valid system estimate was
    /// produced, for feeding to the clock discipline loop.
    fn publish_best_state(&mut self) -> Option<(f64, f64)> {
        // Update ages and dispersion for all peer filters.
        for peer in &mut self.peers {
            peer.filter.update_ages();
        }

        let candidates: Vec<(usize, PeerCandidate)> = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.demobilized && p.filter.best_sample().is_some())
            .map(|(i, p)| {
                let best = p.filter.best_sample().unwrap();
                (
                    i,
                    PeerCandidate {
                        peer_index: i,
                        offset: best.offset,
                        root_delay: p.root_delay_secs,
                        root_dispersion: p.root_dispersion_secs,
                        jitter: p.filter.jitter(),
                        stratum: p.stratum.map_or(protocol::MAXSTRAT, |s| s.0),
                    },
                )
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let (offset, delay, jitter, peer_idx, system_peer_count, root_delay, root_dispersion) =
            if candidates.len() < 3 {
                let (best_idx, _) = candidates
                    .iter()
                    .min_by(|(_, a), (_, b)| {
                        a.root_distance()
                            .partial_cmp(&b.root_distance())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .unwrap();
                let peer = &self.peers[*best_idx];
                let sample = peer.filter.best_sample().unwrap();
                (
                    sample.offset,
                    sample.delay,
                    peer.filter.jitter(),
                    *best_idx,
                    candidates.len(),
                    peer.root_delay_secs,
                    peer.root_dispersion_secs,
                )
            } else {
                let peer_candidates: Vec<PeerCandidate> =
                    candidates.iter().map(|(_, c)| c.clone()).collect();

                let tc_indices = selection::select_truechimers(&peer_candidates);
                if tc_indices.is_empty() {
                    debug!("selection: no truechimer majority, falling back to best peer");
                    let (best_idx, _) = candidates
                        .iter()
                        .min_by(|(_, a), (_, b)| {
                            a.root_distance()
                                .partial_cmp(&b.root_distance())
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .unwrap();
                    let peer = &self.peers[*best_idx];
                    let sample = peer.filter.best_sample().unwrap();
                    (
                        sample.offset,
                        sample.delay,
                        peer.filter.jitter(),
                        *best_idx,
                        1,
                        peer.root_delay_secs,
                        peer.root_dispersion_secs,
                    )
                } else {
                    let mut survivors: Vec<PeerCandidate> = tc_indices
                        .iter()
                        .map(|&i| peer_candidates[i].clone())
                        .collect();
                    selection::cluster_survivors(&mut survivors);

                    match selection::combine(&survivors) {
                        Some(est) => {
                            let sys_peer = &self.peers[est.system_peer_index];
                            let sample = sys_peer.filter.best_sample().unwrap();
                            (
                                est.offset,
                                sample.delay,
                                est.jitter,
                                est.system_peer_index,
                                survivors.len(),
                                sys_peer.root_delay_secs,
                                sys_peer.root_dispersion_secs,
                            )
                        }
                        None => return None,
                    }
                }
            };

        let peer = &self.peers[peer_idx];

        #[cfg(feature = "nts-smol")]
        let nts_authenticated = peer.nts_state.is_some();
        #[cfg(not(feature = "nts-smol"))]
        let nts_authenticated = false;

        #[cfg(feature = "discipline")]
        let (frequency, discipline_state) = match &self.discipline {
            Some(d) => (d.frequency(), format!("{:?}", d.state())),
            None => (0.0, String::new()),
        };
        #[cfg(not(feature = "discipline"))]
        let (frequency, discipline_state) = (0.0, String::new());

        let state = NtpSyncState {
            offset,
            delay,
            jitter,
            stratum: peer.stratum.map_or(protocol::MAXSTRAT, |s| s.0),
            interleaved: peer.interleaved,
            last_update: std::time::Instant::now(),
            total_responses: self.total_responses,
            nts_authenticated,
            root_delay,
            root_dispersion,
            system_peer_count,
            frequency,
            discipline_state,
        };
        if let Ok(mut guard) = self.state.write() {
            *guard = state;
        }
        Some((offset, jitter))
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
    fn test_builder_rejects_empty_servers() {
        smol::block_on(async {
            let result = NtpClient::builder().build().await;
            assert!(result.is_err());
        });
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
