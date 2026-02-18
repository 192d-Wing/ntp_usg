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
use crate::client_common::{PeerState, PollResult, check_kod, select_and_build_state};
use crate::protocol;
use crate::request::{bind_addr_for, build_request_packet, parse_and_validate_response};

#[cfg(feature = "nts-smol")]
use crate::client_common::NtsPeerState;
#[cfg(feature = "nts-smol")]
use crate::nts_common;
#[cfg(feature = "nts-smol")]
use crate::smol_nts;

#[cfg(feature = "ntpv5")]
use crate::client_common::NtpV5PeerState;

/// Builder for configuring and creating an [`NtpClient`].
pub struct NtpClientBuilder {
    servers: Vec<String>,
    #[cfg(feature = "nts-smol")]
    nts_servers: Vec<String>,
    min_poll: u8,
    max_poll: u8,
    initial_poll: Option<u8>,
    socket_opts: crate::socket_opts::SocketOptions,
    #[cfg(feature = "discipline")]
    enable_discipline: bool,
    #[cfg(feature = "ntpv5")]
    enable_ntpv5: bool,
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
            socket_opts: crate::socket_opts::SocketOptions::default(),
            #[cfg(feature = "discipline")]
            enable_discipline: false,
            #[cfg(feature = "ntpv5")]
            enable_ntpv5: false,
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

    /// Restrict IPv6 sockets to IPv6-only traffic (no IPv4-mapped addresses).
    ///
    /// Only applies to IPv6 peer sockets; ignored for IPv4 peers.
    /// Requires the `socket-opts` feature.
    #[cfg(feature = "socket-opts")]
    pub fn v6only(mut self, enabled: bool) -> Self {
        self.socket_opts.v6only = Some(enabled);
        self
    }

    /// Set the DSCP (Differentiated Services Code Point) for outgoing NTP packets.
    ///
    /// The DSCP value (0-63) is placed in the upper 6 bits of the IP TOS /
    /// IPv6 Traffic Class byte. Requires the `socket-opts` feature.
    #[cfg(feature = "socket-opts")]
    pub fn dscp(mut self, value: u8) -> Self {
        self.socket_opts.dscp = Some(value);
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

    /// Enable NTPv5 version negotiation for all peers.
    ///
    /// Requires the `ntpv5` feature.
    #[cfg(feature = "ntpv5")]
    pub fn ntpv5(mut self, enable: bool) -> Self {
        self.enable_ntpv5 = enable;
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
            let addrs: Vec<SocketAddr> =
                crate::request::prefer_addresses(smol::net::resolve(server.as_str()).await?);
            if let Some(&addr) = addrs.first() {
                #[cfg(feature = "ntpv5")]
                let peer = if self.enable_ntpv5 {
                    PeerState::new_v5(addr, initial_poll)
                } else {
                    PeerState::new(addr, initial_poll)
                };
                #[cfg(not(feature = "ntpv5"))]
                let peer = PeerState::new(addr, initial_poll);
                peers.push(peer);
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
            let addrs: Vec<SocketAddr> =
                crate::request::prefer_addresses(smol::net::resolve(addr_str.as_str()).await?);
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
                socket_opts: self.socket_opts,
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
    socket_opts: crate::socket_opts::SocketOptions,
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
    async fn poll_peer(
        peer: &mut PeerState,
        socket_opts: &crate::socket_opts::SocketOptions,
    ) -> io::Result<PollResult> {
        #[cfg(feature = "nts-smol")]
        if peer.nts_state.is_some() {
            let mut nts = peer.nts_state.take().unwrap();
            let result = Self::poll_peer_nts(peer, &mut nts, socket_opts).await;
            peer.nts_state = Some(nts);
            return result;
        }

        #[cfg(feature = "ntpv5")]
        if peer.v5_state.is_some() {
            let mut v5 = peer.v5_state.take().unwrap();
            let result = Self::poll_peer_v5(peer, &mut v5, socket_opts).await;
            peer.v5_state = Some(v5);
            return result;
        }

        #[cfg(feature = "socket-opts")]
        let sock = {
            let bind_addr: SocketAddr = bind_addr_for(&peer.addr).parse().unwrap();
            let std_sock = socket_opts.bind_udp(bind_addr)?;
            UdpSocket::from(smol::Async::new(std_sock)?)
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = socket_opts;
            UdpSocket::bind(bind_addr_for(&peer.addr)).await?
        };

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
            Err(e) => match check_kod(&e) {
                Some(poll_result) => Ok(poll_result),
                None => Err(e),
            },
            Ok((response, t4)) => peer.process_response(&response, t4, t1),
        }
    }

    #[cfg(feature = "nts-smol")]
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

        #[cfg(feature = "socket-opts")]
        let sock = {
            let bind_addr: SocketAddr = bind_addr_for(&peer.addr).parse().unwrap();
            let std_sock = socket_opts.bind_udp(bind_addr)?;
            UdpSocket::from(smol::Async::new(std_sock)?)
        };
        #[cfg(not(feature = "socket-opts"))]
        let sock = {
            let _ = socket_opts;
            UdpSocket::bind(bind_addr_for(&peer.addr)).await?
        };
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
            Err(e) => match check_kod(&e) {
                Some(poll_result) => Ok(poll_result),
                None => Err(e),
            },
            Ok((response, t4)) => {
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
                let (send_buf, t1) = build_v4_negotiation_packet()?;
                peer.current_t1 = Some(t1);
                *attempts += 1;

                #[cfg(feature = "socket-opts")]
                let sock = {
                    let bind_addr: SocketAddr = bind_addr_for(&peer.addr).parse().unwrap();
                    let std_sock = socket_opts.bind_udp(bind_addr)?;
                    UdpSocket::from(smol::Async::new(std_sock)?)
                };
                #[cfg(not(feature = "socket-opts"))]
                let sock = {
                    let _ = socket_opts;
                    UdpSocket::bind(bind_addr_for(&peer.addr)).await?
                };

                let timeout = Duration::from_secs(5);
                futures_lite::future::or(sock.send_to(&send_buf, peer.addr), async {
                    smol::Timer::after(timeout).await;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "NTP send timed out",
                    ))
                })
                .await?;

                let mut recv_buf = [0u8; 1024];
                let (recv_len, src_addr) =
                    futures_lite::future::or(sock.recv_from(&mut recv_buf), async {
                        smol::Timer::after(timeout).await;
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "NTP recv timed out",
                        ))
                    })
                    .await?;

                let parse_result =
                    parse_and_validate_response(&recv_buf, recv_len, src_addr, &[peer.addr]);

                match parse_result {
                    Err(e) => match check_kod(&e) {
                        Some(poll_result) => Ok(poll_result),
                        None => {
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
                let bloom_req = if !*bloom_complete {
                    Some(*bloom_offset)
                } else {
                    None
                };
                let (send_buf, client_cookie) =
                    build_v5_request_packet(*timescale, *server_cookie, bloom_req)?;

                peer.current_t1 = Some(crate::unix_time::Instant::now().into());
                *prev_client_cookie = *current_client_cookie;
                *current_client_cookie = client_cookie;

                #[cfg(feature = "socket-opts")]
                let sock = {
                    let bind_addr: SocketAddr = bind_addr_for(&peer.addr).parse().unwrap();
                    let std_sock = socket_opts.bind_udp(bind_addr)?;
                    UdpSocket::from(smol::Async::new(std_sock)?)
                };
                #[cfg(not(feature = "socket-opts"))]
                let sock = {
                    let _ = socket_opts;
                    UdpSocket::bind(bind_addr_for(&peer.addr)).await?
                };

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
                let (recv_len, src_addr) =
                    futures_lite::future::or(sock.recv_from(&mut recv_buf), async {
                        smol::Timer::after(timeout).await;
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "NTP recv timed out",
                        ))
                    })
                    .await?;

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

                *server_cookie = response.server_cookie;

                peer.process_response_v5(&response, t4, client_cookie)
            }

            NtpV5PeerState::V4Only {
                exchanges_since_probe,
            } => {
                #[cfg(feature = "socket-opts")]
                let sock = {
                    let bind_addr: SocketAddr = bind_addr_for(&peer.addr).parse().unwrap();
                    let std_sock = socket_opts.bind_udp(bind_addr)?;
                    UdpSocket::from(smol::Async::new(std_sock)?)
                };
                #[cfg(not(feature = "socket-opts"))]
                let sock = {
                    let _ = socket_opts;
                    UdpSocket::bind(bind_addr_for(&peer.addr)).await?
                };

                let (send_buf, t1) = build_request_packet()?;
                peer.current_t1 = Some(t1);

                let timeout = Duration::from_secs(5);
                futures_lite::future::or(sock.send_to(&send_buf, peer.addr), async {
                    smol::Timer::after(timeout).await;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "NTP send timed out",
                    ))
                })
                .await?;

                let mut recv_buf = [0u8; 1024];
                let (recv_len, src_addr) =
                    futures_lite::future::or(sock.recv_from(&mut recv_buf), async {
                        smol::Timer::after(timeout).await;
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "NTP recv timed out",
                        ))
                    })
                    .await?;

                let parse_result =
                    parse_and_validate_response(&recv_buf, recv_len, src_addr, &[peer.addr]);

                *exchanges_since_probe += 1;

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

    /// Select the best peer(s) using the RFC 5905 Section 11.2 pipeline,
    /// then publish the system state.
    ///
    /// Returns `Some((offset, jitter))` if a valid system estimate was
    /// produced, for feeding to the clock discipline loop.
    fn publish_best_state(&mut self) -> Option<(f64, f64)> {
        #[cfg(feature = "discipline")]
        let (frequency, discipline_state) = match &self.discipline {
            Some(d) => (d.frequency(), format!("{:?}", d.state())),
            None => (0.0, String::new()),
        };
        #[cfg(not(feature = "discipline"))]
        let (frequency, discipline_state) = (0.0, String::new());

        let result = select_and_build_state(
            &mut self.peers,
            self.total_responses,
            frequency,
            discipline_state,
        )?;

        if let Ok(mut guard) = self.state.write() {
            *guard = result.state;
        }
        Some((result.offset, result.jitter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_rejects_empty_servers() {
        smol::block_on(async {
            let result = NtpClient::builder().build().await;
            assert!(result.is_err());
        });
    }
}
