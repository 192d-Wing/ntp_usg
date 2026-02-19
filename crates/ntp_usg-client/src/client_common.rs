// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared types and logic for the continuous NTP client, used by both the
//! tokio-based [`crate::client`] and smol-based [`crate::smol_client`] modules.
//!
//! Provides peer state management, poll interval adaptation, reachability
//! tracking, response classification (basic vs interleaved mode), the
//! RFC 5905 Section 11.2 selection/clustering/combining pipeline, and
//! the `NtpSyncState` published to consumers.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::debug;

use crate::error::{NtpError, ProtocolError};
use crate::filter::{ClockSample, SampleFilter};
use crate::request::compute_offset_delay;
use crate::selection::{self, PeerCandidate};
use crate::{DisciplineState, KissOfDeathError, protocol, unix_time};

#[cfg(feature = "ntpv5")]
use ntp_proto::protocol::bloom::BloomFilter;
#[cfg(feature = "ntpv5")]
use ntp_proto::protocol::ntpv5::Timescale;

/// Convert an NTP [`ShortFormat`](protocol::ShortFormat) value to seconds as `f64`.
pub(crate) fn short_format_to_secs(sf: &protocol::ShortFormat) -> f64 {
    sf.seconds as f64 + sf.fraction as f64 / 65536.0
}

/// The current synchronization state published by the continuous NTP client.
///
/// Available to consumers via `tokio::sync::watch::Receiver<NtpSyncState>`
/// (tokio client) or `Arc<RwLock<NtpSyncState>>` (smol client).
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
    /// Whether the best peer is using NTS authentication.
    pub nts_authenticated: bool,
    /// Root delay of the best peer (seconds).
    pub root_delay: f64,
    /// Root dispersion of the best peer (seconds).
    pub root_dispersion: f64,
    /// Number of peers that survived the selection/clustering pipeline.
    pub system_peer_count: usize,
    /// Current frequency correction from the clock discipline (seconds/second).
    /// Only populated when the `discipline` feature is enabled.
    pub frequency: f64,
    /// Current discipline state per RFC 5905 Figure 24.
    /// `None` when the `discipline` feature is not enabled or no discipline is active.
    pub discipline_state: Option<DisciplineState>,
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
            nts_authenticated: false,
            root_delay: 0.0,
            root_dispersion: 0.0,
            system_peer_count: 0,
            frequency: 0.0,
            discipline_state: None,
        }
    }
}

/// Result of polling a single peer.
pub(crate) enum PollResult {
    /// Successful basic-mode exchange.
    Sample(ClockSample, bool /* interleaved */),
    /// Server sent RATE kiss code.
    RateKissCode,
    /// Server sent DENY or RSTR kiss code.
    DenyKissCode,
}

/// NTS-specific state for a peer, separated to avoid borrow checker issues.
#[cfg(any(feature = "nts", feature = "nts-smol"))]
pub(crate) struct NtsPeerState {
    /// Client-to-server AEAD key.
    pub(crate) c2s_key: Vec<u8>,
    /// Server-to-client AEAD key.
    pub(crate) s2c_key: Vec<u8>,
    /// Cookies for NTP requests (each used exactly once).
    pub(crate) cookies: Vec<Vec<u8>>,
    /// Negotiated AEAD algorithm ID.
    pub(crate) aead_algorithm: u16,
    /// NTS-KE server hostname for re-keying when cookies run low.
    pub(crate) nts_ke_server: String,
    /// Cookie length from initial NTS-KE (for placeholder sizing).
    pub(crate) cookie_len: usize,
}

/// NTPv5 version negotiation and session state for a peer.
///
/// Follows the version negotiation mechanism in `draft-ietf-ntp-ntpv5-07`
/// Section 5: the client places a magic value in the NTPv4 Reference Timestamp
/// field to signal V5 support. If the server echoes it, the peer transitions
/// to V5 mode; otherwise it stays on V4.
#[cfg(feature = "ntpv5")]
pub(crate) enum NtpV5PeerState {
    /// Probing: send V4 requests with the negotiation magic.
    Negotiating {
        /// Number of V4 requests sent with the magic so far.
        attempts: u8,
    },
    /// Server supports V5 — use V5 packets from now on.
    V5Active {
        /// Assembled Bloom filter for loop detection (boxed to reduce enum size).
        bloom_filter: Box<BloomFilter>,
        /// Whether we have received all chunks of the Bloom filter.
        bloom_complete: bool,
        /// Next byte offset to request from the Bloom filter.
        bloom_offset: u16,
        /// Server cookie from the last response (for interleaved mode).
        server_cookie: u64,
        /// Client cookie we sent in the current/most-recent request.
        current_client_cookie: u64,
        /// Client cookie we sent in the previous request (for interleaved matching).
        prev_client_cookie: u64,
        /// Preferred timescale.
        timescale: Timescale,
    },
    /// Server does not support V5 — stay on V4.
    V4Only {
        /// Number of V4 exchanges since the last V5 probe.
        exchanges_since_probe: u32,
    },
}

/// State maintained for a single NTP server peer.
pub(crate) struct PeerState {
    /// Resolved socket address of this peer.
    pub(crate) addr: SocketAddr,
    /// Current poll exponent (log2 seconds). Bounded by [min_poll, max_poll].
    pub(crate) poll_exponent: u8,
    /// 8-bit shift register for reachability (RFC 5905 Section 9.1).
    pub(crate) reachability: u8,
    /// Clock filter for this peer.
    pub(crate) filter: SampleFilter,
    /// Last stratum received from this peer.
    pub(crate) stratum: Option<protocol::Stratum>,
    /// Root delay from the peer's last response (seconds).
    pub(crate) root_delay_secs: f64,
    /// Root dispersion from the peer's last response (seconds).
    pub(crate) root_dispersion_secs: f64,
    /// Our transmit timestamp (T1) from the previous exchange (for interleaved mode).
    pub(crate) prev_t1: Option<protocol::TimestampFormat>,
    /// Our receive timestamp (T4) from the previous exchange (for interleaved mode).
    pub(crate) prev_t4: Option<protocol::TimestampFormat>,
    /// Our transmit timestamp (T1) from the current (most recent sent) exchange.
    pub(crate) current_t1: Option<protocol::TimestampFormat>,
    /// Whether interleaved mode has been detected for this peer.
    pub(crate) interleaved: bool,
    /// If true, we have received DENY or RSTR and must stop polling.
    pub(crate) demobilized: bool,
    /// NTS state, present only for NTS-authenticated peers.
    #[cfg(any(feature = "nts", feature = "nts-smol"))]
    pub(crate) nts_state: Option<NtsPeerState>,
    /// NTPv5 negotiation/session state, present only when the `ntpv5` feature
    /// is enabled and the peer was created with V5 negotiation.
    #[cfg(feature = "ntpv5")]
    pub(crate) v5_state: Option<NtpV5PeerState>,
}

impl PeerState {
    pub(crate) fn new(addr: SocketAddr, initial_poll: u8) -> Self {
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
            #[cfg(any(feature = "nts", feature = "nts-smol"))]
            nts_state: None,
            #[cfg(feature = "ntpv5")]
            v5_state: None,
        }
    }

    /// Create a peer that will attempt NTPv5 version negotiation.
    ///
    /// The peer starts in the `Negotiating` state and will probe the server
    /// with V4 packets containing the version negotiation magic. If the server
    /// responds with the magic echoed, the peer transitions to `V5Active`.
    #[cfg(feature = "ntpv5")]
    pub(crate) fn new_v5(addr: SocketAddr, initial_poll: u8) -> Self {
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
            #[cfg(any(feature = "nts", feature = "nts-smol"))]
            nts_state: None,
            v5_state: Some(NtpV5PeerState::Negotiating { attempts: 0 }),
        }
    }

    /// Create a peer with NTS state from a completed NTS-KE exchange.
    #[cfg(any(feature = "nts", feature = "nts-smol"))]
    pub(crate) fn new_nts(
        addr: SocketAddr,
        initial_poll: u8,
        ke: crate::nts_common::NtsKeResult,
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
            #[cfg(feature = "ntpv5")]
            v5_state: None,
        }
    }

    /// Get the current poll interval as a Duration.
    pub(crate) fn poll_interval(&self) -> Duration {
        Duration::from_secs(1u64 << self.poll_exponent)
    }

    /// Shift a 1 into the reachability register (successful response).
    pub(crate) fn reach_success(&mut self) {
        self.reachability = (self.reachability << 1) | 1;
    }

    /// Shift a 0 into the reachability register (timeout/failure).
    pub(crate) fn reach_failure(&mut self) {
        self.reachability <<= 1;
    }

    /// Increase poll interval. Clamps at max_poll.
    pub(crate) fn increase_poll(&mut self, max_poll: u8) {
        if self.poll_exponent < max_poll {
            self.poll_exponent += 1;
        }
    }

    /// Decrease poll interval. Clamps at min_poll.
    pub(crate) fn decrease_poll(&mut self, min_poll: u8) {
        if self.poll_exponent > min_poll {
            self.poll_exponent -= 1;
        }
    }

    /// Adjust poll interval based on current jitter and offset.
    pub(crate) fn adjust_poll(&mut self, min_poll: u8, max_poll: u8) {
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

    /// Update peer state from a valid NTP response and classify as basic/interleaved.
    ///
    /// Updates stratum, root delay/dispersion, classifies the response mode,
    /// computes the clock sample, and rotates timestamps for the next exchange.
    pub(crate) fn process_response(
        &mut self,
        response: &protocol::Packet,
        t4: protocol::TimestampFormat,
        t1: protocol::TimestampFormat,
    ) -> io::Result<PollResult> {
        self.stratum = Some(response.stratum);
        self.root_delay_secs = short_format_to_secs(&response.root_delay);
        self.root_dispersion_secs = short_format_to_secs(&response.root_dispersion);

        let (sample, interleaved) =
            classify_and_compute(response, t4, t1, self.prev_t1, self.prev_t4)?;

        // Rotate timestamps for next exchange.
        self.prev_t1 = self.current_t1;
        self.prev_t4 = Some(t4);

        Ok(PollResult::Sample(sample, interleaved))
    }

    /// Update peer state from a valid NTPv5 response.
    ///
    /// NTPv5 uses cookie matching instead of origin timestamp matching for
    /// interleaved mode detection (via the `INTERLEAVED` flag in `NtpV5Flags`).
    #[cfg(feature = "ntpv5")]
    pub(crate) fn process_response_v5(
        &mut self,
        response: &ntp_proto::protocol::ntpv5::PacketV5,
        t4: protocol::TimestampFormat,
        expected_client_cookie: u64,
    ) -> io::Result<PollResult> {
        use ntp_proto::protocol::ntpv5::NtpV5Flags;

        self.stratum = Some(response.stratum);
        self.root_delay_secs = response.root_delay.to_seconds_f64();
        self.root_dispersion_secs = response.root_dispersion.to_seconds_f64();

        // V5 anti-replay: client_cookie in the response must match what we sent.
        if response.client_cookie != expected_client_cookie {
            return Err(NtpError::Protocol(ProtocolError::ClientCookieMismatch).into());
        }

        let interleaved = response.flags.is_interleaved();
        let (t2, t3) = if interleaved {
            // Interleaved mode: T2/T3 are from the *previous* exchange,
            // paired with our prev_t1/prev_t4.
            if let (Some(pt1), Some(pt4)) = (self.prev_t1, self.prev_t4) {
                let _ = pt1; // T1 from previous exchange (used below via prev_t4)
                let t4_instant = unix_time::Instant::from(pt4);
                let t2 = unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
                let t3 = unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);
                let t1 = unix_time::timestamp_to_instant(pt1, &t4_instant);
                let (offset, delay) = compute_offset_delay(&t1, &t2, &t3, &t4_instant);

                self.prev_t1 = self.current_t1;
                self.prev_t4 = Some(t4);

                return Ok(PollResult::Sample(
                    ClockSample {
                        offset,
                        delay,
                        age: 0.0,
                        dispersion: 0.0,
                        epoch: std::time::Instant::now(),
                    },
                    true,
                ));
            } else {
                // First exchange with interleaved flag — fall through to basic.
                (response.receive_timestamp, response.transmit_timestamp)
            }
        } else {
            (response.receive_timestamp, response.transmit_timestamp)
        };

        // Basic mode computation.
        // V5 doesn't put T1 on the wire; we use the T1 we recorded locally.
        let t1_ts = self.current_t1.ok_or_else(|| -> io::Error {
            NtpError::Protocol(ProtocolError::Other(
                "no T1 recorded for V5 exchange".into(),
            ))
            .into()
        })?;

        let t4_instant = unix_time::Instant::from(t4);
        let t1_instant = unix_time::timestamp_to_instant(t1_ts, &t4_instant);
        let t2_instant = unix_time::timestamp_to_instant(t2, &t4_instant);
        let t3_instant = unix_time::timestamp_to_instant(t3, &t4_instant);
        let (offset, delay) =
            compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);

        // Rotate timestamps for next exchange.
        self.prev_t1 = self.current_t1;
        self.prev_t4 = Some(t4);

        // Update V5 state with the new server cookie.
        if let Some(NtpV5PeerState::V5Active {
            ref mut server_cookie,
            ref mut prev_client_cookie,
            current_client_cookie,
            ..
        }) = self.v5_state
        {
            *server_cookie = response.server_cookie;
            *prev_client_cookie = current_client_cookie;
        }

        Ok(PollResult::Sample(
            ClockSample {
                offset,
                delay,
                age: 0.0,
                dispersion: 0.0,
                epoch: std::time::Instant::now(),
            },
            interleaved && response.flags.0 & NtpV5Flags::INTERLEAVED != 0,
        ))
    }
}

/// Check if an I/O error contains a Kiss-o'-Death code and return the
/// appropriate [`PollResult`].
pub(crate) fn check_kod(e: &io::Error) -> Option<PollResult> {
    let inner = e.get_ref()?;
    // Try NtpError downcast first (new typed error path).
    if let Some(NtpError::KissOfDeath(kod)) = inner.downcast_ref::<NtpError>() {
        return Some(match kod.code {
            protocol::KissOfDeath::Rate => PollResult::RateKissCode,
            protocol::KissOfDeath::Deny | protocol::KissOfDeath::Rstr => PollResult::DenyKissCode,
        });
    }
    // Legacy KissOfDeathError downcast for backward compatibility.
    let kod = inner.downcast_ref::<KissOfDeathError>()?;
    Some(match kod.code {
        protocol::KissOfDeath::Rate => PollResult::RateKissCode,
        protocol::KissOfDeath::Deny | protocol::KissOfDeath::Rstr => PollResult::DenyKissCode,
    })
}

/// Classify an NTP response as basic or interleaved mode and compute
/// the clock offset and delay.
///
/// Returns `(sample, interleaved)` where `interleaved` indicates whether
/// the server used interleaved mode (RFC 9769).
pub(crate) fn classify_and_compute(
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
        let t2_instant = unix_time::timestamp_to_instant(response.receive_timestamp, &t4_instant);
        let t3_instant = unix_time::timestamp_to_instant(response.transmit_timestamp, &t4_instant);
        let (offset, delay) =
            compute_offset_delay(&t1_instant, &t2_instant, &t3_instant, &t4_instant);
        Ok((
            ClockSample {
                offset,
                delay,
                age: 0.0,
                dispersion: 0.0,
                epoch: std::time::Instant::now(),
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
                    dispersion: 0.0,
                    epoch: std::time::Instant::now(),
                },
                true,
            ))
        } else {
            Err(NtpError::Protocol(ProtocolError::OriginTimestampMismatch).into())
        }
    } else {
        Err(NtpError::Protocol(ProtocolError::OriginTimestampMismatch).into())
    }
}

/// Result of the peer selection and state-building pipeline.
pub(crate) struct SelectionResult {
    /// The sync state to publish.
    pub(crate) state: NtpSyncState,
    /// Best estimated offset (for feeding to the discipline loop).
    pub(crate) offset: f64,
    /// Best estimated jitter (for feeding to the discipline loop).
    pub(crate) jitter: f64,
}

/// Run the RFC 5905 Section 11.2 selection/clustering/combining pipeline
/// over the given peers and build an [`NtpSyncState`].
///
/// Returns `None` if no valid system estimate could be produced (e.g., no
/// peers have samples).
pub(crate) fn select_and_build_state(
    peers: &mut [PeerState],
    total_responses: u64,
    frequency: f64,
    discipline_state: Option<DisciplineState>,
) -> Option<SelectionResult> {
    // Update ages and dispersion for all peer filters.
    for peer in peers.iter_mut() {
        peer.filter.update_ages();
    }

    // Build candidate list from non-demobilized peers with samples.
    let candidates: Vec<(usize, PeerCandidate)> = peers
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.demobilized && p.filter.best_sample().is_some())
        .map(|(i, p)| {
            let best = p
                .filter
                .best_sample()
                .expect("pre-filtered to have samples");
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

    // For 1-2 peers, use simple min-sync-distance (selection algorithm
    // needs a majority, which requires at least 3 peers).
    let (offset, delay, jitter, peer_idx, system_peer_count, root_delay, root_dispersion) =
        if candidates.len() < 3 {
            let (best_idx, _) = candidates
                .iter()
                .min_by(|(_, a), (_, b)| {
                    a.root_distance()
                        .partial_cmp(&b.root_distance())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .expect("candidates is non-empty");
            let peer = &peers[*best_idx];
            let sample = peer
                .filter
                .best_sample()
                .expect("pre-filtered to have samples");
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
            // Full RFC 5905 pipeline: select → cluster → combine.
            let peer_candidates: Vec<PeerCandidate> =
                candidates.iter().map(|(_, c)| c.clone()).collect();

            let tc_indices = selection::select_truechimers(&peer_candidates);
            if tc_indices.is_empty() {
                // No majority agreement — fall back to best single peer.
                debug!("selection: no truechimer majority, falling back to best peer");
                let (best_idx, _) = candidates
                    .iter()
                    .min_by(|(_, a), (_, b)| {
                        a.root_distance()
                            .partial_cmp(&b.root_distance())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .expect("candidates is non-empty");
                let peer = &peers[*best_idx];
                let sample = peer
                    .filter
                    .best_sample()
                    .expect("pre-filtered to have samples");
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
                // Filter peer_candidates to truechimers, consuming the Vec to
                // avoid a second clone.
                let tc_set: std::collections::HashSet<usize> = tc_indices.into_iter().collect();
                let mut survivors: Vec<PeerCandidate> = peer_candidates
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| tc_set.contains(i))
                    .map(|(_, c)| c)
                    .collect();
                selection::cluster_survivors(&mut survivors);

                match selection::combine(&survivors) {
                    Some(est) => {
                        let sys_peer = &peers[est.system_peer_index];
                        let sample = sys_peer
                            .filter
                            .best_sample()
                            .expect("system peer was pre-filtered to have samples");
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

    let peer = &peers[peer_idx];

    #[cfg(any(feature = "nts", feature = "nts-smol"))]
    let nts_authenticated = peer.nts_state.is_some();
    #[cfg(not(any(feature = "nts", feature = "nts-smol")))]
    let nts_authenticated = false;

    let state = NtpSyncState {
        offset,
        delay,
        jitter,
        stratum: peer.stratum.map_or(protocol::MAXSTRAT, |s| s.0),
        interleaved: peer.interleaved,
        last_update: std::time::Instant::now(),
        total_responses,
        nts_authenticated,
        root_delay,
        root_dispersion,
        system_peer_count,
        frequency,
        discipline_state,
    };

    Some(SelectionResult {
        state,
        offset,
        jitter,
    })
}

// ── Shared builder infrastructure ────────────────────────────────

/// Runtime-independent configuration produced by `NtpClientBuilder::into_config`.
///
/// Contains everything needed to create an NTP client except the
/// runtime-specific DNS resolution, NTS-KE, and state channel creation.
#[allow(dead_code)] // Fields are read behind #[cfg] gates in runtime modules.
pub(crate) struct ClientBuildConfig {
    pub(crate) servers: Vec<String>,
    pub(crate) min_poll: u8,
    pub(crate) max_poll: u8,
    pub(crate) initial_poll: u8,
    pub(crate) socket_opts: crate::socket_opts::SocketOptions,
    pub(crate) enable_discipline: bool,
    pub(crate) enable_ntpv5: bool,
}

/// Define an `NtpClientBuilder` struct with shared NTP client configuration methods.
///
/// Both the tokio [`crate::client`] and smol [`crate::smol_client`] modules
/// invoke this macro to generate their own `NtpClientBuilder` type with
/// identical configuration methods. Each module then adds a runtime-specific
/// `build()` method.
///
/// # Parameters
///
/// - `extra_fields { ... }` — Additional struct fields (e.g., NTS servers with
///   runtime-specific feature gates)
/// - `extra_defaults { ... }` — Default values for the extra fields in `new()`
macro_rules! define_client_builder {
    (
        $(#[$struct_meta:meta])*
        extra_fields { $($extra_field:tt)* }
        extra_defaults { $($extra_default:tt)* }
    ) => {
        $(#[$struct_meta])*
        pub struct NtpClientBuilder {
            servers: Vec<String>,
            min_poll: u8,
            max_poll: u8,
            initial_poll: Option<u8>,
            socket_opts: $crate::socket_opts::SocketOptions,
            #[cfg(feature = "discipline")]
            enable_discipline: bool,
            #[cfg(feature = "ntpv5")]
            enable_ntpv5: bool,
            $($extra_field)*
        }

        impl NtpClientBuilder {
            fn new() -> Self {
                NtpClientBuilder {
                    servers: Vec::new(),
                    min_poll: $crate::protocol::MINPOLL,
                    max_poll: $crate::protocol::MAXPOLL,
                    initial_poll: None,
                    socket_opts: <$crate::socket_opts::SocketOptions
                        as ::std::default::Default>::default(),
                    #[cfg(feature = "discipline")]
                    enable_discipline: false,
                    #[cfg(feature = "ntpv5")]
                    enable_ntpv5: false,
                    $($extra_default)*
                }
            }

            /// Add an NTP server address (hostname:port or ip:port).
            pub fn server(mut self, addr: impl Into<String>) -> Self {
                self.servers.push(addr.into());
                self
            }

            /// Set minimum poll exponent (default: MINPOLL=4, i.e. 16s).
            pub fn min_poll(mut self, exponent: u8) -> Self {
                self.min_poll = exponent.clamp(
                    $crate::protocol::MINPOLL,
                    $crate::protocol::MAXPOLL,
                );
                self
            }

            /// Set maximum poll exponent (default: MAXPOLL=17, i.e. ~36h).
            pub fn max_poll(mut self, exponent: u8) -> Self {
                self.max_poll = exponent.clamp(
                    $crate::protocol::MINPOLL,
                    $crate::protocol::MAXPOLL,
                );
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

            /// Enable the clock discipline loop (PLL/FLL) and periodic clock adjustment.
            ///
            /// When enabled, the client feeds offset measurements from the selection
            /// pipeline into the RFC 5905 Section 11.3 discipline loop and applies
            /// phase/frequency corrections to the system clock via the Section 12
            /// periodic adjustment process.
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
            /// When enabled, peers start in the `Negotiating` state and probe servers
            /// for NTPv5 support using the version negotiation mechanism in
            /// `draft-ietf-ntp-ntpv5-07` Section 5. Servers that respond with the
            /// magic value transition to V5 mode; others stay on V4.
            ///
            /// Requires the `ntpv5` feature.
            #[cfg(feature = "ntpv5")]
            pub fn ntpv5(mut self, enable: bool) -> Self {
                self.enable_ntpv5 = enable;
                self
            }

            /// Convert this builder into a runtime-independent build configuration.
            ///
            /// Validates and clamps poll intervals. Does NOT validate that servers
            /// is non-empty (NTS servers may be added runtime-specifically).
            pub(crate) fn into_config(
                self,
            ) -> $crate::client_common::ClientBuildConfig {
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

                #[cfg(feature = "discipline")]
                let enable_discipline = self.enable_discipline;
                #[cfg(not(feature = "discipline"))]
                let enable_discipline = false;

                #[cfg(feature = "ntpv5")]
                let enable_ntpv5 = self.enable_ntpv5;
                #[cfg(not(feature = "ntpv5"))]
                let enable_ntpv5 = false;

                $crate::client_common::ClientBuildConfig {
                    servers: self.servers,
                    min_poll,
                    max_poll,
                    initial_poll,
                    socket_opts: self.socket_opts,
                    enable_discipline,
                    enable_ntpv5,
                }
            }
        }
    };
}
pub(crate) use define_client_builder;

#[cfg(test)]
#[allow(unreachable_pub, dead_code)]
mod tests {
    use super::*;

    // ── PeerState ────────────────────────────────────────────────

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

    // ── classify_and_compute ─────────────────────────────────────

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

        let (sample, interleaved) = classify_and_compute(&response, t4, t1, None, None).unwrap();
        assert!(!interleaved);
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

        let (sample, interleaved) =
            classify_and_compute(&response, t4, current_t1, Some(prev_t1), Some(prev_t4)).unwrap();
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

    #[test]
    fn test_classify_mismatch_with_prev_values() {
        // Origin doesn't match current OR previous T1.
        let current_t1 = protocol::TimestampFormat {
            seconds: 100,
            fraction: 0,
        };
        let prev_t1 = protocol::TimestampFormat {
            seconds: 90,
            fraction: 0,
        };
        let prev_t4 = protocol::TimestampFormat {
            seconds: 91,
            fraction: 0,
        };
        let t4 = protocol::TimestampFormat {
            seconds: 101,
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
                seconds: 999,
                fraction: 0,
            },
            receive_timestamp: protocol::TimestampFormat::default(),
            transmit_timestamp: protocol::TimestampFormat {
                seconds: 1,
                fraction: 0,
            },
        };

        let result = classify_and_compute(&response, t4, current_t1, Some(prev_t1), Some(prev_t4));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("origin timestamp mismatch")
        );
    }

    // ── NtpSyncState ─────────────────────────────────────────────

    #[cfg(feature = "ntpv5")]
    #[test]
    fn test_peer_state_new_v5_starts_negotiating() {
        let peer = PeerState::new_v5("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        assert!(peer.v5_state.is_some());
        match peer.v5_state.as_ref().unwrap() {
            NtpV5PeerState::Negotiating { attempts } => assert_eq!(*attempts, 0),
            _ => panic!("expected Negotiating state"),
        }
    }

    #[cfg(feature = "ntpv5")]
    #[test]
    fn test_peer_state_new_has_no_v5_state() {
        let peer = PeerState::new("127.0.0.1:123".parse().unwrap(), protocol::MINPOLL);
        assert!(peer.v5_state.is_none());
    }

    // ── short_format_to_secs ──────────────────────────────────────

    #[test]
    fn test_short_format_to_secs_zero() {
        let sf = protocol::ShortFormat {
            seconds: 0,
            fraction: 0,
        };
        assert_eq!(short_format_to_secs(&sf), 0.0);
    }

    #[test]
    fn test_short_format_to_secs_one_second() {
        let sf = protocol::ShortFormat {
            seconds: 1,
            fraction: 0,
        };
        assert_eq!(short_format_to_secs(&sf), 1.0);
    }

    #[test]
    fn test_short_format_to_secs_half_second() {
        let sf = protocol::ShortFormat {
            seconds: 0,
            fraction: 32768,
        };
        assert!((short_format_to_secs(&sf) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_short_format_to_secs_mixed() {
        let sf = protocol::ShortFormat {
            seconds: 2,
            fraction: 16384,
        };
        assert!((short_format_to_secs(&sf) - 2.25).abs() < 1e-6);
    }

    // ── select_and_build_state ─────────────────────────────────────

    #[test]
    fn test_select_and_build_state_empty_peers() {
        let mut peers: Vec<PeerState> = vec![];
        let result = select_and_build_state(&mut peers, 0, 0.0, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_and_build_state_no_samples() {
        let mut peers = vec![PeerState::new("127.0.0.1:123".parse().unwrap(), 4)];
        let result = select_and_build_state(&mut peers, 0, 0.0, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_and_build_state_single_peer_with_sample() {
        let mut peers = vec![PeerState::new("127.0.0.1:123".parse().unwrap(), 4)];
        peers[0].filter.add(0.005, 0.020);
        peers[0].stratum = Some(protocol::Stratum(2));
        peers[0].root_delay_secs = 0.001;
        peers[0].root_dispersion_secs = 0.002;

        let result = select_and_build_state(&mut peers, 1, 0.0, None);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!((r.offset - 0.005).abs() < 1e-9);
        assert_eq!(r.state.stratum, 2);
        assert_eq!(r.state.total_responses, 1);
        assert_eq!(r.state.system_peer_count, 1);
    }

    #[test]
    fn test_select_and_build_state_demobilized_peer_excluded() {
        let mut peers = vec![PeerState::new("127.0.0.1:123".parse().unwrap(), 4)];
        peers[0].filter.add(0.005, 0.020);
        peers[0].stratum = Some(protocol::Stratum(2));
        peers[0].demobilized = true;

        let result = select_and_build_state(&mut peers, 1, 0.0, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_and_build_state_two_peers_picks_best() {
        let mut peers = vec![
            PeerState::new("127.0.0.1:123".parse().unwrap(), 4),
            PeerState::new("127.0.0.2:123".parse().unwrap(), 4),
        ];
        peers[0].filter.add(0.010, 0.100);
        peers[0].stratum = Some(protocol::Stratum(2));
        peers[0].root_delay_secs = 0.050;
        peers[0].root_dispersion_secs = 0.010;

        peers[1].filter.add(0.002, 0.020);
        peers[1].stratum = Some(protocol::Stratum(2));
        peers[1].root_delay_secs = 0.010;
        peers[1].root_dispersion_secs = 0.005;

        let result = select_and_build_state(&mut peers, 2, 0.0, None);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!((r.offset - 0.002).abs() < 1e-9);
        assert_eq!(r.state.system_peer_count, 2);
    }

    // ── NtpSyncState ─────────────────────────────────────────────

    #[test]
    fn test_sync_state_default() {
        let state = NtpSyncState::default();
        assert_eq!(state.offset, 0.0);
        assert_eq!(state.delay, 0.0);
        assert_eq!(state.jitter, 0.0);
        assert_eq!(state.stratum, protocol::MAXSTRAT);
        assert!(!state.interleaved);
        assert_eq!(state.total_responses, 0);
        assert!(!state.nts_authenticated);
        assert_eq!(state.root_delay, 0.0);
        assert_eq!(state.root_dispersion, 0.0);
        assert_eq!(state.system_peer_count, 0);
        assert_eq!(state.frequency, 0.0);
        assert!(state.discipline_state.is_none());
    }

    // ── Builder into_config() ───────────────────────────────────

    // Invoke the macro with empty extras for standalone testing.
    // The macro generates `pub` items which trigger unreachable_pub inside tests.
    define_client_builder! {
        /// Test-only builder.
        extra_fields {}
        extra_defaults {}
    }

    #[test]
    fn test_client_into_config_defaults() {
        let cfg = NtpClientBuilder::new().into_config();
        assert!(cfg.servers.is_empty());
        assert_eq!(cfg.min_poll, protocol::MINPOLL);
        assert_eq!(cfg.max_poll, protocol::MAXPOLL);
        assert_eq!(cfg.initial_poll, protocol::MINPOLL);
        assert!(!cfg.enable_discipline);
        assert!(!cfg.enable_ntpv5);
    }

    #[test]
    fn test_client_into_config_servers() {
        let cfg = NtpClientBuilder::new()
            .server("time.nist.gov")
            .into_config();
        assert_eq!(cfg.servers, vec!["time.nist.gov"]);
    }

    #[test]
    fn test_client_into_config_poll_clamping() {
        // max_poll < min_poll should be floored to min_poll.
        let cfg = NtpClientBuilder::new()
            .min_poll(8)
            .max_poll(6)
            .into_config();
        assert_eq!(cfg.min_poll, 8);
        assert_eq!(cfg.max_poll, 8);
    }

    #[test]
    fn test_client_into_config_initial_defaults_to_min() {
        let cfg = NtpClientBuilder::new()
            .min_poll(6)
            .max_poll(10)
            .into_config();
        assert_eq!(cfg.initial_poll, 6);
    }

    #[test]
    fn test_client_into_config_initial_clamped_high() {
        let cfg = NtpClientBuilder::new()
            .min_poll(6)
            .max_poll(10)
            .initial_poll(15)
            .into_config();
        assert_eq!(cfg.initial_poll, 10);
    }

    #[test]
    fn test_client_into_config_initial_clamped_low() {
        let cfg = NtpClientBuilder::new()
            .min_poll(6)
            .max_poll(10)
            .initial_poll(3)
            .into_config();
        assert_eq!(cfg.initial_poll, 6);
    }

    #[test]
    fn test_client_into_config_multiple_servers() {
        let cfg = NtpClientBuilder::new()
            .server("time.nist.gov")
            .server("time.cloudflare.com")
            .server("time.google.com")
            .into_config();
        assert_eq!(cfg.servers.len(), 3);
        assert_eq!(cfg.servers[0], "time.nist.gov");
        assert_eq!(cfg.servers[2], "time.google.com");
    }
}
