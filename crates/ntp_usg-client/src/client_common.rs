// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared types and logic for the continuous NTP client, used by both the
//! tokio-based [`crate::client`] and smol-based [`crate::smol_client`] modules.
//!
//! Provides peer state management, poll interval adaptation, reachability
//! tracking, response classification (basic vs interleaved mode), the
//! RFC 5905 Section 11.2 selection/clustering/combining pipeline, and
//! the `NtpSyncState` published to consumers.

use log::debug;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::filter::{ClockSample, SampleFilter};
use crate::request::compute_offset_delay;
use crate::selection::{self, PeerCandidate};
use crate::{KissOfDeathError, protocol, unix_time};

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
    /// Current discipline state (e.g., "Nset", "Fset", "Sync", "Spik").
    /// Only populated when the `discipline` feature is enabled.
    pub discipline_state: String,
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
            discipline_state: String::new(),
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
}

/// Check if an I/O error contains a Kiss-o'-Death code and return the
/// appropriate [`PollResult`].
pub(crate) fn check_kod(e: &io::Error) -> Option<PollResult> {
    let kod = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<KissOfDeathError>())?;
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
    discipline_state: String,
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
                .unwrap();
            let peer = &peers[*best_idx];
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
                    .unwrap();
                let peer = &peers[*best_idx];
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
                        let sys_peer = &peers[est.system_peer_index];
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

#[cfg(test)]
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
                .contains("neither basic nor interleaved")
        );
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
        assert!(state.discipline_state.is_empty());
    }
}
