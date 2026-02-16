// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Peer selection, clustering, and combining algorithms per RFC 5905 Section 11.2.
//!
//! The system process runs the following three-stage pipeline after each
//! successful poll to produce the final system offset estimate:
//!
//! 1. **Selection** ([`select_truechimers`]) — Marzullo's algorithm identifies
//!    "truechimer" peers whose correctness intervals overlap with a majority.
//! 2. **Clustering** ([`cluster_survivors`]) — Iteratively removes the outlier
//!    with the highest selection jitter until the remaining set is tight.
//! 3. **Combining** ([`combine`]) — Produces a weighted-average offset from
//!    the surviving peers, weighted inversely by root distance.

/// Minimum number of survivors required after clustering (RFC 5905 Section 11.2.1).
pub const NMIN: usize = 3;

/// One candidate per reachable peer, constructed from [`PeerState`](super::PeerState)
/// and [`SampleFilter`](crate::filter::SampleFilter) data.
#[derive(Clone, Debug)]
pub struct PeerCandidate {
    /// Index into the client's peer list (for mapping back after selection).
    pub peer_index: usize,
    /// Best offset from the clock filter (theta, seconds).
    pub offset: f64,
    /// Root delay from the peer's last response (delta_r, seconds).
    pub root_delay: f64,
    /// Root dispersion from the peer's last response (epsilon_r, seconds).
    pub root_dispersion: f64,
    /// Peer jitter from the clock filter (psi, seconds).
    pub jitter: f64,
    /// Peer stratum.
    pub stratum: u8,
}

impl PeerCandidate {
    /// Root synchronization distance: `epsilon_r + delta_r/2 + jitter`.
    ///
    /// This defines the radius of the correctness interval used by the
    /// selection algorithm. Smaller values indicate a more trustworthy peer.
    pub fn root_distance(&self) -> f64 {
        self.root_dispersion + self.root_delay / 2.0 + self.jitter
    }
}

/// Output of the [`combine`] algorithm.
#[derive(Clone, Debug)]
pub struct CombinedEstimate {
    /// Weighted average system offset (theta_sys, seconds).
    pub offset: f64,
    /// Combined system jitter (psi_sys, seconds).
    pub jitter: f64,
    /// Index (into the original candidate slice) of the system peer
    /// (the survivor with the smallest root distance).
    pub system_peer_index: usize,
}

/// Run the selection algorithm (Marzullo variant) per RFC 5905 Section 11.2.1.
///
/// For each candidate, the correctness interval is
/// `[offset - root_distance, offset + root_distance]`.
/// The algorithm finds the largest intersection containing a majority of peers
/// and returns the indices of candidates whose midpoints lie within it.
///
/// Returns an empty `Vec` if no valid intersection exists (i.e., no majority
/// of peers agrees on a common time interval).
pub fn select_truechimers(candidates: &[PeerCandidate]) -> Vec<usize> {
    let n = candidates.len();
    if n == 0 {
        return Vec::new();
    }

    // Build sorted endpoint list.
    // Each candidate contributes three endpoints: low (-1), midpoint (0), high (+1).
    // The type tag determines sort order when offsets are equal.
    let mut endpoints: Vec<(f64, i8)> = Vec::with_capacity(n * 3);
    for c in candidates {
        let rd = c.root_distance();
        endpoints.push((c.offset - rd, -1)); // low
        endpoints.push((c.offset, 0)); // midpoint
        endpoints.push((c.offset + rd, 1)); // high
    }

    // Sort by offset value, breaking ties: low < midpoint < high.
    endpoints.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });

    // Try increasing numbers of falsetickers (f = 0, 1, 2, ...).
    // We need at least n - f endpoints overlapping (a majority: f < n/2).
    let mut f = 0;
    while f * 2 < n {
        let required = (n - f) as i32;
        let mut count: i32 = 0;
        let mut low = f64::NEG_INFINITY;
        let mut high = f64::INFINITY;
        let mut found_low = false;

        for &(value, tag) in &endpoints {
            match tag {
                -1 => {
                    // Low endpoint: one more interval is active.
                    count += 1;
                    if count >= required && !found_low {
                        low = value;
                        found_low = true;
                    }
                }
                1 => {
                    // High endpoint: one interval ends.
                    if count >= required {
                        high = value;
                    }
                    count -= 1;
                }
                _ => {} // midpoint: ignore for counting
            }
        }

        if found_low && low <= high {
            // Valid intersection [low, high] found.
            // Return candidates whose midpoint (offset) falls within the interval.
            return candidates
                .iter()
                .enumerate()
                .filter(|(_, c)| c.offset >= low && c.offset <= high)
                .map(|(i, _)| i)
                .collect();
        }

        f += 1;
    }

    // No valid intersection found.
    Vec::new()
}

/// Run the cluster algorithm per RFC 5905 Section 11.2.2.
///
/// Iteratively removes the candidate with the highest "selection jitter"
/// (RMS of offset differences to all other survivors) until:
/// - The maximum selection jitter is no greater than the minimum peer jitter, or
/// - Only [`NMIN`] candidates remain.
///
/// Modifies `candidates` in place by removing outliers from the end.
pub fn cluster_survivors(candidates: &mut Vec<PeerCandidate>) {
    loop {
        if candidates.len() <= NMIN {
            break;
        }

        // Compute selection jitter for each candidate.
        let sel_jitters: Vec<f64> = (0..candidates.len())
            .map(|i| selection_jitter(candidates, i))
            .collect();

        // Find the candidate with maximum selection jitter.
        let (max_idx, &max_sel_jitter) = sel_jitters
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();

        // Find the minimum peer jitter among all candidates.
        let min_peer_jitter = candidates
            .iter()
            .map(|c| c.jitter)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0);

        // Stop if the cluster is already tight enough.
        if max_sel_jitter <= min_peer_jitter {
            break;
        }

        // Remove the outlier.
        candidates.remove(max_idx);
    }
}

/// Compute the selection jitter for candidate `idx`: the RMS of offset
/// differences between this candidate and all other candidates.
fn selection_jitter(candidates: &[PeerCandidate], idx: usize) -> f64 {
    let n = candidates.len();
    if n <= 1 {
        return 0.0;
    }
    let offset_i = candidates[idx].offset;
    let sum_sq: f64 = candidates
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != idx)
        .map(|(_, c)| {
            let diff = c.offset - offset_i;
            diff * diff
        })
        .sum();
    (sum_sq / (n - 1) as f64).sqrt()
}

/// Combine surviving peers into a single system estimate per RFC 5905
/// Section 11.2.3.
///
/// Each survivor's contribution is weighted inversely by its root distance.
/// The system peer is the survivor with the minimum root distance.
///
/// Returns `None` if `survivors` is empty.
pub fn combine(survivors: &[PeerCandidate]) -> Option<CombinedEstimate> {
    if survivors.is_empty() {
        return None;
    }

    // Single survivor: no weighting needed.
    if survivors.len() == 1 {
        return Some(CombinedEstimate {
            offset: survivors[0].offset,
            jitter: survivors[0].jitter,
            system_peer_index: survivors[0].peer_index,
        });
    }

    // Compute weights (inverse root distance).
    let weights: Vec<f64> = survivors
        .iter()
        .map(|c| {
            let rd = c.root_distance();
            if rd > 0.0 { 1.0 / rd } else { 1.0 }
        })
        .collect();
    let total_weight: f64 = weights.iter().sum();

    if total_weight <= 0.0 {
        // Degenerate case: all root distances are zero or negative. Use simple average.
        let avg_offset = survivors.iter().map(|c| c.offset).sum::<f64>() / survivors.len() as f64;
        let system_peer = survivors
            .iter()
            .min_by(|a, b| {
                a.root_distance()
                    .partial_cmp(&b.root_distance())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();
        return Some(CombinedEstimate {
            offset: avg_offset,
            jitter: system_peer.jitter,
            system_peer_index: system_peer.peer_index,
        });
    }

    // Weighted average offset.
    let offset: f64 = survivors
        .iter()
        .zip(&weights)
        .map(|(c, &w)| w * c.offset)
        .sum::<f64>()
        / total_weight;

    // Combined jitter: weighted RMS of offset differences from the weighted mean.
    let jitter_sq: f64 = survivors
        .iter()
        .zip(&weights)
        .map(|(c, &w)| {
            let diff = c.offset - offset;
            w * diff * diff
        })
        .sum::<f64>()
        / total_weight;
    let jitter = jitter_sq.sqrt();

    // System peer: minimum root distance.
    let system_peer = survivors
        .iter()
        .min_by(|a, b| {
            a.root_distance()
                .partial_cmp(&b.root_distance())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap();

    Some(CombinedEstimate {
        offset,
        jitter,
        system_peer_index: system_peer.peer_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(
        idx: usize,
        offset: f64,
        root_delay: f64,
        root_disp: f64,
        jitter: f64,
    ) -> PeerCandidate {
        PeerCandidate {
            peer_index: idx,
            offset,
            root_delay,
            root_dispersion: root_disp,
            jitter,
            stratum: 2,
        }
    }

    // ── select_truechimers ──────────────────────────────────────

    #[test]
    fn test_select_empty() {
        assert!(select_truechimers(&[]).is_empty());
    }

    #[test]
    fn test_select_single_peer() {
        let candidates = vec![make_candidate(0, 0.010, 0.050, 0.005, 0.001)];
        let result = select_truechimers(&candidates);
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn test_select_three_agreeing_peers() {
        let candidates = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.011, 0.050, 0.005, 0.001),
            make_candidate(2, 0.009, 0.050, 0.005, 0.001),
        ];
        let result = select_truechimers(&candidates);
        assert_eq!(
            result.len(),
            3,
            "all 3 agreeing peers should be truechimers"
        );
    }

    #[test]
    fn test_select_falseticker_excluded() {
        let candidates = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.011, 0.050, 0.005, 0.001),
            make_candidate(2, 0.009, 0.050, 0.005, 0.001),
            make_candidate(3, 5.000, 0.050, 0.005, 0.001), // way off
        ];
        let result = select_truechimers(&candidates);
        assert!(result.len() >= 3, "at least 3 truechimers");
        assert!(!result.contains(&3), "falseticker should be excluded");
    }

    #[test]
    fn test_select_all_disagree() {
        // Peers with very tight intervals that don't overlap each other.
        let candidates = vec![
            make_candidate(0, 0.0, 0.001, 0.0001, 0.0001),
            make_candidate(1, 10.0, 0.001, 0.0001, 0.0001),
            make_candidate(2, -10.0, 0.001, 0.0001, 0.0001),
        ];
        let result = select_truechimers(&candidates);
        // No majority overlap possible.
        assert!(result.is_empty() || result.len() == 1);
    }

    #[test]
    fn test_select_two_peers() {
        let candidates = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.011, 0.050, 0.005, 0.001),
        ];
        let result = select_truechimers(&candidates);
        assert_eq!(result.len(), 2, "2 overlapping peers should both pass");
    }

    // ── cluster_survivors ──────────────────────────────────────

    #[test]
    fn test_cluster_nmin_floor() {
        let mut candidates = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.011, 0.050, 0.005, 0.001),
            make_candidate(2, 0.009, 0.050, 0.005, 0.001),
        ];
        cluster_survivors(&mut candidates);
        assert_eq!(candidates.len(), NMIN, "should not drop below NMIN");
    }

    #[test]
    fn test_cluster_removes_outlier() {
        let mut candidates = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.011, 0.050, 0.005, 0.001),
            make_candidate(2, 0.009, 0.050, 0.005, 0.001),
            make_candidate(3, 0.500, 0.050, 0.005, 0.001), // outlier
        ];
        cluster_survivors(&mut candidates);
        // The outlier (offset 0.5) should have the highest selection jitter
        // and be removed, leaving 3 tight peers.
        assert!(candidates.len() <= 4);
        let offsets: Vec<f64> = candidates.iter().map(|c| c.offset).collect();
        assert!(
            offsets.iter().all(|&o| o < 0.1),
            "outlier should be removed: {offsets:?}"
        );
    }

    #[test]
    fn test_cluster_tight_group_unchanged() {
        let mut candidates = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.020),
            make_candidate(1, 0.011, 0.050, 0.005, 0.020),
            make_candidate(2, 0.009, 0.050, 0.005, 0.020),
            make_candidate(3, 0.012, 0.050, 0.005, 0.020),
        ];
        cluster_survivors(&mut candidates);
        // All offsets are very close (within 0.003), peer jitter is 0.020.
        // Selection jitter for each peer is tiny compared to peer jitter,
        // so no one should be removed.
        assert_eq!(candidates.len(), 4);
    }

    // ── combine ──────────────────────────────────────────────

    #[test]
    fn test_combine_empty() {
        assert!(combine(&[]).is_none());
    }

    #[test]
    fn test_combine_single() {
        let survivors = vec![make_candidate(7, 0.010, 0.050, 0.005, 0.001)];
        let est = combine(&survivors).unwrap();
        assert_eq!(est.offset, 0.010);
        assert_eq!(est.jitter, 0.001);
        assert_eq!(est.system_peer_index, 7);
    }

    #[test]
    fn test_combine_two_equal_weight() {
        let survivors = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.020, 0.050, 0.005, 0.001),
        ];
        let est = combine(&survivors).unwrap();
        // Equal root distances → equal weights → arithmetic mean.
        assert!(
            (est.offset - 0.015).abs() < 1e-9,
            "expected ~0.015, got {}",
            est.offset
        );
    }

    #[test]
    fn test_combine_weighted() {
        // Peer 0: root_distance ≈ 0.005 + 0.025 + 0.001 = 0.031 → weight ≈ 32.26
        // Peer 1: root_distance ≈ 0.005 + 0.100 + 0.001 = 0.106 → weight ≈ 9.43
        // Weighted offset ≈ (32.26*0.010 + 9.43*0.020) / (32.26+9.43)
        //                 ≈ (0.3226 + 0.1886) / 41.69 ≈ 0.01226
        let survivors = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.020, 0.200, 0.005, 0.001),
        ];
        let est = combine(&survivors).unwrap();
        // Offset should be closer to peer 0 (lower root distance = higher weight).
        assert!(
            est.offset > 0.010 && est.offset < 0.015,
            "weighted offset should favor peer 0: got {}",
            est.offset
        );
        // System peer should be peer 0 (lower root distance).
        assert_eq!(est.system_peer_index, 0);
    }

    #[test]
    fn test_combine_jitter() {
        let survivors = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.020, 0.050, 0.005, 0.001),
        ];
        let est = combine(&survivors).unwrap();
        // Combined jitter should be non-zero since offsets differ.
        assert!(est.jitter > 0.0);
        // And less than the offset spread (0.010).
        assert!(est.jitter < 0.010);
    }

    // ── integration: full pipeline ──────────────────────────

    #[test]
    fn test_full_pipeline_three_good_one_bad() {
        let candidates = vec![
            make_candidate(0, 0.010, 0.050, 0.005, 0.001),
            make_candidate(1, 0.011, 0.050, 0.005, 0.001),
            make_candidate(2, 0.009, 0.050, 0.005, 0.001),
            make_candidate(3, 5.000, 0.050, 0.005, 0.001), // falseticker
        ];

        // Step 1: Select truechimers.
        let tc_indices = select_truechimers(&candidates);
        assert!(!tc_indices.contains(&3), "falseticker should be rejected");

        // Step 2: Build survivor list and cluster.
        let mut survivors: Vec<PeerCandidate> =
            tc_indices.iter().map(|&i| candidates[i].clone()).collect();
        cluster_survivors(&mut survivors);
        assert!(survivors.len() >= NMIN.min(tc_indices.len()));

        // Step 3: Combine.
        let estimate = combine(&survivors).unwrap();
        assert!(
            (estimate.offset - 0.010).abs() < 0.005,
            "combined offset should be near 0.010: got {}",
            estimate.offset
        );
    }

    #[test]
    fn test_full_pipeline_all_agree() {
        let candidates = vec![
            make_candidate(0, 0.100, 0.050, 0.005, 0.001),
            make_candidate(1, 0.101, 0.050, 0.005, 0.001),
            make_candidate(2, 0.099, 0.050, 0.005, 0.001),
            make_candidate(3, 0.100, 0.050, 0.005, 0.001),
            make_candidate(4, 0.102, 0.050, 0.005, 0.001),
        ];

        let tc_indices = select_truechimers(&candidates);
        assert_eq!(tc_indices.len(), 5, "all peers should be truechimers");

        let mut survivors: Vec<PeerCandidate> =
            tc_indices.iter().map(|&i| candidates[i].clone()).collect();
        cluster_survivors(&mut survivors);

        let estimate = combine(&survivors).unwrap();
        assert!(
            (estimate.offset - 0.100).abs() < 0.005,
            "combined offset should be near 0.100: got {}",
            estimate.offset
        );
    }

    // ── root_distance ────────────────────────────────────────

    #[test]
    fn test_root_distance() {
        let c = make_candidate(0, 0.0, 0.100, 0.005, 0.002);
        // root_distance = 0.005 + 0.100/2 + 0.002 = 0.005 + 0.050 + 0.002 = 0.057
        assert!(
            (c.root_distance() - 0.057).abs() < 1e-10,
            "root_distance = {}",
            c.root_distance()
        );
    }
}
