#![cfg(feature = "tokio")]

use ntp_client::selection::{NMIN, PeerCandidate, cluster_survivors, combine, select_truechimers};
use proptest::prelude::*;

fn make_candidates(n: usize) -> Vec<PeerCandidate> {
    (0..n)
        .map(|i| PeerCandidate {
            peer_index: i,
            offset: 0.001 * i as f64,
            root_delay: 0.05,
            root_dispersion: 0.005,
            jitter: 0.001,
            stratum: 2,
        })
        .collect()
}

proptest! {
    /// select_truechimers returns only valid indices into the candidates slice.
    #[test]
    fn select_returns_valid_indices(n in 1usize..15) {
        let candidates = make_candidates(n);
        let result = select_truechimers(&candidates);
        for &idx in &result {
            prop_assert!(idx < candidates.len(), "index {} >= len {}", idx, candidates.len());
        }
    }

    /// cluster_survivors never drops below NMIN peers (if it started with >= NMIN).
    #[test]
    fn cluster_preserves_nmin(n in NMIN..15) {
        let mut candidates = make_candidates(n);
        cluster_survivors(&mut candidates);
        prop_assert!(
            candidates.len() >= NMIN,
            "dropped to {} < NMIN ({})",
            candidates.len(),
            NMIN,
        );
    }

    /// combine returns Some for non-empty input.
    #[test]
    fn combine_non_empty_returns_some(n in 1usize..10) {
        let survivors = make_candidates(n);
        let result = combine(&survivors);
        prop_assert!(result.is_some(), "combine returned None for {} survivors", n);
    }

    /// The combined offset falls within the range of survivor offsets.
    #[test]
    fn combine_offset_within_bounds(n in 2usize..10) {
        let survivors = make_candidates(n);
        let est = combine(&survivors).unwrap();
        let min_offset = survivors.iter().map(|c| c.offset).fold(f64::INFINITY, f64::min);
        let max_offset = survivors.iter().map(|c| c.offset).fold(f64::NEG_INFINITY, f64::max);
        prop_assert!(
            est.offset >= min_offset - 1e-10 && est.offset <= max_offset + 1e-10,
            "offset {} not in [{}, {}]",
            est.offset,
            min_offset,
            max_offset,
        );
    }
}
