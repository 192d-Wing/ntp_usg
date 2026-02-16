// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Clock sample filtering for the continuous NTP client.
//!
//! Implements a simplified version of the RFC 5905 Section 10 clock filter
//! algorithm, maintaining a window of recent samples sorted by delay to
//! select the best offset estimate.

/// Number of samples retained in the filter window.
pub const FILTER_SIZE: usize = 8;

/// A single clock sample from an NTP exchange.
#[derive(Clone, Copy, Debug)]
pub struct ClockSample {
    /// Clock offset in seconds (positive = local clock behind server).
    pub offset: f64,
    /// Round-trip delay in seconds.
    pub delay: f64,
    /// Age of this sample in seconds since it was recorded.
    pub age: f64,
}

/// A moving-window clock filter that retains the last [`FILTER_SIZE`] samples.
///
/// Samples are stored in arrival order. The "best" sample is selected as
/// the one with the minimum delay (closest to the true offset per RFC 5905
/// Section 10). Jitter is computed as the RMS of offset differences from
/// the best sample.
#[derive(Debug)]
pub struct SampleFilter {
    samples: [Option<ClockSample>; FILTER_SIZE],
    next_idx: usize,
    count: u64,
}

impl SampleFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        SampleFilter {
            samples: [None; FILTER_SIZE],
            next_idx: 0,
            count: 0,
        }
    }

    /// Add a new sample to the filter, overwriting the oldest if full.
    pub fn add(&mut self, offset: f64, delay: f64) {
        self.samples[self.next_idx] = Some(ClockSample {
            offset,
            delay,
            age: 0.0,
        });
        self.next_idx = (self.next_idx + 1) % FILTER_SIZE;
        self.count += 1;
    }

    /// Returns the best sample (minimum delay) if any samples exist.
    pub fn best_sample(&self) -> Option<&ClockSample> {
        self.samples.iter().flatten().min_by(|a, b| {
            a.delay
                .partial_cmp(&b.delay)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Compute the peer jitter: RMS of offset differences from the best sample.
    ///
    /// Returns 0.0 if fewer than 2 samples are present.
    pub fn jitter(&self) -> f64 {
        let best = match self.best_sample() {
            Some(s) => s,
            None => return 0.0,
        };
        let valid: Vec<&ClockSample> = self.samples.iter().flatten().collect();
        if valid.len() < 2 {
            return 0.0;
        }
        let sum_sq: f64 = valid
            .iter()
            .map(|s| {
                let diff = s.offset - best.offset;
                diff * diff
            })
            .sum();
        (sum_sq / (valid.len() - 1) as f64).sqrt()
    }

    /// Returns the number of valid samples currently in the filter.
    pub fn len(&self) -> usize {
        self.samples.iter().filter(|s| s.is_some()).count()
    }

    /// Returns true if no samples have been added.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SampleFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter() {
        let f = SampleFilter::new();
        assert!(f.is_empty());
        assert_eq!(f.len(), 0);
        assert!(f.best_sample().is_none());
        assert_eq!(f.jitter(), 0.0);
    }

    #[test]
    fn test_single_sample() {
        let mut f = SampleFilter::new();
        f.add(0.005, 0.050);
        assert_eq!(f.len(), 1);
        assert!(!f.is_empty());
        let best = f.best_sample().unwrap();
        assert_eq!(best.offset, 0.005);
        assert_eq!(best.delay, 0.050);
        assert_eq!(f.jitter(), 0.0);
    }

    #[test]
    fn test_min_delay_selection() {
        let mut f = SampleFilter::new();
        f.add(0.010, 0.100); // delay 100ms
        f.add(0.005, 0.020); // delay 20ms (best)
        f.add(0.008, 0.050); // delay 50ms
        f.add(0.012, 0.200); // delay 200ms
        let best = f.best_sample().unwrap();
        assert_eq!(best.delay, 0.020);
        assert_eq!(best.offset, 0.005);
    }

    #[test]
    fn test_circular_overwrite() {
        let mut f = SampleFilter::new();
        // Add more than FILTER_SIZE samples.
        for i in 0..12 {
            f.add(i as f64 * 0.001, 0.050 + i as f64 * 0.001);
        }
        // Only the last 8 samples should remain.
        assert_eq!(f.len(), FILTER_SIZE);
        // The oldest remaining sample is i=4 (offset 0.004, delay 0.054).
        let best = f.best_sample().unwrap();
        assert!((best.delay - 0.054).abs() < 1e-10);
    }

    #[test]
    fn test_jitter_computation() {
        let mut f = SampleFilter::new();
        // Add samples with known offsets. Best has delay 0.010.
        f.add(0.100, 0.010); // best (min delay), offset 0.100
        f.add(0.110, 0.020); // diff = 0.010
        f.add(0.090, 0.030); // diff = -0.010
        f.add(0.120, 0.040); // diff = 0.020

        let jitter = f.jitter();
        // sum_sq = 0 + 0.01^2 + 0.01^2 + 0.02^2 = 0 + 0.0001 + 0.0001 + 0.0004 = 0.0006
        // jitter = sqrt(0.0006 / 3) = sqrt(0.0002) ≈ 0.01414
        let expected = (0.0006_f64 / 3.0).sqrt();
        assert!(
            (jitter - expected).abs() < 1e-10,
            "jitter={jitter}, expected={expected}"
        );
    }

    #[test]
    fn test_default() {
        let f = SampleFilter::default();
        assert!(f.is_empty());
    }

    #[test]
    fn test_exactly_filter_size_samples() {
        let mut f = SampleFilter::new();
        for i in 0..FILTER_SIZE {
            f.add(i as f64 * 0.001, 0.050 + i as f64 * 0.001);
        }
        assert_eq!(f.len(), FILTER_SIZE);
        // First sample (i=0) has minimum delay 0.050.
        let best = f.best_sample().unwrap();
        assert!((best.delay - 0.050).abs() < 1e-10);
    }

    #[test]
    fn test_identical_delays() {
        let mut f = SampleFilter::new();
        f.add(0.010, 0.050);
        f.add(0.020, 0.050);
        f.add(0.030, 0.050);
        // All delays equal — best_sample should return one of them.
        let best = f.best_sample().unwrap();
        assert_eq!(best.delay, 0.050);
    }

    #[test]
    fn test_identical_samples_zero_jitter() {
        let mut f = SampleFilter::new();
        for _ in 0..4 {
            f.add(0.005, 0.050);
        }
        // All offsets identical → jitter should be 0.
        assert!(f.jitter().abs() < 1e-15);
    }

    #[test]
    fn test_negative_offsets() {
        let mut f = SampleFilter::new();
        f.add(-0.010, 0.050);
        f.add(-0.005, 0.030); // best (min delay)
        let best = f.best_sample().unwrap();
        assert_eq!(best.offset, -0.005);
    }

    #[test]
    fn test_nan_delay_does_not_panic() {
        let mut f = SampleFilter::new();
        f.add(0.005, f64::NAN);
        f.add(0.010, 0.050);
        // NaN delay should not panic; best_sample returns Some.
        let best = f.best_sample();
        assert!(best.is_some());
    }

    #[test]
    fn test_len_consistency() {
        let mut f = SampleFilter::new();
        for i in 0..20 {
            f.add(0.0, 0.0);
            let expected = (i + 1).min(FILTER_SIZE);
            assert_eq!(f.len(), expected, "len wrong after {i} additions");
        }
    }
}
