#![cfg(feature = "tokio")]

use ntp_client::filter::{SampleFilter, FILTER_SIZE};
use proptest::prelude::*;

proptest! {
    /// Filter length is always bounded by FILTER_SIZE.
    #[test]
    fn filter_len_bounded(
        offsets in prop::collection::vec(-1.0f64..1.0, 0..50),
        delays in prop::collection::vec(0.001f64..1.0, 0..50),
    ) {
        let mut f = SampleFilter::new();
        let n = offsets.len().min(delays.len());
        for i in 0..n {
            f.add(offsets[i], delays[i]);
            prop_assert!(f.len() <= FILTER_SIZE);
        }
    }

    /// best_sample always returns the sample with minimum delay among stored samples.
    #[test]
    fn filter_best_is_min_delay(
        offsets in prop::collection::vec(-1.0f64..1.0, 1..20),
        delays in prop::collection::vec(0.001f64..1.0, 1..20),
    ) {
        let mut f = SampleFilter::new();
        let n = offsets.len().min(delays.len());
        for i in 0..n {
            f.add(offsets[i], delays[i]);
        }
        if let Some(best) = f.best_sample() {
            let sorted = f.sorted_by_distance();
            for sample in &sorted {
                prop_assert!(
                    best.delay <= sample.delay || best.delay.is_nan() || sample.delay.is_nan(),
                    "best delay {} > sample delay {}",
                    best.delay,
                    sample.delay,
                );
            }
        }
    }

    /// Jitter is always non-negative.
    #[test]
    fn filter_jitter_non_negative(
        offsets in prop::collection::vec(-10.0f64..10.0, 0..20),
        delays in prop::collection::vec(0.001f64..1.0, 0..20),
    ) {
        let mut f = SampleFilter::new();
        let n = offsets.len().min(delays.len());
        for i in 0..n {
            f.add(offsets[i], delays[i]);
        }
        prop_assert!(f.jitter() >= 0.0, "jitter was {}", f.jitter());
    }
}
