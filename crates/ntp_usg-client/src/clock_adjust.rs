// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Clock adjustment process per RFC 5905 Section 12.
//!
//! Implements the periodic 1-second process that drains residual phase error
//! and applies the current frequency correction to the system clock. This
//! module works in conjunction with [`discipline`](crate::discipline) and
//! [`clock`](crate::clock).
//!
//! The adjuster accumulates phase and frequency corrections from the
//! discipline loop and emits per-tick adjustments suitable for
//! [`clock::slew_clock()`](crate::clock::slew_clock).

/// Time constant for draining residual phase (seconds).
/// Controls how quickly residual offset is applied; higher = slower drain.
const PHASE_DRAIN_TC: f64 = 16.0;

/// The periodic clock adjustment state.
///
/// Tracks residual phase correction and current frequency, producing
/// per-second adjustments for the system clock.
#[derive(Debug)]
pub struct ClockAdjuster {
    /// Residual phase correction remaining to be applied (seconds).
    residual: f64,
    /// Current frequency correction (seconds/second).
    frequency: f64,
}

impl ClockAdjuster {
    /// Create a new adjuster with no pending corrections.
    pub fn new() -> Self {
        ClockAdjuster {
            residual: 0.0,
            frequency: 0.0,
        }
    }

    /// Set a new correction from the discipline loop.
    ///
    /// * `phase` — Phase offset to drain over subsequent ticks (seconds).
    /// * `frequency` — Ongoing frequency correction (seconds/second).
    pub fn set_correction(&mut self, phase: f64, frequency: f64) {
        self.residual = phase;
        self.frequency = frequency;
    }

    /// Compute the adjustment to apply for this 1-second tick.
    ///
    /// Returns the total adjustment in seconds: a fraction of the residual
    /// phase plus the frequency correction. The residual is reduced by the
    /// drained amount.
    ///
    /// This should be called once per second and the result passed to
    /// [`clock::slew_clock()`](crate::clock::slew_clock).
    pub fn tick(&mut self) -> f64 {
        let phase_drain = self.residual / PHASE_DRAIN_TC;
        self.residual -= phase_drain;
        phase_drain + self.frequency
    }

    /// Get the remaining residual phase correction.
    pub fn residual(&self) -> f64 {
        self.residual
    }

    /// Get the current frequency correction.
    pub fn frequency(&self) -> f64 {
        self.frequency
    }
}

impl Default for ClockAdjuster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_adjuster() {
        let mut adj = ClockAdjuster::new();
        assert_eq!(adj.residual(), 0.0);
        assert_eq!(adj.frequency(), 0.0);
        assert_eq!(adj.tick(), 0.0);
    }

    #[test]
    fn test_set_correction() {
        let mut adj = ClockAdjuster::new();
        adj.set_correction(0.100, 10e-6);
        assert_eq!(adj.residual(), 0.100);
        assert_eq!(adj.frequency(), 10e-6);
    }

    #[test]
    fn test_phase_drain() {
        let mut adj = ClockAdjuster::new();
        adj.set_correction(1.0, 0.0); // 1 second of phase, no frequency

        // First tick drains 1/PHASE_DRAIN_TC of the residual.
        let tick1 = adj.tick();
        let expected = 1.0 / PHASE_DRAIN_TC;
        assert!(
            (tick1 - expected).abs() < 1e-12,
            "tick1={tick1}, expected={expected}"
        );

        // Residual should be reduced.
        let remaining = adj.residual();
        assert!(
            (remaining - (1.0 - expected)).abs() < 1e-12,
            "remaining={remaining}"
        );
    }

    #[test]
    fn test_phase_converges_to_zero() {
        let mut adj = ClockAdjuster::new();
        adj.set_correction(1.0, 0.0);

        // After many ticks, residual should approach zero.
        for _ in 0..1000 {
            adj.tick();
        }
        assert!(
            adj.residual().abs() < 1e-10,
            "residual should converge: {}",
            adj.residual()
        );
    }

    #[test]
    fn test_frequency_constant() {
        let mut adj = ClockAdjuster::new();
        adj.set_correction(0.0, 10e-6); // Frequency only, no phase

        // Each tick should return exactly the frequency.
        for _ in 0..10 {
            let tick = adj.tick();
            assert!(
                (tick - 10e-6).abs() < 1e-15,
                "tick should equal frequency: {tick}"
            );
        }
    }

    #[test]
    fn test_combined_phase_and_frequency() {
        let mut adj = ClockAdjuster::new();
        adj.set_correction(0.100, 5e-6);

        let tick = adj.tick();
        let expected_phase_drain = 0.100 / PHASE_DRAIN_TC;
        let expected = expected_phase_drain + 5e-6;
        assert!(
            (tick - expected).abs() < 1e-12,
            "tick={tick}, expected={expected}"
        );
    }

    #[test]
    fn test_set_correction_replaces_previous() {
        let mut adj = ClockAdjuster::new();
        adj.set_correction(1.0, 10e-6);
        adj.tick(); // Drain some
        adj.set_correction(0.5, 5e-6); // Replace
        assert_eq!(adj.residual(), 0.5);
        assert_eq!(adj.frequency(), 5e-6);
    }

    #[test]
    fn test_default() {
        let adj = ClockAdjuster::default();
        assert_eq!(adj.residual(), 0.0);
    }
}
