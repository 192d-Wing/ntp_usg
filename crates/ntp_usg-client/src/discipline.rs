// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Clock discipline algorithm per RFC 5905 Section 11.3.
//!
//! Implements a hybrid PLL/FLL (Phase-Locked Loop / Frequency-Locked Loop)
//! state machine that converts raw offset measurements from the selection
//! pipeline into phase and frequency corrections for the system clock.
//!
//! The discipline tracks four states:
//! - **Nset**: Initial state, waiting for the first offset measurement.
//! - **Fset**: Frequency learning, waiting for a second measurement to
//!   compute the initial frequency estimate.
//! - **Sync**: Normal operation with PLL/FLL hybrid corrections.
//! - **Spik**: Time spike detected; waiting for recovery or timeout.

/// Step threshold in seconds (RFC 5905 Section 11.3).
/// Offsets larger than this trigger the spike/step logic.
pub const STEPT: f64 = 0.128;

/// Stepout timeout in seconds (RFC 5905 Section 11.3).
/// If the offset exceeds STEPT for longer than WATCH seconds, a step is forced.
pub const WATCH: f64 = 900.0;

/// PLL gate: the jitter multiplier for determining when to clamp the
/// time constant (RFC 5905 Section 11.3).
pub const PGATE: f64 = 4.0;

/// Allan intercept in seconds (2^11 = 2048).
const ALLAN: f64 = 2048.0;

/// PLL gain factor.
const PLL_SCALE: f64 = 65536.0;

/// FLL gain factor.
const FLL_SCALE: f64 = 256.0;

/// Maximum frequency tolerance (seconds/second), same as `protocol::TOLERANCE`.
pub const FREQ_TOLERANCE: f64 = 15e-6;

/// Maximum allowed frequency offset (500 PPM). Corrections beyond this
/// indicate a broken clock and are clamped.
const FREQ_MAX: f64 = 500e-6;

pub use crate::DisciplineState;

/// Output of the discipline algorithm, describing the correction to apply.
#[derive(Clone, Debug)]
pub struct DisciplineOutput {
    /// Phase correction to apply (seconds).
    pub phase_correction: f64,
    /// Frequency correction to apply (seconds/second).
    pub frequency_correction: f64,
    /// Whether a step (immediate jump) is required instead of a slew.
    pub step: bool,
}

/// The clock discipline loop state machine.
///
/// Feed offset measurements from the system process (selection/combine)
/// via [`update()`](ClockDiscipline::update) to receive phase and frequency
/// corrections.
#[derive(Debug)]
pub struct ClockDiscipline {
    state: DisciplineState,
    /// Current frequency estimate (seconds/second).
    freq: f64,
    /// Last offset value for FLL computation.
    last_offset: f64,
    /// Monotonic time of last update (seconds since an arbitrary epoch).
    last_update: f64,
    /// PLL time constant (tracks poll exponent, clamped adaptively).
    tc: u8,
    /// Exponentially weighted jitter estimate.
    jitter: f64,
    /// Exponentially weighted frequency wander estimate.
    wander: f64,
    /// Time since the last "good" (non-spike) update, for stepout logic.
    spike_start: Option<f64>,
}

impl ClockDiscipline {
    /// Create a new discipline in the initial (Nset) state.
    pub fn new() -> Self {
        ClockDiscipline {
            state: DisciplineState::Nset,
            freq: 0.0,
            last_offset: 0.0,
            last_update: 0.0,
            tc: 4, // Start at MINPOLL
            jitter: 0.0,
            wander: 0.0,
            spike_start: None,
        }
    }

    /// Feed a new offset measurement from the combine algorithm.
    ///
    /// # Arguments
    ///
    /// * `offset` — System offset from [`combine()`](crate::selection::combine) (seconds).
    /// * `jitter` — System jitter from the combine algorithm (seconds).
    /// * `now` — Current monotonic time (seconds since an arbitrary epoch).
    /// * `poll_exponent` — Current poll interval exponent (log2 seconds).
    ///
    /// # Returns
    ///
    /// `Some(DisciplineOutput)` with the correction to apply, or `None` if
    /// the sample should be absorbed without producing a correction (e.g.,
    /// during the initial frequency learning phase).
    pub fn update(
        &mut self,
        offset: f64,
        jitter: f64,
        now: f64,
        poll_exponent: u8,
    ) -> Option<DisciplineOutput> {
        let mu = now - self.last_update;

        match self.state {
            DisciplineState::Nset => {
                // First measurement: record and transition to Fset.
                self.last_offset = offset;
                self.last_update = now;
                self.jitter = jitter;
                self.state = DisciplineState::Fset;
                // Apply a step to bring the clock close immediately.
                Some(DisciplineOutput {
                    phase_correction: offset,
                    frequency_correction: 0.0,
                    step: offset.abs() > STEPT,
                })
            }
            DisciplineState::Fset => {
                // Second measurement: compute initial frequency estimate.
                if mu > 0.0 {
                    self.freq = (offset - self.last_offset) / mu;
                    self.freq = self.freq.clamp(-FREQ_MAX, FREQ_MAX);
                }
                self.last_offset = offset;
                self.last_update = now;
                self.jitter = jitter;
                self.state = DisciplineState::Sync;
                Some(DisciplineOutput {
                    phase_correction: offset,
                    frequency_correction: self.freq,
                    step: offset.abs() > STEPT,
                })
            }
            DisciplineState::Sync | DisciplineState::Spik => {
                self.handle_sync_spik(offset, jitter, now, mu, poll_exponent)
            }
        }
    }

    /// Handle the Sync and Spik states.
    fn handle_sync_spik(
        &mut self,
        offset: f64,
        system_jitter: f64,
        now: f64,
        mu: f64,
        poll_exponent: u8,
    ) -> Option<DisciplineOutput> {
        // Check for time spike.
        if offset.abs() > STEPT {
            match self.state {
                DisciplineState::Sync => {
                    // Spike detected — transition to Spik.
                    self.spike_start = Some(now);
                    self.state = DisciplineState::Spik;
                    // Don't apply correction yet; wait to see if it persists.
                    return None;
                }
                DisciplineState::Spik => {
                    // Still spiking. Check if we've exceeded the stepout timeout.
                    if let Some(start) = self.spike_start
                        && now - start >= WATCH
                    {
                        // Persistent spike — force a step and reset.
                        self.state = DisciplineState::Nset;
                        self.spike_start = None;
                        self.last_offset = 0.0;
                        self.last_update = now;
                        return Some(DisciplineOutput {
                            phase_correction: offset,
                            frequency_correction: self.freq,
                            step: true,
                        });
                    }
                    // Still within timeout — ignore this spike sample.
                    return None;
                }
                _ => unreachable!(),
            }
        }

        // Offset is within normal range. If we were in Spik, return to Sync.
        if self.state == DisciplineState::Spik {
            self.spike_start = None;
            self.state = DisciplineState::Sync;
        }

        // Adaptive time constant: track poll exponent when offset is small,
        // but clamp lower when the offset exceeds PGATE * jitter.
        if self.jitter > 0.0 && offset.abs() < PGATE * self.jitter {
            // Stable: let tc follow the poll exponent (slowly).
            if (poll_exponent as i16 - self.tc as i16).abs() <= 1 {
                self.tc = poll_exponent;
            } else if poll_exponent > self.tc {
                self.tc += 1;
            } else {
                self.tc = self.tc.saturating_sub(1).max(4);
            }
        } else {
            // Noisy or large offset: reduce tc for faster convergence.
            self.tc = self.tc.saturating_sub(1).max(4);
        }

        // PLL phase correction.
        let tc_f = self.tc as f64;
        let pll_correction = offset / (PLL_SCALE * tc_f);

        // FLL frequency correction (only if mu is reasonable).
        let fll_correction = if mu >= ALLAN / 4.0 {
            (offset - self.last_offset) / (mu * FLL_SCALE)
        } else {
            0.0
        };

        // Update frequency estimate.
        self.freq += pll_correction + fll_correction;
        self.freq = self.freq.clamp(-FREQ_MAX, FREQ_MAX);

        // Update jitter: blend the system jitter from the combine algorithm
        // with exponential averaging of offset differences.
        let jitter_diff = (offset - self.last_offset).abs();
        self.jitter = system_jitter.max(self.jitter + (jitter_diff - self.jitter) / 4.0);

        // Update wander estimate.
        let freq_diff = (pll_correction + fll_correction).abs();
        self.wander += (freq_diff - self.wander) / 4.0;

        self.last_offset = offset;
        self.last_update = now;

        Some(DisciplineOutput {
            phase_correction: offset,
            frequency_correction: self.freq,
            step: false,
        })
    }

    /// Get the current frequency estimate (seconds/second).
    pub fn frequency(&self) -> f64 {
        self.freq
    }

    /// Get the current discipline state.
    pub fn state(&self) -> DisciplineState {
        self.state
    }

    /// Get the current time constant.
    pub fn time_constant(&self) -> u8 {
        self.tc
    }

    /// Get the current jitter estimate.
    pub fn jitter(&self) -> f64 {
        self.jitter
    }

    /// Get the current wander estimate.
    pub fn wander(&self) -> f64 {
        self.wander
    }
}

impl Default for ClockDiscipline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let d = ClockDiscipline::new();
        assert_eq!(d.state(), DisciplineState::Nset);
        assert_eq!(d.frequency(), 0.0);
    }

    #[test]
    fn test_nset_to_fset_transition() {
        let mut d = ClockDiscipline::new();
        let output = d.update(0.050, 0.001, 10.0, 6);
        assert!(output.is_some());
        assert_eq!(d.state(), DisciplineState::Fset);
        let out = output.unwrap();
        assert_eq!(out.phase_correction, 0.050);
        assert!(!out.step); // 50ms < STEPT (128ms)
    }

    #[test]
    fn test_nset_large_offset_triggers_step() {
        let mut d = ClockDiscipline::new();
        let output = d.update(1.0, 0.001, 10.0, 6).unwrap();
        assert!(output.step);
        assert_eq!(d.state(), DisciplineState::Fset);
    }

    #[test]
    fn test_fset_to_sync_transition() {
        let mut d = ClockDiscipline::new();
        d.update(0.050, 0.001, 10.0, 6);
        assert_eq!(d.state(), DisciplineState::Fset);

        let output = d.update(0.040, 0.001, 26.0, 6); // 16s later
        assert!(output.is_some());
        assert_eq!(d.state(), DisciplineState::Sync);
        // Initial frequency should be computed.
        // freq = (0.040 - 0.050) / 16 = -0.000625
        assert!(d.frequency().abs() > 0.0);
    }

    #[test]
    fn test_sync_small_offset_produces_correction() {
        let mut d = ClockDiscipline::new();
        d.update(0.050, 0.001, 0.0, 6);
        d.update(0.040, 0.001, 16.0, 6);
        assert_eq!(d.state(), DisciplineState::Sync);

        let output = d.update(0.005, 0.001, 32.0, 6);
        assert!(output.is_some());
        let out = output.unwrap();
        assert!(!out.step);
        assert!(out.phase_correction.abs() > 0.0);
        assert_eq!(d.state(), DisciplineState::Sync);
    }

    #[test]
    fn test_spike_detection() {
        let mut d = ClockDiscipline::new();
        d.update(0.001, 0.001, 0.0, 6);
        d.update(0.001, 0.001, 16.0, 6);
        assert_eq!(d.state(), DisciplineState::Sync);

        // Large offset triggers spike.
        let output = d.update(5.0, 0.001, 32.0, 6);
        assert!(output.is_none()); // No correction during spike
        assert_eq!(d.state(), DisciplineState::Spik);
    }

    #[test]
    fn test_spike_recovery() {
        let mut d = ClockDiscipline::new();
        d.update(0.001, 0.001, 0.0, 6);
        d.update(0.001, 0.001, 16.0, 6);

        // Enter spike.
        d.update(5.0, 0.001, 32.0, 6);
        assert_eq!(d.state(), DisciplineState::Spik);

        // Recover with normal offset.
        let output = d.update(0.002, 0.001, 48.0, 6);
        assert!(output.is_some());
        assert_eq!(d.state(), DisciplineState::Sync);
    }

    #[test]
    fn test_spike_timeout_forces_step() {
        let mut d = ClockDiscipline::new();
        d.update(0.001, 0.001, 0.0, 6);
        d.update(0.001, 0.001, 16.0, 6);

        // Enter spike at t=32.
        d.update(5.0, 0.001, 32.0, 6);
        assert_eq!(d.state(), DisciplineState::Spik);

        // Still spiking at t=32+WATCH.
        let output = d.update(5.0, 0.001, 32.0 + WATCH, 6);
        assert!(output.is_some());
        let out = output.unwrap();
        assert!(out.step);
        assert_eq!(d.state(), DisciplineState::Nset);
    }

    #[test]
    fn test_frequency_convergence() {
        let mut d = ClockDiscipline::new();
        // Simulate a constant drift of 10 PPM.
        let drift = 10e-6; // 10 PPM
        let poll_interval = 64.0; // 2^6

        d.update(0.0, 0.001, 0.0, 6);
        d.update(drift * poll_interval, 0.001, poll_interval, 6);

        // Feed several samples with increasing offset due to drift.
        for i in 2..20 {
            let t = i as f64 * poll_interval;
            let offset = drift * poll_interval; // Each interval accumulates this much
            d.update(offset, 0.001, t, 6);
        }

        // Frequency should be tracking toward the drift.
        // It won't be exact due to the PLL/FLL dynamics, but should be non-zero
        // and in the right direction.
        assert!(
            d.frequency().abs() > 0.0,
            "frequency should track drift: {}",
            d.frequency()
        );
    }

    #[test]
    fn test_tc_adaptation() {
        let mut d = ClockDiscipline::new();
        d.update(0.001, 0.001, 0.0, 10);
        d.update(0.001, 0.001, 16.0, 10);

        // With small offsets and poll=10, tc should track toward 10.
        for i in 2..50 {
            d.update(0.0001, 0.001, i as f64 * 16.0, 10);
        }
        assert!(
            d.time_constant() > 4,
            "tc should increase toward poll: tc={}",
            d.time_constant()
        );
    }

    #[test]
    fn test_frequency_clamping() {
        let mut d = ClockDiscipline::new();
        d.update(0.0, 0.001, 0.0, 6);
        // Huge offset jump to force extreme frequency estimate.
        d.update(100.0, 0.001, 1.0, 6);
        assert!(d.frequency().abs() <= FREQ_MAX);
    }

    #[test]
    fn test_default() {
        let d = ClockDiscipline::default();
        assert_eq!(d.state(), DisciplineState::Nset);
    }

    #[test]
    fn test_constants() {
        assert_eq!(STEPT, 0.128);
        assert_eq!(WATCH, 900.0);
        assert_eq!(PGATE, 4.0);
        assert!((FREQ_TOLERANCE - 15e-6).abs() < 1e-12);
    }
}
