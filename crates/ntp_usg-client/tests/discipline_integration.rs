// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the clock discipline state machine.

#![cfg(feature = "discipline")]

use ntp_client::DisciplineState;
use ntp_client::discipline::ClockDiscipline;

#[test]
fn test_nset_to_fset_transition() {
    let mut d = ClockDiscipline::new();
    assert_eq!(d.state(), DisciplineState::Nset);

    let output = d.update(0.050, 0.001, 10.0, 6);
    assert!(output.is_some());
    assert_eq!(d.state(), DisciplineState::Fset);

    let out = output.unwrap();
    assert_eq!(out.phase_correction, 0.050);
    assert!(!out.step); // 50ms < STEPT (128ms)
}

#[test]
fn test_fset_to_sync_transition() {
    let mut d = ClockDiscipline::new();

    // First sample: Nset → Fset
    d.update(0.001, 0.001, 0.0, 6);
    assert_eq!(d.state(), DisciplineState::Fset);

    // Second sample: Fset → Sync
    let output = d.update(0.002, 0.001, 16.0, 6);
    assert!(output.is_some());
    assert_eq!(d.state(), DisciplineState::Sync);
}

#[test]
fn test_large_offset_triggers_step() {
    let mut d = ClockDiscipline::new();

    // Large offset should trigger step.
    let output = d.update(5.0, 0.001, 0.0, 6);
    assert!(output.is_some());
    let out = output.unwrap();
    assert!(out.step, "offset of 5s should trigger a step");
}

#[test]
fn test_spike_detection_in_sync() {
    let mut d = ClockDiscipline::new();

    // Get to Sync state with small offsets.
    d.update(0.001, 0.001, 0.0, 6);
    d.update(0.001, 0.001, 16.0, 6);
    assert_eq!(d.state(), DisciplineState::Sync);

    // Large offset should trigger spike detection.
    let output = d.update(5.0, 0.001, 32.0, 6);
    assert!(output.is_none(), "no correction during spike");
    assert_eq!(d.state(), DisciplineState::Spik);
}

#[test]
fn test_spike_recovery() {
    let mut d = ClockDiscipline::new();

    // Get to Sync.
    d.update(0.001, 0.001, 0.0, 6);
    d.update(0.001, 0.001, 16.0, 6);
    assert_eq!(d.state(), DisciplineState::Sync);

    // Trigger spike.
    d.update(5.0, 0.001, 32.0, 6);
    assert_eq!(d.state(), DisciplineState::Spik);

    // Normal offset should recover.
    let output = d.update(0.002, 0.001, 48.0, 6);
    assert!(output.is_some());
    assert_eq!(d.state(), DisciplineState::Sync);
}

#[test]
fn test_frequency_direction_with_consistent_drift() {
    let mut d = ClockDiscipline::new();
    let drift_ppm = 10e-6; // 10 PPM positive drift
    let poll_interval = 64.0; // 2^6 seconds

    // Initialize.
    d.update(0.0, 0.001, 0.0, 6);
    d.update(drift_ppm * poll_interval, 0.001, poll_interval, 6);
    assert_eq!(d.state(), DisciplineState::Sync);

    // Feed consistent drift samples.
    for i in 2..15 {
        let t = i as f64 * poll_interval;
        d.update(drift_ppm * poll_interval, 0.001, t, 6);
    }

    // Frequency should be positive (tracking the drift).
    let freq = d.frequency();
    assert!(
        freq > 0.0,
        "frequency should be positive for positive drift, got {}",
        freq
    );
}

#[test]
fn test_ten_samples_converge() {
    let mut d = ClockDiscipline::new();
    let poll_interval = 64.0;

    for i in 0..10 {
        let t = i as f64 * poll_interval;
        let offset = 0.010 * (-0.5f64).powi(i); // Decaying offset
        d.update(offset, 0.001, t, 6);
    }

    // After 10 samples, should be in Sync.
    assert_eq!(d.state(), DisciplineState::Sync);

    // Jitter should have some value.
    assert!(d.jitter() >= 0.0);
}
