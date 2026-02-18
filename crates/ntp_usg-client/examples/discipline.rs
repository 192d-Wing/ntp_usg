// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Clock discipline demonstration.
//!
//! Shows how the PLL/FLL clock discipline algorithm (RFC 5905 Section 11.3)
//! processes offset measurements and transitions through states:
//! Nset → Fset → Sync (normal operation).
//!
//! Run with:
//! ```sh
//! cargo run -p ntp_usg-client --example discipline --features discipline
//! ```

use ntp_client::discipline::{ClockDiscipline, DisciplineState};

fn main() {
    let mut discipline = ClockDiscipline::new();

    println!("Clock Discipline State Machine Demo");
    println!("====================================");
    println!("Initial state: {:?}", discipline.state());
    assert_eq!(discipline.state(), DisciplineState::Nset);
    println!();

    // Simulated offset measurements at 16-second poll intervals.
    let offsets = [
        0.050, // Large initial offset
        0.045, // Converging
        0.020, 0.010, 0.005, 0.003, 0.001, -0.001, 0.002, 0.000,
    ];

    let mut time = 0.0_f64;
    let poll_exponent = 4_u8; // 2^4 = 16 seconds
    let poll_interval = 2.0_f64.powi(poll_exponent as i32);

    for (i, &offset) in offsets.iter().enumerate() {
        time += poll_interval;
        let jitter = 0.005; // Simulated constant jitter

        let output = discipline.update(offset, jitter, time, poll_exponent);
        let state = discipline.state();
        let freq = discipline.frequency();

        println!(
            "Sample {:2}: offset={:+.6}s  state={:?}  freq={:+.9}s/s",
            i + 1,
            offset,
            state,
            freq,
        );

        if let Some(out) = output {
            println!(
                "           → correction: phase={:+.9}s  freq={:+.9}s/s  step={}",
                out.phase_correction, out.frequency_correction, out.step
            );
        }
    }

    println!();
    println!("Final state: {:?}", discipline.state());
    println!("Final frequency: {:+.9} s/s", discipline.frequency());
    println!();
    println!("State transitions:");
    println!("  Nset → first offset received → Fset");
    println!("  Fset → second offset for frequency estimate → Sync");
    println!("  Sync → normal PLL/FLL hybrid corrections");
    println!("  (Spik → detected if offset > STEPT for extended period)");
}
