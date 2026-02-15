//! Example demonstrating how to access detailed NTP packet information.
//!
//! This example shows how to extract and display all the fields from an
//! NTP response packet, which is useful for debugging or detailed analysis.

use chrono::TimeZone;

fn main() {
    let address = "pool.ntp.org:123";

    println!("Requesting NTP packet from {}...\n", address);

    match ntp::request(address) {
        Ok(result) => {
            let packet = &result.packet;
            println!("=== NTP Packet Details ===\n");

            // Header fields
            println!("Header Information:");
            println!("  Leap Indicator: {:?}", packet.leap_indicator);
            println!("  Version: {:?}", packet.version);
            println!("  Mode: {:?}", packet.mode);
            println!("  Stratum: {} ({:?})", packet.stratum.0, packet.stratum);
            println!(
                "  Poll Interval: {} (2^{} seconds)",
                1u32 << packet.poll,
                packet.poll
            );
            println!(
                "  Precision: {} (2^{} seconds)",
                2.0f64.powi(packet.precision.into()),
                packet.precision
            );

            // Reference information
            println!("\nReference Information:");
            println!("  Reference ID: {:?}", packet.reference_id);
            println!(
                "  Root Delay: {} sec, {} frac",
                packet.root_delay.seconds, packet.root_delay.fraction
            );
            println!(
                "  Root Dispersion: {} sec, {} frac",
                packet.root_dispersion.seconds, packet.root_dispersion.fraction
            );

            // Timestamps
            println!("\nTimestamps (NTP format):");
            println!(
                "  Reference:  {} . {}",
                packet.reference_timestamp.seconds, packet.reference_timestamp.fraction
            );
            println!(
                "  Origin:     {} . {}",
                packet.origin_timestamp.seconds, packet.origin_timestamp.fraction
            );
            println!(
                "  Receive:    {} . {}",
                packet.receive_timestamp.seconds, packet.receive_timestamp.fraction
            );
            println!(
                "  Transmit:   {} . {}",
                packet.transmit_timestamp.seconds, packet.transmit_timestamp.fraction
            );

            // Convert timestamps to human-readable format
            println!("\nTimestamps (Human-readable):");

            let ref_time = ntp::unix_time::Instant::from(packet.reference_timestamp);
            let ref_local = chrono::Local
                .timestamp_opt(ref_time.secs(), ref_time.subsec_nanos() as _)
                .unwrap();
            println!("  Reference:  {}", ref_local);

            let orig_time = ntp::unix_time::Instant::from(packet.origin_timestamp);
            let orig_local = chrono::Local
                .timestamp_opt(orig_time.secs(), orig_time.subsec_nanos() as _)
                .unwrap();
            println!("  Origin:     {}", orig_local);

            let recv_time = ntp::unix_time::Instant::from(packet.receive_timestamp);
            let recv_local = chrono::Local
                .timestamp_opt(recv_time.secs(), recv_time.subsec_nanos() as _)
                .unwrap();
            println!("  Receive:    {}", recv_local);

            let trans_time = ntp::unix_time::Instant::from(packet.transmit_timestamp);
            let trans_local = chrono::Local
                .timestamp_opt(trans_time.secs(), trans_time.subsec_nanos() as _)
                .unwrap();
            println!("  Transmit:   {}", trans_local);

            // Quality indicators
            println!("\nQuality Indicators:");
            match packet.stratum.0 {
                0 => println!("  ⚠ Stratum 0: Kiss-of-death or unspecified"),
                1 => println!("  ✓ Stratum 1: Primary reference (GPS, atomic clock, etc.)"),
                2..=15 => println!("  ✓ Stratum {}: Secondary reference", packet.stratum.0),
                _ => println!("  ✗ Invalid stratum"),
            }

            match packet.leap_indicator {
                ntp::protocol::LeapIndicator::NoWarning => println!("  ✓ No leap second warning"),
                ntp::protocol::LeapIndicator::AddOne => println!("  ⚠ Leap second will be added"),
                ntp::protocol::LeapIndicator::SubOne => {
                    println!("  ⚠ Leap second will be subtracted")
                }
                ntp::protocol::LeapIndicator::Unknown => println!("  ✗ Clock not synchronized"),
            }

            // Timing information (RFC 5905 Section 8)
            println!("\nTiming:");
            println!("  Clock offset: {:.6} seconds", result.offset_seconds);
            println!("  Round-trip delay: {:.6} seconds", result.delay_seconds);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
