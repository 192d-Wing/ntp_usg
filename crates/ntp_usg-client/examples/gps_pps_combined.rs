// Combined GPS + PPS receiver example
//
// Demonstrates using GPS and PPS together for optimal time synchronization.
// GPS provides coarse time (100µs - 1ms accuracy) while PPS provides fine
// precision (< 1µs accuracy). This combination is ideal for Stratum 1 NTP servers.
//
// Usage:
//   cargo run -p ntp_usg-client --example gps_pps_combined --features gps,pps -- /dev/ttyUSB0 /dev/pps0
//
// Requirements:
//   - GPS receiver with NMEA output on serial port
//   - GPS receiver with PPS output connected to GPIO/kernel PPS
//   - Linux kernel with CONFIG_PPS enabled
//   - Root privileges or appropriate permissions
//
// Typical Setup (Raspberry Pi):
//   1. GPS NMEA on /dev/ttyAMA0 (GPIO UART)
//   2. GPS PPS on GPIO 18 → /dev/pps0
//   3. Add to /boot/config.txt: dtoverlay=pps-gpio,gpiopin=18
//   4. Load module: sudo modprobe pps-gpio

use ntp_client::refclock::gps::{GpsConfig, GpsReceiver};
use ntp_client::refclock::pps::{PpsCaptureMode, PpsConfig, PpsReceiver};
use ntp_client::refclock::RefClock;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Get devices from command line args
    let args: Vec<String> = std::env::args().collect();
    let gps_device = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("/dev/ttyUSB0")
    };
    let pps_device = if args.len() > 2 {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from("/dev/pps0")
    };

    println!("Combined GPS + PPS Example");
    println!("==========================");
    println!("GPS device: {}", gps_device.display());
    println!("PPS device: {}", pps_device.display());
    println!();

    // Configure GPS receiver
    let gps_config = GpsConfig {
        device: gps_device,
        baud_rate: 9600,
        min_satellites: 3,
        min_quality: ntp_client::refclock::nmea::FixQuality::Gps,
        reference_id: *b"GPS\0",
        poll_interval: Duration::from_secs(1),
    };

    // Configure PPS receiver
    let pps_config = PpsConfig {
        device: pps_device,
        capture_mode: PpsCaptureMode::Assert,
        reference_id: *b"PPS\0",
        timeout: Duration::from_secs(2),
        dispersion: 0.000001, // 1 microsecond
    };

    // Open GPS receiver
    println!("Opening GPS receiver...");
    let mut gps: GpsReceiver = match GpsReceiver::new(gps_config) {
        Ok(gps) => {
            println!("✓ GPS receiver opened successfully");
            println!();
            gps
        }
        Err(e) => {
            eprintln!("✗ Failed to open GPS receiver: {}", e);
            eprintln!("Continuing with PPS only...");
            eprintln!();
            return Err(e.into());
        }
    };

    // Open PPS receiver
    println!("Opening PPS receiver...");
    let mut pps: PpsReceiver = match PpsReceiver::new(pps_config) {
        Ok(pps) => {
            println!("✓ PPS receiver opened successfully");
            println!("  Capabilities: 0x{:08x}", pps.capabilities());
            println!();
            pps
        }
        Err(e) => {
            eprintln!("✗ Failed to open PPS receiver: {}", e);
            eprintln!("Continuing with GPS only...");
            eprintln!();
            return Err(e.into());
        }
    };

    println!("Waiting for GPS fix and PPS sync...");
    println!();

    // Wait for initial GPS fix
    let gps_sample = loop {
        match gps.read_sample().await {
            Ok(sample) => {
                println!("✓ GPS fix acquired!");
                println!("  Offset: {:.6}s ({:.3}ms)", sample.offset, sample.offset * 1000.0);
                println!("  Dispersion: {:.6}s ({:.3}µs)", sample.dispersion, sample.dispersion * 1e6);
                println!("  Quality: {}/255", sample.quality);
                println!();
                break sample;
            }
            Err(e) => {
                println!("⏳ Waiting for GPS fix: {}", e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    // Wait for initial PPS pulse
    let pps_sample = loop {
        match pps.read_sample().await {
            Ok(sample) => {
                println!("✓ PPS pulse detected!");
                println!("  Offset: {:.9}s ({:.3}ns)", sample.offset, sample.offset * 1e9);
                println!("  Dispersion: {:.9}s ({:.3}µs)", sample.dispersion, sample.dispersion * 1e6);
                println!("  Quality: {}/255", sample.quality);
                println!();
                break sample;
            }
            Err(e) => {
                println!("⏳ Waiting for PPS pulse: {}", e);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    println!("═══════════════════════════════════════════════════════");
    println!("Both GPS and PPS synchronized!");
    println!("═══════════════════════════════════════════════════════");
    println!();

    // Compare GPS and PPS offsets
    let difference = (gps_sample.offset - pps_sample.offset).abs();
    println!("Initial Offset Comparison:");
    println!("  GPS offset:  {:.6}s ({:.3}ms)", gps_sample.offset, gps_sample.offset * 1000.0);
    println!("  PPS offset:  {:.9}s ({:.3}µs)", pps_sample.offset, pps_sample.offset * 1e6);
    println!("  Difference:  {:.9}s ({:.3}µs)", difference, difference * 1e6);
    println!();

    if difference < 0.001 {
        println!("✓ Excellent agreement (< 1ms)");
    } else if difference < 0.01 {
        println!("✓ Good agreement (< 10ms)");
    } else {
        println!("⚠ Large difference - GPS may not be synchronized yet");
    }
    println!();

    println!("Starting continuous monitoring...");
    println!();

    // Continuous monitoring loop
    let mut sample_count = 0;
    let mut last_gps_offset = gps_sample.offset;
    let mut last_pps_offset = pps_sample.offset;

    loop {
        sample_count += 1;

        // Spawn concurrent GPS and PPS reads
        let gps_future = gps.read_sample();
        let pps_future = pps.read_sample();

        // Wait for both with timeout
        let results = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::join!(gps_future, pps_future)
        ).await;

        match results {
            Ok((gps_result, pps_result)) => {
                println!("Sample #{}", sample_count);
                println!("────────────────────────────────────────");

                // Process GPS sample
                match gps_result {
                    Ok(gps_sample) => {
                        let gps_drift = gps_sample.offset - last_gps_offset;
                        last_gps_offset = gps_sample.offset;

                        println!("📡 GPS:");
                        println!("  Offset:     {:.6}s ({:>8.3}ms)", gps_sample.offset, gps_sample.offset * 1000.0);
                        println!("  Dispersion: {:.6}s ({:>8.3}µs)", gps_sample.dispersion, gps_sample.dispersion * 1e6);
                        println!("  Quality:    {}/255", gps_sample.quality);
                        if sample_count > 1 {
                            println!("  Drift:      {:.6}s ({:>8.3}ms)", gps_drift, gps_drift * 1000.0);
                        }
                    }
                    Err(e) => {
                        println!("📡 GPS: ✗ {}", e);
                    }
                }

                // Process PPS sample
                match pps_result {
                    Ok(pps_sample) => {
                        let pps_drift = pps_sample.offset - last_pps_offset;
                        last_pps_offset = pps_sample.offset;

                        println!("⚡ PPS:");
                        println!("  Offset:     {:.9}s ({:>8.3}µs)", pps_sample.offset, pps_sample.offset * 1e6);
                        println!("  Dispersion: {:.9}s ({:>8.3}ns)", pps_sample.dispersion, pps_sample.dispersion * 1e9);
                        println!("  Quality:    {}/255", pps_sample.quality);
                        if sample_count > 1 {
                            println!("  Drift:      {:.9}s ({:>8.3}ns)", pps_drift, pps_drift * 1e9);
                        }

                        // Calculate combined precision
                        if let Ok(ref gps) = gps_result {
                            let diff = (gps.offset - pps_sample.offset).abs();
                            println!("🎯 Combined:");
                            println!("  Difference: {:.9}s ({:>8.3}µs)", diff, diff * 1e6);

                            // Assessment
                            if diff < 0.000001 {
                                println!("  Status:     ✓ Excellent sync (< 1µs)");
                            } else if diff < 0.000010 {
                                println!("  Status:     ✓ Very good sync (< 10µs)");
                            } else if diff < 0.000100 {
                                println!("  Status:     ✓ Good sync (< 100µs)");
                            } else if diff < 0.001 {
                                println!("  Status:     ⚠ Acceptable (< 1ms)");
                            } else {
                                println!("  Status:     ✗ Poor sync (≥ 1ms)");
                            }
                        }
                    }
                    Err(e) => {
                        println!("⚡ PPS: ✗ {}", e);
                    }
                }

                println!();

                // Summary every 10 samples
                if sample_count % 10 == 0 {
                    println!("═══════════════════════════════════════════════════════");
                    println!("Summary after {} samples:", sample_count);
                    println!("  GPS offset:  {:.6}s ({:.3}ms)", last_gps_offset, last_gps_offset * 1000.0);
                    println!("  PPS offset:  {:.9}s ({:.3}µs)", last_pps_offset, last_pps_offset * 1e6);
                    println!("  GPS health:  {}", if gps.is_healthy() { "✓" } else { "✗" });
                    println!("  PPS health:  {}", if pps.is_healthy() { "✓" } else { "✗" });
                    println!("═══════════════════════════════════════════════════════");
                    println!();
                }
            }
            Err(_) => {
                eprintln!("⏱ Timeout waiting for samples");
                eprintln!();
            }
        }

        // Small delay before next iteration
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
