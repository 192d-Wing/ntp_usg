// PPS receiver example
//
// Demonstrates using a PPS (Pulse Per Second) signal as a reference clock
// for nanosecond-precision time synchronization.
//
// Usage:
//   cargo run -p ntp_usg-client --example pps_receiver --features pps -- /dev/pps0
//
// Requirements:
//   - Linux kernel with CONFIG_PPS enabled
//   - PPS device (typically from GPS receiver)
//   - Root privileges or appropriate permissions on /dev/pps*
//
// Common PPS devices:
//   - GPS receivers with PPS output: /dev/pps0
//   - Multiple PPS sources: /dev/pps0, /dev/pps1, etc.
//
// Setup PPS on Raspberry Pi:
//   - Enable PPS in /boot/config.txt: dtoverlay=pps-gpio,gpiopin=18
//   - Load kernel module: sudo modprobe pps-gpio
//   - Verify device: ls -l /dev/pps*
//   - Test with ppstest: sudo ppstest /dev/pps0

use ntp_client::refclock::RefClock;
use ntp_client::refclock::pps::{PpsCaptureMode, PpsConfig, PpsReceiver};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Get PPS device from command line args, or use default
    let args: Vec<String> = std::env::args().collect();
    let device = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("/dev/pps0")
    };

    println!("PPS Receiver Example");
    println!("====================");
    println!("PPS device: {}", device.display());
    println!();

    // Configure PPS receiver
    let config = PpsConfig {
        device,
        capture_mode: PpsCaptureMode::Assert,
        reference_id: *b"PPS\0",
        timeout: Duration::from_secs(2),
        dispersion: 0.000001, // 1 microsecond
    };

    println!("Opening PPS receiver...");
    let mut pps: PpsReceiver = match PpsReceiver::new(config) {
        Ok(pps) => {
            println!("✓ PPS receiver opened successfully");
            println!("  Capabilities: 0x{:08x}", pps.capabilities());
            println!();
            pps
        }
        Err(e) => {
            eprintln!("✗ Failed to open PPS receiver: {}", e);
            eprintln!();
            eprintln!("Common issues:");
            eprintln!("  - PPS device does not exist (check /dev/pps*)");
            eprintln!("  - Kernel PPS support not enabled (CONFIG_PPS)");
            eprintln!("  - Insufficient permissions (try running as root)");
            eprintln!("  - PPS hardware not connected or not configured");
            eprintln!();
            eprintln!("Setup on Raspberry Pi:");
            eprintln!("  1. Add to /boot/config.txt: dtoverlay=pps-gpio,gpiopin=18");
            eprintln!("  2. Reboot or load module: sudo modprobe pps-gpio");
            eprintln!("  3. Verify device: ls -l /dev/pps*");
            eprintln!("  4. Test with ppstest: sudo ppstest /dev/pps0");
            eprintln!();
            eprintln!("Check kernel messages:");
            eprintln!("  dmesg | grep pps");
            return Err(e.into());
        }
    };

    println!("PPS Information:");
    println!("  Description: {}", pps.description());
    println!("  Stratum: {}", pps.stratum());
    println!(
        "  Reference ID: {}",
        String::from_utf8_lossy(&pps.reference_id())
    );
    println!("  Poll interval: {:?}", pps.poll_interval());
    println!("  Expected dispersion: {:.9}s", 0.000001);
    println!();

    println!("Waiting for PPS pulses...");
    println!("(Connect PPS signal to configured GPIO pin)");
    println!();

    // Read samples continuously
    let mut sample_count = 0;
    let mut last_offset = 0.0;

    loop {
        match pps.read_sample().await {
            Ok(sample) => {
                sample_count += 1;

                // Extract timestamp
                let ts_secs = sample.timestamp.secs();
                let ts_nanos = sample.timestamp.subsec_nanos();

                // Calculate drift rate if we have multiple samples
                let drift = if sample_count > 1 {
                    sample.offset - last_offset
                } else {
                    0.0
                };
                last_offset = sample.offset;

                // Format output
                println!("PPS Pulse #{}", sample_count);
                println!("  Timestamp: {}.{:09} (Unix)", ts_secs, ts_nanos);
                println!(
                    "  Offset: {:.9} seconds ({:.3} µs)",
                    sample.offset,
                    sample.offset * 1e6
                );
                println!(
                    "  Dispersion: {:.9} seconds ({:.3} µs)",
                    sample.dispersion,
                    sample.dispersion * 1e6
                );
                println!("  Quality: {}/255 (maximum)", sample.quality);
                println!(
                    "  Health: {}",
                    if pps.is_healthy() {
                        "✓ Healthy"
                    } else {
                        "✗ Unhealthy"
                    }
                );

                if sample_count > 1 {
                    println!("  Drift: {:.9} seconds ({:.3} µs)", drift, drift * 1e6);
                }

                // Precision assessment
                let offset_ns = sample.offset.abs() * 1e9;
                if offset_ns < 10.0 {
                    println!("  Precision: ✓ Excellent (< 10ns offset)");
                } else if offset_ns < 100.0 {
                    println!("  Precision: ✓ Very Good (< 100ns offset)");
                } else if offset_ns < 1000.0 {
                    println!("  Precision: ✓ Good (< 1µs offset)");
                } else if offset_ns < 10000.0 {
                    println!("  Precision: ⚠ Acceptable (< 10µs offset)");
                } else {
                    println!("  Precision: ✗ Poor (≥ 10µs offset)");
                }

                println!();

                // Statistics every 10 samples
                if sample_count % 10 == 0 {
                    println!("─────────────────────────────────────────");
                    println!("Statistics after {} samples:", sample_count);
                    println!(
                        "  Average offset: {:.9}s ({:.3} µs)",
                        last_offset,
                        last_offset * 1e6
                    );
                    println!("─────────────────────────────────────────");
                    println!();
                }
            }
            Err(e) => {
                eprintln!("Error reading PPS sample: {}", e);
                eprintln!();

                // Check if it's a timeout
                if e.kind() == std::io::ErrorKind::TimedOut as std::io::ErrorKind {
                    eprintln!("PPS timeout - no pulse received within timeout period");
                    eprintln!("Possible causes:");
                    eprintln!("  - PPS signal not connected");
                    eprintln!("  - GPS receiver has no fix (no PPS output)");
                    eprintln!("  - Incorrect GPIO pin configuration");
                    eprintln!();
                }

                eprintln!("Retrying in 2 seconds...");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }

        // PPS typically fires once per second, so brief sleep
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
