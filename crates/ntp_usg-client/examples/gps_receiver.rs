// GPS receiver example
//
// Demonstrates using a GPS receiver as a reference clock for time synchronization.
// This example reads NMEA 0183 sentences from a serial GPS receiver and displays
// timing information.
//
// Usage:
//   cargo run -p ntp_usg-client --example gps_receiver --features gps -- /dev/ttyUSB0
//
// Requirements:
//   - GPS receiver with NMEA 0183 output via serial port
//   - Serial port permissions (may require running as root or adding user to dialout group)
//
// Common GPS devices:
//   - USB GPS receivers: /dev/ttyUSB0, /dev/ttyACM0
//   - Raspberry Pi GPIO UART: /dev/ttyAMA0, /dev/serial0
//   - Windows: COM3, COM4, etc.

use ntp_client::refclock::gps::{GpsConfig, GpsReceiver};
use ntp_client::refclock::RefClock;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Get serial port from command line args, or use default
    let args: Vec<String> = std::env::args().collect();
    let device = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("/dev/ttyUSB0")
    };

    println!("GPS Receiver Example");
    println!("====================");
    println!("Serial device: {}", device.display());
    println!();

    // Configure GPS receiver
    let config = GpsConfig {
        device,
        baud_rate: 9600,
        min_satellites: 3,
        min_quality: ntp_client::refclock::nmea::FixQuality::Gps,
        reference_id: *b"GPS\0",
        poll_interval: Duration::from_secs(1),
    };

    println!("Opening GPS receiver...");
    let mut gps = match GpsReceiver::new(config) {
        Ok(gps) => {
            println!("✓ GPS receiver opened successfully");
            println!();
            gps
        }
        Err(e) => {
            eprintln!("✗ Failed to open GPS receiver: {}", e);
            eprintln!();
            eprintln!("Common issues:");
            eprintln!("  - Serial port does not exist or is in use");
            eprintln!("  - Insufficient permissions (try running as root or add user to dialout group)");
            eprintln!("  - GPS device not connected");
            eprintln!();
            eprintln!("Try:");
            eprintln!("  ls -l /dev/tty*  # List available serial ports");
            eprintln!("  sudo usermod -a -G dialout $USER  # Add user to dialout group");
            return Err(e.into());
        }
    };

    println!("GPS Information:");
    println!("  Description: {}", gps.description());
    println!("  Stratum: {}", gps.stratum());
    println!("  Reference ID: {}", String::from_utf8_lossy(&gps.reference_id()));
    println!("  Poll interval: {:?}", gps.poll_interval());
    println!();

    println!("Waiting for GPS fix...");
    println!("(This may take 30-60 seconds for cold start)");
    println!();

    // Read samples continuously
    let mut sample_count = 0;
    loop {
        match gps.read_sample().await {
            Ok(sample) => {
                sample_count += 1;

                // Extract timestamp
                let ts_secs = sample.timestamp.secs();
                let ts_nanos = sample.timestamp.subsec_nanos();

                // Format output
                println!("Sample #{}", sample_count);
                println!("  Timestamp: {}.{:09} (Unix)", ts_secs, ts_nanos);
                println!("  Offset: {:.6} seconds", sample.offset);
                println!("  Dispersion: {:.6} seconds", sample.dispersion);
                println!("  Quality: {}/255", sample.quality);
                println!("  Health: {}", if gps.is_healthy() { "✓ Healthy" } else { "✗ Unhealthy" });

                // Interpretation
                let offset_ms = sample.offset * 1000.0;
                if offset_ms.abs() < 1.0 {
                    println!("  Status: ✓ Excellent sync (< 1ms offset)");
                } else if offset_ms.abs() < 10.0 {
                    println!("  Status: ✓ Good sync (< 10ms offset)");
                } else if offset_ms.abs() < 100.0 {
                    println!("  Status: ⚠ Acceptable sync (< 100ms offset)");
                } else {
                    println!("  Status: ✗ Poor sync (≥ 100ms offset)");
                }

                println!();

                // Wait for next poll interval
                tokio::time::sleep(gps.poll_interval()).await;
            }
            Err(e) => {
                eprintln!("Error reading GPS sample: {}", e);
                eprintln!("Waiting 5 seconds before retry...");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
