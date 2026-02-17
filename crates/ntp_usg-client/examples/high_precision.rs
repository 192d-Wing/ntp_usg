// High-Precision Time Synchronization: PPS + Hardware Timestamping
//
// Demonstrates combining a PPS reference clock with SO_TIMESTAMPING for
// sub-microsecond NTP accuracy. PPS provides nanosecond-level timing pulses
// while hardware timestamping eliminates kernel jitter from NTP packet I/O.
//
// Usage:
//   sudo cargo run -p ntp_usg-client --example high_precision \
//       --features pps,hwts -- [/dev/pps0] [eth0]
//
// Requirements:
//   - Linux kernel 2.6.30+ with CONFIG_PPS and SO_TIMESTAMPING
//   - PPS source (GPS receiver with PPS output -> /dev/pps0)
//   - Network interface with hardware timestamping (Intel i210, i350, etc.)
//   - Root privileges
//
// Architecture:
//   PPS provides sub-microsecond offset measurements.
//   HWTS provides sub-microsecond NTP packet timestamps.
//   Together they enable validating NTP accuracy against a ground-truth PPS.
//
// Expected accuracy:
//   PPS alone:        < 1 us
//   HWTS NTP alone:   ~10-100 ns (NIC-level)
//   Combined:         validates sub-ms NTP against sub-us PPS

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example requires Linux (PPS and SO_TIMESTAMPING support).");
}

#[cfg(target_os = "linux")]
use ntp_client::refclock::RefClock;
#[cfg(target_os = "linux")]
use ntp_client::refclock::hwts::{
    TimestampMode, enable_timestamping, get_timestamping_capabilities,
    is_hardware_timestamping_available,
};
#[cfg(target_os = "linux")]
use ntp_client::refclock::pps::{PpsCaptureMode, PpsConfig, PpsReceiver};
#[cfg(target_os = "linux")]
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let pps_device = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("/dev/pps0")
    };
    let interface = if args.len() > 2 {
        args[2].clone()
    } else {
        "eth0".to_string()
    };

    println!("High-Precision Time Synchronization");
    println!("====================================");
    println!("PPS device:    {}", pps_device.display());
    println!("NIC interface: {}", interface);
    println!();

    // ── Hardware timestamping capability check ─────────────────────────

    println!("Checking hardware timestamping support...");

    if !is_hardware_timestamping_available() {
        println!("  SO_TIMESTAMPING is NOT available on this system.");
        println!("  Continuing with PPS only.");
        println!();
    } else {
        println!("  SO_TIMESTAMPING is available.");

        let sock = UdpSocket::bind("0.0.0.0:0")?;
        match get_timestamping_capabilities(sock.as_raw_fd(), &interface) {
            Ok(caps) => {
                println!("  NIC capabilities for {}:", interface);
                println!(
                    "    Hardware TX: {}",
                    if caps.tx_hardware { "yes" } else { "no" }
                );
                println!(
                    "    Hardware RX: {}",
                    if caps.rx_hardware { "yes" } else { "no" }
                );
                println!(
                    "    Software TX: {}",
                    if caps.tx_software { "yes" } else { "no" }
                );
                println!(
                    "    Software RX: {}",
                    if caps.rx_software { "yes" } else { "no" }
                );
                println!(
                    "    Raw HW:      {}",
                    if caps.raw_hardware { "yes" } else { "no" }
                );

                let ts_mode = if caps.tx_hardware && caps.rx_hardware {
                    TimestampMode::Hardware
                } else {
                    println!();
                    println!("  Falling back to software timestamping.");
                    TimestampMode::Software
                };

                match enable_timestamping(sock.as_raw_fd(), ts_mode) {
                    Ok(()) => println!("  Enabled {:?} timestamping on test socket.", ts_mode),
                    Err(e) => println!("  Failed to enable timestamping: {}", e),
                }
            }
            Err(e) => {
                println!("  Failed to query NIC capabilities: {}", e);
            }
        }
        println!();
    }

    // ── PPS receiver setup ─────────────────────────────────────────────

    println!("Opening PPS receiver...");

    let pps_config = PpsConfig {
        device: pps_device,
        capture_mode: PpsCaptureMode::Assert,
        reference_id: *b"PPS\0",
        timeout: Duration::from_secs(2),
        dispersion: 0.000_001, // 1 microsecond
    };

    let mut pps = match PpsReceiver::new(pps_config) {
        Ok(pps) => {
            println!("  PPS receiver opened successfully.");
            println!("  Capabilities: 0x{:08x}", pps.capabilities());
            pps
        }
        Err(e) => {
            eprintln!("  Failed to open PPS receiver: {}", e);
            return Err(e.into());
        }
    };
    println!();

    // ── Wait for initial PPS pulse ─────────────────────────────────────

    println!("Waiting for initial PPS pulse...");
    let initial_sample = loop {
        match tokio::time::timeout(Duration::from_secs(5), pps.read_sample()).await {
            Ok(Ok(sample)) => {
                println!(
                    "  PPS pulse acquired: offset {:.9}s ({:.3} ns)",
                    sample.offset,
                    sample.offset * 1e9
                );
                break sample;
            }
            Ok(Err(e)) => {
                println!("  Waiting: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(_) => {
                println!("  Timeout, retrying...");
            }
        }
    };
    println!();

    // ── Continuous precision monitoring ─────────────────────────────────

    println!("Starting continuous high-precision monitoring...");
    println!();

    let mut sample_count = 0u64;
    let mut last_offset = initial_sample.offset;
    let mut window_offsets: Vec<f64> = Vec::with_capacity(10);

    loop {
        sample_count += 1;

        match tokio::time::timeout(Duration::from_secs(3), pps.read_sample()).await {
            Ok(Ok(sample)) => {
                let offset_ns = sample.offset * 1e9;
                let drift_ns = (sample.offset - last_offset) * 1e9;
                last_offset = sample.offset;

                let tier = if offset_ns.abs() < 10.0 {
                    "Excellent (< 10 ns)"
                } else if offset_ns.abs() < 100.0 {
                    "Very good (< 100 ns)"
                } else if offset_ns.abs() < 1_000.0 {
                    "Good (< 1 us)"
                } else if offset_ns.abs() < 10_000.0 {
                    "Acceptable (< 10 us)"
                } else {
                    "Poor (>= 10 us)"
                };

                println!(
                    "#{:<5} PPS offset: {:+.9}s ({:+10.3} ns) | disp: {:.3} us | quality: {}/255 | {}",
                    sample_count,
                    sample.offset,
                    offset_ns,
                    sample.dispersion * 1e6,
                    sample.quality,
                    tier,
                );

                if sample_count > 1 {
                    println!(
                        "       drift: {:+.3} ns | health: {}",
                        drift_ns,
                        if pps.is_healthy() { "OK" } else { "DEGRADED" }
                    );
                }

                // 10-sample statistical window
                window_offsets.push(sample.offset);
                if window_offsets.len() == 10 {
                    let min = window_offsets.iter().copied().fold(f64::INFINITY, f64::min);
                    let max = window_offsets
                        .iter()
                        .copied()
                        .fold(f64::NEG_INFINITY, f64::max);
                    let mean = window_offsets.iter().sum::<f64>() / 10.0;
                    let jitter = max - min;

                    println!();
                    println!(
                        "  10-sample summary: mean {:+.3} ns | min {:+.3} ns | max {:+.3} ns | jitter {:.3} ns",
                        mean * 1e9,
                        min * 1e9,
                        max * 1e9,
                        jitter * 1e9
                    );
                    println!();
                    window_offsets.clear();
                }
            }
            Ok(Err(e)) => {
                eprintln!("#{:<5} PPS error: {}", sample_count, e);
            }
            Err(_) => {
                eprintln!("#{:<5} PPS timeout", sample_count);
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
