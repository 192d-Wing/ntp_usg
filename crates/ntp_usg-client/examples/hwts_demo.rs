// Hardware timestamping demonstration
//
// Demonstrates NIC-level hardware timestamping for NTP packets using
// SO_TIMESTAMPING on Linux. Hardware timestamps eliminate kernel scheduling
// jitter and provide sub-microsecond accuracy.
//
// Usage:
//   sudo cargo run -p ntp_usg-client --example hwts_demo --features hwts
//
// Requirements:
//   - Linux kernel 2.6.30+ with SO_TIMESTAMPING support
//   - Network interface with hardware timestamping capability
//   - Root privileges (required for SO_TIMESTAMPING)
//
// Check NIC support:
//   ethtool -T eth0
//
// Common NICs with hardware timestamping:
//   - Intel i210, i350, X540, X550 (igb, ixgbe drivers)
//   - Broadcom NetXtreme (bnxt_en driver)
//   - Mellanox ConnectX series (mlx5 driver)

use ntp_client::refclock::hwts::{
    enable_timestamping, get_timestamping_capabilities, is_hardware_timestamping_available,
    HwTimestampConfig, TimestampMode,
};
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hardware Timestamping Demonstration");
    println!("====================================");
    println!();

    // Check if hardware timestamping is available
    println!("Checking system support...");
    if is_hardware_timestamping_available() {
        println!("✓ SO_TIMESTAMPING is available on this system");
    } else {
        eprintln!("✗ SO_TIMESTAMPING is NOT available");
        eprintln!();
        eprintln!("Possible reasons:");
        eprintln!("  - Kernel too old (< 2.6.30)");
        eprintln!("  - Insufficient permissions");
        eprintln!();
        return Err("SO_TIMESTAMPING not available".into());
    }
    println!();

    // Create a test UDP socket
    println!("Creating test UDP socket...");
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let local_addr = sock.local_addr()?;
    println!("✓ Socket bound to {}", local_addr);
    println!();

    // Get default network interface capabilities
    println!("Querying network interface capabilities...");
    let interface = "eth0"; // Change to your interface
    match get_timestamping_capabilities(sock.as_raw_fd(), interface) {
        Ok(caps) => {
            println!("✓ Capabilities for {}:", interface);
            println!("  Hardware TX:  {}", if caps.tx_hardware { "✓ Supported" } else { "✗ Not supported" });
            println!("  Hardware RX:  {}", if caps.rx_hardware { "✓ Supported" } else { "✗ Not supported" });
            println!("  Software TX:  {}", if caps.tx_software { "✓ Supported" } else { "✗ Not supported" });
            println!("  Software RX:  {}", if caps.rx_software { "✓ Supported" } else { "✗ Not supported" });
            println!("  Raw hardware: {}", if caps.raw_hardware { "✓ Supported" } else { "✗ Not supported" });
            println!();

            if !caps.tx_hardware && !caps.rx_hardware {
                println!("⚠ Warning: Hardware timestamping not supported on {}", interface);
                println!("  Falling back to software timestamping");
                println!();
                println!("To check NIC support, run:");
                println!("  sudo ethtool -T {}", interface);
                println!();
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to query capabilities: {}", e);
            println!();
        }
    }

    // Test different timestamping modes
    println!("Testing timestamping modes:");
    println!();

    // 1. Software timestamping
    println!("1. Software Timestamping");
    match enable_timestamping(sock.as_raw_fd(), TimestampMode::Software) {
        Ok(()) => println!("   ✓ Software timestamping enabled"),
        Err(e) => println!("   ✗ Failed: {}", e),
    }

    // 2. Hardware timestamping
    println!("2. Hardware Timestamping");
    match enable_timestamping(sock.as_raw_fd(), TimestampMode::Hardware) {
        Ok(()) => {
            println!("   ✓ Hardware timestamping enabled");
            println!("   This provides nanosecond-precision timestamps");
            println!("   directly from the NIC hardware");
        }
        Err(e) => {
            println!("   ✗ Failed: {}", e);
            println!("   Your NIC may not support hardware timestamping");
            println!("   Run: sudo ethtool -T eth0");
        }
    }

    // 3. Raw hardware timestamping
    println!("3. Raw Hardware Timestamping");
    match enable_timestamping(sock.as_raw_fd(), TimestampMode::HardwareRaw) {
        Ok(()) => println!("   ✓ Raw hardware timestamping enabled"),
        Err(e) => println!("   ✗ Failed: {}", e),
    }
    println!();

    // Display configuration recommendation
    println!("═══════════════════════════════════════════════════════");
    println!("Recommended Configuration for NTP:");
    println!("═══════════════════════════════════════════════════════");
    println!();

    let config = HwTimestampConfig::default();
    println!("Default HwTimestampConfig:");
    println!("  Mode:        {:?}", config.mode);
    println!("  Interface:   {:?}", config.interface.as_deref().unwrap_or("auto-detect"));
    println!("  TX enabled:  {}", config.tx_enabled);
    println!("  RX enabled:  {}", config.rx_enabled);
    println!();

    println!("Expected Accuracy:");
    println!("  Software timestamps:  ~10-100 µs");
    println!("  Hardware timestamps:  ~10-100 ns");
    println!();

    println!("Benefits for NTP:");
    println!("  • Eliminates kernel scheduling jitter");
    println!("  • Provides deterministic packet timestamps");
    println!("  • Enables sub-microsecond NTP accuracy");
    println!("  • Critical for Stratum 1 servers");
    println!();

    println!("NICs with Hardware Timestamping Support:");
    println!("  • Intel i210, i350 (igb driver)");
    println!("  • Intel X540, X550 (ixgbe driver)");
    println!("  • Broadcom NetXtreme (bnxt_en driver)");
    println!("  • Mellanox ConnectX (mlx5 driver)");
    println!();

    println!("Verify NIC support:");
    println!("  sudo ethtool -T eth0");
    println!();

    println!("Example ethtool output (supported):");
    println!("  Time stamping parameters for eth0:");
    println!("  Capabilities:");
    println!("    hardware-transmit     (SOF_TIMESTAMPING_TX_HARDWARE)");
    println!("    hardware-receive      (SOF_TIMESTAMPING_RX_HARDWARE)");
    println!("    hardware-raw-clock    (SOF_TIMESTAMPING_RAW_HARDWARE)");
    println!();

    Ok(())
}
