// Stratum 1 NTP Server with Reference Clock
//
// Demonstrates running an NTP server with a LocalClock reference clock.
// The server automatically sets its stratum based on the reference clock and
// updates system state from clock samples.
//
// This example uses LocalClock for simplicity. For production Stratum 1 servers,
// use a GPS receiver or PPS signal instead.
//
// Usage:
//   cargo run -p ntp_usg-server --example stratum1_server --features refclock
//
// Requirements:
//   - Root privileges or CAP_SYS_TIME for binding to port 123
//
// Testing:
//   ntpdate -q localhost
//   ntpq -p localhost
//
// For GPS/PPS examples, see the ntp_usg-client crate:
//   - examples/gps_receiver.rs
//   - examples/pps_receiver.rs
//   - examples/gps_pps_combined.rs

use std::io;

#[cfg(all(feature = "tokio", feature = "refclock"))]
use ntp_server::server::NtpServer;

#[cfg(feature = "refclock")]
use ntp_client::refclock::{LocalClock, RefClock};

#[tokio::main]
async fn main() -> io::Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("═══════════════════════════════════════════════════════");
    println!("Stratum 1 NTP Server with Reference Clock");
    println!("═══════════════════════════════════════════════════════");
    println!();

    #[cfg(feature = "refclock")]
    {
        println!("Reference Clock: Local Clock (simulated)");
        println!("Accuracy: ±1ms");
        println!();
        println!("Note: This is for testing only. Use GPS or PPS for production.");
        println!();

        // Create a local clock reference
        let local_clock = LocalClock::new(0.001); // 1ms accuracy
        println!("✓ Local clock initialized");
        println!("  Stratum: {}", local_clock.stratum());
        println!("  Reference ID: {}", String::from_utf8_lossy(&local_clock.reference_id()));
        println!();

        // Build and start the server with the reference clock
        println!("Starting NTP server...");
        println!();

        let server = NtpServer::builder()
            .listen("0.0.0.0:123")
            .reference_clock(local_clock)  // Automatically sets stratum and reference ID
            .enable_interleaved(true)
            .build()
            .await?;

        let local_addr = server.local_addr()?;

        println!("═══════════════════════════════════════════════════════");
        println!("✓ Stratum 1 NTP Server Running");
        println!("═══════════════════════════════════════════════════════");
        println!();
        println!("Listening on: {}", local_addr);
        println!();
        println!("Test with:");
        println!("  ntpdate -q {}", local_addr.ip());
        println!("  ntpq -p {}", local_addr.ip());
        println!();
        println!("The server will automatically update its state from the");
        println!("reference clock. Press Ctrl+C to stop.");
        println!();

        // Run the server
        server.run().await
    }

    #[cfg(not(feature = "refclock"))]
    {
        eprintln!("Error: This example requires the 'refclock' feature.");
        eprintln!("Build with: cargo run -p ntp_usg-server --example stratum1_server --features refclock");
        Err(io::Error::new(io::ErrorKind::Other, "refclock feature not enabled"))
    }
}
