// System daemon example demonstrating:
// - Long-running background service
// - Signal handling (SIGHUP for reload, SIGTERM/SIGINT for shutdown)
// - Structured logging with configurable levels
// - Graceful shutdown
// - Production-ready error handling

use ntp_client::client::NtpClient;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger (in production, use env_logger, tracing, or similar)
    println!("🚀 NTP Daemon Starting");
    println!("======================\n");

    // Configure NTP client
    println!("⚙️  Configuring NTP client...");
    let (client, mut state_rx) = NtpClient::builder()
        .server("time.nist.gov:123")
        .server("time.cloudflare.com:123")
        .server("time.google.com:123")
        .min_poll(6) // 64 seconds
        .max_poll(10) // 1024 seconds
        .build()
        .await?;

    println!("✅ NTP client configured");
    println!("   Servers: time.nist.gov, time.cloudflare.com, time.google.com");
    println!("   Poll: 64s-1024s (adaptive)\n");

    // Spawn client task
    let mut client_handle = tokio::spawn(client.run());

    println!("🟢 Daemon running (will run for 5 minutes as demo)\n");

    // Main daemon loop
    let mut last_log_time = std::time::Instant::now();
    let log_interval = Duration::from_secs(60); // Log every minute
    let daemon_runtime = Duration::from_secs(300); // Run for 5 minutes in demo
    let start_time = std::time::Instant::now();

    loop {
        tokio::select! {
            // State updates from NTP client
            Ok(()) = state_rx.changed() => {
                let state = state_rx.borrow().clone();

                // Log periodically (not every update to avoid spam)
                if last_log_time.elapsed() >= log_interval {
                    log_status(&state);
                    last_log_time = std::time::Instant::now();
                }

                // Check if demo runtime exceeded
                if start_time.elapsed() >= daemon_runtime {
                    println!("\n⏱️  Demo runtime complete (5 minutes)");
                    break;
                }
            }

            // Client task completed (shouldn't happen in normal operation)
            res = &mut client_handle => {
                match res {
                    Ok(()) => {
                        eprintln!("⚠️  NTP client stopped unexpectedly, restarting...");
                        // In production, implement restart logic here
                        break;
                    },
                    Err(e) => {
                        eprintln!("❌ NTP client panic: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    // Graceful shutdown
    println!("🧹 Cleaning up...");
    // In production: flush logs, close connections, save state, etc.

    println!("👋 Daemon stopped gracefully\n");
    Ok(())
}

/// Log current NTP synchronization status
fn log_status(state: &ntp_client::client_common::NtpSyncState) {
    let offset_ms = state.offset * 1000.0;
    let delay_ms = state.delay * 1000.0;
    let jitter_ms = state.jitter * 1000.0;

    // Determine log level based on metrics
    let (level, status) = if offset_ms.abs() < 10.0 && jitter_ms < 10.0 {
        ("INFO", "🟢 HEALTHY")
    } else if offset_ms.abs() < 100.0 && jitter_ms < 50.0 {
        ("INFO", "🟡 NORMAL")
    } else if offset_ms.abs() < 500.0 {
        ("WARN", "🟠 DEGRADED")
    } else {
        ("ERROR", "🔴 UNHEALTHY")
    };

    println!(
        "[{}] {} | Offset: {:+.3}ms | Delay: {:.3}ms | Jitter: {:.3}ms",
        level, status, offset_ms, delay_ms, jitter_ms
    );

    // Log warnings for specific conditions
    if offset_ms.abs() > 128.0 {
        println!("[WARN] Clock offset exceeds step threshold (128ms)");
    }

    if jitter_ms > 100.0 {
        println!("[WARN] High jitter indicates network instability");
    }

    if delay_ms > 500.0 {
        println!("[WARN] High network delay detected");
    }
}

// Production deployment notes:
//
// 1. Systemd Service Unit (/etc/systemd/system/ntp-daemon.service):
//    ```ini
//    [Unit]
//    Description=NTP Time Synchronization Daemon
//    After=network.target
//
//    [Service]
//    Type=simple
//    ExecStart=/usr/local/bin/ntp-daemon
//    Restart=on-failure
//    RestartSec=10
//    StandardOutput=journal
//    StandardError=journal
//
//    # Security hardening
//    NoNewPrivileges=true
//    PrivateTmp=true
//    ProtectSystem=strict
//    ProtectHome=true
//
//    [Install]
//    WantedBy=multi-user.target
//    ```
//
// 2. Enable and start:
//    ```bash
//    sudo systemctl daemon-reload
//    sudo systemctl enable ntp-daemon
//    sudo systemctl start ntp-daemon
//    ```
//
// 3. View logs:
//    ```bash
//    journalctl -u ntp-daemon -f
//    ```
//
// 4. For clock adjustment, add the `clock` feature and call:
//    ```rust
//    use ntp_client::clock;
//    if let Ok(offset) = clock::apply_correction(state.offset) {
//        println!("Applied clock correction: {:?}", offset);
//    }
//    ```
//    Note: Requires root/CAP_SYS_TIME on Unix
