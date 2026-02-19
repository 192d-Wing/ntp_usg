// System daemon example demonstrating:
// - Long-running background service with structured tracing
// - EnvFilter for RUST_LOG support
// - Graceful shutdown and health-based alerting
//
// Run with:
//   RUST_LOG=info cargo run -p ntp_usg-client --example daemon --features ntp_usg-client/tokio
//
// Filter to NTP client spans:
//   RUST_LOG=ntp_client=debug cargo run -p ntp_usg-client --example daemon --features ntp_usg-client/tokio

use ntp_client::client::NtpClient;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber with:
    // - EnvFilter: respects RUST_LOG env var (default: info)
    // - fmt layer: human-readable output with timestamps
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();

    info!("NTP daemon starting");

    // Configure NTP client
    let (client, mut state_rx) = NtpClient::builder()
        .server("time.nist.gov:123")
        .server("time.cloudflare.com:123")
        .server("time.google.com:123")
        .min_poll(6) // 64 seconds
        .max_poll(10) // 1024 seconds
        .build()
        .await?;

    info!(
        servers = "time.nist.gov, time.cloudflare.com, time.google.com",
        poll_min_s = 1u64 << 6,
        poll_max_s = 1u64 << 10,
        "NTP client configured"
    );

    // Spawn client task
    let mut client_handle = tokio::spawn(client.run());

    info!("daemon running (will run for 5 minutes as demo)");

    // Main daemon loop
    let mut last_log_time = std::time::Instant::now();
    let log_interval = Duration::from_secs(60);
    let daemon_runtime = Duration::from_secs(300);
    let start_time = std::time::Instant::now();

    loop {
        tokio::select! {
            Ok(()) = state_rx.changed() => {
                let state = state_rx.borrow().clone();

                if last_log_time.elapsed() >= log_interval {
                    log_status(&state);
                    last_log_time = std::time::Instant::now();
                }

                if start_time.elapsed() >= daemon_runtime {
                    info!("demo runtime complete (5 minutes)");
                    break;
                }
            }

            res = &mut client_handle => {
                match res {
                    Ok(()) => {
                        warn!("NTP client stopped unexpectedly");
                        break;
                    },
                    Err(e) => {
                        error!(error = %e, "NTP client panicked");
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    info!("daemon stopped gracefully");
    Ok(())
}

/// Log current NTP synchronization status using structured tracing fields.
fn log_status(state: &ntp_client::client_common::NtpSyncState) {
    let offset_ms = state.offset * 1000.0;
    let delay_ms = state.delay * 1000.0;
    let jitter_ms = state.jitter * 1000.0;

    if offset_ms.abs() < 10.0 && jitter_ms < 10.0 {
        info!(
            offset_ms = format_args!("{:+.3}", offset_ms),
            delay_ms = format_args!("{:.3}", delay_ms),
            jitter_ms = format_args!("{:.3}", jitter_ms),
            status = "healthy",
            "NTP sync status"
        );
    } else if offset_ms.abs() < 100.0 && jitter_ms < 50.0 {
        info!(
            offset_ms = format_args!("{:+.3}", offset_ms),
            delay_ms = format_args!("{:.3}", delay_ms),
            jitter_ms = format_args!("{:.3}", jitter_ms),
            status = "normal",
            "NTP sync status"
        );
    } else if offset_ms.abs() < 500.0 {
        warn!(
            offset_ms = format_args!("{:+.3}", offset_ms),
            delay_ms = format_args!("{:.3}", delay_ms),
            jitter_ms = format_args!("{:.3}", jitter_ms),
            status = "degraded",
            "NTP sync status"
        );
    } else {
        error!(
            offset_ms = format_args!("{:+.3}", offset_ms),
            delay_ms = format_args!("{:.3}", delay_ms),
            jitter_ms = format_args!("{:.3}", jitter_ms),
            status = "unhealthy",
            "NTP sync status"
        );
    }

    if offset_ms.abs() > 128.0 {
        warn!(
            offset_ms = format_args!("{:+.3}", offset_ms),
            "clock offset exceeds step threshold (128ms)"
        );
    }
    if jitter_ms > 100.0 {
        warn!(
            jitter_ms = format_args!("{:.3}", jitter_ms),
            "high jitter indicates network instability"
        );
    }
    if delay_ms > 500.0 {
        warn!(
            delay_ms = format_args!("{:.3}", delay_ms),
            "high network delay detected"
        );
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
//    Environment=RUST_LOG=info
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
// 3. View structured logs:
//    ```bash
//    journalctl -u ntp-daemon -f
//    ```
//
// 4. Filter by level at runtime:
//    RUST_LOG=ntp_client=debug,ntp_daemon=info
//
// 5. For clock adjustment, add the `clock` feature and call:
//    ```rust
//    use ntp_client::clock;
//    if let Ok(offset) = clock::apply_correction(state.offset) {
//        println!("Applied clock correction: {:?}", offset);
//    }
//    ```
//    Note: Requires root/CAP_SYS_TIME on Unix
