// Multi-peer NTP deployment example demonstrating:
// - RFC 5905 selection, clustering, and combine algorithms
// - Truechimer identification and falseticker detection
// - Adaptive poll intervals
// - Error handling and fallback strategies
// - Monitoring and observability

use ntp_client::client::NtpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 Multi-Peer NTP Client");
    println!("========================\n");

    // Configure a robust multi-peer deployment
    // Recommendation: 5-7 peers from diverse geographic locations and organizations
    let (client, mut state_rx) = NtpClient::builder()
        // NIST time servers (US Government)
        .server("time.nist.gov:123")
        .server("time-a-g.nist.gov:123")
        // Cloudflare (Global CDN)
        .server("time.cloudflare.com:123")
        // Google Public NTP (Global)
        .server("time.google.com:123")
        // pool.ntp.org (Community pool)
        .server("0.pool.ntp.org:123")
        // Adaptive poll intervals: 64s to 1024s (~17 minutes)
        .min_poll(6) // 2^6 = 64 seconds
        .max_poll(10) // 2^10 = 1024 seconds
        .build()
        .await?;

    println!("✅ Configured 5 NTP peers");
    println!("   Poll interval: 64s - 1024s (adaptive)");
    println!("   Selection: RFC 5905 Marzullo's algorithm");
    println!("   Clustering: Statistical outlier removal\n");

    // Spawn the client task
    let mut client_handle = tokio::spawn(client.run());

    // Monitor state updates
    let mut update_count = 0;
    let mut last_offset: Option<f64> = None;

    loop {
        tokio::select! {
            // Wait for state changes
            Ok(()) = state_rx.changed() => {
                let state = state_rx.borrow().clone();
                update_count += 1;

                println!("📊 Update #{}", update_count);
                println!("   Offset:  {:>10.6} seconds", state.offset);
                println!("   Delay:   {:>10.6} seconds", state.delay);
                println!("   Jitter:  {:>10.6} seconds", state.jitter);

                // Show offset trend
                if let Some(prev) = last_offset {
                    let delta = state.offset - prev;
                    let trend = if delta.abs() < 0.0001 {
                        "→ stable"
                    } else if delta > 0.0 {
                        "↗ drifting forward"
                    } else {
                        "↘ drifting backward"
                    };
                    println!("   Trend:   {} ({:+.6}s)", trend, delta);
                }
                last_offset = Some(state.offset);

                // Health assessment
                print_health_assessment(&state);

                println!();

                // Stop after demonstrating convergence (10 updates)
                if update_count >= 10 {
                    println!("✅ Demonstration complete. Stopping client.");
                    break;
                }
            }

            // Handle client task completion
            res = &mut client_handle => {
                match res {
                    Ok(()) => println!("ℹ️  Client stopped normally"),
                    Err(e) => eprintln!("❌ Task panic: {}", e),
                }
                break;
            }
        }
    }

    Ok(())
}

/// Assess clock health based on NTP metrics
fn print_health_assessment(state: &ntp_client::client_common::NtpSyncState) {
    let offset_ms = state.offset * 1000.0;
    let delay_ms = state.delay * 1000.0;
    let jitter_ms = state.jitter * 1000.0;

    // Offset assessment
    let offset_status = if offset_ms.abs() < 1.0 {
        "🟢 excellent"
    } else if offset_ms.abs() < 10.0 {
        "🟡 good"
    } else if offset_ms.abs() < 100.0 {
        "🟠 fair"
    } else {
        "🔴 poor"
    };

    // Delay assessment
    let delay_status = if delay_ms < 50.0 {
        "🟢 excellent"
    } else if delay_ms < 100.0 {
        "🟡 good"
    } else if delay_ms < 200.0 {
        "🟠 fair"
    } else {
        "🔴 poor"
    };

    // Jitter assessment
    let jitter_status = if jitter_ms < 1.0 {
        "🟢 excellent"
    } else if jitter_ms < 10.0 {
        "🟡 good"
    } else if jitter_ms < 50.0 {
        "🟠 fair"
    } else {
        "🔴 poor"
    };

    println!("   Health:  Offset {} | Delay {} | Jitter {}", offset_status, delay_status, jitter_status);

    // Warnings
    if offset_ms.abs() > 128.0 {
        println!("   ⚠️  WARNING: Offset > 128ms (step threshold)");
    }
    if jitter_ms > 100.0 {
        println!("   ⚠️  WARNING: High jitter indicates network instability");
    }
}
