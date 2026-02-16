// NTS-authenticated multi-peer continuous client example demonstrating:
// - Network Time Security (RFC 8915) with multiple servers
// - Automatic cookie replenishment and key exchange
// - Re-keying strategies and failure recovery
// - Combined authenticated and unauthenticated servers
// - Monitoring NTS session health

use ntp_client::client::NtpClient;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 NTS Multi-Peer Authenticated Client");
    println!("======================================\n");

    // Build a robust NTS deployment with multiple authenticated servers
    // Mixed deployment: NTS servers for security + standard NTP for redundancy
    let (client, mut state_rx) = NtpClient::builder()
        // Primary: Cloudflare NTS (Global CDN, excellent NTS support)
        .nts_server("time.cloudflare.com")
        // Secondary: NTP Pool NTS (European server)
        .nts_server("ntppool-nts.time.nl")
        // Fallback: Standard NTP servers (no authentication but faster)
        .server("time.nist.gov:123")
        .server("time.google.com:123")
        // Adaptive polling
        .min_poll(6) // 64 seconds
        .max_poll(10) // 1024 seconds
        .build()
        .await?;

    println!("✅ Configured NTS client");
    println!("   NTS servers: time.cloudflare.com, ntppool-nts.time.nl");
    println!("   Fallback:    time.nist.gov, time.google.com");
    println!("   Security:    TLS 1.3 key exchange + AEAD authentication\n");

    // Spawn the client task
    let mut client_handle = tokio::spawn(client.run());

    // Monitor state with emphasis on NTS health
    let mut update_count = 0;
    let mut nts_failure_count = 0;
    let mut last_nts_status = false;

    loop {
        tokio::select! {
            // Wait for state changes
            Ok(()) = state_rx.changed() => {
                let state = state_rx.borrow().clone();
                update_count += 1;

                println!("📊 Update #{}", update_count);
                println!("   Offset:   {:>10.6} seconds", state.offset);
                println!("   Delay:    {:>10.6} seconds", state.delay);
                println!("   Jitter:   {:>10.6} seconds", state.jitter);

                // NTS authentication status
                let nts_indicator = if state.nts_authenticated {
                    "🔐 AUTHENTICATED"
                } else {
                    "⚠️  UNAUTHENTICATED"
                };
                println!("   NTS:      {}", nts_indicator);

                // Track NTS failures
                if !state.nts_authenticated && last_nts_status {
                    nts_failure_count += 1;
                    println!("   ⚠️  NTS authentication lost (failure #{})", nts_failure_count);
                } else if state.nts_authenticated && !last_nts_status {
                    println!("   ✅ NTS authentication restored");
                }
                last_nts_status = state.nts_authenticated;

                // Security posture assessment
                print_security_posture(&state, nts_failure_count);

                println!();

                // Demonstrate for 15 updates
                if update_count >= 15 {
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

            // Timeout after 5 minutes
            _ = tokio::time::sleep(Duration::from_secs(300)) => {
                println!("⏱️  Timeout reached, stopping demonstration.");
                break;
            }
        }
    }

    // Final statistics
    println!("\n📈 Session Summary");
    println!("   Total updates:        {}", update_count);
    println!("   NTS failures:         {}", nts_failure_count);
    let reliability = if update_count > 0 {
        100.0 * (1.0 - (nts_failure_count as f64 / update_count as f64))
    } else {
        0.0
    };
    println!("   NTS reliability:      {:.1}%", reliability);

    Ok(())
}

/// Assess security posture based on NTS authentication and metrics
fn print_security_posture(
    state: &ntp_client::client_common::NtpSyncState,
    failure_count: u32,
) {
    let offset_ms = state.offset.abs() * 1000.0;
    let jitter_ms = state.jitter * 1000.0;

    // Security level assessment
    let security_level = if state.nts_authenticated && offset_ms < 10.0 && jitter_ms < 10.0 {
        "🟢 EXCELLENT - Authenticated & Stable"
    } else if state.nts_authenticated && offset_ms < 100.0 {
        "🟡 GOOD - Authenticated"
    } else if !state.nts_authenticated && failure_count == 0 {
        "🟠 ACCEPTABLE - Unauthenticated by design"
    } else if !state.nts_authenticated && failure_count < 3 {
        "🟠 WARNING - NTS degraded, using fallback"
    } else {
        "🔴 CRITICAL - NTS failed, security compromised"
    };

    println!("   Security: {}", security_level);

    // Recommendations
    if !state.nts_authenticated && failure_count > 0 {
        println!("   💡 Tip: Check network connectivity to NTS servers");
        println!("          NTS requires TLS 1.3 support (port 4460)");
    }

    if offset_ms > 100.0 {
        println!("   ⚠️  Large offset detected - possible time manipulation");
        println!("          Verify server authenticity if not using NTS");
    }

    if jitter_ms > 50.0 && state.nts_authenticated {
        println!("   ⚠️  High jitter with NTS may indicate network issues");
    }
}
