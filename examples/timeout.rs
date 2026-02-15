//! Example demonstrating the use of custom timeouts with NTP requests.
//!
//! This example shows how to use `request_with_timeout()` to specify custom
//! timeout durations for NTP requests, which is useful when dealing with
//! slow or unreliable network connections.

use std::time::Duration;

fn main() {
    // Example 1: Using a longer timeout for slow networks
    println!("Example 1: Request with 10 second timeout");
    match ntp::request_with_timeout("pool.ntp.org:123", Duration::from_secs(10)) {
        Ok(response) => {
            println!("  Success! Stratum: {:?}", response.stratum);
            println!("  Server mode: {:?}", response.mode);
        }
        Err(e) => println!("  Error: {}", e),
    }

    // Example 2: Using a shorter timeout for fast fail
    println!("\nExample 2: Request with 2 second timeout");
    match ntp::request_with_timeout("time.google.com:123", Duration::from_secs(2)) {
        Ok(response) => {
            println!("  Success! Leap indicator: {:?}", response.leap_indicator);
        }
        Err(e) => println!("  Error (expected on slow connections): {}", e),
    }

    // Example 3: Using the default 5 second timeout
    println!("\nExample 3: Request with default timeout (5 seconds)");
    match ntp::request("0.pool.ntp.org:123") {
        Ok(response) => {
            println!("  Success! Version: {:?}", response.version);
        }
        Err(e) => println!("  Error: {}", e),
    }

    // Example 4: Very short timeout to demonstrate timeout errors
    println!("\nExample 4: Request with very short timeout (100ms)");
    match ntp::request_with_timeout("pool.ntp.org:123", Duration::from_millis(100)) {
        Ok(_) => println!("  Unlikely success!"),
        Err(e) => println!("  Expected timeout error: {}", e),
    }
}
