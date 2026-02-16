// Reference clock support for high-precision time synchronization
//
// This module provides interfaces for hardware reference clocks including:
// - GPS receivers (NMEA protocol)
// - PPS (Pulse Per Second) signals
// - Atomic clocks
// - Hardware timestamping
//
// Reference clocks enable Stratum 1 NTP server operation.

use std::io;
use std::time::Duration;

#[cfg(feature = "tokio")]
use async_trait::async_trait;

/// NMEA 0183 sentence parser for GPS receivers
pub mod nmea;

/// GPS receiver reference clock implementation
#[cfg(feature = "gps")]
pub mod gps;

#[cfg(all(feature = "pps", target_os = "linux"))]
pub mod pps;

/// A sample from a reference clock
#[derive(Debug, Clone)]
pub struct RefClockSample {
    /// The timestamp from the reference clock
    pub timestamp: crate::unix_time::Instant,

    /// Clock offset in seconds (if available)
    /// Positive means reference clock is ahead
    pub offset: f64,

    /// Estimated dispersion/uncertainty in seconds
    pub dispersion: f64,

    /// Quality indicator (0-100, where 100 is best)
    /// Affected by: satellite count, signal strength, HDOP, etc.
    pub quality: u8,
}

/// Generic interface for reference clocks
///
/// Reference clocks provide authoritative time sources for NTP servers
/// and clients. Implementations include GPS receivers, PPS signals,
/// atomic clocks, and other high-precision time sources.
#[cfg(feature = "tokio")]
#[async_trait]
pub trait RefClock: Send + Sync {
    /// Read a time sample from the reference clock
    ///
    /// This may block waiting for the next time update (e.g., GPS sentence,
    /// PPS pulse). Returns an error if the clock is unavailable or the
    /// sample is invalid.
    async fn read_sample(&mut self) -> io::Result<RefClockSample>;

    /// Get the stratum to advertise when using this reference clock
    ///
    /// Typically 0 for actual reference clocks (GPS, atomic), which
    /// makes the server Stratum 1. Return 1 or higher if this is a
    /// secondary reference.
    fn stratum(&self) -> u8;

    /// Get the reference identifier for this clock
    ///
    /// Common values:
    /// - `GPS` - GPS receiver
    /// - `PPS` - Pulse per second
    /// - `ATOM` - Atomic clock
    /// - `GOOG` - Google NTP (for testing)
    /// - `LOCL` - Local clock (testing only)
    fn reference_id(&self) -> [u8; 4];

    /// Get the recommended poll interval for this clock
    ///
    /// How often to query this reference clock. GPS typically
    /// updates once per second, so a 1-second poll is appropriate.
    fn poll_interval(&self) -> Duration;

    /// Check if the reference clock is currently healthy
    ///
    /// Returns false if the clock has lost sync, has no fix,
    /// or is otherwise unavailable. The server should not
    /// advertise Stratum 1 when this returns false.
    fn is_healthy(&self) -> bool {
        true  // Default implementation
    }

    /// Get a human-readable description of this reference clock
    fn description(&self) -> &str {
        "Generic reference clock"
    }
}

/// Local system clock reference (for testing only)
///
/// This "reference clock" simply returns the local system time.
/// It should NEVER be used in production as it provides no actual
/// time reference. Useful for testing the RefClock infrastructure.
#[cfg(feature = "tokio")]
pub struct LocalClock {
    dispersion: f64,
}

#[cfg(feature = "tokio")]
impl LocalClock {
    /// Create a new local clock reference
    ///
    /// # Arguments
    /// * `dispersion` - Uncertainty to report (typically high, e.g., 1.0 second)
    pub fn new(dispersion: f64) -> Self {
        Self { dispersion }
    }
}

#[cfg(feature = "tokio")]
#[async_trait]
impl RefClock for LocalClock {
    async fn read_sample(&mut self) -> io::Result<RefClockSample> {
        Ok(RefClockSample {
            timestamp: crate::unix_time::Instant::now(),
            offset: 0.0,
            dispersion: self.dispersion,
            quality: 50,  // Medium quality
        })
    }

    fn stratum(&self) -> u8 {
        10  // High stratum for local clock
    }

    fn reference_id(&self) -> [u8; 4] {
        *b"LOCL"
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn is_healthy(&self) -> bool {
        true
    }

    fn description(&self) -> &str {
        "Local system clock (testing only)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn test_local_clock() {
        let mut clock = LocalClock::new(1.0);

        let sample = clock.read_sample().await.unwrap();
        assert_eq!(sample.offset, 0.0);
        assert_eq!(sample.dispersion, 1.0);
        assert_eq!(sample.quality, 50);

        assert_eq!(clock.stratum(), 10);
        assert_eq!(clock.reference_id(), *b"LOCL");
        assert_eq!(clock.poll_interval(), Duration::from_secs(1));
        assert!(clock.is_healthy());
    }
}
