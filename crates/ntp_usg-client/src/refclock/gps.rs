// GPS receiver reference clock implementation
//
// Reads NMEA 0183 sentences from a serial GPS receiver and provides
// timing information via the RefClock trait.

use super::nmea::{FixQuality, GpsFix, parse_sentence};
use super::{RefClock, RefClockSample};
use crate::unix_time;
use async_trait::async_trait;
use log::{debug, warn};
use serialport::SerialPort;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task;

/// GPS receiver configuration
#[derive(Clone, Debug)]
pub struct GpsConfig {
    /// Serial port device path (e.g., "/dev/ttyUSB0", "/dev/ttyAMA0", "COM3")
    pub device: PathBuf,

    /// Baud rate (typically 4800 or 9600 for GPS receivers)
    pub baud_rate: u32,

    /// Minimum number of satellites required for a valid fix
    pub min_satellites: u8,

    /// Minimum fix quality required (default: Gps)
    pub min_quality: FixQuality,

    /// Reference ID to report (e.g., b"GPS\0" or b"NMEA")
    pub reference_id: [u8; 4],

    /// Poll interval (how often to return samples)
    pub poll_interval: Duration,
}

impl Default for GpsConfig {
    fn default() -> Self {
        Self {
            device: PathBuf::from("/dev/ttyUSB0"),
            baud_rate: 9600,
            min_satellites: 3,
            min_quality: FixQuality::Gps,
            reference_id: *b"GPS\0",
            poll_interval: Duration::from_secs(1),
        }
    }
}

/// GPS receiver reference clock
///
/// Reads NMEA sentences from a serial GPS receiver and provides precise
/// time synchronization. Suitable for Stratum 1 operation when combined
/// with PPS.
pub struct GpsReceiver {
    config: GpsConfig,
    last_fix: Option<GpsFix>,
    sample_rx: mpsc::UnboundedReceiver<GpsFix>,
    _reader_task: task::JoinHandle<()>,
}

impl GpsReceiver {
    /// Create a new GPS receiver reference clock
    ///
    /// Opens the specified serial port and starts reading NMEA sentences.
    /// The receiver runs in the background and samples are retrieved via
    /// the RefClock trait.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Serial port cannot be opened
    /// - Serial port configuration fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ntp_client::refclock::gps::{GpsConfig, GpsReceiver};
    /// use std::path::PathBuf;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let config = GpsConfig {
    ///     device: PathBuf::from("/dev/ttyUSB0"),
    ///     baud_rate: 9600,
    ///     ..Default::default()
    /// };
    ///
    /// let gps = GpsReceiver::new(config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: GpsConfig) -> io::Result<Self> {
        // Open serial port
        let port = serialport::new(config.device.to_string_lossy(), config.baud_rate)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(|e| io::Error::other(format!("Failed to open GPS serial port: {}", e)))?;

        let (sample_tx, sample_rx) = mpsc::unbounded_channel();

        // Spawn background reader task
        let reader_task = task::spawn_blocking(move || {
            Self::reader_loop(port, sample_tx);
        });

        Ok(Self {
            config,
            last_fix: None,
            sample_rx,
            _reader_task: reader_task,
        })
    }

    /// Background reader loop that reads NMEA sentences from serial port
    fn reader_loop(port: Box<dyn SerialPort>, sample_tx: mpsc::UnboundedSender<GpsFix>) {
        let mut reader = BufReader::new(port.try_clone().expect("Failed to clone serial port"));
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // EOF - shouldn't happen on serial port
                    warn!("GPS receiver: unexpected EOF on serial port");
                    break;
                }
                Ok(_) => {
                    // Try to parse NMEA sentence
                    match parse_sentence(line.trim()) {
                        Ok(Some(fix)) => {
                            debug!(
                                "GPS fix: quality={:?}, sats={}, time={:?}",
                                fix.quality, fix.satellites, fix.time
                            );
                            // Send to channel (ignore errors if receiver dropped)
                            let _ = sample_tx.send(fix);
                        }
                        Ok(None) => {
                            // Unsupported sentence type - ignore
                        }
                        Err(e) => {
                            debug!("GPS parse error: {}", e);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    // Timeout is normal - just continue
                    continue;
                }
                Err(e) => {
                    warn!("GPS receiver read error: {}", e);
                    break;
                }
            }
        }

        debug!("GPS receiver loop exiting");
    }

    /// Check if the GPS receiver has a valid fix
    pub fn has_valid_fix(&self) -> bool {
        self.last_fix
            .as_ref()
            .map(|fix| {
                fix.quality.is_valid()
                    && fix.quality as u8 >= self.config.min_quality as u8
                    && fix.satellites >= self.config.min_satellites
                    && fix.date.is_some()
            })
            .unwrap_or(false)
    }
}

#[async_trait]
impl RefClock for GpsReceiver {
    async fn read_sample(&mut self) -> io::Result<RefClockSample> {
        // Drain all pending fixes and keep the latest
        while let Ok(fix) = self.sample_rx.try_recv() {
            self.last_fix = Some(fix);
        }

        // Wait for a new fix if we don't have one
        if self.last_fix.is_none() {
            self.last_fix = self.sample_rx.recv().await;
        }

        let fix = self
            .last_fix
            .as_ref()
            .ok_or_else(|| io::Error::other("GPS receiver channel closed"))?;

        // Check if fix is valid
        if !fix.quality.is_valid() {
            return Err(io::Error::other(format!(
                "GPS fix quality insufficient: {:?}",
                fix.quality
            )));
        }

        if (fix.quality as u8) < (self.config.min_quality as u8) {
            return Err(io::Error::other(format!(
                "GPS fix quality {:?} below minimum {:?}",
                fix.quality, self.config.min_quality
            )));
        }

        if fix.satellites < self.config.min_satellites {
            return Err(io::Error::other(format!(
                "GPS satellite count {} below minimum {}",
                fix.satellites, self.config.min_satellites
            )));
        }

        // Convert GPS time to Unix timestamp
        let gps_timestamp = fix
            .to_unix_timestamp()
            .ok_or_else(|| io::Error::other("GPS fix missing date information"))?;

        // Get current system time for offset calculation
        let now = unix_time::Instant::now();
        let now_secs = now.secs() as f64 + (now.subsec_nanos() as f64 / 1e9);

        // Offset = GPS time - system time
        let offset = gps_timestamp - now_secs;

        // Quality indicator: higher quality = lower dispersion
        // PPS fix (quality 3) gets best dispersion, GPS (1) gets moderate
        let dispersion = match fix.quality {
            FixQuality::Pps => 0.000001,                       // 1 microsecond
            FixQuality::DGps => 0.00001,                       // 10 microseconds
            FixQuality::Rtk | FixQuality::FloatRtk => 0.00005, // 50 microseconds
            FixQuality::Gps => 0.0001,                         // 100 microseconds
            _ => 0.001,                                        // 1 millisecond
        };

        // Quality score: 0 (worst) to 255 (best)
        // Based on satellite count and fix quality
        let quality =
            ((fix.satellites.min(16) as u16 * 10 + fix.quality as u16 * 5).min(255)) as u8;

        Ok(RefClockSample {
            timestamp: now,
            offset,
            dispersion,
            quality,
        })
    }

    fn stratum(&self) -> u8 {
        // GPS is a Stratum 0 source, so we report Stratum 1
        1
    }

    fn reference_id(&self) -> [u8; 4] {
        self.config.reference_id
    }

    fn poll_interval(&self) -> Duration {
        self.config.poll_interval
    }

    fn is_healthy(&self) -> bool {
        self.has_valid_fix()
    }

    fn description(&self) -> &str {
        "GPS receiver (NMEA 0183)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gps_config_default() {
        let config = GpsConfig::default();
        assert_eq!(config.baud_rate, 9600);
        assert_eq!(config.min_satellites, 3);
        assert_eq!(config.reference_id, *b"GPS\0");
        assert_eq!(config.min_quality, FixQuality::Gps);
    }

    #[test]
    fn test_gps_config_custom() {
        let config = GpsConfig {
            device: PathBuf::from("/dev/ttyAMA0"),
            baud_rate: 4800,
            min_satellites: 4,
            min_quality: FixQuality::DGps,
            reference_id: *b"NMEA",
            poll_interval: Duration::from_secs(2),
        };

        assert_eq!(config.device, PathBuf::from("/dev/ttyAMA0"));
        assert_eq!(config.baud_rate, 4800);
        assert_eq!(config.min_satellites, 4);
        assert_eq!(config.min_quality, FixQuality::DGps);
        assert_eq!(config.reference_id, *b"NMEA");
        assert_eq!(config.poll_interval, Duration::from_secs(2));
    }

    // Note: Actual GPS receiver tests require hardware and are omitted.
    // Integration tests with mock serial ports could be added separately.
}
