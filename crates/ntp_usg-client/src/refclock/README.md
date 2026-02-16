# Reference Clock Support

This module provides interfaces for hardware reference clocks that enable Stratum 1 NTP server operation.

## Features

### GPS Receiver (`gps` feature)

GPS receivers provide highly accurate time synchronization via satellite signals. This implementation supports NMEA 0183 protocol over serial ports.

**Supported NMEA Sentences:**
- `$GPGGA` / `$GNGGA` - Global Positioning System Fix Data
- `$GPRMC` / `$GNRMC` - Recommended Minimum Specific GPS Data
- `$GPZDA` / `$GNZDA` - Date & Time (preferred for NTP)

**Fix Quality Levels:**
- GPS (quality 1) - Standard GPS fix
- DGPS (quality 2) - Differential GPS
- PPS (quality 3) - PPS-disciplined GPS
- RTK (quality 4-5) - Real-Time Kinematic

**Example Usage:**

```rust
use ntp_client::refclock::gps::{GpsConfig, GpsReceiver};
use ntp_client::refclock::RefClock;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = GpsConfig {
        device: PathBuf::from("/dev/ttyUSB0"),
        baud_rate: 9600,
        min_satellites: 3,
        min_quality: ntp_client::refclock::nmea::FixQuality::Gps,
        reference_id: *b"GPS\0",
        poll_interval: Duration::from_secs(1),
    };

    let mut gps = GpsReceiver::new(config)?;

    loop {
        let sample = gps.read_sample().await?;
        println!("GPS offset: {:.6}s, dispersion: {:.6}s",
                 sample.offset, sample.dispersion);
        tokio::time::sleep(gps.poll_interval()).await;
    }
}
```

**Hardware Requirements:**
- GPS receiver with NMEA 0183 output via serial port
- Common devices:
  - USB GPS receivers: `/dev/ttyUSB0`, `/dev/ttyACM0`
  - Raspberry Pi GPIO UART: `/dev/ttyAMA0`, `/dev/serial0`
  - Windows: `COM3`, `COM4`, etc.

**Permissions:**
On Linux, you may need to add your user to the `dialout` group:
```bash
sudo usermod -a -G dialout $USER
```

### PPS (Pulse Per Second) - Coming Soon

High-precision timing via PPS signals from GPS receivers or atomic clocks.

**Planned Features:**
- Kernel PPS support on Linux
- Hardware timestamping
- Nanosecond-level precision
- Automatic drift compensation

### Hardware Timestamping - Coming Soon

Network Interface Card (NIC) hardware timestamps for reduced network jitter.

**Planned Features:**
- `SO_TIMESTAMPING` support
- PTP hardware clock integration
- Sub-microsecond NTP accuracy

## RefClock Trait

All reference clocks implement the `RefClock` trait:

```rust
#[async_trait]
pub trait RefClock: Send + Sync {
    /// Read a time sample from the reference clock
    async fn read_sample(&mut self) -> io::Result<RefClockSample>;

    /// Get the stratum to advertise (typically 0 or 1)
    fn stratum(&self) -> u8;

    /// Get the reference identifier (e.g., "GPS\0", "PPS\0")
    fn reference_id(&self) -> [u8; 4];

    /// Get the recommended poll interval
    fn poll_interval(&self) -> Duration;

    /// Check if the reference clock is currently healthy
    fn is_healthy(&self) -> bool;

    /// Get a human-readable description
    fn description(&self) -> &str;
}
```

## Examples

See [`examples/gps_receiver.rs`](../../examples/gps_receiver.rs) for a complete GPS receiver example.

**Run the example:**
```bash
cargo run -p ntp_usg-client --example gps_receiver --features gps -- /dev/ttyUSB0
```

## Testing

GPS receiver functionality requires actual hardware. For testing without hardware, use the `LocalClock` implementation:

```rust
use ntp_client::refclock::{LocalClock, RefClock};

#[tokio::test]
async fn test_refclock_interface() {
    let mut clock = LocalClock::new(1.0);
    let sample = clock.read_sample().await.unwrap();
    assert_eq!(sample.offset, 0.0);
}
```

## Stratum 1 NTP Server

Reference clocks enable Stratum 1 NTP server operation. Future versions will integrate reference clocks with `ntp_usg-server`.

**Planned API:**
```rust
let server = NtpServer::builder()
    .bind("0.0.0.0:123")
    .reference_clock(gps_receiver)
    .stratum(1)
    .build()
    .await?;
```

## Platform Support

| Feature | Linux | macOS | Windows | Embedded |
|---------|-------|-------|---------|----------|
| GPS NMEA | ✅ | ✅ | ✅ | ✅ (no_std with alloc) |
| PPS | 🚧 Planned (Linux kernel PPS) | ❌ | ❌ | 🚧 Planned |
| Hardware Timestamping | 🚧 Planned | ❌ | ❌ | ❌ |

## Performance

**GPS Receiver:**
- Accuracy: 100μs - 1ms (depends on fix quality)
- Latency: ~1 second (NMEA sentence rate)
- Dispersion: 1μs (PPS) to 1ms (standard GPS)

**With PPS:**
- Accuracy: < 1μs
- Latency: < 1ms
- Dispersion: < 10μs

## See Also

- [RFC 5905 - Network Time Protocol Version 4](https://www.rfc-editor.org/rfc/rfc5905.html)
- [NMEA 0183 Specification](https://www.nmea.org/content/STANDARDS/NMEA_0183_Standard)
- [Linux Kernel PPS Documentation](https://www.kernel.org/doc/html/latest/driver-api/pps.html)
- [GPS Time vs UTC](https://en.wikipedia.org/wiki/Global_Positioning_System#Timekeeping)

## Roadmap

See [ROADMAP.md](../../../../ROADMAP.md) for the complete v3.3.0 Hardware Integration plan.

**Current Status:**
- ✅ GPS receiver (NMEA 0183)
- 🚧 PPS integration
- 🚧 Hardware timestamping
- 🚧 Stratum 1 server mode
