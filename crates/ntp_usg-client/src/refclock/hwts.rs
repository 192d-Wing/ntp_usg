// Hardware timestamping support for NTP packets
//
// Provides NIC-level hardware timestamps via SO_TIMESTAMPING on Linux.
// Hardware timestamping eliminates kernel scheduling jitter and provides
// sub-microsecond accuracy for NTP packets.
//
// Requires Linux kernel 2.6.30+ with hardware timestamping support.
#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::time::Duration;

/// Hardware timestamping capabilities (from <linux/net_tstamp.h>)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwTimestampCapabilities {
    /// Hardware transmit timestamp
    pub tx_hardware: bool,
    /// Hardware receive timestamp
    pub rx_hardware: bool,
    /// Software transmit timestamp
    pub tx_software: bool,
    /// Software receive timestamp
    pub rx_software: bool,
    /// Raw hardware timestamp
    pub raw_hardware: bool,
}

/// Hardware timestamp mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampMode {
    /// No timestamping
    None,
    /// Software timestamping only
    Software,
    /// Hardware timestamping (requires NIC support)
    Hardware,
    /// Hardware timestamping with raw timestamps
    HardwareRaw,
}

// Linux SO_TIMESTAMPING constants
const SOF_TIMESTAMPING_TX_HARDWARE: u32 = 1 << 0;
const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
const SOF_TIMESTAMPING_RX_HARDWARE: u32 = 1 << 2;
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
const SOF_TIMESTAMPING_RAW_HARDWARE: u32 = 1 << 6;

const SO_TIMESTAMPING: i32 = 37;

/// Hardware timestamp from kernel (from struct timespec)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HwTimestamp {
    /// Seconds since Unix epoch
    pub sec: i64,
    /// Nanoseconds
    pub nsec: i64,
}

impl HwTimestamp {
    /// Convert to Duration since Unix epoch.
    ///
    /// The kernel should always deliver `0 <= nsec < 1e9` and `sec >= 0`, but
    /// this is driver-supplied data: a buggy or malicious driver must not be
    /// able to panic the client. Negative seconds clamp to zero and
    /// out-of-range nanoseconds are normalised rather than truncated.
    pub fn to_duration(&self) -> Duration {
        let secs = u64::try_from(self.sec).unwrap_or(0);
        let nanos = u64::try_from(self.nsec).unwrap_or(0);
        Duration::from_secs(secs).saturating_add(Duration::from_nanos(nanos))
    }

    /// Get timestamp as f64 seconds
    pub fn as_secs_f64(&self) -> f64 {
        self.sec as f64 + (self.nsec as f64 / 1e9)
    }
}

/// Enable hardware timestamping on a socket
///
/// # Arguments
///
/// * `fd` - Socket file descriptor
/// * `mode` - Timestamping mode to enable
///
/// # Returns
///
/// Returns Ok(()) if timestamping was enabled, or an error if the operation failed.
///
/// # Examples
///
/// ```no_run
/// use std::net::UdpSocket;
/// use std::os::unix::io::AsRawFd;
/// use ntp_client::refclock::hwts::{enable_timestamping, TimestampMode};
///
/// let sock = UdpSocket::bind("0.0.0.0:0")?;
/// enable_timestamping(sock.as_raw_fd(), TimestampMode::Hardware)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn enable_timestamping(fd: i32, mode: TimestampMode) -> io::Result<()> {
    let flags = match mode {
        TimestampMode::None => 0,
        TimestampMode::Software => {
            SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE
        }
        TimestampMode::Hardware => {
            SOF_TIMESTAMPING_TX_HARDWARE
                | SOF_TIMESTAMPING_RX_HARDWARE
                | SOF_TIMESTAMPING_RAW_HARDWARE
        }
        TimestampMode::HardwareRaw => SOF_TIMESTAMPING_RAW_HARDWARE,
    };

    // SAFETY: setsockopt(2) with SOL_SOCKET/SO_TIMESTAMPING enables kernel packet
    // timestamping on a valid socket fd. The flags pointer references a stack-allocated
    // u32 with the correct size passed via size_of::<u32>(). Return != 0 indicates
    // error (checked inside).
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TIMESTAMPING,
            &flags as *const u32 as *const libc::c_void,
            mem::size_of::<u32>() as libc::socklen_t,
        );

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Get hardware timestamping capabilities of a network interface
///
/// # Arguments
///
/// * `fd` - Socket file descriptor
/// * `interface` - Network interface name (e.g., "eth0")
///
/// # Returns
///
/// Returns the hardware timestamping capabilities, or an error if not supported.
///
/// # Examples
///
/// ```no_run
/// use std::net::UdpSocket;
/// use std::os::unix::io::AsRawFd;
/// use ntp_client::refclock::hwts::get_timestamping_capabilities;
///
/// let sock = UdpSocket::bind("0.0.0.0:0")?;
/// let caps = get_timestamping_capabilities(sock.as_raw_fd(), "eth0")?;
/// println!("Hardware TX: {}", caps.tx_hardware);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn get_timestamping_capabilities(
    fd: i32,
    _interface: &str,
) -> io::Result<HwTimestampCapabilities> {
    // This is a simplified implementation. Full implementation would use
    // SIOCETHTOOL ioctl with ETHTOOL_GET_TS_INFO to query NIC capabilities.
    // For now, we attempt to enable hardware timestamping and report success/failure.

    let test_flags =
        SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;

    // SAFETY: setsockopt(2) with SO_TIMESTAMPING to probe hardware timestamping
    // support. The test_flags pointer references a stack-allocated u32. The socket fd
    // is caller-provided and assumed valid. Success (ret == 0) indicates the NIC
    // supports the requested mode; failure is not fatal (we just report unsupported).
    let hw_supported = unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TIMESTAMPING,
            &test_flags as *const u32 as *const libc::c_void,
            mem::size_of::<u32>() as libc::socklen_t,
        );
        ret == 0
    };

    // Software timestamping is always supported on Linux 2.6.30+
    Ok(HwTimestampCapabilities {
        tx_hardware: hw_supported,
        rx_hardware: hw_supported,
        tx_software: true,
        rx_software: true,
        raw_hardware: hw_supported,
    })
}

/// Extract hardware timestamp from ancillary message data
///
/// This function parses the control message returned by recvmsg()
/// to extract hardware timestamps. The data is `SCM_TIMESTAMPING`:
/// three consecutive `struct timespec` values laid out as
/// `[software, deprecated, hardware]`.
///
/// Passing arbitrary bytes is safe: too-short input yields `None`, and the
/// value is read with an unaligned load so the slice's alignment does not
/// matter.
pub fn extract_timestamp(cmsg_data: &[u8]) -> Option<HwTimestamp> {
    const TS_SIZE: usize = mem::size_of::<HwTimestamp>();

    if cmsg_data.len() < TS_SIZE * 3 {
        // Not enough data for hardware timestamp
        return None;
    }

    // Hardware timestamp is at index 2 in the [software, deprecated, hardware] array
    let hw_ts_offset = TS_SIZE * 2;
    // SAFETY: The length check above guarantees `hw_ts_offset + TS_SIZE <=
    // cmsg_data.len()`, so the read stays inside the slice. `HwTimestamp` is
    // `#[repr(C)]` plain-old-data (two `i64`s) for which every bit pattern is
    // valid. `cmsg_data` is a `&[u8]` and therefore only 1-byte aligned, so
    // `read_unaligned` is required: a plain dereference of a `*const
    // HwTimestamp` here would be UB whenever the buffer is not 8-byte aligned.
    let hw_ts = unsafe {
        let ts_ptr = cmsg_data.as_ptr().add(hw_ts_offset) as *const HwTimestamp;
        ts_ptr.read_unaligned()
    };

    // Check if timestamp is non-zero (zero means not available)
    if hw_ts.sec == 0 && hw_ts.nsec == 0 {
        None
    } else {
        Some(hw_ts)
    }
}

/// Check if hardware timestamping is available on this system
///
/// # Returns
///
/// Returns true if the kernel supports SO_TIMESTAMPING.
pub fn is_hardware_timestamping_available() -> bool {
    // Try to create a test socket and enable timestamping
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;

    match UdpSocket::bind("127.0.0.1:0") {
        Ok(sock) => enable_timestamping(sock.as_raw_fd(), TimestampMode::Software).is_ok(),
        Err(_) => false,
    }
}

/// Configuration for hardware timestamping
#[derive(Debug, Clone)]
pub struct HwTimestampConfig {
    /// Timestamping mode
    pub mode: TimestampMode,

    /// Network interface to use (e.g., "eth0")
    pub interface: Option<String>,

    /// Enable transmit timestamps
    pub tx_enabled: bool,

    /// Enable receive timestamps
    pub rx_enabled: bool,
}

impl Default for HwTimestampConfig {
    fn default() -> Self {
        Self {
            mode: TimestampMode::Hardware,
            interface: None,
            tx_enabled: true,
            rx_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_mode() {
        assert_eq!(TimestampMode::None, TimestampMode::None);
        assert_ne!(TimestampMode::Hardware, TimestampMode::Software);
    }

    #[test]
    fn test_hw_timestamp_conversion() {
        let ts = HwTimestamp {
            sec: 1234567890,
            nsec: 123456789,
        };

        let duration = ts.to_duration();
        assert_eq!(duration.as_secs(), 1234567890);
        assert_eq!(duration.subsec_nanos(), 123456789);

        let secs_f64 = ts.as_secs_f64();
        assert!((secs_f64 - 1_234_567_890.123_456_7).abs() < 1e-9);
    }

    #[test]
    fn test_hw_timestamp_conversion_out_of_range_does_not_panic() {
        // nsec >= 1e9 must normalise, not truncate or panic.
        let ts = HwTimestamp {
            sec: 10,
            nsec: 2_500_000_000,
        };
        assert_eq!(ts.to_duration(), Duration::new(12, 500_000_000));

        // Negative values from a broken driver clamp to zero.
        let ts = HwTimestamp { sec: -5, nsec: -1 };
        assert_eq!(ts.to_duration(), Duration::ZERO);

        // Extreme values saturate.
        let ts = HwTimestamp {
            sec: i64::MAX,
            nsec: i64::MAX,
        };
        let _ = ts.to_duration();
    }

    #[test]
    fn test_extract_timestamp_unaligned_buffer() {
        // Build [sw, deprecated, hw] timespecs at a deliberately misaligned
        // offset (1 byte) inside an over-allocated buffer.
        let hw = HwTimestamp {
            sec: 1_700_000_000,
            nsec: 42,
        };
        let mut buf = vec![0u8; 1 + 3 * mem::size_of::<HwTimestamp>()];
        let off = 1 + 2 * mem::size_of::<HwTimestamp>();
        buf[off..off + 8].copy_from_slice(&hw.sec.to_ne_bytes());
        buf[off + 8..off + 16].copy_from_slice(&hw.nsec.to_ne_bytes());

        let got = extract_timestamp(&buf[1..]).expect("hw timestamp present");
        assert_eq!(got.sec, hw.sec);
        assert_eq!(got.nsec, hw.nsec);
    }

    #[test]
    fn test_extract_timestamp_short_or_zero() {
        assert!(extract_timestamp(&[0u8; 10]).is_none());
        assert!(extract_timestamp(&[0u8; 3 * mem::size_of::<HwTimestamp>()]).is_none());
    }

    #[test]
    fn test_is_available() {
        // This test just ensures the function doesn't panic
        let _available = is_hardware_timestamping_available();
    }

    #[test]
    fn test_config_default() {
        let config = HwTimestampConfig::default();
        assert_eq!(config.mode, TimestampMode::Hardware);
        assert!(config.tx_enabled);
        assert!(config.rx_enabled);
    }

    // Note: Actual hardware timestamping tests require specific NIC hardware
    // and elevated privileges, so they are omitted from unit tests.
}
