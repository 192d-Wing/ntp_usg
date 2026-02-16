use crate::protocol;
#[cfg(feature = "std")]
use std::time;

/// The number of seconds from 1st January 1900 UTC to the start of the Unix epoch.
pub const EPOCH_DELTA: i64 = 2_208_988_800;

/// The number of seconds in one NTP era (2^32 seconds, approximately 136 years).
///
/// Era 0 spans from 1900-01-01 00:00:00 UTC to 2036-02-07 06:28:15 UTC.
/// Era 1 begins at 2036-02-07 06:28:16 UTC.
pub const ERA_SECONDS: i64 = 4_294_967_296; // 1i64 << 32

// The NTP fractional scale (32-bit).
const NTP_SCALE: f64 = u32::MAX as f64;

// The NTP fractional scale (64-bit, for DateFormat).
const NTP_SCALE_64: f64 = u64::MAX as f64;

/// Describes an instant relative to the `UNIX_EPOCH` - 00:00:00 Coordinated Universal Time (UTC),
/// Thursay, 1 January 1970 in seconds with the fractional part in nanoseconds.
///
/// If the **Instant** describes some moment prior to `UNIX_EPOCH`, both the `secs` and
/// `subsec_nanos` components will be negative.
///
/// The sole purpose of this type is for retrieving the "current" time using the `std::time` module
/// and for converting between the ntp timestamp formats. If you are interested in converting from
/// unix time to some other more human readable format, perhaps see the [chrono
/// crate](https://crates.io/crates/chrono).
///
/// ## Example
///
/// Here is a demonstration of displaying the **Instant** in local time using the chrono crate
/// (requires the `std` feature):
///
/// ```ignore
/// use chrono::TimeZone;
///
/// let unix_time = ntp_proto::unix_time::Instant::now();
/// let local_time = chrono::Local.timestamp(unix_time.secs(), unix_time.subsec_nanos() as _);
/// println!("{}", local_time);
/// ```
#[derive(Copy, Clone, Debug)]
pub struct Instant {
    secs: i64,
    subsec_nanos: i32,
}

impl Instant {
    /// Create a new **Instant** given its `secs` and `subsec_nanos` components.
    ///
    /// To indicate a time following `UNIX_EPOCH`, both `secs` and `subsec_nanos` must be positive.
    /// To indicate a time prior to `UNIX_EPOCH`, both `secs` and `subsec_nanos` must be negative.
    /// Violating these invariants will result in a **panic!**.
    pub fn new(secs: i64, subsec_nanos: i32) -> Instant {
        if secs > 0 && subsec_nanos < 0 {
            panic!("invalid instant: secs was positive but subsec_nanos was negative");
        }
        if secs < 0 && subsec_nanos > 0 {
            panic!("invalid instant: secs was negative but subsec_nanos was positive");
        }
        Instant { secs, subsec_nanos }
    }

    /// Uses `std::time::SystemTime::now` and `std::time::UNIX_EPOCH` to determine the current
    /// **Instant**.
    ///
    /// ## Example
    ///
    /// ```
    /// println!("{:?}", ntp_proto::unix_time::Instant::now());
    /// ```
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        match time::SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(duration) => {
                let secs = duration.as_secs() as i64;
                let subsec_nanos = duration.subsec_nanos() as i32;
                Instant::new(secs, subsec_nanos)
            }
            Err(sys_time_err) => {
                let duration_pre_unix_epoch = sys_time_err.duration();
                let secs = -(duration_pre_unix_epoch.as_secs() as i64);
                let subsec_nanos = -(duration_pre_unix_epoch.subsec_nanos() as i32);
                Instant::new(secs, subsec_nanos)
            }
        }
    }

    /// The "seconds" component of the **Instant**.
    pub fn secs(&self) -> i64 {
        self.secs
    }

    /// The fractional component of the **Instant** in nanoseconds.
    pub fn subsec_nanos(&self) -> i32 {
        self.subsec_nanos
    }
}

// Era-aware conversion helpers.

/// Given a raw 32-bit NTP timestamp seconds value and a pivot `Instant`,
/// return the absolute NTP seconds (i64) by selecting the era closest to the pivot.
///
/// The algorithm assumes the timestamp is within half an era (~68 years) of the pivot.
fn era_aware_ntp_seconds(raw_seconds: u32, pivot: &Instant) -> i64 {
    let pivot_ntp = pivot.secs + EPOCH_DELTA;
    let raw = raw_seconds as i64;

    // Candidate in the same era as the pivot.
    let pivot_era = pivot_ntp.div_euclid(ERA_SECONDS);
    let candidate = pivot_era * ERA_SECONDS + raw;

    // Check if the candidate is within half an era of the pivot.
    // If not, try the adjacent era.
    let diff = candidate - pivot_ntp;
    if diff > ERA_SECONDS / 2 {
        candidate - ERA_SECONDS
    } else if diff < -(ERA_SECONDS / 2) {
        candidate + ERA_SECONDS
    } else {
        candidate
    }
}

/// Convert a [`protocol::TimestampFormat`] to an [`Instant`] using the given pivot
/// for era disambiguation.
///
/// The 32-bit NTP timestamp format is ambiguous across eras (each era spans ~136 years).
/// This function resolves the ambiguity by selecting the era that places the timestamp
/// closest to the provided pivot (within ~68 years).
///
/// For live NTP usage, pass `Instant::now()` as the pivot. For offline or replay
/// scenarios, pass a known reference time.
pub fn timestamp_to_instant(ts: protocol::TimestampFormat, pivot: &Instant) -> Instant {
    let ntp_secs = era_aware_ntp_seconds(ts.seconds, pivot);
    let secs = ntp_secs - EPOCH_DELTA;
    let subsec_nanos = (ts.fraction as f64 / NTP_SCALE * 1e9) as i32;
    Instant::new(secs, subsec_nanos)
}

// Conversion implementations.

impl From<protocol::ShortFormat> for Instant {
    fn from(t: protocol::ShortFormat) -> Self {
        let secs = t.seconds as i64 - EPOCH_DELTA;
        let subsec_nanos = (t.fraction as f64 / NTP_SCALE * 1e9) as i32;
        Instant::new(secs, subsec_nanos)
    }
}

#[cfg(feature = "std")]
impl From<protocol::TimestampFormat> for Instant {
    /// Converts a 32-bit NTP timestamp to a Unix [`Instant`], using the current system
    /// time as a pivot for era disambiguation.
    ///
    /// This is correct for live NTP usage where timestamps are close to "now".
    /// For offline or replay scenarios, use [`timestamp_to_instant`] with an explicit pivot.
    fn from(t: protocol::TimestampFormat) -> Self {
        timestamp_to_instant(t, &Instant::now())
    }
}

impl From<Instant> for protocol::ShortFormat {
    fn from(t: Instant) -> Self {
        let sec = t.secs() + EPOCH_DELTA;
        let frac = t.subsec_nanos() as f64 * NTP_SCALE / 1e9;
        protocol::ShortFormat {
            seconds: sec as u16,
            fraction: frac as u16,
        }
    }
}

impl From<Instant> for protocol::TimestampFormat {
    /// Converts a Unix [`Instant`] to a 32-bit NTP timestamp.
    ///
    /// **Note**: This truncates to 32 bits, losing era information. The resulting
    /// [`protocol::TimestampFormat`] is correct for NTPv4 on-wire use, but the era must
    /// be inferred by the receiver using a pivot-based approach (see [`timestamp_to_instant`]).
    fn from(t: Instant) -> Self {
        let sec = t.secs() + EPOCH_DELTA;
        let frac = t.subsec_nanos() as f64 * NTP_SCALE / 1e9;
        protocol::TimestampFormat {
            seconds: sec as u32,
            fraction: frac as u32,
        }
    }
}

impl From<protocol::DateFormat> for Instant {
    /// Converts a 128-bit NTP date format (with explicit era) to a Unix [`Instant`].
    ///
    /// This conversion is unambiguous because [`protocol::DateFormat`] includes the era number.
    fn from(d: protocol::DateFormat) -> Self {
        let ntp_secs = d.era_number as i64 * ERA_SECONDS + d.era_offset as i64;
        let secs = ntp_secs - EPOCH_DELTA;
        let subsec_nanos = (d.fraction as f64 / NTP_SCALE_64 * 1e9) as i32;
        Instant::new(secs, subsec_nanos)
    }
}

impl From<Instant> for protocol::DateFormat {
    /// Converts a Unix [`Instant`] to a 128-bit NTP date format with explicit era.
    ///
    /// This conversion preserves era information and is unambiguous.
    fn from(t: Instant) -> Self {
        let ntp_secs = t.secs() + EPOCH_DELTA;
        let era_number = ntp_secs.div_euclid(ERA_SECONDS) as i32;
        let era_offset = ntp_secs.rem_euclid(ERA_SECONDS) as u32;
        let fraction = (t.subsec_nanos().unsigned_abs() as f64 / 1e9 * NTP_SCALE_64) as u64;
        protocol::DateFormat {
            era_number,
            era_offset,
            fraction,
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn era0_timestamp_to_instant() {
        // 2024-01-01 00:00:00 UTC: Unix=1704067200, NTP=3913056000
        let ts = protocol::TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        };
        let pivot = Instant::new(1_704_067_200, 0);
        let result = timestamp_to_instant(ts, &pivot);
        assert_eq!(result.secs(), 1_704_067_200);
    }

    #[test]
    fn era1_timestamp_with_era1_pivot() {
        // Era 1, offset 100_000_000 => absolute NTP = 2^32 + 100_000_000
        // Unix = 4_294_967_296 + 100_000_000 - 2_208_988_800 = 2_185_978_496
        let ts = protocol::TimestampFormat {
            seconds: 100_000_000,
            fraction: 0,
        };
        let pivot = Instant::new(2_185_978_496, 0);
        let result = timestamp_to_instant(ts, &pivot);
        assert_eq!(result.secs(), 2_185_978_496);
    }

    #[test]
    fn era_boundary_pivot_before_ts_after() {
        // Pivot in Jan 2036 (Era 0). Timestamp NTP=1000 should resolve to Era 1.
        let pivot = Instant::new(2_082_758_400, 0); // ~2036-01-01
        let ts = protocol::TimestampFormat {
            seconds: 1000,
            fraction: 0,
        };
        let result = timestamp_to_instant(ts, &pivot);
        let expected = ERA_SECONDS + 1000 - EPOCH_DELTA;
        assert_eq!(result.secs(), expected);
    }

    #[test]
    fn era_boundary_pivot_after_ts_before() {
        // Pivot in Mar 2036 (Era 1). Timestamp near u32::MAX should resolve to Era 0.
        let pivot = Instant::new(2_087_942_400, 0); // ~2036-03-01
        let ts = protocol::TimestampFormat {
            seconds: u32::MAX,
            fraction: 0,
        };
        let result = timestamp_to_instant(ts, &pivot);
        let expected = u32::MAX as i64 - EPOCH_DELTA;
        assert_eq!(result.secs(), expected);
    }

    #[test]
    fn date_format_roundtrip_era0() {
        let instant = Instant::new(1_704_067_200, 500_000_000);
        let date: protocol::DateFormat = instant.into();
        assert_eq!(date.era_number, 0);
        let back: Instant = date.into();
        assert_eq!(back.secs(), instant.secs());
        assert!((back.subsec_nanos() - instant.subsec_nanos()).abs() <= 1);
    }

    #[test]
    fn date_format_roundtrip_era1() {
        let instant = Instant::new(2_185_978_496, 0); // ~2039
        let date: protocol::DateFormat = instant.into();
        assert_eq!(date.era_number, 1);
        let back: Instant = date.into();
        assert_eq!(back.secs(), instant.secs());
    }

    #[test]
    fn timestamp_format_roundtrip_with_pivot() {
        let original = Instant::new(1_704_067_200, 0);
        let ts: protocol::TimestampFormat = original.into();
        let restored = timestamp_to_instant(ts, &original);
        assert_eq!(restored.secs(), original.secs());
    }

    #[test]
    fn date_format_negative_era() {
        // A time before 1900 => era -1
        let instant = Instant::new(-2_300_000_000, 0);
        let date: protocol::DateFormat = instant.into();
        assert_eq!(date.era_number, -1);
        let back: Instant = date.into();
        assert_eq!(back.secs(), instant.secs());
    }
}
