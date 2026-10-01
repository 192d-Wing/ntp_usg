#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::protocol::{DateFormat, ShortFormat, TimestampFormat};
use ntp_proto::unix_time::{Instant, timestamp_to_instant};

fuzz_target!(|data: &[u8]| {
    // Timestamp -> Instant conversions take network-supplied values and an
    // arbitrary pivot; none of them may panic.
    if data.len() < 32 {
        return;
    }
    let u32_at = |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    let ts = TimestampFormat {
        seconds: u32_at(0),
        fraction: u32_at(4),
    };
    let pivot_secs = i64::from_be_bytes(data[8..16].try_into().unwrap());
    // Keep the pivot inside the range the era logic can represent without
    // overflowing (± ~2^62 seconds covers every realistic deployment).
    let pivot = Instant::new(pivot_secs >> 2, 0).unwrap_or_else(|_| Instant::new(0, 0).unwrap());
    let _ = timestamp_to_instant(ts, &pivot);

    let _ = Instant::from(ShortFormat {
        seconds: u16::from_be_bytes([data[16], data[17]]),
        fraction: u16::from_be_bytes([data[18], data[19]]),
    });

    let _ = Instant::from(DateFormat {
        era_number: i32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        era_offset: u32_at(24),
        fraction: u64::from_be_bytes(data[24..32].try_into().unwrap()),
    });
});
