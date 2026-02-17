// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

// Embedded / no_std NTP packet parsing demo
//
// Demonstrates ntp_usg-proto's no_std-compatible API: `FromBytes`, `ToBytes`,
// and `ConstPackedSizeBytes`. These traits operate on `&[u8]` / `&mut [u8]`
// slices with no heap allocation and no I/O dependency, making them safe to use
// in `no_std` environments (microcontrollers, RTOS, bare-metal firmware).
//
// The `std` feature is active here (examples always compile with defaults), but
// every API called below is available without it.
//
// Usage:
//   cargo run -p ntp_usg-proto --example embedded_nostd

use ntp_proto::error::ParseError;
use ntp_proto::protocol::{
    ConstPackedSizeBytes, FromBytes, LeapIndicator, Mode, Packet, PrimarySource,
    ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, ToBytes, Version,
};

fn main() {
    println!("=== no_std-Compatible NTP Packet API ===");
    println!();

    // ── 1. Compile-time size constants ──────────────────────────────────
    //
    // These are `const` values available in no_std with zero runtime cost.
    // An embedded system can statically allocate buffers of exactly the
    // right size.

    println!("Compile-time size constants (ConstPackedSizeBytes):");
    println!(
        "  Packet::PACKED_SIZE_BYTES          = {} bytes",
        Packet::PACKED_SIZE_BYTES
    );
    println!(
        "  TimestampFormat::PACKED_SIZE_BYTES  = {} bytes",
        TimestampFormat::PACKED_SIZE_BYTES
    );
    println!(
        "  ShortFormat::PACKED_SIZE_BYTES      = {} bytes",
        ShortFormat::PACKED_SIZE_BYTES
    );
    println!(
        "  Stratum::PACKED_SIZE_BYTES          = {} byte",
        Stratum::PACKED_SIZE_BYTES
    );
    println!();

    // ── 2. Build a client request packet (stack-only, no heap) ─────────
    //
    // All fields are public and all types implement Copy. An embedded NTP
    // client builds the packet directly as a struct literal — no allocator,
    // no builder, no I/O.

    println!("Building NTPv4 client-mode request packet...");

    let request = Packet {
        leap_indicator: LeapIndicator::default(), // NoWarning
        version: Version::V4,
        mode: Mode::Client,
        stratum: Stratum::UNSPECIFIED,
        poll: 6,        // 2^6 = 64 seconds
        precision: -20, // ~1 microsecond
        root_delay: ShortFormat::default(),
        root_dispersion: ShortFormat::default(),
        reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Null),
        reference_timestamp: TimestampFormat::default(),
        origin_timestamp: TimestampFormat::default(),
        receive_timestamp: TimestampFormat::default(),
        transmit_timestamp: TimestampFormat {
            seconds: 3_910_000_000, // example NTP timestamp
            fraction: 0,
        },
    };

    println!("  Mode:      {:?}", request.mode);
    println!("  Version:   {:?}", request.version);
    println!(
        "  Poll:      {} (2^{} = {}s)",
        request.poll,
        request.poll,
        1u64 << request.poll
    );
    println!(
        "  Precision: {} (2^{} ~ {:.1} us)",
        request.precision,
        request.precision,
        1e6 * 2f64.powi(request.precision as i32)
    );
    println!();

    // ── 3. Serialize to a fixed-size stack buffer via ToBytes ───────────
    //
    // `to_bytes()` writes into a `&mut [u8]` — no Vec, no Write trait,
    // no I/O. Returns the number of bytes written.

    println!("Serializing to stack buffer via ToBytes...");

    let mut tx_buf = [0u8; Packet::PACKED_SIZE_BYTES];
    let written = request
        .to_bytes(&mut tx_buf)
        .expect("buffer is exactly the right size");

    println!("  Written: {} bytes", written);
    println!(
        "  First 8 bytes (hex): {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
        tx_buf[0], tx_buf[1], tx_buf[2], tx_buf[3], tx_buf[4], tx_buf[5], tx_buf[6], tx_buf[7]
    );
    assert_eq!(written, Packet::PACKED_SIZE_BYTES);
    println!();

    // ── 4. Parse back via FromBytes — verify round-trip ────────────────
    //
    // `from_bytes()` reads from a `&[u8]` — no Read trait, no I/O.
    // Returns the parsed value and the number of bytes consumed.

    println!("Parsing back via FromBytes...");

    let (parsed, consumed) = Packet::from_bytes(&tx_buf).expect("valid packet bytes");

    assert_eq!(consumed, Packet::PACKED_SIZE_BYTES);
    assert_eq!(parsed.mode, Mode::Client);
    assert_eq!(parsed.version, Version::V4);
    assert_eq!(parsed.stratum, Stratum::UNSPECIFIED);
    assert_eq!(parsed.transmit_timestamp.seconds, 3_910_000_000);

    println!("  Consumed: {} bytes", consumed);
    println!("  Round-trip verified: all fields match");
    println!();

    // ── 5. Error handling (no_std compatible) ──────────────────────────
    //
    // ParseError uses `core::fmt` only — no std::error, no heap.

    println!("Demonstrating error handling with truncated buffer...");

    let short_buf = [0u8; 10];
    match Packet::from_bytes(&short_buf) {
        Err(ParseError::BufferTooShort { needed, available }) => {
            println!("  Got expected error: BufferTooShort");
            println!("    needed:    {} bytes", needed);
            println!("    available: {} bytes", available);
        }
        other => {
            panic!("expected BufferTooShort, got: {:?}", other);
        }
    }
    println!();

    // ── 6. Individual field round-trips ────────────────────────────────

    println!("Individual field round-trips:");

    let ts = TimestampFormat {
        seconds: 3_910_000_000,
        fraction: 123_456_789,
    };
    let mut ts_buf = [0u8; TimestampFormat::PACKED_SIZE_BYTES];
    let n = ts.to_bytes(&mut ts_buf).unwrap();
    let (ts2, _) = TimestampFormat::from_bytes(&ts_buf).unwrap();
    assert_eq!(ts, ts2);
    println!("  TimestampFormat: {} bytes, round-trip OK", n);

    let sf = ShortFormat {
        seconds: 1,
        fraction: 32768,
    };
    let mut sf_buf = [0u8; ShortFormat::PACKED_SIZE_BYTES];
    let n = sf.to_bytes(&mut sf_buf).unwrap();
    let (sf2, _) = ShortFormat::from_bytes(&sf_buf).unwrap();
    assert_eq!(sf, sf2);
    println!("  ShortFormat:     {} bytes, round-trip OK", n);
    println!();

    // ── 7. Deployment notes ────────────────────────────────────────────

    println!("=== no_std Deployment Notes ===");
    println!();
    println!("To use in a no_std environment, add to your Cargo.toml:");
    println!();
    println!("  [dependencies]");
    println!("  ntp_usg-proto = {{ version = \"3\", default-features = false }}");
    println!();
    println!("This gives you:");
    println!("  - FromBytes / ToBytes  (buffer-based parsing, no I/O)");
    println!("  - ConstPackedSizeBytes (compile-time size constants)");
    println!("  - All protocol types   (Packet, Timestamp, Stratum, etc.)");
    println!("  - ParseError           (core::fmt only, no heap)");
    println!();
    println!("Add the 'alloc' feature for Vec-based extension fields:");
    println!();
    println!(
        "  ntp_usg-proto = {{ version = \"3\", default-features = false, features = [\"alloc\"] }}"
    );
    println!();
    println!("Add the 'std' feature for io::Read/Write-based parsing:");
    println!();
    println!("  ntp_usg-proto = {{ version = \"3\" }}  # std is the default");
}
