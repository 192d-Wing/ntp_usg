# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-02-15

### Added

- **IO-independent parsing** (always available, no feature flag required)
  - `FromBytes` / `ToBytes` traits for buffer-based parsing decoupled from `std::io`
  - Implementations for all protocol types: `Packet`, `TimestampFormat`, `ShortFormat`, `DateFormat`, `Stratum`, `PacketByte1`, `ReferenceIdentifier`
  - Custom `ParseError` enum with `BufferTooShort`, `InvalidField`, `InvalidExtensionLength`, `ExtensionOverflow` variants
  - `parse_extension_fields_buf()` / `write_extension_fields_buf()` for buffer-based extension field handling
  - Zero-allocation extension field iterator: `iter_extension_fields()` returning `ExtensionFieldIter` / `ExtensionFieldRef`
- **System clock adjustment** (requires `clock` feature)
  - `slew_clock()` for gradual offset correction via `adjtime` (macOS) / `clock_adjtime` (Linux) / `SetSystemTimeAdjustment` (Windows)
  - `step_clock()` for immediate clock step via `settimeofday` (macOS) / `clock_settime` (Linux) / `SetSystemTime` (Windows)
  - `apply_correction()` with ntpd convention: |offset| <= 128ms slews, otherwise steps
  - `NtpClient::run_with_clock_correction()` for automatic clock discipline in continuous client
  - New example: `clock_adjust.rs`
- **`no_std` support** (use `default-features = false`)
  - Core parsing (`FromBytes`/`ToBytes`, `Packet`, timestamps) works without `std` or `alloc`
  - `alloc` feature enables `Vec`-based types (`ExtensionField`, NTS types)
  - `std` feature (default) enables full I/O, networking, and `byteorder`-based APIs
- **async-std runtime support** (requires `async-std-runtime` feature)
  - `async_std_ntp::request()` / `request_with_timeout()` for one-shot queries
  - `async_std_client::NtpClient` continuous client with `Arc<RwLock<NtpSyncState>>` state sharing
  - New examples: `async_std_request.rs`, `async_std_continuous.rs`
- **NTS over async-std** (requires `nts-async-std` feature)
  - `async_std_nts::NtsSession` using `futures-rustls` for TLS
  - Full NTS-KE and AEAD authentication, mirroring the tokio-based NTS module

### Changed

- `#![forbid(unsafe_code)]` relaxed to `#![deny(unsafe_code)]` at crate level to allow platform FFI in the `clock` module
- `filter` module now available with either `tokio` or `async-std-runtime` features
- `NtsAuthenticator::to_extension_field` uses `to_be_bytes()` instead of `byteorder::WriteBytesExt`
- `byteorder` dependency is now optional (only pulled in by `std` feature)

### New Feature Flags

| Feature | Description |
|---------|-------------|
| `alloc` | Enables `Vec`-based extension field types without full `std` |
| `clock` | System clock slew/step adjustment (Linux, macOS, Windows) |
| `async-std-runtime` | async-std one-shot and continuous NTP client |
| `nts-async-std` | NTS authentication over async-std runtime |

### New Dependencies (all optional)

- `async-std` 1.x (for `async-std-runtime`)
- `futures-rustls` 0.26 (for `nts-async-std`)
- `futures-lite` 2.x (for `nts-async-std`)
- `libc` 0.2 (for `clock`, Unix)
- `windows-sys` 0.59 (for `clock`, Windows)

## [1.1.0] - 2026-02-15

### Added

- **NTS in continuous client** (requires `nts` feature)
  - `NtpClientBuilder::nts_server()` for NTS-authenticated peers
  - NTS-KE performed during `build()` with automatic cookie replenishment during polling
  - `NtpSyncState::nts_authenticated` field indicates NTS status
  - Interleaved mode works with NTS (orthogonal protocols)
- New example: `nts_continuous.rs`
- Project roadmap (`ROADMAP.md`)

### Changed

- Extracted `build_nts_request()` and `validate_nts_response()` from `NtsSession` for reuse by continuous client
- Updated `rand` to 0.10 and `webpki-roots` to 1.0

## [1.0.0] - 2026-02-15

### Added

- **IPv6 dual-stack support**: Automatic socket binding based on target address family
- **Continuous NTP client** (`client` module, requires `tokio` feature)
  - `NtpClient::builder()` with multi-server support and configurable poll intervals
  - Adaptive poll interval management per RFC 5905 Section 7.3
  - 8-bit reachability shift register for peer health tracking
  - `NtpSyncState` published via `tokio::sync::watch` channel
  - Kiss-o'-Death handling (RATE reduces poll, DENY/RSTR demobilizes peer)
- **Interleaved mode** (RFC 9769) in continuous client for improved timestamp accuracy
- **Clock sample filter** (`filter` module, requires `tokio` feature)
  - Circular buffer of 8 samples per RFC 5905 Section 10
  - Best sample selection by minimum delay, jitter computation
- **NTP extension field parsing** (`extension` module)
  - Generic `ExtensionField` type with `parse_extension_fields` / `write_extension_fields`
  - NTS-specific types: `UniqueIdentifier`, `NtsCookie`, `NtsCookiePlaceholder`, `NtsAuthenticator`
- **Network Time Security (NTS)** (`nts` module, requires `nts` feature)
  - NTS Key Establishment over TLS 1.3 (`nts_ke()`)
  - `NtsSession` for AEAD-authenticated NTP requests
  - Automatic cookie replenishment from server responses
  - Supports AEAD_AES_SIV_CMAC_256 and AEAD_AES_SIV_CMAC_512
  - Dependencies: `rustls`, `tokio-rustls`, `ring`, `aes-siv`, `rand`, `webpki-roots`
- New examples: `continuous.rs`, `nts_request.rs`
- CI now tests `--features nts` alongside tokio and default features

### Changed

- Extracted `parse_and_validate_response()` from `validate_response()` for reuse by continuous client
- Made `compute_offset_delay()` and `build_request_packet()` `pub(crate)` for module reuse
- Added `io-util` to tokio features for NTS TLS stream handling

## [0.9.0] - 2026-02-15

### Added

- **Async support** via optional `tokio` feature flag
  - `async_ntp::request()` and `async_ntp::request_with_timeout()` using `tokio::net::UdpSocket`
  - Async DNS resolution via `tokio::net::lookup_host`
  - Timeout via `tokio::time::timeout` wrapping entire operation
  - New example: `async_request.rs` demonstrating concurrent queries
  - 3 async integration tests gated behind `cfg(feature = "tokio")`
- **NTP era handling (Y2036)** with pivot-based timestamp disambiguation
  - `unix_time::ERA_SECONDS` constant (2^32 seconds per era)
  - `unix_time::timestamp_to_instant()` for era-aware conversion with explicit pivot
  - `From<DateFormat> for Instant` and `From<Instant> for DateFormat` conversions
  - 8 unit tests covering era boundaries, round-trips, and negative eras
- CI now tests with `--features tokio` alongside default tests

### Changed

- **BREAKING**: Offset/delay computation now uses era-aware `Instant` arithmetic instead of raw 32-bit timestamp values
- `From<TimestampFormat> for Instant` now uses `Instant::now()` as pivot for era disambiguation (behavior unchanged for Era 0 timestamps)
- Extracted `build_request_packet()` and `validate_response()` as `pub(crate)` helpers shared between sync and async paths

## [0.8.0] - 2026-02-15

### Added

- `NtpResult` return type with clock offset and round-trip delay computed per RFC 5905 Section 8
  - Implements `Deref<Target = Packet>` for backward-compatible field access
  - Exposes `offset_seconds`, `delay_seconds`, and `destination_timestamp` (T4)
- `KissOfDeathError` type for programmatic handling of Kiss-o'-Death responses
- `ReferenceIdentifier::Unknown([u8; 4])` variant for unrecognized reference identifiers
- `ReferenceIdentifier::as_bytes()` and `is_kiss_of_death()` helper methods
- Client-side response validation per RFC 5905:
  - Origin timestamp verification (anti-replay)
  - Source IP address verification
  - Server mode validation
  - Non-zero transmit timestamp check
  - Unsynchronized clock detection (LI=Unknown with non-zero stratum)
  - Kiss-o'-Death enforcement (DENY, RSTR, RATE)
- Larger receive buffer (1024 bytes) to tolerate extension fields and MAC
- 8 new protocol tests covering KoD parsing, unknown reference IDs, stratum 16, and round-trips

### Changed

- **BREAKING**: `request()` and `request_with_timeout()` now return `io::Result<NtpResult>` instead of `io::Result<Packet>`
- **BREAKING**: Removed `#[repr(u32)]` from `ReferenceIdentifier` enum (required for `Unknown` variant)

### Fixed

- Stratum 0 (Kiss-o'-Death) packets no longer cause parse errors
- Stratum 1 packets with unrecognized reference IDs no longer cause parse errors
- Stratum 16 (unsynchronized) and 17-255 (reserved) packets no longer cause parse errors

## [0.7.1] - 2026-02-15

### Fixed

- Removed macOS from CI test matrix due to network test failures
- Fixed `Swatinem/rust-cache` version from v3 to v2
- Fixed publish workflow trigger syntax

## [0.7.0] - 2026-02-15

### Added

- Configurable timeout support via `request_with_timeout()` function
- Comprehensive documentation for all public APIs (zero missing docs warnings)
- Three new example programs:
  - `timeout.rs` - Demonstrates custom timeout usage
  - `multiple_servers.rs` - Shows querying multiple NTP servers for reliability
  - `packet_details.rs` - Displays detailed NTP packet information
- GitHub Actions CI/CD pipeline with:
  - Multi-platform testing (Linux, macOS, Windows)
  - Multiple Rust versions (stable, beta)
  - Clippy lints, rustfmt checks, and security audits
  - MSRV verification (1.93)
- `#![forbid(unsafe_code)]` to ensure memory safety
- `#![warn(missing_docs)]` lint to maintain documentation quality

### Changed

- **BREAKING**: Updated to Rust Edition 2024 with MSRV 1.93
- Removed `custom_derive` and `conv` dependencies, using standard library traits instead
- Manually implemented `TryFrom` for all protocol enums (`LeapIndicator`, `Mode`, `PrimarySource`, `KissOfDeath`)
- Updated dependencies:
  - `byteorder`: 1.1 → 1.5
  - `log`: 0.3.6 → 0.4
  - `chrono`: 0.4.4 → 0.4 (dev-dependency)
- Removed all `extern crate` declarations (no longer needed in Edition 2024)
- Updated deprecated `chrono::timestamp()` to `timestamp_opt()`
- `request()` now calls `request_with_timeout()` internally (maintaining backward compatibility)
- Improved README with Edition 2024 usage examples and MSRV information

### Fixed

- Anonymous parameter syntax in trait methods (required for Edition 2024)
- Module imports to use crate-relative paths
- Broken rustdoc links for RFC references
- Legacy numeric constants (`std::u32::MAX` → `u32::MAX`)
- Unnecessary lifetime elisions and needless borrows
- UTC to NTP timestamp conversion

### Removed

- `#![recursion_limit = "1024"]` (no longer necessary)
- Unused `#[macro_use]` attributes
- Travis CI configuration (replaced with GitHub Actions)
- `custom_derive` and `conv` dependencies

## [0.6.0] - Previous Release

Historical release information prior to the Edition 2024 migration.

[1.2.0]: https://github.com/192d-Wing/ntp_usg/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/192d-Wing/ntp_usg/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/192d-Wing/ntp_usg/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/192d-Wing/ntp_usg/releases/tag/v0.6.0
