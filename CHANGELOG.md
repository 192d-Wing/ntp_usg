# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.8.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/192d-Wing/ntp_usg/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/192d-Wing/ntp_usg/releases/tag/v0.6.0
