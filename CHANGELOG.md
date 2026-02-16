# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.3.1] - 2026-02-16

### Fixed

- CI image now includes `libudev-dev` for `gps` feature support on Linux

## [3.3.0] - 2026-02-16

### Added

#### Reference Clock Support (`refclock` feature)

- **GPS receiver** (`refclock/gps.rs`) - NMEA 0183 serial GPS reference clock with `$GPRMC`/`$GPGGA` sentence parsing, configurable baud rate, and async tokio integration
- **PPS (Pulse Per Second)** (`refclock/pps.rs`) - Kernel PPS discipline via `/dev/pps*` with sub-microsecond timing, configurable edge selection, and jitter filtering
- **Hardware timestamping** (`refclock/hwts.rs`) - NIC hardware timestamp support via `SO_TIMESTAMPING` for nanosecond-precision packet timing
- **NMEA parser** (`refclock/nmea.rs`) - Zero-allocation NMEA 0183 sentence parser with checksum validation
- **RefClock trait** (`refclock/mod.rs`) - Generic `RefClock` async trait for pluggable reference clock implementations

#### Server Integration

- **Stratum 1 server** - `NtpServer` now supports `RefClock` sources for Stratum 1 operation, automatically setting reference ID and stratum from the clock source
- New example: `stratum1_server.rs` demonstrating GPS-disciplined Stratum 1 NTP server

#### Client Examples

- **GPS receiver** (`examples/gps_receiver.rs`) - Standalone GPS reference clock demo
- **PPS receiver** (`examples/pps_receiver.rs`) - Standalone PPS discipline demo
- **GPS+PPS combined** (`examples/gps_pps_combined.rs`) - Combined GPS time + PPS discipline for maximum accuracy
- **Hardware timestamping** (`examples/hwts_demo.rs`) - NIC hardware timestamp demo

#### Documentation

- `crates/ntp_usg-client/src/refclock/README.md` - Reference clock module documentation

### New Feature Flags

| Crate | Feature | Description |
|-------|---------|-------------|
| `ntp_usg-client` | `refclock` | Base reference clock trait and infrastructure |
| `ntp_usg-client` | `gps` | GPS receiver via serial port (NMEA 0183) |
| `ntp_usg-client` | `pps` | Kernel PPS discipline |
| `ntp_usg-client` | `hwts` | NIC hardware timestamping |
| `ntp_usg-server` | `refclock` | Server-side RefClock integration for Stratum 1 |
| `ntp_usg-server` | `gps` | GPS support forwarded from client |
| `ntp_usg-server` | `pps` | PPS support forwarded from client |

### New Dependencies (all optional)

- `serialport` 4.6 (for `gps` feature, serial port access)
- `async-trait` 0.1 (for `refclock` trait)
- `ntp_usg-client` (server dependency, for `refclock` feature)

## [3.2.0] - 2026-02-16

### Added

#### Production Examples

- **Multi-peer deployment** (`examples/multi_peer_deployment.rs`) - 5-peer configuration with RFC 5905 selection/clustering, health monitoring, and offset trend analysis
- **NTS multi-peer** (`examples/nts_multi_peer.rs`) - Mixed NTS + standard NTP deployment with security posture tracking
- **System daemon** (`examples/daemon.rs`) - Production-ready service with structured logging, health-based alerts, and systemd integration
- **Web dashboard** (`examples/web_dashboard.rs`) - Real-time monitoring with Chart.js, 3 API endpoints (HTML, JSON, Prometheus metrics), auto-refresh, comprehensive documentation

#### Integration Tests (16 tests)

- **Basic NTP tests** (`tests/integration.rs`) - 10 tests against NIST, Cloudflare, Google, NTP Pool with multi-server consistency validation, IPv6, SNTP API
- **NTS tests** (`tests/nts_integration.rs`) - 6 tests for NTS-KE, cookie rotation, continuous client, mixed deployment
- **Resilient framework** - Graceful network failure handling, `SKIP_NETWORK_TESTS` env var, comprehensive documentation in `tests/README.md`

#### Docker Testing Environment

- **Three Dockerfiles** - NTP server, NTS server with auto-generated certificates, test runner
- **Docker Compose** - Full orchestration with health checks, isolated network, automatic certificate generation, documented in `docker/README.md`
- **CI/CD ready** - GitHub Actions and GitLab CI examples, fast layer caching (~10s builds)

#### Documentation

- `ALGORITHMS.md` - 600+ lines documenting RFC 5905 algorithms (filter, selection, clustering, combine, discipline)
- `PERFORMANCE.md` - Performance analysis, benchmarks, optimization recommendations
- `examples/WEB_DASHBOARD.md` - Complete web dashboard documentation with deployment guides
- `tests/README.md` - Integration test documentation
- `docker/README.md` - Docker environment guide with troubleshooting

### Changed

- Updated README with production examples section
- Enhanced ROADMAP.md with v3.2.0 completion status (4/4 objectives complete)
- Docker base images updated to `rust:1-slim` and `debian:trixie-slim`

### Dependencies

- Added `serde_json` to dev-dependencies
- Added tokio `net` and `io-util` features

## [3.1.0] - 2026-02-16

### Added

- **RFC 5905 full compliance** - Selection (Marzullo), clustering, combine, clock discipline PLL/FLL, enhanced filter, symmetric modes, broadcast mode
- **RFC 4330 SNTP API** - Simple one-off query interface with sync/async variants
- **RFC 7822 extension registry** - Generic handler trait and dispatch system
- `ALGORITHMS.md` and `PERFORMANCE.md` documentation

### Changed

- Replaced unmaintained `rustls-pemfile` with `rustls-pki-types`
- Eliminated RUSTSEC-2025-0134 security advisory

## [3.0.1] - 2026-02-16

### Fixed

- Clippy `dead_code` errors on NTS server helpers (`NtsRequestContext`, `process_nts_extensions`, `build_nts_response`)
- Broken `[ParseError]` intra-doc link in `ntp_usg-proto` error module
- Publish workflow ordering: deprecated `ntp_usg` stub now published after its dependencies

## [3.0.0] - 2026-02-16

### Breaking Changes

- **Workspace restructure**: The monolithic `ntp_usg` crate has been split into three crates:
  - `ntp_usg-proto` (lib: `ntp_proto`) — Protocol types, extension fields, NTS crypto primitives
  - `ntp_usg-client` (lib: `ntp_client`) — Sync/async NTP client, NTS, clock adjustment
  - `ntp_usg-server` (lib: `ntp_server`) — NTP server, NTS-KE (tokio/smol)
- **All import paths changed**: `ntp::` → `ntp_client::`, `ntp_server::`, or `ntp_proto::`
- Feature flags are now per-crate (e.g., `ntp_usg-client/tokio` instead of `ntp_usg/tokio`)

### Migration Guide

Replace in your `Cargo.toml`:
```diff
- ntp_usg = { version = "2.0", features = ["tokio"] }
+ ntp_usg-client = { version = "3.0", features = ["tokio"] }
```

Replace in your code:
```diff
- use ntp::request;
- use ntp::async_ntp;
- use ntp::client::NtpClient;
- use ntp::nts::NtsSession;
+ use ntp_client::request;
+ use ntp_client::async_ntp;
+ use ntp_client::client::NtpClient;
+ use ntp_client::nts::NtsSession;
```

For server code:
```diff
- use ntp::server::NtpServer;
- use ntp::protocol::Stratum;
+ use ntp_server::server::NtpServer;
+ use ntp_server::protocol::Stratum;
```

For protocol types only (including `no_std`):
```diff
- ntp_usg = { version = "2.0", default-features = false }
+ ntp_usg-proto = { version = "3.0", default-features = false }
```

### Changed

- `nts_common` module items changed from `pub(crate)` to `pub` for cross-crate access
- CI workflows updated for workspace-level feature testing (`-F <package>/<feature>`)
- Publish workflow now publishes crates in dependency order: proto → client → server

## [2.0.3] - 2026-02-16

### Fixed

- CI container jobs failing due to missing `packages: read` permission for GHCR
- Clock tests failing on Windows CI runners that have admin privileges
- Publish workflow now uses CI container image (drops manual toolchain install)
- Added `gh` CLI to CI Docker image for GitHub release creation
- Fixed clippy `assign_op_pattern` lint in protocol tests

### Changed

- Updated `windows-sys` dependency from 0.59 to 0.61
- Improved unit test coverage from 71% to 74% (protocol, clock, client modules)

## [2.0.2] - 2026-02-15

### Changed

- Migrated all examples, doc comments, and README to use NIST NTP servers (`time.nist.gov`, `time-a-g.nist.gov`) for consistency with tests
- Custom Docker CI runner image on ghcr.io with pre-installed tools (nextest, llvm-cov, audit, deny) for faster CI
- Multi-arch CI image (linux/amd64 + linux/arm64) built via QEMU + buildx
- Expanded CI test matrix: Linux x64/arm64, Windows x64/arm64, macOS arm64 (10 jobs total)
- Switched CI from `cargo test` to `cargo-nextest` for parallel test execution
- Added `cargo-llvm-cov` coverage reporting to Codecov

### Added

- Integration tests for smol runtime (`tests/smol_ntp.rs`, `tests/smol_client.rs`)
- Nextest configuration (`.config/nextest.toml`) with per-test timeout control

## [2.0.1] - 2026-02-15

### Changed

- Extracted `nts_common` module to eliminate ~400 lines of duplicated NTS code between tokio and smol variants
- Extracted `client_common` module to share `NtpSyncState` and `classify_and_compute` between client variants
- Fixed stale version strings in `lib.rs` doc comments (now reference 2.0)
- Added `#![warn(unreachable_pub)]` lint and fixed all warnings
- Added unit tests for `smol_client` (poll interval, reachability, builder validation)
- Improved `smol_ntp` documentation (differences from `async_ntp`)

## [2.0.0] - 2026-02-15

### Breaking Changes

- **`async-std` replaced with `smol`** — Resolves RUSTSEC-2025-0052 (async-std unmaintained)
  - Feature `async-std-runtime` renamed to `smol-runtime`
  - Feature `nts-async-std` renamed to `nts-smol`
  - Module `async_std_ntp` renamed to `smol_ntp`
  - Module `async_std_client` renamed to `smol_client`
  - Module `async_std_nts` renamed to `smol_nts`
  - `async-std` dependency replaced with `smol` 2.x
  - Examples `async_std_request` / `async_std_continuous` renamed to `smol_request` / `smol_continuous`

### Migration Guide

Replace in your `Cargo.toml`:
```diff
- ntp_usg = { version = "1.2", features = ["async-std-runtime"] }
+ ntp_usg = { version = "2.0", features = ["smol-runtime"] }
```

Replace in your code:
```diff
- use ntp::async_std_ntp;
+ use ntp::smol_ntp;
- use ntp::async_std_client::NtpClient;
+ use ntp::smol_client::NtpClient;
- use ntp::async_std_nts::NtsSession;
+ use ntp::smol_nts::NtsSession;
```

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
- `futures-lite` 2.x (for `nts-async-std`)
- `futures-rustls` 0.26 (for `nts-async-std`)
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

[3.3.1]: https://github.com/192d-Wing/ntp_usg/compare/v3.3.0...v3.3.1
[3.3.0]: https://github.com/192d-Wing/ntp_usg/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/192d-Wing/ntp_usg/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/192d-Wing/ntp_usg/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/192d-Wing/ntp_usg/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/192d-Wing/ntp_usg/compare/v2.0.3...v3.0.0
[2.0.3]: https://github.com/192d-Wing/ntp_usg/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/192d-Wing/ntp_usg/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/192d-Wing/ntp_usg/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/192d-Wing/ntp_usg/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/192d-Wing/ntp_usg/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/192d-Wing/ntp_usg/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/192d-Wing/ntp_usg/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/192d-Wing/ntp_usg/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/192d-Wing/ntp_usg/releases/tag/v0.6.0
