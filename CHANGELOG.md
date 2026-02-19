# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.10.0] - 2026-02-19

### Added

#### Performance

- **Pre-allocated loop buffer in `cluster_survivors()`**: Eliminated per-iteration `Vec` allocation by pre-allocating `sel_jitters` outside the loop and reusing with `clear()` + `extend()` each iteration.
- **Cached `root_distance()` in `combine()`**: Root distances are now computed once and reused for both weight calculation and system peer selection, eliminating redundant recomputation.
- **Eliminated double-clone in selection pipeline**: `peer_candidates` is now consumed with `into_iter()` after truechimer selection instead of being cloned twice.
- **NTS AEAD benchmarks**: Added `bench_nts_aead_encrypt_256`, `bench_nts_aead_encrypt_512`, `bench_nts_aead_decrypt_256`, and `bench_nts_aead_decrypt_512` benchmarks to `ntp_usg-proto`.
- **Server ACL/rate-limit benchmarks**: Added `bench_access_control_large_acl` (1000 /24 subnets) and `bench_rate_limit_full_table` (pre-filled ClientTable) to server throughput benchmarks.

#### Error Handling

- **NTS protocol errors (`NtsProtoError`)**: New typed error enum in `ntp_usg-proto` with variants `UnsupportedAeadAlgorithm`, `AeadKeyInit`, `AeadEncryptFailed`, `AeadDecryptFailed`, `MissingField`, and `ValidationFailed`. Migrated 15 `io::Error::new()` call sites in `nts_common.rs`.
- **Protocol parse errors**: Migrated 3 `io::Error::new()` call sites in `protocol/io.rs` to use `ParseError::InvalidField` for leap indicator, mode, and timescale parsing.
- **Reference clock errors (`NmeaError`, `PpsError`)**: New typed error enums in `ntp_usg-client` refclock module. Migrated 13 NMEA parser and 1 PPS `io::Error::new()` call sites.

#### Testing

- **NTPv5 integration tests**: V5 request/response roundtrip, V4 backward compatibility, and response length matching tests (`ntpv5_integration.rs`).
- **Broadcast integration tests**: Parse valid mode-5 packet, reject non-broadcast mode, reject zero transmit, reject short buffer (`broadcast_integration.rs`).
- **Symmetric integration tests**: Symmetric active mode construction and field verification (`symmetric_integration.rs`).
- **Error downcast tests**: Roundtrip all `NtpError` variants through `io::Error` boundary with downcast verification (`error_downcast.rs`).
- **Clock discipline integration tests**: Nset→Fset→Sync state transitions, spike detection and recovery, frequency correction direction (`discipline_integration.rs`).

#### Cryptography

- **`NtsAead` trait**: Abstraction layer for NTS AEAD operations in `ntp_usg-proto`, enabling future FIPS 140-3 backend swap without changing callers. Default implementation (`AesSivCmacAead`) delegates to existing `aes-siv` RustCrypto crate.
- **`fips-aead` feature flag**: Placeholder feature in `ntp_usg-proto` for future FIPS-certified AES-SIV-CMAC backend. Currently a no-op — activates when a certified implementation becomes available.
- **Updated `docs/CRYPTO.md`**: Added FIPS Migration Path section documenting the `NtsAead` trait, `AesSivCmacAead` default, and 4-step migration plan.

### Fixed

- **Doc warnings**: Fixed 3 broken intra-doc links for feature-gated modules (`crate::nts`, `client_common::NtpSyncState`, `server_common::validation`) that caused `RUSTDOCFLAGS="-D warnings"` failures when building without `--all-features`.

## [4.9.0] - 2026-02-19

### Added

#### Observability

- **Async tracing spans via `Instrument`**: Wrapped 10 async functions across 6 files with `tracing::Instrument` spans. Client `run()` gets an `info_span!("ntp_client")` with peer count and poll interval fields; `poll_peer()`, `poll_peer_nts()`, `poll_peer_v5()` get `debug_span!` with peer address; `nts_ke()` gets hostname/port fields. NTS-KE server connections get per-connection spans with peer address. Span hierarchy enables structured trace filtering (e.g., `RUST_LOG=ntp_client=debug`).
- **Tracing subscriber example**: Updated `daemon.rs` to demonstrate `tracing-subscriber` with `EnvFilter` + `fmt` layer, structured fields (offset_ms, delay_ms, jitter_ms), and `RUST_LOG` environment variable usage. Other examples retain `env_logger` to demonstrate the backward-compatible `log` bridge path.

#### Error Handling

- **Custom error types (client)**: New `NtpError` enum with `Protocol`, `Timeout`, `Config`, `Nts`, `KissOfDeath`, and `Io` variants. Public API remains `io::Result<T>` — users can downcast via `io::Error::get_ref().downcast_ref::<NtpError>()` for programmatic error matching. Migrated ~60 internal `io::Error::new()` call sites across `request.rs`, `nts_ke_exchange.rs`, `client.rs`, `smol_client.rs`, `nts.rs`, `smol_nts.rs`, `async_ntp.rs`, `smol_ntp.rs`, `client_common.rs`, `broadcast_client.rs`, and `roughtime.rs`.
- **Custom error types (server)**: New `NtpServerError` enum with `Protocol`, `Nts`, `Config`, and `Io` variants. Same downcast pattern as client. Migrated ~25 internal `io::Error::new()` call sites across `validation.rs`, `ntpv5.rs`, `nts_server_common.rs`, `nts_ke_server_common.rs`, `server.rs`, `smol_server.rs`, and `tls_config.rs`.

### Changed

#### Documentation

- **README refresh**: Updated version references from 3.1 → 4.9 throughout. Added WASM crate to crate table (now 4 crates). Expanded feature flag tables with 11 new client features and 6 new server features. Added Observability section demonstrating `tracing-subscriber` vs `env_logger`. Updated roadmap with completed items (reference clocks, hardware timestamping, NTPv5, Roughtime, post-quantum NTS, WASM, tracing, custom error types). Updated test count from 290+ to 750+.

## [4.8.0] - 2026-02-18

### Added

#### Testing

- **8 unit tests for server builder `into_config()`**: Defaults, listen addr, stratum/precision, allow/deny, multiple allow entries, rate limit, interleaved/max_clients, metrics.
- **7 unit tests for client builder `into_config()`**: Defaults, servers, poll clamping, initial poll defaults/clamping, multiple servers.
- **5 unit tests for `NtsKeServerConfig::from_pem()`**: Valid PEM parsing, garbage cert (yields empty chain), invalid key, empty cert (yields empty chain), config field access.

#### Documentation

- **`docs/DUPLICATION_AUDIT.md`**: Documents remaining ~570 lines of tokio/smol duplication with similarity percentages, the 4 categories of runtime-specific differences, rationale for not extracting further, and maintenance guidelines.

### Changed

#### Observability

- **Replaced `log` with `tracing`** across all 20 source files in client and server crates. The `tracing` crate's `log` feature auto-emits `log` records when no tracing subscriber is installed, so existing `env_logger` users see identical output. When a tracing subscriber is installed, get spans and structured fields.
- **Structured tracing fields** on 15 high-value log sites: peer polling (`peer`, `poll_interval_s`), sample results (`offset`, `delay`, `interleaved`), NTS-KE negotiation (`protocol`, `aead_algorithm`, `cookie_len`), server request handling (`client`, `error`), and NTS-KE connection events (`peer`, `error`).
- **`handle_request()` span**: Added `tracing::debug_span!("handle_request", client = %src_ip)` to the server request processing pipeline.
- **`ntp_usg-proto`** unchanged — retains optional `log` dependency with zero call sites.

## [4.7.0] - 2026-02-18

### Changed

#### Code Deduplication

- **Server builder**: Extracted `define_server_builder!` macro and `ServerBuildConfig` into `server_common/builder.rs`. Both tokio and smol `NtpServerBuilder` types are now generated from the same macro with runtime-specific `extra_fields`/`extra_defaults`. All builder configuration methods (listen, stratum, precision, leap indicator, reference ID, root delay/dispersion, allow/deny, rate limit, interleaved, max clients, metrics, v6only, dscp, NTPv5, refclock) exist in a single location.
- **NTS-KE server**: Extracted `NtsKeServerConfig` struct, `from_pem()`, and `process_nts_ke_records()` into `nts_ke_server_common.rs`. Both tokio and smol NTS-KE server implementations now share all NTS-KE record processing, AEAD negotiation, TLS key export, and cookie generation logic. Runtime-specific code reduced to thin TLS accept/read/write wrappers.
- **Client builder**: Extracted `define_client_builder!` macro and `ClientBuildConfig` into `client_common.rs`. Both tokio and smol `NtpClientBuilder` types are now generated from the same macro. All builder configuration methods (server, min/max/initial poll, v6only, dscp, discipline, NTPv5) and poll interval validation exist in a single location.
- **NTS client**: Extracted `parse_nts_ke_server_addr()`, `build_nts_ke_request()`, and `process_nts_ke_records()` into `nts_ke_exchange.rs`. Both tokio and smol NTS client implementations now share all NTS-KE request building, response parsing, AEAD algorithm selection, and TLS key export logic. Runtime-specific code reduced to thin TLS connect/read/write wrappers.

**Total**: ~1,300 lines of duplication eliminated across 4 file pairs. Each bug fix or feature change to shared logic now applies once instead of twice.

## [4.6.0] - 2026-02-18

### Added

#### Testing

- **12 unit tests for `nts.rs`**: NTS-KE server address parsing, `NtsKeResult` field validation, `NtsSession` construction and cookie management, NTS request building with unique identifiers.
- **10 unit tests for `client.rs`**: Builder defaults, poll interval clamping (min/max/initial), server accumulation, DNS resolution, `max_poll` flooring to `min_poll`.
- **10 unit tests for `client_common.rs`**: `short_format_to_secs` conversions (zero, integer, fractional, mixed), peer selection with empty/no-sample/single/demobilized/multi-peer scenarios.
- **19 unit tests for `server.rs`**: Builder defaults, all configuration methods (listen, stratum, precision, leap indicator, reference ID, root delay/dispersion, interleaved, max clients, allow/deny, rate limit, metrics), method chaining, socket binding, system state access, config handle.

### Changed

#### Code Quality

- **Replaced 6 `unwrap()` calls with `expect()`** in `client_common.rs` production code: All `unwrap()` calls on `best_sample()` and `min_by()` now use `expect()` with invariant documentation (`"pre-filtered to have samples"`, `"candidates is non-empty"`).

## [4.5.0] - 2026-02-18

### Changed

#### Cryptography

- **Prefer AES-SIV-CMAC-512 (256-bit AES)**: Client now proposes CMAC-512 first with CMAC-256 fallback. Server prefers CMAC-512 when client supports it. Server cookie encryption upgraded from CMAC-256 (32-byte master key) to CMAC-512 (64-byte master key). Both algorithms remain supported for interoperability.

### Added

#### Documentation

- **`docs/CRYPTO.md`**: Cryptographic architecture document covering all algorithms, libraries, and FIPS 140-3 certification status. Documents the FIPS gap in NTS AEAD (`aes-siv` crate) and NTPv5 MAC (`cmac`/`aes` crates), and confirms TLS layer uses FIPS-validated `aws-lc-rs`.

## [4.4.0] - 2026-02-18

### Added

#### Testing

- **25 unit tests for `protocol/io.rs`**: Full coverage for `WriteToBytes`/`ReadFromBytes` implementations — round-trip serialization for `ShortFormat`, `TimestampFormat`, `DateFormat`, `Stratum`, `(LeapIndicator, Version, Mode)`, `ReferenceIdentifier`, and `Packet`. Edge values, buffer-too-short errors, all leap indicator and mode variants.
- **32 unit tests for `protocol/bytes.rs`**: Full coverage for `FromBytes`/`ToBytes` implementations — round-trip serialization, `ParseError::BufferTooShort` validation, `ReferenceIdentifier::from_bytes_with_stratum()` per stratum level (KoD, Primary, Secondary, Unknown), cross-module consistency test verifying `bytes.rs` and `io.rs` produce identical output.
- **5 NTS edge-case tests**: Multiple cookie response validation, `write_ke_record` empty body, `read_be_u16`, RFC 8915 constant validation, wrong-key AEAD decryption failure.

### Changed

#### Dependencies

- **`socket2` upgraded from 0.5 to 0.6**: Eliminates dual-version dependency (0.5 direct + 0.6 via tokio). Updated `set_tos()` → `set_tos_v4()`/`set_tclass_v6()` for the socket2 0.6 IPv4/IPv6-split API. MSRV 1.93 meets socket2 0.6's minimum (1.70).

#### Code Quality

- **Removed `#[allow(dead_code)]` from NTS server**: Promoted `NtsRequestContext`, `process_nts_extensions()`, and `build_nts_response()` from `pub(crate)` to `pub` — available to users building custom NTS-authenticated NTP server handlers. Module already gated behind `#[cfg(any(feature = "nts", feature = "nts-smol"))]`.
- **Eliminated `.parse().unwrap()` on const addresses**: `broadcast.rs` default (`"224.0.1.1:123"`) and `multicast.rs` default (`"ff02::101"`) replaced with compile-time `SocketAddr`/`Ipv6Addr` constructors.

## [4.3.0] - 2026-02-18

### Added

#### Testing

- **48 unit tests for `protocol/types.rs`**: Full coverage for `TimestampFormat`, `ShortFormat`, `DateFormat`, `LeapIndicator`, `Version`, `Mode`, `Stratum`, `ReferenceIdentifier`, `PrimarySource`, `KissOfDeath`, and `Packet` — round-trip serialization, edge values, error cases.
- **11 unit tests for `validation.rs`**: Buffer size validation, mode/version rejection, zero transmit timestamp.
- **10 unit tests for `response.rs`**: Server response field echoing, KoD responses (DENY/RATE), serialization length.
- **6 unit tests for `interleaved.rs`**: Interleaved mode detection, origin/receive timestamp correctness, client state updates.

#### Benchmarks

- **6 protocol parsing benchmarks** (`ntp_usg-proto`): `packet_from_bytes`, `packet_to_bytes`, `timestamp_from_bytes`, `timestamp_to_bytes`, `packet_roundtrip`, `extension_field_iter` using criterion 0.8.
- **3 server throughput benchmarks** (`ntp_usg-server`): `handle_request_basic`, `handle_request_with_rate_limit`, `serialize_response_with_t3` using criterion 0.8.
- **CI benchmark compilation check**: `cargo bench --workspace --no-run` in Linux CI.

#### CI

- **7 new feature combination tests**: `gps`, `pps`, `hwts`, `broadcast + symmetric`, `pq-nts` (tokio), `pq-nts` (smol), benchmark compilation.

#### Documentation

- **`docs/FEATURE_FLAGS.md`**: Complete feature matrix for all 4 crates with incompatibility notes and CI coverage status.
- **`docs/PLATFORM_SUPPORT.md`**: Platform support matrix (Linux/macOS/Windows/WASM) with per-feature availability and platform-specific notes.

### Changed

#### Safety & Correctness

- **`Instant::new()` returns `Result`**: Changed from panicking to returning `Result<Instant, InvalidInstantError>` for mixed-sign arguments. All callers updated with `.expect()` documenting invariants.
- **SAFETY comments on all unsafe blocks**: Added `// SAFETY:` documentation to all 16 unsafe blocks in `clock.rs` (9 blocks: Linux/macOS/Windows FFI), `pps.rs` (2 blocks: PPS ioctls), and `hwts.rs` (3 blocks: setsockopt, pointer arithmetic).

#### Public API

- **`handle_request()`, `HandleResult`, `ClientTable`, `ClientState`, `serialize_response_with_t3()`**: Promoted from `pub(crate)` to `pub` in `server_common` — enables custom server loop implementations and benchmarking.

## [4.2.0] - 2026-02-18

### Added

#### Testing & CI

- **12 smol server integration tests**: Mirrors the tokio integration test suite for the smol runtime — server bind/respond, client library roundtrip, stratum/reference echo, KoD (DENY/RSTR/RATE), rate limiting, interleaved mode, NTPv3 compat, concurrent clients, origin timestamp echo.
- **2 new fuzz targets**: `fuzz_packet_v5` (NTPv5 `PacketV5::from_bytes`) and `fuzz_roughtime` (Roughtime `TagValueMap::from_bytes`) added to `ntp_usg-proto/fuzz`.
- **CI enhancements**: `cargo deny` license/advisory check, `discipline` and `refclock` feature testing, new fuzz targets in smoke test, Miri NTPv5 test.

#### Examples

- **`discipline.rs`** (client) — Clock discipline loop with `DisciplineState` transitions (Nset→Fset→Sync).
- **`ntpv5_client.rs`** (client) — NTPv5 packet construction and parsing (draft-ietf-ntp-ntpv5).
- **`nts_smol.rs`** (client) — NTS-secured request using smol runtime.
- **`symmetric.rs`** (client) — Symmetric active/passive mode exchange.
- **`socket_opts.rs`** (client) — Socket options (SO_TIMESTAMPNS, IP_TOS/DSCP) for precision timestamping.
- **`ntpv5_server.rs`** (server) — NTPv5-capable server demonstration.

### Changed

#### Performance

- **`NtpSyncState::discipline_state`**: Changed from `String` to `Option<DisciplineState>` — eliminates heap allocation, enables pattern matching. (**Breaking**: field type changed.)
- **`SampleFilter::jitter()`**: Replaced `Vec` collection with iterator-based computation — eliminates heap allocation in the filter hot path.
- **`cluster_survivors()`**: Replaced `Vec::remove()` (O(n) shift) with `Vec::swap_remove()` (O(1)) — order is irrelevant for the pruning algorithm.
- **`bind_addr_for()`**: Returns `SocketAddr` directly instead of `&'static str` — eliminates 10 call sites of `.parse().unwrap()`.

#### Dependency Cleanup

- **Removed `async-trait`**: Manual desugaring (`fn -> Pin<Box<dyn Future + Send + '_>>`) for the `RefClock` trait and all implementations. MSRV 1.93 has native async fn in traits, but `dyn RefClock` requires manual desugaring for object safety. Eliminates proc-macro compile cost.

## [4.1.0] - 2026-02-18

### Added

#### Server Improvements

- **Runtime metrics** (`ServerMetrics`): Lock-free `AtomicU64` counters for requests received/sent/dropped, KoD responses (DENY/RSTR/RATE), interleaved responses, and active clients. Attach via `.metrics(Arc<ServerMetrics>)` builder method; read via `.snapshot()`.
- **Runtime configuration** (`ConfigHandle`): Update access control, rate limiting, and interleaved mode while the server is running via `Arc<RwLock<ServerConfig>>`. Obtain a `ConfigHandle` from `server.config_handle()` before calling `.run()`.
- **12 server integration tests**: In-process loopback tests on ephemeral ports covering happy-path, KoD (DENY/RSTR/RATE), rate limiting, interleaved mode, NTPv3 compatibility, concurrent clients, and origin timestamp echo.

#### API Polish & Developer Experience

- **Trait derives**: Added `Default` for `Version` (V4), `Mode` (Client), `Stratum` (UNSPECIFIED), `ReferenceIdentifier` (Unknown), `Packet` (NTPv4 client template). Added `Eq`/`Hash` on `Instant`, `ParseError`, `ExtensionField`/`ExtensionFieldRef`, `KissOfDeathError`, `RateLimitConfig`, `IpNet`.
- **`Version::new(v: u8)`**: Validated constructor for `Version` (1..=5), needed by external crates where the inner field is `pub(super)`.
- **`Packet::default()`**: Produces a valid NTPv4 client request template. Simplified `build_request_packet()` and `buildClientRequest()` using struct update syntax.
- **WASM API**: Added `NtpPacket.clientRequest()` static constructor, setters (`setVersion`, `setMode`, `setStratum`, `setPoll`, `setPrecision`, `setTransmitTimestamp`, `setOriginTimestamp`, `setReceiveTimestamp`, `setReferenceTimestamp`, `setLeapIndicator`), `computeOffsetDelay()` (RFC 5905 offset/delay from four timestamps), and `validateResponse()` (RFC 5905 response validation with KoD detection).
- **Feature flag documentation**: Added feature flag tables to `ntp_usg-client` and `ntp_usg-server` lib.rs explaining all feature gates, their implications, and incompatibilities.

### Changed

- Server `run()` loop scopes config read lock in a block instead of using explicit `drop()`, ensuring `Send`-safety for the async future.

## [4.0.1] - 2026-02-18

### Fixed

- Publish pipeline: install `cargo-cyclonedx`, collect SBOMs from crate subdirectories, clean up before `cargo publish`
- Added `ntp_usg-wasm` to crates.io publish workflow
- Added publishing metadata (docs.rs, keywords, categories) to `ntp_usg-wasm`

## [4.0.0] - 2026-02-18

### Breaking Changes

- **Major version bump**: Protocol-level additions (NTPv5, Roughtime) and new public API surface warrant a semver-major release. Existing NTPv4 APIs are unchanged.

### Added

#### Roughtime Protocol Client (`roughtime` feature)

- Authenticated coarse time synchronization per `draft-ietf-ntp-roughtime-15`
- Tag-value map encoder/decoder (zero-copy `TagValueMap<'a>`)
- Ed25519 signature verification (delegation certificate + response)
- SHA-512 Merkle tree path verifier (client-side proof validation)
- Sync and async API: `roughtime::request()` / `roughtime::async_request()`
- Multi-server chaining via `build_chained_request()` (SHA-512 nonce derivation)
- Integration tests against Cloudflare Roughtime (`roughtime.cloudflare.com:2003`)

#### Post-Quantum NTS (`pq-nts` feature)

- ML-KEM hybrid X25519MLKEM768 key exchange for NTS-KE via `aws-lc-rs` backend
- `prefer-post-quantum` enabled by default when `nts` or `nts-smol` features are active
- Automatic fallback to classical X25519 when server doesn't support PQ
- Centralized TLS config modules (`tls_config.rs`) with `builder_with_provider()`

#### IPv6-only Mode Optimizations

- IPv6-first DNS resolution (`prefer_addresses()` helper)
- Server default listen addresses changed to `[::]` (dual-stack)
- `ipv4` feature gate to restore IPv4-only behavior
- Type-safe RefId helpers: `from_ipv4()`, `from_ipv6()` (MD5 hash), `matches_ipv4()`
- IPv6 multicast server discovery (`[ff02::101]:123`) with `MulticastConfig`
- `IPV6_V6ONLY` socket option via `v6only()` builder method (`socket-opts` feature)
- DSCP/Traffic Class marking via `dscp()` builder method (`socket-opts` feature)

#### NTPv5 Support (`ntpv5` feature)

- Full NTPv4-to-NTPv5 protocol per `draft-ietf-ntp-ntpv5-07`
- 48-byte `PacketV5` header with era number, timescale, flags, client/server cookies
- `Time32` type: 4 integer + 28 fractional bits (~3.7 ns resolution)
- 120-bit Bloom filter Reference IDs for loop detection
- AES-CMAC-128 MAC extension field (0xF502)
- 0xF501–0xF509 + 0xF5FF extension fields (Padding, MAC, Reference IDs, Server Info, Correction, timestamps, Draft Identification)
- NTPv5 server (client-server mode only)
- NTPv5 client with version negotiation and Bloom filter assembly
- NTS-KE NTPv5 protocol ID negotiation (0x8001)

#### WASM Support (`ntp_usg-wasm` crate)

- New `ntp_usg-wasm` crate: JavaScript-friendly API via `wasm-bindgen`
- Exports: `NtpPacket` (parse/inspect/serialize), `buildClientRequest()`, `ntpTimestampToUnixSeconds()`, `unixSecondsToNtpTimestamp()`, `parseExtensionFields()`
- 37 KB WASM binary, 6 wasm-bindgen tests
- CI: `wasm32-unknown-unknown` target with 4 feature combos + `wasm-pack build`

### Fixed

- Network tests now gracefully skip on `ENETUNREACH` (101), `EHOSTUNREACH` (113), `ConnectionRefused`, `ConnectionReset`, and `AddrNotAvailable` — shared `is_network_skip_error()` helper across all integration tests
- `cargo cyclonedx` invalid `--output-prefix` flag removed from publish workflow
- Miri CI: excluded network/GPS/PPS tests, added sysroot caching
- Minimal-versions: resolved transitive dependency conflicts

### New Dependencies

| Dependency | Feature | Purpose |
|------------|---------|---------|
| `ring` 0.17 | `roughtime` | Ed25519 signatures, SHA-512 Merkle proofs |
| `aes` 0.8 | `ntpv5` | AES-CMAC-128 MAC extension field |
| `cmac` 0.7 | `ntpv5` | CMAC construction for NTPv5 |
| `wasm-bindgen` 0.2 | `ntp_usg-wasm` | JS interop for WASM builds |
| `js-sys` 0.3 | `ntp_usg-wasm` | JavaScript built-in object bindings |

### New Feature Flags

| Crate | Feature | Description |
|-------|---------|-------------|
| `ntp_usg-proto` | `roughtime` | Roughtime tag-value maps and verification |
| `ntp_usg-proto` | `ntpv5` | NTPv5 protocol types and extensions |
| `ntp_usg-client` | `roughtime` | Roughtime sync/async client |
| `ntp_usg-server` | `ntpv5` | NTPv5 server mode |
| `ntp_usg-server` | `pq-nts` | Post-quantum NTS key exchange |
| `ntp_usg-server` | `ipv4` | IPv4-only mode (default is dual-stack) |

## [3.4.0] - 2026-02-17

### Added

- Embedded/no_std example (`ntp_usg-proto/examples/embedded_nostd.rs`) demonstrating `FromBytes`/`ToBytes` API with zero heap allocation
- High-precision time synchronization example (`ntp_usg-client/examples/high_precision.rs`) combining PPS + hardware timestamping
- Rate limiter/access control example (`ntp_usg-server/examples/rate_limiter.rs`) with per-client rate limiting and IP-based ACLs

### Changed

- Extracted `request.rs` from client `lib.rs` — `lib.rs` reduced from ~898 to ~141 lines
- Split `protocol.rs` (~1,293 lines) into `protocol/` module (types, traits, io, bytes, mod)
- Split `server_common.rs` (~1,350 lines) into `server_common/` module (9 files)
- Deduplicated ~840 lines between `client.rs` and `smol_client.rs` into `client_common.rs`
- Added `#[cfg(target_os = "linux")]` guards to Linux-only examples for cross-platform CI

## [3.3.3] - 2026-02-16

### Fixed

- NMEA test checksums corrected for GGA, RMC, and ZDA sentences
- Clippy `io_other_error` lint: migrated to `io::Error::other()` in GPS and PPS modules
- Clippy `let_and_return` and `if_same_then_else` lints in NTP server
- Clippy `excessive_precision` lint in hardware timestamping test
- `tokio::join!` compile error in GPS+PPS combined example (wrapped in `async` block for `timeout`)
- Borrow-after-move in GPS+PPS example (`match gps_result` → `match &gps_result`)
- macOS CI: handle `WouldBlock` (os error 35) in SNTP test when NTP port is blocked
- Windows CI: handle TLS `close_notify` errors in NTS integration tests
- macOS CI: gracefully skip continuous client test when no NTP updates received
- Add missing version specifier on `ntp_usg-client` dependency for crates.io publish

## [3.3.2] - 2026-02-16 [YANKED]

_Partially published — `ntp_usg-server` failed to publish due to missing dependency version._

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

[4.10.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.9.0...v4.10.0
[4.9.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.8.0...v4.9.0
[4.8.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.7.0...v4.8.0
[4.7.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.6.0...v4.7.0
[4.6.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.5.0...v4.6.0
[4.5.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.4.0...v4.5.0
[4.4.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.3.0...v4.4.0
[4.3.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.2.0...v4.3.0
[4.2.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.1.0...v4.2.0
[4.1.0]: https://github.com/192d-Wing/ntp_usg/compare/v4.0.1...v4.1.0
[4.0.1]: https://github.com/192d-Wing/ntp_usg/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/192d-Wing/ntp_usg/compare/v3.4.0...v4.0.0
[3.4.0]: https://github.com/192d-Wing/ntp_usg/compare/v3.3.3...v3.4.0
[3.3.3]: https://github.com/192d-Wing/ntp_usg/compare/v3.3.2...v3.3.3
[3.3.2]: https://github.com/192d-Wing/ntp_usg/compare/v3.3.1...v3.3.2
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
