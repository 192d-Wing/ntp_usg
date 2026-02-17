# ntp_usg Roadmap

This document outlines the development roadmap for the ntp_usg project.

## Version 3.1.0 - 100% RFC Compliance ✅

**Released**: 2026-02-16

### Completed Features
- ✅ RFC 5905 full compliance (selection, discipline, filter, symmetric, broadcast)
- ✅ RFC 4330 SNTP API wrapper
- ✅ RFC 7822 extension field registry
- ✅ Replaced unmaintained rustls-pemfile with rustls-pki-types
- ✅ Comprehensive algorithm documentation (ALGORITHMS.md)
- ✅ Performance analysis and benchmarks (PERFORMANCE.md)
- ✅ 290+ tests, zero security vulnerabilities

### Previous Milestones (v3.0.0 and earlier)

- ✅ Async support (tokio) — `async_ntp::request()` and `async_ntp::request_with_timeout()`
- ✅ NTP era handling (Y2036) — Pivot-based timestamp disambiguation across era boundaries
- ✅ IPv6 dual-stack support — Automatic socket binding based on target address family
- ✅ Continuous client with adaptive polling — `NtpClient::builder()` with multi-server support, reachability tracking, and RFC 5905 poll interval management
- ✅ Interleaved mode (RFC 9769) — Improved timestamp accuracy in the continuous client
- ✅ Network Time Security (RFC 8915) — NTS-KE over TLS 1.3, AEAD-authenticated NTP, automatic cookie replenishment
- ✅ NTS in continuous client — `NtpClientBuilder::nts_server()` with cookie replenishment and re-keying
- ✅ IO-independent parsing — `FromBytes`/`ToBytes` traits for buffer-based parsing decoupled from `std::io`
- ✅ no_std support — Core parsing works without `std` or `alloc`; `alloc` feature enables `Vec`-based types
- ✅ smol support — `smol_ntp`, `smol_client`, and `smol_nts` modules mirroring the tokio API surface
- ✅ System clock adjustment — Platform-native slew/step correction on Linux, macOS, and Windows via `clock` feature
- ✅ NTP server — NTPv4 server mode with builder pattern, KoD generation, IP-based access control, per-client rate limiting (RFC 8633), interleaved mode (RFC 9769), and both tokio and smol runtimes
- ✅ NTS server — Server-side NTS support (RFC 8915) including NTS-KE TLS 1.3 key establishment, cookie generation/validation with master key rotation, and AEAD-authenticated NTP request processing
- ✅ Workspace restructure — Split monolith into three crates: `ntp_usg-proto` (protocol types, extensions, NTS crypto), `ntp_usg-client` (sync/async client, NTS, clock), `ntp_usg-server` (server, NTS-KE)

---

## Version 3.2.0 - Developer Experience & Testing ✅

**Released**: 2026-02-16

### 1. More Extensive Examples 📚 ✅

**Priority**: High
**Status**: Completed

Comprehensive, production-ready examples covering real-world use cases:

- [x] **Multi-peer deployment example** (`examples/multi_peer_deployment.rs`)
  - 5-peer configuration with NIST, Cloudflare, Google, NTP Pool
  - RFC 5905 selection/clustering demonstration
  - Real-time health assessment with color indicators
  - Offset trend analysis

- [x] **NTS-authenticated continuous client** (`examples/nts_multi_peer.rs`)
  - Mixed NTS + standard NTP for resilience
  - Security posture tracking
  - NTS failure monitoring
  - Cookie management demonstration

- [x] **System daemon example** (`examples/daemon.rs`)
  - Production-ready long-running service
  - Structured logging with health-based log levels
  - 60-second periodic status reporting
  - Systemd integration documentation

- [x] **Embedded system example** (`ntp_usg-proto/examples/embedded_nostd.rs`)
  - `no_std`-compatible API demonstration (FromBytes/ToBytes)
  - Zero heap allocation, stack-only buffers
  - Compile-time size constants, round-trip parsing, error handling

- [x] **High-precision time synchronization** (`examples/high_precision.rs`)
  - PPS (Pulse Per Second) integration with nanosecond precision
  - Hardware timestamping (SO_TIMESTAMPING) capability detection
  - Continuous monitoring with 10-sample statistical windows

- [x] **Load balancer / rate limiter** (`ntp_usg-server/examples/rate_limiter.rs`)
  - Per-client rate limiting (RFC 8633 BCP 223)
  - IP-based access control lists (allow/deny with CIDR)
  - KoD responses (RATE, DENY, RSTR)

### 2. Integration Tests with Real NTP Servers 🧪 ✅

**Priority**: High
**Status**: Completed

End-to-end integration tests against live NTP infrastructure (16 tests total):

- [x] **Public NTP server tests** (10 tests in `tests/integration.rs`)
  - Individual servers: NIST, Cloudflare, Google Public NTP, NTP Pool
  - Multi-server consistency validation (servers agree within tolerance)
  - Continuous client convergence testing
  - SNTP API validation (RFC 4330)
  - IPv6 dual-stack support
  - Rapid successive query testing
  - Pool server DNS round-robin handling

- [x] **NTS server tests** (6 tests in `tests/nts_integration.rs`)
  - time.cloudflare.com NTS-KE and authenticated queries
  - Cookie rotation and persistence testing
  - Continuous NTS client verification
  - Mixed NTS + standard NTP deployment
  - Timeout and error handling
  - Multiple request cookie exhaustion prevention

- [x] **Resilient testing framework**
  - Graceful network failure handling
  - `SKIP_NETWORK_TESTS` environment variable for CI
  - Relaxed tolerances for various network conditions
  - Comprehensive test documentation in `tests/README.md`

- [x] **CI/CD ready**
  - All tests pass consistently
  - Network-aware skipping (no spurious failures)
  - Respect public server rate limits

### 3. Docker Containers for Testing 🐳 ✅

**Priority**: Medium
**Status**: Completed

Docker-based testing infrastructure with full orchestration:

- [x] **NTP server container** (`docker/ntp-server.Dockerfile`)
  - Rust-based NTPv4 server built from workspace
  - Stratum 2 configuration
  - Health checks via UDP connectivity
  - Optimized multi-stage builds

- [x] **NTS server container** (`docker/nts-server.Dockerfile`)
  - Full NTS-KE TLS 1.3 key establishment
  - Automatic certificate generation
  - NTP + NTS-KE dual service
  - Production-ready security configuration

- [x] **Test orchestration** (`docker/docker-compose.yml`)
  - Three-service architecture (NTP, NTS, test-runner)
  - Service dependencies and health checks
  - Isolated bridge network (172.28.0.0/16)
  - Automatic certificate generation service
  - Volume management for TLS certificates

- [x] **Test runner container** (`docker/test-runner.Dockerfile`)
  - Integration test execution against local servers
  - Dependency layer caching for fast rebuilds
  - Full workspace test suite support

- [x] **Documentation** (`docker/README.md`)
  - Quick start guide
  - CI/CD integration examples (GitHub Actions, GitLab CI)
  - Troubleshooting section
  - Production deployment patterns
  - Architecture diagrams

- [x] **CI/CD ready**
  - GitHub Actions workflow examples provided
  - Fast iteration with layer caching (~10s cached builds)
  - Reproducible test environment

### 4. Web Dashboard for Monitoring 📊 ✅

**Priority**: Low
**Status**: Completed

Web-based monitoring dashboard for real-time NTP client monitoring (`examples/web_dashboard.rs`):

- [x] **Real-time metrics**
  - Live clock offset, delay, and jitter display
  - Update count tracking
  - Last update timestamp
  - Auto-refresh every 2 seconds
  - Historical data (last 100 points)

- [x] **Health indicators**
  - Color-coded status (green/yellow/red)
  - Dynamic thresholds based on offset and jitter
  - Visual pulse animation for live status
  - Status messages (Excellent, Good, Degraded, Poor)

- [x] **API endpoints**
  - `/` - HTML dashboard with interactive charts
  - `/api/state` - JSON REST API with full state and history
  - `/metrics` - Prometheus-compatible metrics export

- [x] **Visualization**
  - Time series charts using Chart.js
  - Dual-axis plotting (offset and delay)
  - Last 50 data points displayed
  - Responsive design with gradient styling

- [x] **Technology stack**
  - Backend: Pure Tokio (no web framework needed)
  - HTTP server with TcpListener and manual routing
  - Frontend: Vanilla HTML/CSS/JS with Chart.js CDN
  - Production-ready with minimal dependencies

- [x] **Integration support**
  - Prometheus scraping ready
  - Grafana dashboard compatible
  - CORS enabled for custom clients
  - Example integrations in documentation

- [x] **Documentation** (`examples/WEB_DASHBOARD.md`)
  - API reference with examples
  - Deployment guides (systemd, Docker, nginx)
  - Security considerations
  - Troubleshooting guide

---

## Version 3.3.0 - Hardware Integration ✅

**Released**: 2026-02-16
**Status**: Complete (100%)

### Reference Clock Interface

Full support for high-precision reference clocks and Stratum 1 NTP server operation:

- [x] **GPS receivers** ✅
  - NMEA protocol parsing (GGA, RMC, ZDA)
  - Serial port communication
  - Fix quality validation
  - Unix timestamp conversion
  - Example: `examples/gps_receiver.rs`

- [x] **PPS (Pulse Per Second)** ✅
  - Linux kernel PPS API support
  - Assert/Clear/Both edge capture
  - Nanosecond precision timestamps
  - Async ioctl interface
  - Example: `examples/pps_receiver.rs`

- [x] **Reference clock API** ✅
  - Generic RefClock trait
  - RefClockSample with offset/dispersion/quality
  - LocalClock for testing
  - Documentation: `src/refclock/README.md`

- [x] **Hardware timestamping** ✅
  - NIC hardware timestamps via SO_TIMESTAMPING
  - Software/Hardware/HardwareRaw modes
  - NIC capability detection
  - Sub-microsecond accuracy
  - Example: `examples/hwts_demo.rs`

- [x] **Combined GPS+PPS example** ✅
  - Demonstrates optimal Stratum 1 setup
  - Parallel sample reading
  - Real-time comparison
  - Example: `examples/gps_pps_combined.rs`

- [x] **Stratum 1 server integration** ✅
  - RefClock integration with NtpServer
  - Automatic stratum and reference ID extraction
  - Background task for clock sample updates
  - Real-time root dispersion tracking
  - Example: `examples/stratum1_server.rs`

---

## Version 4.0.0 - Major Enhancements

**Target**: 2027

### 1. Roughtime Protocol Client 🔐

**Priority**: High — near-RFC, deps already in workspace
**Status**: Planned

Authenticated coarse (~1 second) time synchronization with cryptographic proof of server malfeasance per `draft-ietf-ntp-roughtime-15` (IESG "Waiting for AD Go-Ahead" — one step from RFC publication).

- [ ] Tag-value map encoder/decoder (little-endian 32-bit tags)
- [ ] Ed25519 signature verification (delegation certificate `DELE`/`MINT`/`MAXT`)
- [ ] SHA-512 Merkle tree path verifier (client-side proof validation)
- [ ] Single-server `RoughtimeClient::request()` returning timestamp + radius
- [ ] Multi-server chaining for cryptographic malfeasance detection
- [ ] Feature gate: `roughtime`

**Use case**: Complementary sanity-check layer alongside NTP. Detects grossly wrong NTP servers (minutes/hours off) with a cryptographically verifiable receipt. Replaces deprecated NTP broadcast mode validation use case per RFC 8633.

**New deps**: `ed25519-dalek` or `ring` (already transitive via rustls), `sha2` (RustCrypto). `rand` and `byteorder` already in workspace.

**Reference**: `roughenough` 2.0.0-draft14 (existing Rust impl targeting draft-14)

---

### 2. Post-Quantum NTS 🔒

**Priority**: Medium — very low effort, partially blocked on CA ecosystem
**Status**: Planned

Enable quantum-resistant key exchange for NTS-KE (RFC 8915) using ML-KEM hybrid X25519MLKEM768 per `draft-ietf-tls-ecdhe-mlkem-04`. NTS-KE runs over TLS 1.3 — no NTS protocol changes needed, only the TLS backend.

- [ ] Swap `ring` backend for `aws-lc-rs` in rustls (ML-KEM support)
- [ ] Enable `prefer-post-quantum` feature on rustls (X25519MLKEM768 preferred)
- [ ] Feature gate: `pq-nts`
- [ ] Document: PQ key exchange protects against "Harvest Now, Decrypt Later" attacks

**Blocker**: PQ certificates (server authentication) require CA ecosystem support (CA/Browser Forum approval). Only the key exchange portion is unblocked today.

**Performance**: ~1,600 bytes additional per TLS handshake, ~80–150 µs extra compute — negligible for NTS-KE (one-time per session).

**New deps**: `aws-lc-rs = "1"` (replaces `ring` for rustls backend)

**Note**: FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) finalized by NIST August 2024. Cloudflare reports 50%+ of TLS connections now use hybrid PQ key exchange (Oct 2025).

---

### 3. IPv6-only Mode Optimizations 🌐

**Priority**: Medium — incremental improvements, no new deps
**Status**: Planned

Improve correctness and ergonomics for IPv6-only deployments.

- [ ] Type-safe `RefId` enum: `Ipv4(Ipv4Addr)`, `Ipv6Hash([u8;4])`, `KissCode([u8;4])`, `ClockSource([u8;4])` — with loop-detection collision warning for IPv6 peers
- [ ] IPv6 multicast server discovery (`FF02::101:123`) — zero-configuration NTP on local segment
- [ ] `IPV6_V6ONLY` socket option for IPv6-only binding (`socket2` crate)
- [ ] Happy Eyeballs (RFC 8305) — prefer IPv6 when both A/AAAA records resolve for pool hostnames
- [ ] DSCP/Traffic Class marking (`IPV6_TCLASS`) for QoS-aware networks

**Background**: RFC 5905 hashes IPv6 addresses to 4-byte REFIDs via MD5 — creating documented collision risk with IPv4 addresses. `draft-ietf-ntp-refid-updates-05` proposes a fix but is stalled. NTPv5's 120-bit Bloom filter REFIDs eliminate the problem entirely.

**New deps**: `socket2 = "0.5"` for fine-grained socket options

---

### 4. NTPv5 Support ⏱️

**Priority**: Low — blocked on draft stabilization (not yet RFC)
**Status**: Waiting on `draft-ietf-ntp-ntpv5` RFC publication

Full NTPv4-to-NTPv5 protocol upgrade per `draft-ietf-ntp-ntpv5-07` (active, expires Apr 2026).

- [ ] New 48-byte header struct: era number, timescale, flags, client/server cookies
- [ ] `time32` type: 4 integer + 28 fractional bits, ~3.7 ns resolution (vs NTPv4's ~15 µs)
- [ ] 120-bit Bloom filter Reference IDs for loop detection (replaces 32-bit REFID)
- [ ] Explicit interleaved mode via `ServerCookie`/`ClientCookie` fields
- [ ] AES-CMAC MAC extension field (0xF502) — requires `cmac` + `aes` crates
- [ ] 0xF503–0xF509 extension fields (Reference IDs, Server Info, Correction, timestamps)
- [ ] NTPv5 server: remove symmetric/broadcast/control modes (client-server only)
- [ ] Feature gate: `ntpv5`

**Key differences from NTPv4**: Removes symmetric, broadcast, control modes. Adds era-aware timestamps, explicit timescale, 120-bit loop detection, and unambiguous extension field architecture.

**Interop**: NTPv5 clients can negotiate with NTPv4 servers (version downgrade path defined in spec).

**Existing Rust impl**: ntpd-rs v1.7.1 has experimental NTPv5 support targeting draft-06.

**New deps**: `cmac = "0.7"` (RustCrypto AES-CMAC for MAC extension field)

---

### 5. WASM Support 🕸️

**Priority**: Low — parsing-only in browser, full client needs WASI
**Status**: Planned (documentation + CI target, limited scope)

`ntp_usg-proto` already compiles to `wasm32-unknown-unknown` with `default-features = false`. Browser-based full NTP client is not feasible (UDP unavailable in browser sandbox).

- [ ] Verify and document `ntp_usg-proto` WASM compatibility (`wasm32-unknown-unknown` CI target)
- [ ] Publish `wasm-pack` build of `ntp_usg-proto` for browser packet inspection tools
- [ ] WASI (`wasm32-wasip2`) support for full NTP client in server-side WASM (Cloudflare Workers, Fastly Compute)
- [ ] Feature gate: no change needed — `default-features = false` already works

**Scope**: Packet parsing, timestamp conversion, extension field handling work today. Full NTP client (tokio/smol) requires WASI with `wasi-sockets`. No browser-native NTP API exists (confirmed: no W3C Network Time API spec).

**Note**: "Network Time API integration" removed from roadmap — no such browser spec exists.

---

## Contributing

We welcome contributions! If you'd like to work on any of these roadmap items:

1. Check for existing issues or create a new one
2. Discuss the approach before implementing
3. Follow the coding standards and test requirements
4. Submit a PR with clear description and tests

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## Feedback

Have ideas for the roadmap? Open an issue with the `enhancement` label or start a discussion in [GitHub Discussions](https://github.com/192d-Wing/ntp_usg/discussions).

---

**Last Updated**: 2026-02-17 (v4.0.0 features researched and detailed)
**Current Version**: 3.4.0
**Next Planned Release**: 4.0.0 (2027)

## Version 3.2.0 Progress Summary

**Completion Status**: 4/4 major objectives completed (100%) ✅

- ✅ More Extensive Examples: 3 production examples
- ✅ Integration Tests: 16 tests against real servers
- ✅ Docker Testing Environment: Full Docker Compose setup
- ✅ Web Dashboard: Real-time monitoring with 3 API endpoints

All major v3.2.0 deliverables completed!

## Version 3.3.0 Progress Summary

**Completion Status**: 6/6 major objectives completed (100%) ✅

- ✅ GPS Receiver Support: NMEA parser, serial interface, example
- ✅ PPS Integration: Linux kernel PPS API, nanosecond precision
- ✅ RefClock Trait: Generic hardware time source abstraction
- ✅ Hardware Timestamping: SO_TIMESTAMPING, NIC capability detection
- ✅ GPS+PPS Combined: Optimal Stratum 1 example
- ✅ Stratum 1 Server Mode: RefClock integration with NtpServer
- ✅ Production Deployment Guide: Complete hardware setup documentation
- ✅ Performance Benchmarks: Comprehensive testing suite

**Delivered Features:**

- ~10,000 lines of new code (GPS + PPS + RefClock + HWTS + examples + benchmarks + docs)
- 6 new examples (gps_receiver, pps_client, hw_timestamp, combined, stratum1_server, etc.)
- 4 new feature flags (refclock, gps, pps, hw-timestamp)
- 5 reference clock modules (RefClock trait, GPS, PPS, LocalClock, HW timestamp)
- 8 benchmark test scripts (~40KB)
- 2 comprehensive guides (DEPLOYMENT.md 969 lines, BENCHMARKS.md 969 lines)
- 60+ tests across all modules

All major v3.3.0 deliverables completed!
