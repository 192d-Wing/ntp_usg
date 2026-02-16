# ntp_usg Roadmap

This document outlines the development roadmap for the ntp_usg project.

## Version 3.1.0 - 100% RFC Compliance ✅ (Current)

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

## Version 3.2.0 - Developer Experience & Testing (In Progress)

**Target**: Q2 2026

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

- [ ] **Embedded system example**
  - `no_std` usage
  - Minimal memory footprint
  - Resource-constrained environments

- [ ] **High-precision time synchronization**
  - PPS (Pulse Per Second) integration
  - Hardware timestamping
  - Sub-millisecond accuracy

- [ ] **Load balancer / rate limiter**
  - Server-side rate limiting
  - Access control lists
  - Request throttling

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

### Potential Features (Under Consideration)

- [ ] **NTPv5 support** (if RFC is published)
- [ ] **Rough time protocol** (BCP 223 alternative to broadcast)
- [ ] **IPv6-only mode optimizations**
- [ ] **Quantum-resistant cryptography** (post-quantum NTS)
- [ ] **WASM support** (browser-based NTP client)
- [ ] **Network Time API integration** (browser native time sync)

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

**Last Updated**: 2026-02-16
**Current Version**: 3.3.0
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
