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

### 1. More Extensive Examples 📚

**Priority**: High
**Status**: In Progress

Add comprehensive, production-ready examples covering real-world use cases:

- [x] **Multi-peer deployment example** (`examples/multi_peer_deployment.rs`)
  - 5-7 peer configuration
  - Selection/clustering demonstration
  - Error handling and fallback strategies

- [x] **NTS-authenticated continuous client** (`examples/nts_multi_peer.rs`)
  - Cookie management
  - Re-keying strategies
  - Failure recovery

- [x] **System daemon example** (`examples/daemon.rs`)
  - Background service
  - Logging configuration
  - Systemd integration notes

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

### 2. Integration Tests with Real NTP Servers 🧪

**Priority**: High
**Status**: Planned

Add end-to-end integration tests against live NTP infrastructure:

- [ ] **Public NTP pool tests**
  - pool.ntp.org queries
  - NIST time servers
  - Cloudflare time.cloudflare.com

- [ ] **NTS server tests**
  - time.cloudflare.com NTS
  - ntppool-nts.time.nl
  - Certificate validation

- [ ] **Interoperability tests**
  - ntpd (reference implementation)
  - chrony
  - Windows Time Service

- [ ] **Failure mode tests**
  - Network outages
  - Server unresponsiveness
  - Kiss-o'-Death handling

- [ ] **CI/CD integration**
  - Optional integration tests (not blocking)
  - Rate-limited to respect public servers
  - Network-dependent test isolation

### 3. Docker Containers for Testing 🐳

**Priority**: Medium
**Status**: Planned

Create Docker-based testing infrastructure:

- [ ] **NTP server container**
  - chrony-based reference server
  - Configurable stratum and parameters
  - Network simulation (latency, jitter, packet loss)

- [ ] **NTS server container**
  - Full NTS-KE setup
  - Auto-generated TLS certificates
  - Cookie key rotation

- [ ] **Test orchestration**
  - docker-compose setup
  - Multi-server topology
  - Automated test scenarios

- [ ] **Performance testing environment**
  - Isolated network namespace
  - Benchmark harness
  - Reproducible results

- [ ] **CI/CD integration**
  - GitHub Actions workflow
  - Parallel test execution
  - Artifact collection

### 4. Web Dashboard for Monitoring 📊

**Priority**: Low
**Status**: Planned

Create a web-based monitoring dashboard for NTP client/server deployments:

- [ ] **Real-time metrics**
  - Clock offset graph
  - Round-trip delay
  - Jitter history
  - Peer status (truechimers, falsetickers)

- [ ] **Server monitoring**
  - Active connections
  - Request rate
  - NTS session count
  - Rate limiting stats

- [ ] **API endpoints**
  - Prometheus-compatible metrics export
  - JSON REST API
  - WebSocket real-time updates

- [ ] **Visualization**
  - Time series graphs (using Chart.js or similar)
  - Peer selection visualization
  - Discipline algorithm state

- [ ] **Technology stack**
  - Backend: Axum or Actix-web
  - Frontend: HTML/CSS/JS (vanilla or lightweight framework)
  - Optional: Integration with Grafana

---

## Version 3.3.0 - Hardware Integration

**Target**: Q3 2026

### Reference Clock Interface

**Status**: Planned

Add support for high-precision reference clocks:

- [ ] **GPS receivers**
  - NMEA protocol parsing
  - PPS signal integration
  - Stratum 1 operation

- [ ] **PPS (Pulse Per Second)**
  - Kernel PPS support (Linux)
  - Hardware timestamping
  - Nanosecond precision

- [ ] **Hardware timestamping**
  - NIC hardware timestamps
  - SO_TIMESTAMPING support
  - Reduced network jitter

- [ ] **Reference clock API**
  - Generic RefClock trait
  - Multiple clock sources
  - Weighted combination

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
**Current Version**: 3.1.0
**Next Planned Release**: 3.2.0 (Q2 2026)
