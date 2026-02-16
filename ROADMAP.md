# Roadmap

This document outlines the planned features and improvements for `ntp_usg`.

## Completed

- [x] **Async support** (tokio) — `async_ntp::request()` and `async_ntp::request_with_timeout()`
- [x] **NTP era handling** (Y2036) — Pivot-based timestamp disambiguation across era boundaries
- [x] **IPv6 dual-stack support** — Automatic socket binding based on target address family
- [x] **Continuous client with adaptive polling** — `NtpClient::builder()` with multi-server support, reachability tracking, and RFC 5905 poll interval management
- [x] **Interleaved mode** (RFC 9769) — Improved timestamp accuracy in the continuous client
- [x] **Network Time Security** (RFC 8915) — NTS-KE over TLS 1.3, AEAD-authenticated NTP, automatic cookie replenishment
- [x] **NTS in continuous client** — `NtpClientBuilder::nts_server()` with cookie replenishment and re-keying
- [x] **IO-independent parsing** — `FromBytes`/`ToBytes` traits for buffer-based parsing decoupled from `std::io`
- [x] **no_std support** — Core parsing works without `std` or `alloc`; `alloc` feature enables `Vec`-based types
- [x] **smol support** — `smol_ntp`, `smol_client`, and `smol_nts` modules mirroring the tokio API surface
- [x] **System clock adjustment** — Platform-native slew/step correction on Linux, macOS, and Windows via `clock` feature
- [x] **NTP server** — NTPv4 server mode with builder pattern, KoD generation, IP-based access control, per-client rate limiting (RFC 8633), interleaved mode (RFC 9769), and both tokio and smol runtimes
- [x] **NTS server** — Server-side NTS support (RFC 8915) including NTS-KE TLS 1.3 key establishment, cookie generation/validation with master key rotation, and AEAD-authenticated NTP request processing
- [x] **Workspace restructure** — Split monolith into three crates: `ntp_usg-proto` (protocol types, extensions, NTS crypto), `ntp_usg-client` (sync/async client, NTS, clock), `ntp_usg-server` (server, NTS-KE)

## Planned

### Reference clock interface

Disciplining to hardware sources (GPS, PPS) for stratum-1 operation.
