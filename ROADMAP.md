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
- [x] **async-std support** — `async_std_ntp`, `async_std_client`, and `async_std_nts` modules mirroring the tokio API surface
- [x] **System clock adjustment** — Platform-native slew/step correction on Linux and macOS via `clock` feature

## Planned

### NTP server functionality

Implement an NTP server that can respond to client requests. This would include:

- Basic NTPv4 server mode responding with accurate timestamps
- Reference clock interface for disciplining to hardware sources (GPS, PPS)
- Kiss-o'-Death response generation for rate limiting
- Access control lists
- NTS server support (requires server-side cookie generation and AEAD)
