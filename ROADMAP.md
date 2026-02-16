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

## Planned

### no-std support

Decouple the packet parsing and protocol types from `std::io` so the library can be used in embedded or bare-metal environments. This would involve:

- Making `protocol`, `unix_time`, and `extension` modules available without `std`
- Using a custom error type instead of `std::io::Error` for parsing
- Feature-gating all network I/O behind a `std` feature (enabled by default)

### io-independent parsing

Separate the packet parsing logic from any I/O traits so that users can parse NTP packets from arbitrary byte buffers without depending on `Read`/`Write` traits. This is a prerequisite for no-std support and also useful for packet capture analysis.

### async-std support

Add an optional `async-std` feature flag providing the same async API surface as the `tokio` feature but using `async-std` runtime primitives. This would include:

- `async_ntp` equivalents using `async_std::net::UdpSocket`
- A continuous client variant using `async-std` timers and channels

### Setting system clocks

Provide optional utilities for applying NTP offset corrections to the system clock. This is OS-specific and would require:

- Platform-specific implementations (Linux `clock_adjtime`/`adjtimex`, macOS `adjtime`, Windows `SetSystemTime`)
- A safe abstraction over these APIs
- Integration with the continuous client's `NtpSyncState`

### NTP server functionality

Implement an NTP server that can respond to client requests. This would include:

- Basic NTPv4 server mode responding with accurate timestamps
- Reference clock interface for disciplining to hardware sources (GPS, PPS)
- Kiss-o'-Death response generation for rate limiting
- Access control lists
- NTS server support (requires server-side cookie generation and AEAD)
