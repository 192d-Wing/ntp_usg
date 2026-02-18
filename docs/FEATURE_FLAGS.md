# Feature Flags

Complete feature matrix for all crates in the `ntp_usg` workspace.

## ntp_usg-proto

Core protocol library. Supports `no_std`.

| Feature | Default | Description | Implies |
|---------|---------|-------------|---------|
| `std` | **yes** | Standard library support (logging, I/O traits) | |
| `alloc` | no | Heap allocation without full `std` (for `no_std + alloc` targets) | |
| `nts` | no | NTS cookie encryption/decryption (RFC 8915) via `aes-siv` | `std` |
| `roughtime` | no | Roughtime protocol parsing (draft-ietf-ntp-roughtime) via `ring` | `std` |
| `ntpv5` | no | NTPv5 draft support (draft-ietf-ntp-ntpv5) | `std` |

**`no_std` usage**: Disable default features (`default-features = false`). The core
`protocol` module (parsing, serialization) works without `std` or `alloc`.

## ntp_usg-client

NTP client library.

| Feature | Default | Description | Implies |
|---------|---------|-------------|---------|
| `tokio` | no | Async NTP client using the tokio runtime | |
| `smol-runtime` | no | Async NTP client using the smol runtime | |
| `nts` | no | NTS client (RFC 8915) via tokio + tokio-rustls | `tokio`, `pq-nts` |
| `nts-smol` | no | NTS client via smol + futures-rustls | `smol-runtime`, `pq-nts` |
| `pq-nts` | no | Post-quantum key exchange (ML-KEM) for NTS via aws-lc-rs | |
| `clock` | no | System clock read/adjust via platform APIs (libc/windows-sys) | |
| `discipline` | no | Clock discipline algorithm (PLL/FLL) | `clock` |
| `symmetric` | no | Symmetric active mode (RFC 5905 mode 1) | |
| `broadcast` | no | Broadcast mode (RFC 5905 mode 5, deprecated by RFC 8633) | |
| `refclock` | no | Reference clock support for Stratum 1 servers | `tokio` |
| `gps` | no | GPS NMEA reference clock driver (Linux only) | `refclock` |
| `pps` | no | PPS (Pulse Per Second) reference clock (Linux only) | `refclock` |
| `hwts` | no | Hardware timestamping via `SO_TIMESTAMPING` (Linux only) | `refclock` |
| `roughtime` | no | Roughtime client | `tokio` |
| `ipv4` | no | Default to `0.0.0.0` instead of `[::]` for bind addresses | |
| `socket-opts` | no | DSCP, `IPV6_V6ONLY`, and multicast socket options via `socket2` | |
| `ntpv5` | no | NTPv5 draft client support | |

## ntp_usg-server

NTP server library.

| Feature | Default | Description | Implies |
|---------|---------|-------------|---------|
| `tokio` | no | Async NTP server using the tokio runtime | |
| `smol-runtime` | no | Async NTP server using the smol runtime | |
| `nts` | no | NTS-KE server (RFC 8915) via tokio + tokio-rustls | `tokio`, `pq-nts` |
| `nts-smol` | no | NTS-KE server via smol + futures-rustls | `smol-runtime`, `pq-nts` |
| `pq-nts` | no | Post-quantum key exchange (ML-KEM) for NTS via aws-lc-rs | |
| `symmetric` | no | Symmetric passive mode (RFC 5905 mode 2) | |
| `broadcast` | no | Broadcast mode (RFC 5905 mode 5, deprecated by RFC 8633) | |
| `refclock` | no | Reference clock support for Stratum 1 servers | `tokio` |
| `gps` | no | GPS reference clock (passes through to `ntp_usg-client`) | `refclock` |
| `pps` | no | PPS reference clock (passes through to `ntp_usg-client`) | `refclock` |
| `ipv4` | no | Default to `0.0.0.0` instead of `[::]` for listen addresses | |
| `socket-opts` | no | DSCP, `IPV6_V6ONLY`, and multicast socket options via `socket2` | |
| `ntpv5` | no | NTPv5 draft server support | |

## ntp_usg-wasm

WebAssembly bindings. No feature flags — always builds the full WASM API.

## Incompatible Combinations

- **`nts` + `nts-smol`**: Both enable TLS but use different backends
  (`tokio-rustls` vs `futures-rustls`). Use one or the other, not both.
- **`tokio` + `smol-runtime`**: Both work simultaneously for testing, but
  production code should pick one runtime.

## Platform-Restricted Features

| Feature | Linux | macOS | Windows | WASM |
|---------|-------|-------|---------|------|
| `gps` | yes | no | no | no |
| `pps` | yes | no | no | no |
| `hwts` | yes | no | no | no |
| `clock` | yes | yes | yes | no |

See [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) for details.

## CI Coverage

All feature combinations listed above are tested in CI. See
`.github/workflows/ci.yml` for the complete test matrix.
