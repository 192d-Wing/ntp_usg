# Platform Support

Feature availability across supported platforms.

## Support Matrix

| Feature | Linux x64 | Linux arm64 | macOS | Windows | WASM |
|---------|-----------|-------------|-------|---------|------|
| Core protocol (`ntp_usg-proto`) | yes | yes | yes | yes | yes |
| `no_std` protocol | yes | yes | yes | yes | yes |
| NTP client (`tokio`) | yes | yes | yes | yes | no |
| NTP client (`smol`) | yes | yes | yes | yes | no |
| NTP server (`tokio`) | yes | yes | yes | yes | no |
| NTP server (`smol`) | yes | yes | yes | yes | no |
| NTS (RFC 8915) | yes | yes | yes | yes | no |
| Post-quantum NTS (`pq-nts`) | yes | yes | yes | yes | no |
| NTPv5 draft | yes | yes | yes | yes | no |
| Clock adjust (`clock`) | yes | yes | yes | yes | no |
| Clock discipline | yes | yes | yes | yes | no |
| Symmetric mode | yes | yes | yes | yes | no |
| Broadcast mode | yes | yes | yes | yes | no |
| Roughtime | yes | yes | yes | yes | no |
| GPS reference clock | yes | yes | no | no | no |
| PPS reference clock | yes | yes | no | no | no |
| Hardware timestamping | yes | yes | no | no | no |
| WASM bindings | no | no | no | no | yes |

## Platform Notes

### Linux

Full feature support. The only platform with GPS, PPS, and hardware
timestamping. These features use Linux-specific APIs:

- **GPS**: Serial port access via the `serialport` crate.
- **PPS**: `PPS_GETCAP` and `PPS_FETCH` ioctls on `/dev/pps*` devices.
- **Hardware timestamping**: `SO_TIMESTAMPING` socket option and
  `SCM_TIMESTAMPING` control messages.
- **Clock adjust**: `clock_adjtime(2)` and `clock_gettime(2)` syscalls.

### macOS

Most features work. Clock adjustment uses `adjtime(2)` and
`gettimeofday(2)`/`settimeofday(2)`. GPS, PPS, and hardware timestamping
are not available (no kernel support for the required APIs).

### Windows

Most features work. Clock adjustment uses `SetSystemTimeAdjustment`,
`GetSystemTimeAsFileTime`, and `SetSystemTime` from `windows-sys`.
GPS, PPS, and hardware timestamping are not available.

### WASM (wasm32-unknown-unknown)

Only `ntp_usg-proto` and `ntp_usg-wasm` are supported. The protocol
library works in `no_std` mode for parsing and serialization. The WASM
crate provides JavaScript-friendly bindings for NTP packet handling
and time conversion.

Networking, clock access, and async runtimes are not available in WASM.

## CI Test Matrix

| Platform | Architectures | Rust Channels |
|----------|---------------|---------------|
| Linux | x64, arm64 | stable, beta |
| macOS | arm64 | stable, beta |
| Windows | x64, arm64 | stable, beta |
| WASM | wasm32 | stable |

Additional CI checks: clippy, rustfmt, cargo-audit, cargo-deny, Miri,
fuzzing (smoke), MSRV (1.93), minimal-versions, and code coverage.
