# ntp_usg

[![docs.rs](https://img.shields.io/docsrs/ntp_usg-proto?style=for-the-badge&logo=rust&label=proto%20docs)](https://docs.rs/ntp_usg-proto/latest/ntp_proto/)
[![docs.rs](https://img.shields.io/docsrs/ntp_usg-client?style=for-the-badge&logo=rust&label=client%20docs)](https://docs.rs/ntp_usg-client/latest/ntp_client/)
[![docs.rs](https://img.shields.io/docsrs/ntp_usg-server?style=for-the-badge&logo=rust&label=server%20docs)](https://docs.rs/ntp_usg-server/latest/ntp_server/)
[![Crates.io](https://img.shields.io/crates/v/ntp_usg-proto.svg?style=for-the-badge&logo=rust&label=proto%20crate)](https://crates.io/crates/ntp_usg-proto)
[![Crates.io](https://img.shields.io/crates/v/ntp_usg-client.svg?style=for-the-badge&logo=rust&label=client%20crate)](https://crates.io/crates/ntp_usg-client)
[![Crates.io](https://img.shields.io/crates/v/ntp_usg-server.svg?style=for-the-badge&logo=rust&label=server%20crate)](https://crates.io/crates/ntp_usg-server)
[![License](https://img.shields.io/crates/l/ntp_usg-proto.svg?style=for-the-badge)](https://github.com/192d-Wing/ntp_usg#license)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/192d-Wing/ntp_usg/ci.yml?branch=master&style=for-the-badge&logo=github)](https://github.com/192d-Wing/ntp_usg/actions/workflows/ci.yml)
[![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/192d-Wing/ntp_usg?style=for-the-badge&logo=github)](https://github.com/192d-Wing/ntp_usg/issues)
[![GitHub Issues or Pull Requests](https://img.shields.io/github/issues-pr/192d-Wing/ntp_usg?style=for-the-badge&logo=github)](https://github.com/192d-Wing/ntp_usg/pulls)
[![Codecov](https://img.shields.io/codecov/c/github/192d-Wing/ntp_usg?style=for-the-badge&logo=codecov)](https://codecov.io/github/192d-Wing/ntp_usg)

A Network Time Protocol (NTP) library written in Rust, organized as a Cargo workspace with three crates:

| Crate | Lib name | Description |
|-------|----------|-------------|
| [`ntp_usg-proto`](crates/ntp_usg-proto) | `ntp_proto` | Protocol types, extension fields, and NTS cryptographic primitives |
| [`ntp_usg-client`](crates/ntp_usg-client) | `ntp_client` | NTP client (sync, async tokio/smol, NTS, clock adjustment) |
| [`ntp_usg-server`](crates/ntp_usg-server) | `ntp_server` | NTP server (tokio/smol, NTS-KE) |

## Features

- 🔒 **Safe & Secure**: `#![deny(unsafe_code)]` crate-wide; only platform FFI in the optional `clock` module uses unsafe
- 📚 **Well Documented**: Comprehensive API documentation with examples
- ⚡ **Configurable Timeouts**: Control request timeouts for different network conditions
- 🔄 **Async Ready**: Optional async support via Tokio or smol
- 🕐 **Y2036 Safe**: Era-aware timestamp handling for the NTP 32-bit rollover
- 🌍 **Multi-Server Support**: Query multiple NTP servers for improved reliability
- 🔐 **Network Time Security**: NTS (RFC 8915) with TLS 1.3 key establishment and AEAD authentication
- 📡 **Continuous Client**: Adaptive poll interval, multi-peer, and interleaved mode (RFC 9769)
- 🌐 **IPv6 Dual-Stack**: Automatic IPv4/IPv6 socket binding
- 🧩 **`no_std` Support**: Core protocol parsing works without `std` or `alloc`
- ⏱️ **Clock Adjustment**: Platform-native slew/step correction (Linux, macOS, Windows)
- 📡 **NTP Server**: Full NTPv4 server with rate limiting, access control, and interleaved mode
- 🦀 **Modern Rust**: Edition 2024 with MSRV 1.93
- ✅ **Well Tested**: CI/CD on Linux, macOS, and Windows

## Installation

Add the crate(s) you need to your `Cargo.toml`:

```toml
[dependencies]
# Protocol types only (also supports no_std)
ntp_usg-proto = "3.0"

# NTP client
ntp_usg-client = { version = "3.0", features = ["tokio"] }

# NTP server
ntp_usg-server = { version = "3.0", features = ["tokio"] }
```

**Minimum Supported Rust Version (MSRV):** 1.93
**Edition:** 2024

### Feature Flags

#### ntp_usg-proto

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Full I/O and `byteorder`-based APIs |
| `alloc` | No | `Vec`-based extension field types without full `std` |
| `nts` | No | NTS cryptographic primitives (AEAD, cookie handling) |

#### ntp_usg-client

| Feature | Default | Description |
|---------|---------|-------------|
| `tokio` | No | Async NTP client using Tokio |
| `smol-runtime` | No | Async NTP client using smol |
| `nts` | No | NTS authentication (Tokio + rustls) |
| `nts-smol` | No | NTS authentication (smol + futures-rustls) |
| `clock` | No | System clock slew/step adjustment (Linux, macOS, Windows) |

#### ntp_usg-server

| Feature | Default | Description |
|---------|---------|-------------|
| `tokio` | No | NTP server using Tokio |
| `smol-runtime` | No | NTP server using smol |
| `nts` | No | NTS-KE server (Tokio + rustls) |
| `nts-smol` | No | NTS-KE server (smol + futures-rustls) |

For `no_std` environments, use the proto crate with default features disabled:

```toml
[dependencies]
ntp_usg-proto = { version = "3.0", default-features = false }          # core parsing only
ntp_usg-proto = { version = "3.0", default-features = false, features = ["alloc"] }  # + Vec-based types
```

## Usage

### Basic Example

```rust
use chrono::TimeZone;

fn main() {
    let address = "time.nist.gov:123";
    let response = ntp_client::request(address).unwrap();
    let unix_time = ntp_client::unix_time::Instant::from(response.transmit_timestamp);
    let local_time = chrono::Local
        .timestamp_opt(unix_time.secs(), unix_time.subsec_nanos() as _)
        .unwrap();
    println!("Current time: {}", local_time);
}
```

### Custom Timeout

```rust
use std::time::Duration;

let response = ntp_client::request_with_timeout("time.nist.gov:123", Duration::from_secs(10))?;
```

### Async with Tokio

Enable the `tokio` feature:

```toml
[dependencies]
ntp_usg-client = { version = "3.0", features = ["tokio"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = ntp_client::async_ntp::request("time.nist.gov:123").await?;
    println!("Offset: {:.6} seconds", result.offset_seconds);
    Ok(())
}
```

### Continuous Client

The continuous client polls servers with adaptive intervals and supports interleaved mode (RFC 9769):

```rust
use ntp_client::client::NtpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client, mut state_rx) = NtpClient::builder()
        .server("time.nist.gov:123")
        .min_poll(4)
        .max_poll(10)
        .build()
        .await?;

    tokio::spawn(client.run());

    // Wait for sync state updates.
    while state_rx.changed().await.is_ok() {
        let state = state_rx.borrow();
        println!("Offset: {:.6}s, Delay: {:.6}s", state.offset, state.delay);
    }
    Ok(())
}
```

### NTS (Network Time Security)

Enable the `nts` feature for authenticated NTP:

```toml
[dependencies]
ntp_usg-client = { version = "3.0", features = ["nts"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use ntp_client::nts::NtsSession;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = NtsSession::from_ke("time.cloudflare.com").await?;
    let result = session.request().await?;
    println!("NTS offset: {:.6}s", result.offset_seconds);
    Ok(())
}
```

### NTS Continuous Client

Combine NTS authentication with the continuous polling client:

```rust
use ntp_client::client::NtpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client, mut state_rx) = NtpClient::builder()
        .nts_server("time.cloudflare.com")
        .min_poll(4)
        .max_poll(10)
        .build()
        .await?;

    tokio::spawn(client.run());

    while state_rx.changed().await.is_ok() {
        let state = state_rx.borrow();
        println!("Offset: {:.6}s, NTS: {}", state.offset, state.nts_authenticated);
    }
    Ok(())
}
```

### Async with smol

Enable the `smol-runtime` feature:

```toml
[dependencies]
ntp_usg-client = { version = "3.0", features = ["smol-runtime"] }
smol = "2"
```

```rust
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    smol::block_on(async {
        let result = ntp_client::smol_ntp::request_with_timeout(
            "time.nist.gov:123",
            Duration::from_secs(5),
        ).await?;
        println!("Offset: {:.6} seconds", result.offset_seconds);
        Ok(())
    })
}
```

The smol continuous client uses `Arc<RwLock<NtpSyncState>>` for state sharing:

```rust
use ntp_client::smol_client::NtpClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    smol::block_on(async {
        let (client, state) = NtpClient::builder()
            .server("time.nist.gov:123")
            .build()
            .await?;

        smol::spawn(client.run()).detach();

        loop {
            smol::Timer::after(std::time::Duration::from_secs(5)).await;
            let s = state.read().unwrap();
            println!("Offset: {:.6}s, Delay: {:.6}s", s.offset, s.delay);
        }
    })
}
```

### Clock Adjustment

Enable the `clock` feature to correct the system clock based on NTP measurements:

```toml
[dependencies]
ntp_usg-client = { version = "3.0", features = ["clock", "tokio"] }
```

```rust
use ntp_client::clock;

// Gradual correction (slew) for small offsets
clock::slew_clock(0.05)?;

// Immediate correction (step) for large offsets
clock::step_clock(-1.5)?;

// Automatic: slew if |offset| <= 128ms, step otherwise
let method = clock::apply_correction(offset)?;
```

### NTP Server

Enable the `tokio` feature on the server crate:

```toml
[dependencies]
ntp_usg-server = { version = "3.0", features = ["tokio"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use ntp_server::protocol::Stratum;
use ntp_server::server::NtpServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server = NtpServer::builder()
        .listen("0.0.0.0:123")
        .stratum(Stratum(2))
        .build()
        .await?;

    server.run().await
}
```

### Multiple Servers

See [crates/ntp_usg-client/examples/multiple_servers.rs](crates/ntp_usg-client/examples/multiple_servers.rs) for a complete example of querying multiple NTP servers.

## Examples

Run the included examples to see the library in action:

```bash
# Basic request example
cargo run -p ntp_usg-client --example request

# Custom timeout demonstration
cargo run -p ntp_usg-client --example timeout

# Query multiple servers
cargo run -p ntp_usg-client --example multiple_servers

# Detailed packet information
cargo run -p ntp_usg-client --example packet_details

# Async concurrent queries (requires tokio feature)
cargo run -p ntp_usg-client --example async_request --features ntp_usg-client/tokio

# Continuous client with poll management (requires tokio feature)
cargo run -p ntp_usg-client --example continuous --features ntp_usg-client/tokio

# NTS-authenticated request (requires nts feature)
cargo run -p ntp_usg-client --example nts_request --features ntp_usg-client/nts

# NTS continuous client (requires nts feature)
cargo run -p ntp_usg-client --example nts_continuous --features ntp_usg-client/nts

# Smol one-shot request
cargo run -p ntp_usg-client --example smol_request --features ntp_usg-client/smol-runtime

# Smol continuous client
cargo run -p ntp_usg-client --example smol_continuous --features ntp_usg-client/smol-runtime

# Clock adjustment (requires root/sudo on Unix, Administrator on Windows)
cargo run -p ntp_usg-client --example clock_adjust --features "ntp_usg-client/clock ntp_usg-client/tokio"

# NTP server (requires tokio feature)
cargo run -p ntp_usg-server --example server --features ntp_usg-server/tokio

# NTS server (requires nts feature + TLS certs)
cargo run -p ntp_usg-server --example nts_server --features ntp_usg-server/nts -- --cert server.crt --key server.key
```

## Roadmap

- [x] async support (tokio)
- [x] NTP era handling (Y2036)
- [x] IPv6 dual-stack support
- [x] Continuous client with adaptive polling
- [x] Interleaved mode (RFC 9769)
- [x] Network Time Security (RFC 8915)
- [x] IO-independent parsing (`FromBytes`/`ToBytes` traits)
- [x] `no_std` support (with optional `alloc`)
- [x] smol support (one-shot, continuous, and NTS)
- [x] System clock adjustment (slew/step on Linux, macOS, Windows)
- [x] NTP server with NTS-KE
- [x] Workspace restructure (proto, client, server crates)
- [ ] Reference clock interface (GPS, PPS)

## Contributing

Pull requests and issues are welcome! Please see our [GitHub repository](https://github.com/192d-Wing/ntp_usg) for more information.

## License

`ntp_usg` is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
