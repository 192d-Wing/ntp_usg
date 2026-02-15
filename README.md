# ntp_usg

[![Documentation](https://docs.rs/ntp_usg/badge.svg)](https://docs.rs/ntp_usg)
[![Crates.io](https://img.shields.io/crates/v/ntp_usg.svg?maxAge=2592000)](https://crates.io/crates/ntp_usg)
[![License](https://img.shields.io/crates/l/ntp_usg.svg)](https://github.com/192d-Wing/ntp_usg#license)
[![CI](https://github.com/192d-Wing/ntp_usg/workflows/CI/badge.svg)](https://github.com/192d-Wing/ntp_usg/actions)

A Network Time Protocol (NTP) packet parsing and client library written in Rust.

## Features

- 🔒 **Safe & Secure**: Zero unsafe code with `#![forbid(unsafe_code)]`
- 📚 **Well Documented**: Comprehensive API documentation with examples
- ⚡ **Configurable Timeouts**: Control request timeouts for different network conditions
- 🌍 **Multi-Server Support**: Query multiple NTP servers for improved reliability
- 🦀 **Modern Rust**: Edition 2024 with MSRV 1.93
- ✅ **Well Tested**: CI/CD on Linux, macOS, and Windows

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ntp_usg = "0.7"
```

**Minimum Supported Rust Version (MSRV):** 1.93
**Edition:** 2024

## Usage

### Basic Example

```rust
use chrono::TimeZone;

fn main() {
    let address = "pool.ntp.org:123";
    let response = ntp::request(address).unwrap();
    let unix_time = ntp::unix_time::Instant::from(response.transmit_timestamp);
    let local_time = chrono::Local
        .timestamp_opt(unix_time.secs(), unix_time.subsec_nanos() as _)
        .unwrap();
    println!("Current time: {}", local_time);
}
```

### Custom Timeout

```rust
use std::time::Duration;

let response = ntp::request_with_timeout("pool.ntp.org:123", Duration::from_secs(10))?;
```

### Multiple Servers

See [examples/multiple_servers.rs](examples/multiple_servers.rs) for a complete example of querying multiple NTP servers.

## Examples

Run the included examples to see the library in action:

```bash
# Basic request example
cargo run --example request

# Custom timeout demonstration
cargo run --example timeout

# Query multiple servers
cargo run --example multiple_servers

# Detailed packet information
cargo run --example packet_details
```

## Roadmap

- [ ] no-std support
- [ ] io-independent parsing
- [ ] async support (tokio/async-std)
- [ ] setting system clocks
- [ ] NTP server functionality

## Contributing

Pull requests and issues are welcome! Please see our [GitHub repository](https://github.com/192d-Wing/ntp_usg) for more information.

## License

`ntp_usg` is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
