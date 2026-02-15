Ntplib
------------

[![Documentation](https://docs.rs/ntp_usg/badge.svg)](https://docs.rs/ntp_usg)
[![Crates.io](https://img.shields.io/crates/v/ntp_usg.svg?maxAge=2592000)](https://crates.io/crates/ntp_usg)
[![License](https://img.shields.io/crates/l/ntp.svg)](https://github.com/192d-Wing/ntp_usg#license)

An ntp packet parsing library written in Rust.

Usage
-----

Add this to your `Cargo.toml`:

```toml
[dependencies]
ntp = "0.6"
```

**Minimum Supported Rust Version (MSRV):** 1.93
**Edition:** 2024

Example:

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

Todo
----

- [ ] no-std
- [ ] io independent parsing
- [ ] async support
- [ ] setting clocks
- [ ] ntp server functionality

Contributions
-------------

Pull Requests and Issues welcome!

License
-------

`ntp` is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See LICENSE-APACHE and LICENSE-MIT for details.
