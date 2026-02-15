Ntplib
------------

[![Documentation](https://docs.rs/ntp_usg/badge.svg)](https://docs.rs/ntp_usg)
[![Crates.io](https://img.shields.io/crates/v/ntp_usg.svg?maxAge=2592000)](https://crates.io/crates/ntp_usg)
[![License](https://img.shields.io/crates/l/ntp.svg)](https://github.com/192d-Wing/ntp_usg#license)

An ntp packet parsing library written in Rust.

Usage
-----

Add this to your `Cargo.toml`:

```ini
[dependencies]
ntp = "0.5"
```

and this to your crate root:

```rust
extern crate ntp;
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
