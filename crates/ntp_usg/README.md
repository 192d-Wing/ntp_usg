# ⚠️ DEPRECATED: ntp_usg

> **Note:** This crate is excluded from the workspace and retained as a
> historical reference. It is not built, tested, or published.

**This crate is deprecated as of version 3.0.0 and is no longer maintained.**

The monolithic `ntp_usg` crate has been split into three focused, well-maintained crates:

| Crate | Description | Documentation |
|-------|-------------|---------------|
| [`ntp_usg-proto`](https://crates.io/crates/ntp_usg-proto) | NTP protocol types, extension fields, and NTS cryptographic primitives | [docs.rs](https://docs.rs/ntp_usg-proto/) |
| [`ntp_usg-client`](https://crates.io/crates/ntp_usg-client) | NTP client library with sync, async (tokio/smol), and NTS support | [docs.rs](https://docs.rs/ntp_usg-client/) |
| [`ntp_usg-server`](https://crates.io/crates/ntp_usg-server) | NTP server library with tokio/smol and NTS-KE support | [docs.rs](https://docs.rs/ntp_usg-server/) |

## Why was this crate split?

The split provides several benefits:

1. **Reduced dependencies**: Use only what you need (client, server, or just protocol types)
2. **Faster compile times**: Smaller crates compile faster
3. **Better maintainability**: Each crate has a focused purpose
4. **Clearer documentation**: Each crate's docs focus on its specific use case
5. **Independent versioning**: Each component can evolve at its own pace

## Migration Guide

### For NTP Client Users

**Before (v2.x):**
```toml
[dependencies]
ntp_usg = "2.0"
```

```rust
use ntp_usg::request;

fn main() {
    let response = request("time.nist.gov:123").unwrap();
    println!("Offset: {} seconds", response.offset_seconds);
}
```

**After (v3.x):**
```toml
[dependencies]
ntp_usg-client = "3.0"
```

```rust
use ntp_client::request;

fn main() {
    let response = request("time.nist.gov:123").unwrap();
    println!("Offset: {} seconds", response.offset_seconds);
}
```

### For NTP Server Users

**After (v3.x):**
```toml
[dependencies]
ntp_usg-server = { version = "3.0", features = ["tokio"] }
```

```rust
use ntp_server::*;
// See ntp_usg-server documentation for examples
```

### For Protocol/Type Users

If you only need NTP protocol types and parsing (no network I/O):

```toml
[dependencies]
ntp_usg-proto = "3.0"
```

```rust
use ntp_proto::{protocol::*, unix_time::*};
```

## Feature Flags

The new crates use more granular feature flags:

- **`ntp_usg-proto`**: `std` (default), `alloc`, `nts`
- **`ntp_usg-client`**: `tokio`, `nts`, `clock`, `smol-runtime`, `nts-smol`
- **`ntp_usg-server`**: `tokio`, `nts`, `smol-runtime`, `nts-smol`

See each crate's documentation for detailed feature information.

## Compatibility

This v3.0.0 release of `ntp_usg` re-exports all three new crates for backwards compatibility, but you will receive deprecation warnings. **We strongly recommend migrating to the new crates.**

Versions 2.0.3 and below have been yanked from crates.io to encourage migration.

## Links

- **Repository**: [github.com/192d-Wing/ntp_usg](https://github.com/192d-Wing/ntp_usg)
- **Issues**: [github.com/192d-Wing/ntp_usg/issues](https://github.com/192d-Wing/ntp_usg/issues)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
