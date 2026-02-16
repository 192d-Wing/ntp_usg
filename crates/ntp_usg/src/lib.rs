// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

#![deprecated(
    since = "3.0.0",
    note = "The ntp_usg crate has been split into separate crates. \
            Use `ntp_usg-proto` for protocol types, \
            `ntp_usg-client` for client functionality, and \
            `ntp_usg-server` for server functionality."
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # DEPRECATED: This crate has been split into multiple crates
//!
//! **This crate is deprecated as of version 3.0.0.**
//!
//! The monolithic `ntp_usg` crate has been split into three focused crates:
//!
//! - **[`ntp_usg-proto`](https://crates.io/crates/ntp_usg-proto)**: NTP protocol types, extension fields, and NTS cryptographic primitives
//! - **[`ntp_usg-client`](https://crates.io/crates/ntp_usg-client)**: NTP client library with sync, async (tokio/smol), and NTS support
//! - **[`ntp_usg-server`](https://crates.io/crates/ntp_usg-server)**: NTP server library with tokio/smol and NTS-KE support
//!
//! ## Migration Guide
//!
//! ### For Client Users
//!
//! Replace:
//! ```toml
//! [dependencies]
//! ntp_usg = "2.0"
//! ```
//!
//! With:
//! ```toml
//! [dependencies]
//! ntp_usg-client = "3.0"
//! ```
//!
//! Update imports:
//! ```rust,ignore
//! // Old
//! use ntp_usg::*;
//!
//! // New
//! use ntp_client::*;
//! ```
//!
//! ### For Server Users
//!
//! Add:
//! ```toml
//! [dependencies]
//! ntp_usg-server = "3.0"
//! ```
//!
//! Update imports:
//! ```rust,ignore
//! use ntp_server::*;
//! ```
//!
//! ### For Protocol/Type Users
//!
//! If you only need protocol types and parsing:
//! ```toml
//! [dependencies]
//! ntp_usg-proto = "3.0"
//! ```
//!
//! Update imports:
//! ```rust,ignore
//! use ntp_proto::*;
//! ```
//!
//! ## Compatibility Re-exports
//!
//! This crate re-exports all three new crates for backwards compatibility,
//! but you will receive deprecation warnings when using it. We strongly
//! recommend migrating to the new crates.

#[deprecated(
    since = "3.0.0",
    note = "Use `ntp_usg-proto` crate directly: https://crates.io/crates/ntp_usg-proto"
)]
pub use ntp_proto as proto;

#[deprecated(
    since = "3.0.0",
    note = "Use `ntp_usg-client` crate directly: https://crates.io/crates/ntp_usg-client"
)]
pub use ntp_client as client;

#[deprecated(
    since = "3.0.0",
    note = "Use `ntp_usg-server` crate directly: https://crates.io/crates/ntp_usg-server"
)]
pub use ntp_server as server;

// Re-export commonly used items for backwards compatibility
#[deprecated(
    since = "3.0.0",
    note = "Use `ntp_usg-proto` or `ntp_usg-client` crate directly"
)]
pub use ntp_proto::{error, extension, protocol, unix_time};

#[deprecated(
    since = "3.0.0",
    note = "Use `ntp_usg-client::request` from the `ntp_usg-client` crate"
)]
pub use ntp_client::request;
