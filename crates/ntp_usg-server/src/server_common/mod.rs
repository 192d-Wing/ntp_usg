// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Shared types and logic for the NTP server, used by both the
//! tokio-based [`crate::server`] and smol-based [`crate::smol_server`] modules.
//!
//! Provides request validation, response building, rate limiting, access control,
//! and interleaved mode tracking per RFC 5905, RFC 8633, and RFC 9769.

mod access_control;
mod config;
mod interleaved;
mod metrics;
mod network;
#[cfg(feature = "ntpv5")]
mod ntpv5;
mod pipeline;
mod rate_limit;
mod response;
mod state;
mod validation;

pub use self::access_control::AccessControl;
pub use self::config::{ConfigHandle, ConfigSnapshot, ServerConfig};
pub use self::metrics::{MetricsSnapshot, ServerMetrics};
pub use self::network::IpNet;
pub use self::rate_limit::RateLimitConfig;
pub use self::state::ServerSystemState;

pub use self::pipeline::{HandleResult, handle_request};
pub use self::rate_limit::{ClientState, ClientTable};
pub use self::response::serialize_response_with_t3;

pub(crate) use self::access_control::AccessResult;
pub(crate) use self::interleaved::{build_interleaved_response, update_client_state};
pub(crate) use self::rate_limit::{RateLimitResult, check_rate_limit};
#[cfg(feature = "symmetric")]
pub(crate) use self::response::build_symmetric_passive_response;
pub(crate) use self::response::{build_kod_response, build_server_response};
pub(crate) use self::validation::validate_client_request;
