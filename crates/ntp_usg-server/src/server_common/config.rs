// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Runtime-updatable server configuration.
//!
//! [`ServerConfig`] bundles access control, rate limiting, and interleaved mode
//! settings behind an `Arc<RwLock<>>` so they can be changed while the server
//! is running.
//!
//! Callers obtain a [`ConfigHandle`] from the server before calling
//! [`NtpServer::run()`](crate::server::NtpServer::run) and use it to push
//! updates from any task.
//!
//! # Examples
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! use ntp_server::server::NtpServer;
//! use ntp_server::server_common::IpNet;
//!
//! let server = NtpServer::builder()
//!     .listen("[::]:1234")
//!     .build()
//!     .await?;
//!
//! let config = server.config_handle();
//! // Update access control from another task:
//! config.update(|c| {
//!     c.access_control.set_deny_list(
//!         Some(vec![IpNet::new("10.0.0.0".parse().unwrap(), 8)])
//!     );
//! });
//! # Ok(())
//! # }
//! ```

use std::sync::{Arc, RwLock};

use super::{AccessControl, RateLimitConfig};

/// Runtime-updatable server configuration.
///
/// This struct is held behind `Arc<RwLock<>>` and read once per incoming
/// request (synchronous read lock, never held across an `await` point).
#[derive(Debug)]
pub struct ServerConfig {
    /// IP-based access control (allow/deny lists).
    pub access_control: AccessControl,
    /// Optional per-client rate limiting configuration.
    pub rate_limit: Option<RateLimitConfig>,
    /// Whether interleaved mode (RFC 9769) is enabled.
    pub enable_interleaved: bool,
}

/// A cloneable handle for updating server configuration at runtime.
///
/// Obtained via [`NtpServer::config_handle()`](crate::server::NtpServer::config_handle).
/// Cloning this handle is cheap (it shares the inner `Arc`).
#[derive(Clone, Debug)]
pub struct ConfigHandle {
    inner: Arc<RwLock<ServerConfig>>,
}

impl ConfigHandle {
    /// Create a new handle wrapping the given config.
    pub(crate) fn new(inner: Arc<RwLock<ServerConfig>>) -> Self {
        Self { inner }
    }

    /// Apply a mutation to the server configuration.
    ///
    /// The closure receives a mutable reference to [`ServerConfig`] and can
    /// modify any field. The write lock is held only for the duration of the
    /// closure.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn update(&self, f: impl FnOnce(&mut ServerConfig)) {
        let mut config = self.inner.write().expect("config lock poisoned");
        f(&mut config);
    }

    /// Return a snapshot of the current configuration.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn snapshot(&self) -> ConfigSnapshot {
        let config = self.inner.read().expect("config lock poisoned");
        ConfigSnapshot {
            rate_limit: config.rate_limit.clone(),
            enable_interleaved: config.enable_interleaved,
        }
    }
}

/// A point-in-time copy of key configuration values (non-locking, cloneable).
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    /// The rate limit configuration, if any.
    pub rate_limit: Option<RateLimitConfig>,
    /// Whether interleaved mode is enabled.
    pub enable_interleaved: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_handle_update() {
        let config = Arc::new(RwLock::new(ServerConfig {
            access_control: AccessControl::default(),
            rate_limit: None,
            enable_interleaved: false,
        }));
        let handle = ConfigHandle::new(config.clone());

        handle.update(|c| {
            c.enable_interleaved = true;
        });

        let snap = handle.snapshot();
        assert!(snap.enable_interleaved);
    }

    #[test]
    fn test_config_handle_clone_shares_state() {
        let config = Arc::new(RwLock::new(ServerConfig {
            access_control: AccessControl::default(),
            rate_limit: None,
            enable_interleaved: false,
        }));
        let handle1 = ConfigHandle::new(config);
        let handle2 = handle1.clone();

        handle1.update(|c| {
            c.enable_interleaved = true;
        });

        let snap = handle2.snapshot();
        assert!(snap.enable_interleaved);
    }

    #[test]
    fn test_config_snapshot_rate_limit() {
        let config = Arc::new(RwLock::new(ServerConfig {
            access_control: AccessControl::default(),
            rate_limit: Some(RateLimitConfig::default()),
            enable_interleaved: false,
        }));
        let handle = ConfigHandle::new(config);
        let snap = handle.snapshot();
        assert!(snap.rate_limit.is_some());
    }
}
