// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Lock-free server metrics using atomic counters.
//!
//! All counters use relaxed ordering for maximum performance on the hot path.
//! Consumers that need a consistent snapshot should accept that individual
//! values are approximate when read concurrently.

use std::sync::atomic::{AtomicU64, Ordering};

/// Runtime server metrics, updated atomically on every request.
///
/// Create an instance with [`ServerMetrics::new()`], wrap in `Arc`, and pass
/// to [`NtpServerBuilder::metrics()`](crate::server::NtpServerBuilder::metrics).
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> std::io::Result<()> {
/// use std::sync::Arc;
/// use ntp_server::server::NtpServer;
/// use ntp_server::server_common::ServerMetrics;
///
/// let metrics = Arc::new(ServerMetrics::new());
/// let server = NtpServer::builder()
///     .listen("[::]:1234")
///     .metrics(metrics.clone())
///     .build()
///     .await?;
///
/// // Read metrics from another task
/// let snap = metrics.snapshot();
/// println!("requests: {}", snap.requests_received);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct ServerMetrics {
    /// Total NTP requests received (valid + invalid).
    pub requests_received: AtomicU64,
    /// Total valid responses sent.
    pub responses_sent: AtomicU64,
    /// Requests dropped (invalid packet, parse error).
    pub requests_dropped: AtomicU64,
    /// KoD DENY responses sent (access denied).
    pub kod_deny_sent: AtomicU64,
    /// KoD RSTR responses sent (access restricted).
    pub kod_rstr_sent: AtomicU64,
    /// KoD RATE responses sent (rate limited).
    pub kod_rate_sent: AtomicU64,
    /// Interleaved mode responses sent (RFC 9769).
    pub interleaved_responses: AtomicU64,
    /// Current number of tracked clients in the client table.
    pub active_clients: AtomicU64,
}

impl ServerMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a point-in-time snapshot of all metrics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_received: self.requests_received.load(Ordering::Relaxed),
            responses_sent: self.responses_sent.load(Ordering::Relaxed),
            requests_dropped: self.requests_dropped.load(Ordering::Relaxed),
            kod_deny_sent: self.kod_deny_sent.load(Ordering::Relaxed),
            kod_rstr_sent: self.kod_rstr_sent.load(Ordering::Relaxed),
            kod_rate_sent: self.kod_rate_sent.load(Ordering::Relaxed),
            interleaved_responses: self.interleaved_responses.load(Ordering::Relaxed),
            active_clients: self.active_clients.load(Ordering::Relaxed),
        }
    }

    #[inline]
    pub(crate) fn inc_requests_received(&self) {
        self.requests_received.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn inc_responses_sent(&self) {
        self.responses_sent.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn inc_requests_dropped(&self) {
        self.requests_dropped.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn inc_kod_deny(&self) {
        self.kod_deny_sent.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn inc_kod_rstr(&self) {
        self.kod_rstr_sent.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn inc_kod_rate(&self) {
        self.kod_rate_sent.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn inc_interleaved(&self) {
        self.interleaved_responses.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn set_active_clients(&self, count: u64) {
        self.active_clients.store(count, Ordering::Relaxed);
    }
}

/// A point-in-time snapshot of server metrics (non-atomic, copyable).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricsSnapshot {
    /// Total NTP requests received (valid + invalid).
    pub requests_received: u64,
    /// Total valid responses sent.
    pub responses_sent: u64,
    /// Requests dropped (invalid packet, parse error).
    pub requests_dropped: u64,
    /// KoD DENY responses sent.
    pub kod_deny_sent: u64,
    /// KoD RSTR responses sent.
    pub kod_rstr_sent: u64,
    /// KoD RATE responses sent.
    pub kod_rate_sent: u64,
    /// Interleaved mode responses sent.
    pub interleaved_responses: u64,
    /// Current number of tracked clients.
    pub active_clients: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_default_is_zero() {
        let m = ServerMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.requests_received, 0);
        assert_eq!(s.responses_sent, 0);
        assert_eq!(s.requests_dropped, 0);
        assert_eq!(s.kod_deny_sent, 0);
        assert_eq!(s.kod_rstr_sent, 0);
        assert_eq!(s.kod_rate_sent, 0);
        assert_eq!(s.interleaved_responses, 0);
        assert_eq!(s.active_clients, 0);
    }

    #[test]
    fn test_metrics_increment() {
        let m = ServerMetrics::new();
        m.inc_requests_received();
        m.inc_requests_received();
        m.inc_responses_sent();
        m.inc_kod_deny();
        m.set_active_clients(42);
        let s = m.snapshot();
        assert_eq!(s.requests_received, 2);
        assert_eq!(s.responses_sent, 1);
        assert_eq!(s.kod_deny_sent, 1);
        assert_eq!(s.active_clients, 42);
    }
}
