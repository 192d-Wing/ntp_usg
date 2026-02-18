// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! UDP socket creation with configurable options (`IPV6_V6ONLY`, DSCP/Traffic Class).
//!
//! The [`SocketOptions`] struct is always available (as a zero-sized type when
//! `socket-opts` is disabled), so callers can pass it unconditionally. When the
//! `socket-opts` feature is enabled, [`SocketOptions::bind_udp`] uses `socket2`
//! for cross-platform socket option control.

#[cfg(feature = "socket-opts")]
use std::net::SocketAddr;

/// Socket options applied when creating UDP sockets.
///
/// When the `socket-opts` feature is disabled this is a zero-sized type and
/// all operations are no-ops. When enabled, it controls `IPV6_V6ONLY` and
/// DSCP (Differentiated Services Code Point) via the `socket2` crate.
#[derive(Clone, Debug, Default)]
pub(crate) struct SocketOptions {
    /// If `Some(true)`, restrict IPv6 sockets to IPv6-only (no IPv4-mapped addresses).
    /// If `Some(false)`, explicitly enable dual-stack (accept both IPv4 and IPv6).
    /// If `None`, use the OS default.
    #[cfg(feature = "socket-opts")]
    pub v6only: Option<bool>,

    /// DSCP (Differentiated Services Code Point) value for outgoing packets.
    ///
    /// Only the lower 6 bits are used; they are placed in the upper 6 bits of
    /// the IP TOS / IPv6 Traffic Class byte. Common values:
    /// - 46 (EF) — Expedited Forwarding, suitable for NTP
    /// - 0 — Best effort (default)
    #[cfg(feature = "socket-opts")]
    pub dscp: Option<u8>,
}

#[cfg(feature = "socket-opts")]
impl SocketOptions {
    /// Create and bind a UDP socket with the configured options.
    ///
    /// The socket is set to non-blocking mode for use with async runtimes.
    pub(crate) fn bind_udp(&self, bind_addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        if let Some(v6only) = self.v6only
            && bind_addr.is_ipv6()
        {
            socket.set_only_v6(v6only)?;
        }

        if let Some(dscp) = self.dscp {
            // DSCP occupies bits 7-2 of the TOS/Traffic Class byte.
            let tos = u32::from(dscp & 0x3F) << 2;
            if bind_addr.is_ipv4() {
                socket.set_tos_v4(tos)?;
            } else {
                socket.set_tclass_v6(tos)?;
            }
        }

        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        Ok(socket.into())
    }
}

#[cfg(test)]
#[cfg(feature = "socket-opts")]
mod tests {
    use super::*;

    #[test]
    fn test_default_socket_options() {
        let opts = SocketOptions::default();
        assert_eq!(opts.v6only, None);
        assert_eq!(opts.dscp, None);
    }

    #[test]
    fn test_bind_udp_v4() {
        let opts = SocketOptions::default();
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let sock = opts.bind_udp(addr).unwrap();
        assert!(sock.local_addr().unwrap().is_ipv4());
    }

    #[test]
    fn test_bind_udp_v6() {
        let opts = SocketOptions {
            v6only: Some(true),
            dscp: None,
        };
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let sock = opts.bind_udp(addr).unwrap();
        assert!(sock.local_addr().unwrap().is_ipv6());
    }

    #[test]
    fn test_bind_udp_with_dscp() {
        let opts = SocketOptions {
            v6only: None,
            dscp: Some(46), // EF
        };
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let sock = opts.bind_udp(addr).unwrap();
        // Just verify it doesn't error — TOS value can't be easily read back portably.
        assert!(sock.local_addr().is_ok());
    }
}
