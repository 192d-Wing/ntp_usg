// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! IPv6 multicast NTP discovery support.
//!
//! Extends the existing [`crate::broadcast`] module with IPv6-specific multicast
//! group management using `socket2` for `IPV6_JOIN_GROUP` socket options.
//!
//! The standard NTP multicast group for IPv6 link-local scope is `[ff02::101]:123`.
//!
//! # Security Warning
//!
//! Like broadcast mode, multicast NTP provides no authentication by default and
//! is vulnerable to spoofing attacks. Use only on trusted networks. Consider NTS
//! (RFC 8915) for authenticated time synchronization instead.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};

/// Configuration for IPv6 multicast NTP transmission or reception.
#[derive(Clone, Debug)]
pub struct MulticastConfig {
    /// Multicast group address (default: `[ff02::101]:123` for link-local NTP).
    pub group_addr: SocketAddrV6,
    /// Network interface index for link-local scope (0 = default interface).
    pub interface: u32,
    /// Interval between multicast packets in seconds (server only).
    pub interval_secs: u64,
    /// Poll exponent for multicast packets (log2 seconds).
    pub poll_exponent: u8,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        MulticastConfig {
            group_addr: SocketAddrV6::new(
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x101),
                123,
                0,
                0,
            ),
            interface: 0,
            interval_secs: 64,
            poll_exponent: 6,
        }
    }
}

/// Create and bind a UDP socket joined to an IPv6 multicast group.
///
/// This creates an IPv6-only UDP socket, sets `SO_REUSEADDR`, binds to the
/// group port on all interfaces, and joins the specified multicast group.
///
/// Useful for both server (sending) and client (receiving) multicast NTP.
pub fn join_multicast_v6(config: &MulticastConfig) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    // IPv6-only (no IPv4-mapped addresses for multicast).
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // Bind to the multicast port on all interfaces.
    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, config.group_addr.port(), 0, 0);
    socket.bind(&SocketAddr::V6(bind_addr).into())?;

    // Join the multicast group on the specified interface.
    socket.join_multicast_v6(config.group_addr.ip(), config.interface)?;

    Ok(socket.into())
}

/// Set the outgoing multicast interface for an IPv6 socket.
///
/// This should be called on the server's send socket to control which
/// network interface multicast packets are transmitted on.
pub fn set_multicast_interface_v6(socket: &std::net::UdpSocket, interface: u32) -> io::Result<()> {
    let socket2 = socket2::SockRef::from(socket);
    socket2.set_multicast_if_v6(interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicast_config_default() {
        let config = MulticastConfig::default();
        assert_eq!(
            *config.group_addr.ip(),
            "ff02::101".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(config.group_addr.port(), 123);
        assert_eq!(config.interface, 0);
        assert_eq!(config.interval_secs, 64);
        assert_eq!(config.poll_exponent, 6);
    }

    #[test]
    fn test_multicast_config_custom() {
        let config = MulticastConfig {
            group_addr: SocketAddrV6::new("ff05::101".parse::<Ipv6Addr>().unwrap(), 123, 0, 0),
            interface: 2,
            interval_secs: 128,
            poll_exponent: 7,
        };
        assert_eq!(
            *config.group_addr.ip(),
            "ff05::101".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(config.interface, 2);
    }

    #[test]
    fn test_join_multicast_v6() {
        let config = MulticastConfig::default();
        // This may fail on systems without IPv6 or loopback multicast support.
        match join_multicast_v6(&config) {
            Ok(sock) => {
                let local = sock.local_addr().unwrap();
                assert!(local.is_ipv6());
                assert_eq!(local.port(), 123);
            }
            Err(e) => {
                // Permission denied (port 123) or no IPv6 — acceptable in CI.
                eprintln!("skipping test_join_multicast_v6: {e}");
            }
        }
    }
}
