use std::io;
use std::net::IpAddr;

/// Classify an error from `recv_from` on the server socket.
///
/// A UDP server must not exit because one datagram failed: on Windows an ICMP
/// Port Unreachable for a reply we sent surfaces as `WSAECONNRESET` on the
/// *next* `recv_from`, and other kernels can report `ConnectionRefused` /
/// `Interrupted` similarly. Such errors are per-datagram and the socket is
/// still usable, so the serve loop should log and continue. Anything else
/// (the socket was closed, a programming error, resource exhaustion) is fatal.
pub(crate) fn recv_error_is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

/// An IP network (address + prefix length) for access control matching.
///
/// Supports both IPv4 and IPv6 addresses. Prefix lengths are bounded to
/// the address type's maximum (32 for IPv4, 128 for IPv6).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IpNet {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    /// Create a new IP network.
    ///
    /// The prefix length is clamped to the maximum for the address type
    /// (32 for IPv4, 128 for IPv6).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        IpNet {
            addr,
            prefix_len: prefix_len.min(max),
        }
    }

    /// Check whether the given IP address falls within this network.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        // Treat IPv4-mapped IPv6 addresses as their IPv4 form so an IPv4 rule
        // matches a client reached through a dual-stack IPv6 socket.
        let ip = ip.to_canonical();
        match (&self.addr, &ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX
                    .checked_shl(32 - self.prefix_len as u32)
                    .unwrap_or(0);
                (u32::from(*net) & mask) == (u32::from(*addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX
                    .checked_shl(128 - self.prefix_len as u32)
                    .unwrap_or(0);
                (u128::from(*net) & mask) == (u128::from(*addr) & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 clients on a dual-stack `[::]` socket appear as `::ffff:a.b.c.d`
    /// and must still match IPv4 rules.
    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_rule() {
        let net = IpNet::new("10.0.0.0".parse().unwrap(), 8);
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(net.contains(&mapped));
        let other: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(!net.contains(&other));
    }

    #[test]
    fn test_ipnet_contains_exact() {
        let net = IpNet::new("192.168.1.1".parse().unwrap(), 32);
        assert!(net.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!net.contains(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_contains_subnet() {
        let net = IpNet::new("192.168.1.0".parse().unwrap(), 24);
        assert!(net.contains(&"192.168.1.0".parse().unwrap()));
        assert!(net.contains(&"192.168.1.255".parse().unwrap()));
        assert!(!net.contains(&"192.168.2.0".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_contains_slash_zero() {
        let net = IpNet::new("0.0.0.0".parse().unwrap(), 0);
        assert!(net.contains(&"1.2.3.4".parse().unwrap()));
        assert!(net.contains(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_v4_v6_mismatch() {
        let net = IpNet::new("192.168.1.0".parse().unwrap(), 24);
        assert!(!net.contains(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_ipnet_ipv6() {
        let net = IpNet::new("2001:db8::".parse().unwrap(), 32);
        assert!(net.contains(&"2001:db8::1".parse().unwrap()));
        assert!(net.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!net.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn recv_error_classification() {
        for k in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
        ] {
            assert!(recv_error_is_transient(&io::Error::from(k)), "{k:?}");
        }
        for k in [
            io::ErrorKind::NotConnected,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::Other,
        ] {
            assert!(!recv_error_is_transient(&io::Error::from(k)), "{k:?}");
        }
    }
}
