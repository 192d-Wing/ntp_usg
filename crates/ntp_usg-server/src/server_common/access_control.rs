use std::net::IpAddr;

use super::IpNet;

/// Result of an access control check.
pub(crate) enum AccessResult {
    /// Request is allowed.
    Allow,
    /// Client is explicitly denied — send KoD DENY.
    Deny,
    /// Client is restricted (not on allow list) — send KoD RSTR.
    Restrict,
}

/// IP-based access control lists for the NTP server.
///
/// If a deny list is configured, any matching client receives a KoD DENY.
/// If an allow list is configured, non-matching clients receive a KoD RSTR.
/// If neither list is configured, all clients are allowed.
#[derive(Clone, Debug, Default)]
pub struct AccessControl {
    allow_list: Option<Vec<IpNet>>,
    deny_list: Option<Vec<IpNet>>,
}

impl AccessControl {
    /// Create an access control with optional allow and deny lists.
    pub fn new(allow_list: Option<Vec<IpNet>>, deny_list: Option<Vec<IpNet>>) -> Self {
        AccessControl {
            allow_list,
            deny_list,
        }
    }

    /// Check whether the given client IP is allowed.
    pub(crate) fn check(&self, client_ip: &IpAddr) -> AccessResult {
        // Deny list checked first.
        if let Some(deny) = &self.deny_list
            && deny.iter().any(|net| net.contains(client_ip))
        {
            return AccessResult::Deny;
        }
        // If allow list exists, client must match.
        if let Some(allow) = &self.allow_list
            && !allow.iter().any(|net| net.contains(client_ip))
        {
            return AccessResult::Restrict;
        }
        AccessResult::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_no_lists() {
        let ac = AccessControl::new(None, None);
        assert!(matches!(
            ac.check(&"1.2.3.4".parse().unwrap()),
            AccessResult::Allow
        ));
    }

    #[test]
    fn test_access_deny_list() {
        let deny = vec![IpNet::new("10.0.0.0".parse().unwrap(), 8)];
        let ac = AccessControl::new(None, Some(deny));
        assert!(matches!(
            ac.check(&"10.1.2.3".parse().unwrap()),
            AccessResult::Deny
        ));
        assert!(matches!(
            ac.check(&"192.168.1.1".parse().unwrap()),
            AccessResult::Allow
        ));
    }

    #[test]
    fn test_access_allow_list() {
        let allow = vec![IpNet::new("192.168.0.0".parse().unwrap(), 16)];
        let ac = AccessControl::new(Some(allow), None);
        assert!(matches!(
            ac.check(&"192.168.1.1".parse().unwrap()),
            AccessResult::Allow
        ));
        assert!(matches!(
            ac.check(&"10.0.0.1".parse().unwrap()),
            AccessResult::Restrict
        ));
    }

    #[test]
    fn test_access_deny_overrides_allow() {
        let allow = vec![IpNet::new("10.0.0.0".parse().unwrap(), 8)];
        let deny = vec![IpNet::new("10.0.0.1".parse().unwrap(), 32)];
        let ac = AccessControl::new(Some(allow), Some(deny));
        // 10.0.0.1 is in both — deny wins.
        assert!(matches!(
            ac.check(&"10.0.0.1".parse().unwrap()),
            AccessResult::Deny
        ));
        // 10.0.0.2 is in allow but not deny — allowed.
        assert!(matches!(
            ac.check(&"10.0.0.2".parse().unwrap()),
            AccessResult::Allow
        ));
    }
}
