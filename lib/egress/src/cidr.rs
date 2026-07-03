//! CIDR-block matching for IP-address egress rules.

use std::net::IpAddr;

use ipnet::IpNet;

/// A set of CIDR blocks, matched by linear containment test. Rule lists
/// here are small (per-tenant/per-run egress allow/deny lists), so a
/// trie/interval-tree isn't warranted.
#[derive(Debug, Default, Clone)]
pub struct CidrSet {
    nets: Vec<IpNet>,
}

impl CidrSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, net: IpNet) {
        self.nets.push(net);
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_an_address_inside_the_block() {
        let mut set = CidrSet::new();
        set.insert("10.0.0.0/8".parse().unwrap());
        assert!(set.matches("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn does_not_match_an_address_outside_the_block() {
        let mut set = CidrSet::new();
        set.insert("10.0.0.0/8".parse().unwrap());
        assert!(!set.matches("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn matches_across_multiple_blocks() {
        let mut set = CidrSet::new();
        set.insert("10.0.0.0/8".parse().unwrap());
        set.insert("192.168.0.0/16".parse().unwrap());
        assert!(set.matches("192.168.1.1".parse().unwrap()));
        assert!(!set.matches("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn matches_ipv6_blocks() {
        let mut set = CidrSet::new();
        set.insert("2001:db8::/32".parse().unwrap());
        assert!(set.matches("2001:db8::1".parse().unwrap()));
        assert!(!set.matches("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = CidrSet::new();
        assert!(!set.matches("10.0.0.1".parse().unwrap()));
    }
}
