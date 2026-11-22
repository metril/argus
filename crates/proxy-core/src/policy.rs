//! Destination policy (what the proxy may connect to) and client access control (who may use it).
//!
//! The classifier, [`DestPolicy`] and the guarded DNS resolver live in `common::net_policy`
//! (shared with the control plane); this module re-exports them and adds the client ACL.

use crate::{Error, Result};
use ipnet::IpNet;
use std::net::IpAddr;

pub use common::net_policy::{
    canonical, classify, is_refusal, Class, GuardedResolver as PolicyResolver, NetPolicy as DestPolicy,
    PolicyRefused, Refusal, ResolveError,
};

impl From<ResolveError> for Error {
    fn from(e: ResolveError) -> Self {
        match e {
            ResolveError::Refused(r) => Error::DestinationRefused(r.to_string()),
            ResolveError::NoAddresses(h) => Error::Connection(format!("no addresses for {h}")),
            ResolveError::Io(e) => Error::Io(e),
        }
    }
}

fn parse_nets(entries: &[String]) -> Result<Vec<IpNet>> {
    common::net_policy::parse_nets(entries).map_err(|e| Error::Config(e.to_string()))
}

/// Precomputed client ACL: one linear scan over integer prefixes, no locks, no allocation.
#[derive(Debug, Clone, Default)]
pub struct ClientAcl {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl ClientAcl {
    pub fn new(entries: &[String]) -> Result<Self> {
        let mut acl = Self::default();
        for net in parse_nets(entries)? {
            match net {
                IpNet::V4(n) => acl
                    .v4
                    .push((u32::from(n.network()), u32::from(n.netmask()))),
                IpNet::V6(n) => acl
                    .v6
                    .push((u128::from(n.network()), u128::from(n.netmask()))),
            }
        }
        Ok(acl)
    }

    /// Whether a client at `ip` may use the proxy.
    pub fn allows(&self, ip: IpAddr) -> bool {
        match canonical_client(ip) {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4.iter().any(|(net, mask)| a & mask == *net)
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6.iter().any(|(net, mask)| a & mask == *net)
            }
        }
    }
}

/// Client addresses only fold the IPv4-mapped form (dual-stack sockets).
fn canonical_client(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Whether a dial error is a policy refusal.
pub fn is_refused_error(e: &Error) -> bool {
    matches!(e, Error::DestinationRefused(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn client_acl_matching() {
        let acl = ClientAcl::new(&crate::config::default_allowed_clients()).unwrap();
        for a in [
            "127.0.0.1",
            "::1",
            "10.2.3.4",
            "172.20.0.9",
            "192.168.50.2",
            "100.100.1.1",
            "169.254.3.3",
            "fd12::1",
            "fe80::abcd",
            "::ffff:192.168.1.5",
        ] {
            assert!(acl.allows(ip(a)), "{a}");
        }
        for a in ["8.8.8.8", "172.32.0.1", "2606:4700::1", "::ffff:8.8.8.8"] {
            assert!(!acl.allows(ip(a)), "{a}");
        }
        assert!(!ClientAcl::new(&[]).unwrap().allows(ip("127.0.0.1")));
        let only = ClientAcl::new(&strs(&["203.0.113.0/24", "198.51.100.7"])).unwrap();
        assert!(only.allows(ip("203.0.113.200")));
        assert!(only.allows(ip("198.51.100.7")));
        assert!(!only.allows(ip("198.51.100.8")));
        assert!(ClientAcl::new(&strs(&["bogus"])).is_err());
    }
}
