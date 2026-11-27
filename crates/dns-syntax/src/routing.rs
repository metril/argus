//! Which names are "private": LAN names and reverse zones that belong to a local resolver.

use std::net::IpAddr;

const PRIVATE_TLDS: &[&str] = &[
    "lan",
    "local",
    "localdomain",
    "home.arpa",
    "internal",
    "intranet",
    "home",
    "corp",
    "private",
];

/// LAN suffixes (RFC 6762, RFC 8375 and common router defaults), single-label names, and the
/// reverse zones of RFC 1918, CGNAT, loopback, link-local and ULA addresses.
pub fn is_private_name(name: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || !n.contains('.') {
        return true;
    }
    if PRIVATE_TLDS
        .iter()
        .any(|t| n == *t || n.ends_with(&format!(".{t}")))
    {
        return true;
    }
    reverse_ip(&n).is_some_and(is_private_ip)
}

/// The address an `in-addr.arpa` / `ip6.arpa` name stands for. A partial zone (`10.in-addr.arpa`)
/// is padded with zeros, so it is judged by its leading part.
pub fn reverse_ip(n: &str) -> Option<IpAddr> {
    if let Some(p) = n.strip_suffix(".in-addr.arpa") {
        let o: Vec<u8> = p
            .split('.')
            .map(|x| x.parse().ok())
            .collect::<Option<_>>()?;
        if o.is_empty() || o.len() > 4 {
            return None;
        }
        let mut v = [0u8; 4];
        for (i, x) in o.iter().rev().enumerate() {
            v[i] = *x;
        }
        return Some(IpAddr::from(v));
    }
    if let Some(p) = n.strip_suffix(".ip6.arpa") {
        let nib: Vec<&str> = p.split('.').collect();
        if nib.is_empty() || nib.len() > 32 || nib.iter().any(|x| x.len() != 1) {
            return None;
        }
        let mut s: Vec<char> = nib
            .iter()
            .rev()
            .map(|x| x.chars().next().unwrap())
            .collect();
        while s.len() < 32 {
            s.push('0');
        }
        let seg: Vec<String> = s.chunks(4).map(|c| c.iter().collect()).collect();
        return seg.join(":").parse().ok();
    }
    None
}

/// Whether `ip` is loopback, link-local, ULA, RFC 1918 or CGNAT.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The `in-addr.arpa` / `ip6.arpa` name of `ip`.
pub fn private_reverse_zone(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => {
            let mut s = String::new();
            for b in v.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}
