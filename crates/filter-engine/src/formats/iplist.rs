//! IP / CIDR / range lists and the matcher for them.
//!
//! CIDR ranges cannot be written as hostname rules, so they are kept as an [`IpSet`] that the
//! shared engine consults for requests whose host is an IP literal.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{ConvertOptions, Converted, ListMeta, Out};

/// An inclusive range of addresses of one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

impl IpRange {
    pub fn single(ip: IpAddr) -> Self {
        Self { start: ip, end: ip }
    }

    pub fn cidr(ip: IpAddr, prefix: u8) -> Option<Self> {
        match ip {
            IpAddr::V4(a) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let s = u32::from(a) & mask;
                Some(Self {
                    start: IpAddr::V4(Ipv4Addr::from(s)),
                    end: IpAddr::V4(Ipv4Addr::from(s | !mask)),
                })
            }
            IpAddr::V6(a) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let s = u128::from(a) & mask;
                Some(Self {
                    start: IpAddr::V6(Ipv6Addr::from(s)),
                    end: IpAddr::V6(Ipv6Addr::from(s | !mask)),
                })
            }
            _ => None,
        }
    }

    /// Parse `1.2.3.4`, `1.2.3.0/24`, `::1/128` or `1.2.3.4-1.2.3.9`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if let Some((a, p)) = s.split_once('/') {
            return Self::cidr(IpAddr::from_str(a).ok()?, p.parse().ok()?);
        }
        if let Some((a, b)) = s.split_once('-') {
            let (a, b) = (
                IpAddr::from_str(a.trim()).ok()?,
                IpAddr::from_str(b.trim()).ok()?,
            );
            return (a.is_ipv4() == b.is_ipv4() && key(a) <= key(b))
                .then_some(Self { start: a, end: b });
        }
        Some(Self::single(IpAddr::from_str(s).ok()?))
    }
}

fn key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u32::from(a) as u128,
        IpAddr::V6(a) => u128::from(a),
    }
}

/// Merged, sorted ranges for fast membership tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy + Into<u128>>(
    mut v: Vec<(T, T)>,
    max: T,
    one: impl Fn(T) -> T,
) -> Vec<(T, T)> {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        if let Some(last) = out.last_mut() {
            if last.1 == max || s <= one(last.1) {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        out.push((s, e));
    }
    out
}

impl IpSet {
    pub fn from_ranges<'a>(ranges: impl IntoIterator<Item = &'a IpRange>) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for r in ranges {
            match (r.start, r.end) {
                (IpAddr::V4(a), IpAddr::V4(b)) => v4.push((u32::from(a), u32::from(b))),
                (IpAddr::V6(a), IpAddr::V6(b)) => v6.push((u128::from(a), u128::from(b))),
                _ => {}
            }
        }
        Self {
            v4: merge(v4, u32::MAX, |x| x + 1),
            v6: merge(v6, u128::MAX, |x| x + 1),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// The merged ranges (for persistence).
    pub fn ranges(&self) -> Vec<IpRange> {
        let v4 = self.v4.iter().map(|(a, b)| IpRange {
            start: IpAddr::V4(Ipv4Addr::from(*a)),
            end: IpAddr::V4(Ipv4Addr::from(*b)),
        });
        let v6 = self.v6.iter().map(|(a, b)| IpRange {
            start: IpAddr::V6(Ipv6Addr::from(*a)),
            end: IpAddr::V6(Ipv6Addr::from(*b)),
        });
        v4.chain(v6).collect()
    }

    /// Number of merged ranges.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // IPv4-mapped IPv6 addresses are matched as IPv4.
        let ip = match ip {
            IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
            v4 => v4,
        };
        match ip {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                let i = self.v4.partition_point(|r| r.0 <= x);
                i > 0 && self.v4[i - 1].1 >= x
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                let i = self.v6.partition_point(|r| r.0 <= x);
                i > 0 && self.v6[i - 1].1 >= x
            }
        }
    }
}

fn strip_comment(line: &str) -> &str {
    let end = line.find(['#', ';']).unwrap_or(line.len());
    line[..end].trim()
}

fn tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| c.is_whitespace() || c == ',' || c == '\t')
        .filter(|t| !t.is_empty())
}

/// Parse the first entry of a line, treating two leading addresses as a `start end` range
/// (DShield) and the first CSV field as the entry (MaxMind).
fn parse_line(line: &str) -> Option<IpRange> {
    let line = strip_comment(line);
    let mut t = tokens(line);
    let first = t.next()?;
    let r = IpRange::parse(first)?;
    if !first.contains(['/', '-']) {
        if let Some(second) = t.next() {
            if let Ok(b) = IpAddr::from_str(second) {
                if b.is_ipv4() == r.start.is_ipv4() && key(b) >= key(r.start) {
                    return Some(IpRange {
                        start: r.start,
                        end: b,
                    });
                }
            }
        }
    }
    Some(r)
}

pub(crate) fn parses_as_ip_entry(line: &str) -> bool {
    parse_line(line).is_some()
}

pub(crate) fn convert_ip_list(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        match parse_line(line) {
            Some(r) => out.ip(r, false),
            None if i == 0 || line.starts_with("network") => out.stats.skip("header"),
            None => out.stats.error(i + 1, "not an IP, CIDR or range"),
        }
    }
    out.finish(ListMeta::default())
}
