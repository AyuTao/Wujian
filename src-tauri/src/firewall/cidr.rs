use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cidr {
    pub address: IpAddr,
    pub prefix: u8,
}
impl Cidr {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (address, prefix) = text.split_once('/').ok_or("CIDR 缺少前缀")?;
        let address: IpAddr = address.parse().map_err(|_| "CIDR 地址无效")?;
        let prefix: u8 = prefix.parse().map_err(|_| "CIDR 前缀无效")?;
        let bits = if address.is_ipv4() { 32 } else { 128 };
        if prefix > bits {
            return Err("CIDR 前缀越界".into());
        }
        let result = Self { address, prefix };
        if result.start() != result.numeric() {
            return Err("CIDR 含非零主机位".into());
        }
        Ok(result)
    }
    fn numeric(self) -> u128 {
        match self.address {
            IpAddr::V4(v) => u32::from(v) as u128,
            IpAddr::V6(v) => u128::from(v),
        }
    }
    pub fn start(self) -> u128 {
        self.numeric() & mask(self.prefix, self.bits())
    }
    pub fn end(self) -> u128 {
        self.start() | (full(self.bits()) ^ mask(self.prefix, self.bits()))
    }
    fn bits(self) -> u8 {
        if self.address.is_ipv4() {
            32
        } else {
            128
        }
    }
    pub fn contains(self, ip: IpAddr) -> bool {
        self.address.is_ipv4() == ip.is_ipv4()
            && Self {
                address: ip,
                prefix: self.prefix,
            }
            .start()
                == self.start()
    }
}
impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}
fn full(bits: u8) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}
fn mask(prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        full(bits) << (bits - prefix) & full(bits)
    }
}
fn from_range(mut start: u128, end: u128, bits: u8, out: &mut Vec<Cidr>) {
    loop {
        let alignment = start.trailing_zeros().min(bits as u32) as u8;
        let mut power = alignment;
        while power > 0 && start.saturating_add(full(power)) > end {
            power -= 1;
        }
        let address = if bits == 32 {
            IpAddr::V4((start as u32).into())
        } else {
            IpAddr::V6(start.into())
        };
        out.push(Cidr {
            address,
            prefix: bits - power,
        });
        let last = start | full(power);
        if last >= end {
            break;
        }
        start = last + 1;
    }
}
/// Minimal exact CIDR cover of the complement. No /0 allow/block precedence
/// tricks: Windows block rules must never overlap our allowed address sets.
pub fn complement(allowed: &[Cidr], ipv4: bool) -> Vec<Cidr> {
    let bits = if ipv4 { 32 } else { 128 };
    let mut ranges: Vec<_> = allowed
        .iter()
        .filter(|v| v.address.is_ipv4() == ipv4)
        .map(|v| (v.start(), v.end()))
        .collect();
    ranges.sort_unstable();
    let mut cursor = 0;
    let mut result = Vec::new();
    for (start, end) in ranges {
        if end < cursor {
            continue;
        }
        if start > cursor {
            from_range(cursor, start - 1, bits, &mut result);
        }
        if end == full(bits) {
            return result;
        }
        cursor = cursor.max(end + 1);
    }
    from_range(cursor, full(bits), bits, &mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_bad_or_noncanonical_input() {
        for value in [
            "1.2.3.4/24",
            "0.0.0.0/33",
            "::/129",
            "1.2.3.4;pass/32",
            "::1/64",
        ] {
            assert!(Cidr::parse(value).is_err(), "{value}");
        }
    }
    #[test]
    fn complement_is_exact_with_overlap_and_endpoints() {
        let allowed: Vec<_> = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "10.2.0.0/16",
            "255.255.255.255/32",
        ]
        .into_iter()
        .map(|v| Cidr::parse(v).unwrap())
        .collect();
        let denied = complement(&allowed, true);
        // Deterministic addresses exercise interval joins and alignment.
        let mut value = 11u32;
        for _ in 0..20000 {
            value = value.wrapping_mul(1664525).wrapping_add(1013904223);
            let ip = IpAddr::V4(value.into());
            assert_ne!(
                allowed.iter().any(|c| c.contains(ip)),
                denied.iter().any(|c| c.contains(ip))
            );
        }
        for value in [0u32, 0x00ffffff, 0x01000000, 0x0affffff, 0xffffffff] {
            let ip = IpAddr::V4(value.into());
            assert_ne!(
                allowed.iter().any(|c| c.contains(ip)),
                denied.iter().any(|c| c.contains(ip))
            );
        }
    }
    #[test]
    fn ipv6_extremes_do_not_overflow_or_leave_gaps() {
        assert_eq!(complement(&[], false), vec![Cidr::parse("::/0").unwrap()]);
        assert!(complement(&[Cidr::parse("::/0").unwrap()], false).is_empty());
        let allowed = [
            Cidr::parse("::1/128").unwrap(),
            Cidr::parse("fc00::/7").unwrap(),
        ];
        let denied = complement(&allowed, false);
        for ip in [
            "::",
            "::1",
            "fc00::",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe00::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            let ip = ip.parse().unwrap();
            assert_ne!(
                allowed.iter().any(|c| c.contains(ip)),
                denied.iter().any(|c| c.contains(ip))
            );
        }
    }
}
