use super::cidr::{complement, Cidr};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const LOCAL4: &[&str] = &[
    "0.0.0.0/32",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15", // RFC 2544 / Clash / Surge / Sing-box TUN Fake-IP
    "224.0.0.0/24",
    "255.255.255.255/32",
    // 常用权威公共 DNS，确保域名解析绝不断死
    "8.8.8.8/32",
    "8.8.4.4/32",
    "1.1.1.1/32",
    "1.0.0.1/32",
    "114.114.114.114/32",
    "223.5.5.5/32",
];
pub const LOCAL6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10", "ff02::/16"];
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    #[serde(default)]
    pub lockdown: bool,
    #[serde(default)]
    pub ipv6_only: bool,
    pub version: u32,
    pub generation: String,
    pub cn_networks: Vec<String>,
    #[serde(default)]
    pub extra_allowed: Vec<String>,
}
impl Policy {
    pub fn isolation() -> Self {
        Self {
            ipv6_only: false,
            lockdown: true,
            version: 1,
            generation: uuid::Uuid::new_v4().simple().to_string(),
            cn_networks: vec![],
            extra_allowed: vec![],
        }
    }
    pub fn ipv6_block() -> Self {
        Self {
            lockdown: false,
            ipv6_only: true,
            version: 1,
            generation: uuid::Uuid::new_v4().simple().to_string(),
            cn_networks: vec![],
            extra_allowed: vec![],
        }
    }
    pub fn from_database(path: &Path) -> Result<Self, String> {
        let networks = crate::geo::CountryDb::open(path)?.china_networks()?;
        let cn_networks = networks.into_iter().filter(|v| !v.contains(':')).collect();
        let result = Self {
            lockdown: false,
            ipv6_only: false,
            version: 1,
            generation: uuid::Uuid::new_v4().simple().to_string(),
            cn_networks,
            extra_allowed: vec![],
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.generation.len() != 32
            || !self.generation.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("规则版本或代次无效".into());
        }
        if self.lockdown || self.ipv6_only {
            if self.lockdown && self.ipv6_only {
                return Err("规则模式冲突".into());
            }
            return if self.cn_networks.is_empty() && self.extra_allowed.is_empty() {
                Ok(())
            } else {
                Err("整机隔离策略不能包含额外放行地址".into())
            };
        }
        if self.cn_networks.is_empty() || self.cn_networks.len() > 100_000 {
            return Err("CN IPv4 网段为空或超过限制".into());
        }
        for text in &self.cn_networks {
            let cidr = Cidr::parse(text)?;
            if !cidr.address.is_ipv4() || cidr.prefix < 8 {
                return Err("CN IPv4 网段格式无效或过宽".into());
            }
        }
        for text in &self.extra_allowed {
            let cidr = Cidr::parse(text)?;
            if !cidr.address.is_ipv4() {
                return Err("额外放行网段格式无效".into());
            }
        }
        Ok(())
    }
    pub fn allowed4(&self) -> Vec<Cidr> {
        if self.ipv6_only {
            return vec![Cidr::parse("0.0.0.0/0").unwrap()];
        }
        if self.lockdown {
            return vec![Cidr::parse("127.0.0.0/8").unwrap()];
        }
        self.cn_networks
            .iter()
            .map(String::as_str)
            .chain(self.extra_allowed.iter().map(String::as_str))
            .chain(LOCAL4.iter().copied())
            .map(|v| Cidr::parse(v).expect("validated policy"))
            .collect()
    }
    pub fn allowed6(&self) -> Vec<Cidr> {
        if self.lockdown || self.ipv6_only {
            return vec![Cidr::parse("::1/128").unwrap()];
        }
        LOCAL6
            .iter()
            .map(|v| Cidr::parse(v).expect("static CIDR"))
            .collect()
    }
    pub fn denied(&self) -> Vec<Cidr> {
        let mut result = complement(&self.allowed4(), true);
        result.extend(complement(&self.allowed6(), false));
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    pub fn fixture() -> Policy {
        Policy {
            lockdown: false,
            ipv6_only: false,
            version: 1,
            generation: "a".repeat(32),
            cn_networks: vec!["223.5.5.0/24".into()],
            extra_allowed: vec![],
        }
    }
    #[test]
    fn policy_is_closed_to_unknown_public_and_public_ipv6() {
        let p = fixture();
        p.validate().unwrap();
        let blocked = p.denied();
        for ip in ["9.9.9.9", "160.79.104.1", "2001:4860::1", "2400::1"] {
            let ip = ip.parse().unwrap();
            assert!(blocked.iter().any(|c| c.contains(ip)));
        }
        for ip in [
            "223.5.5.5",
            "127.0.0.1",
            "100.100.100.100",
            "192.168.1.2",
            "198.18.0.1",
            "8.8.8.8",
            "fd7a:115c:a1e0::53",
            "fe80::1",
        ] {
            let ip = ip.parse().unwrap();
            assert!(!blocked.iter().any(|c| c.contains(ip)));
        }
    }
    #[test]
    fn untrusted_generation_or_cidrs_cannot_inject_commands() {
        let mut p = fixture();
        p.generation = "x\";Remove-NetFirewallRule".into();
        assert!(p.validate().is_err());
        p = fixture();
        p.cn_networks = vec!["0.0.0.0/0".into()];
        assert!(p.validate().is_err());
        p.cn_networks = vec!["223.5.5.0/24\npass all".into()];
        assert!(p.validate().is_err());
    }
    #[test]
    fn isolation_has_no_dns_or_lan_bypass_and_ipv6_mode_keeps_ipv4() {
        let isolation = Policy::isolation();
        isolation.validate().unwrap();
        let blocked = isolation.denied();
        for value in [
            "1.1.1.1",
            "8.8.8.8",
            "223.5.5.5",
            "192.168.1.1",
            "fd00::1",
            "2001:db8::1",
        ] {
            assert!(blocked.iter().any(|n| n.contains(value.parse().unwrap())));
        }
        for value in ["127.0.0.1", "::1"] {
            assert!(!blocked.iter().any(|n| n.contains(value.parse().unwrap())));
        }
        let ipv6 = Policy::ipv6_block();
        ipv6.validate().unwrap();
        assert!(!ipv6
            .denied()
            .iter()
            .any(|n| n.contains("203.0.113.1".parse().unwrap())));
        assert!(ipv6
            .denied()
            .iter()
            .any(|n| n.contains("2001:db8::1".parse().unwrap())));
    }
}
