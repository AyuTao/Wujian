use super::cidr::{complement, Cidr};
use super::policy::Policy;
use super::tunnel::TunnelGuard;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
pub const PF_ANCHOR: &str = "com.apple/000.io.wujian";
pub const NFT_TABLE: &str = "wujian_guard";
pub const WINDOWS_GROUP: &str = "Wujian.Firewall";
pub const OWNER: &str = "io.wujian.firewall.v1";

/// One Windows Firewall rule. Block rules win over allow rules, so the TUN is
/// omitted from InterfaceAlias instead of being allow-listed. Node addresses are
/// outside the broad block; extra block rules then close every other port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelRule {
    pub suffix: String,
    pub direction: &'static str,
    pub addresses: Vec<Cidr>,
    pub protocol: &'static str,
    pub ports: Vec<String>,
}

pub fn tunnel_exempt(guard: &TunnelGuard) -> Vec<Cidr> {
    let mut allow = vec![
        Cidr::parse("127.0.0.0/8").expect("loopback"),
        Cidr::parse("10.0.0.0/8").expect("lan"),
        Cidr::parse("172.16.0.0/12").expect("lan"),
        Cidr::parse("192.168.0.0/16").expect("lan"),
        Cidr::parse("255.255.255.255/32").expect("dhcp"),
        Cidr::parse("::1/128").expect("loopback6"),
    ];
    for ip in endpoint_ips(guard) {
        allow.push(Cidr::parse(&format!("{ip}/32")).expect("endpoint"));
    }
    allow
}

pub fn tunnel_blocked(guard: &TunnelGuard) -> Vec<Cidr> {
    let exempt = tunnel_exempt(guard);
    let mut result = complement(&exempt, true);
    result.extend(complement(&exempt, false));
    result
}

pub fn tunnel_plan(guard: &TunnelGuard) -> Vec<TunnelRule> {
    let mut rules = Vec::new();
    for (index, chunk) in tunnel_blocked(guard).chunks(128).enumerate() {
        for direction in ["Inbound", "Outbound"] {
            rules.push(TunnelRule {
                suffix: format!("phys-{direction}-{index}"),
                direction,
                addresses: chunk.to_vec(),
                protocol: "Any",
                ports: vec![],
            });
        }
    }
    for (index, (ip, (tcp, udp))) in allowed_ports(guard).into_iter().enumerate() {
        let address = vec![Cidr::parse(&format!("{ip}/32")).expect("endpoint")];
        for (protocol, ports) in [("TCP", tcp), ("UDP", udp)] {
            let ports = if ports.is_empty() {
                Vec::new()
            } else {
                excluded_port_ranges(&ports)
            };
            for direction in ["Inbound", "Outbound"] {
                rules.push(TunnelRule {
                    suffix: format!("svc-{index}-{protocol}-{direction}"),
                    direction,
                    addresses: address.clone(),
                    protocol,
                    ports: ports.clone(),
                });
            }
        }
        for direction in ["Inbound", "Outbound"] {
            rules.push(TunnelRule {
                suffix: format!("svc-{index}-ICMPv4-{direction}"),
                direction,
                addresses: address.clone(),
                protocol: "ICMPv4",
                ports: vec![],
            });
        }
    }
    rules
}

fn endpoint_ips(guard: &TunnelGuard) -> Vec<Ipv4Addr> {
    let mut ips = guard.addresses.clone();
    for pin in &guard.dns_pins {
        ips.extend(pin.addresses.iter().copied());
    }
    ips.sort();
    ips.dedup();
    ips
}

fn allowed_ports(guard: &TunnelGuard) -> BTreeMap<Ipv4Addr, (Vec<u16>, Vec<u16>)> {
    let mut map: BTreeMap<Ipv4Addr, (Vec<u16>, Vec<u16>)> = BTreeMap::new();
    let mut add = |ip: Ipv4Addr, port: u16, protocols: &[String]| {
        let entry = map.entry(ip).or_default();
        for protocol in protocols {
            if protocol == "tcp" {
                entry.0.push(port);
            } else if protocol == "udp" {
                entry.1.push(port);
            }
        }
    };
    for ip in &guard.addresses {
        add(*ip, guard.port, &guard.protocols);
    }
    for pin in &guard.dns_pins {
        for ip in &pin.addresses {
            add(*ip, pin.port, &pin.protocols);
        }
    }
    map
}

fn excluded_port_ranges(ports: &[u16]) -> Vec<String> {
    let mut ports: Vec<u32> = ports
        .iter()
        .copied()
        .map(u32::from)
        .filter(|p| *p > 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    let mut ranges = Vec::new();
    let mut cursor = 1u32;
    for port in ports {
        if port > cursor {
            ranges.push(port_range(cursor, port - 1));
        }
        cursor = port.saturating_add(1);
    }
    if cursor <= 65535 {
        ranges.push(port_range(cursor, 65535));
    }
    ranges
}

fn port_range(start: u32, end: u32) -> String {
    if start == end {
        format!("{start}")
    } else {
        format!("{start}-{end}")
    }
}

fn list(values: impl IntoIterator<Item = impl ToString>) -> String {
    values
        .into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
pub fn pf(policy: &Policy) -> Result<String, String> {
    policy.validate()?;
    if let Some(guard) = &policy.tunnel_guard {
        let generation = &policy.generation;
        let mut result = format!("# {OWNER}; global tunnel guard; all permits are stateless\npass quick on lo0 all no state label \"wj-{generation}-loop\"\npass quick on {} all no state label \"wj-{generation}-tun\"\npass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 no state label \"wj-{generation}-dhcp-out\"\npass in quick inet proto udp from any port 67 to any port 68 no state label \"wj-{generation}-dhcp-in\"\n", guard.interface);
        for (index, ip) in guard.addresses.iter().enumerate() {
            for protocol in &guard.protocols {
                let flags = if protocol == "tcp" { " flags any" } else { "" };
                result.push_str(&format!("pass out quick inet proto {protocol} from any to {ip} port {}{flags} no state label \"wj-{generation}-{index}-{protocol}-out\"\npass in quick inet proto {protocol} from {ip} port {} to any{flags} no state label \"wj-{generation}-{index}-{protocol}-in\"\n", guard.port, guard.port));
            }
        }
        for (pin_index, pin) in guard.dns_pins.iter().enumerate() {
            for (addr_index, ip) in pin.addresses.iter().enumerate() {
                for protocol in &pin.protocols {
                    let flags = if protocol == "tcp" { " flags any" } else { "" };
                    result.push_str(&format!("pass out quick inet proto {protocol} from any to {ip} port {}{flags} no state label \"wj-{generation}-d{pin_index}-{addr_index}-{protocol}-out\"\npass in quick inet proto {protocol} from {ip} port {} to any{flags} no state label \"wj-{generation}-d{pin_index}-{addr_index}-{protocol}-in\"\n", pin.port, pin.port));
                }
            }
        }
        for cidr in super::policy::LAN4 {
            let tag = cidr.split('.').next().unwrap_or("lan");
            result.push_str(&format!("pass out quick inet from any to {cidr} no state label \"wj-{generation}-lan{tag}-out\"\npass in quick inet from {cidr} to any no state label \"wj-{generation}-lan{tag}-in\"\n"));
        }
        result.push_str(&format!("block drop out quick all label \"wj-{generation}-out\"\nblock drop in quick all label \"wj-{generation}-in\"\n"));
        return Ok(result);
    }
    let generation = &policy.generation;
    Ok(format!("# {OWNER}; owned anchor only; no global pass rules\ntable <wj_allow4> const {{ {} }}\ntable <wj_allow6> const {{ {} }}\nblock drop out quick inet to ! <wj_allow4> label \"wj-{generation}-4-out\"\nblock drop in quick inet from ! <wj_allow4> label \"wj-{generation}-4-in\"\nblock drop out quick inet6 to ! <wj_allow6> label \"wj-{generation}-6-out\"\nblock drop in quick inet6 from ! <wj_allow6> label \"wj-{generation}-6-in\"\n", list(policy.allowed4()), list(policy.allowed6())))
}
pub fn nft(policy: &Policy, replace: bool) -> Result<String, String> {
    policy.validate()?;
    if let Some(guard) = &policy.tunnel_guard {
        return nft_tunnel(policy, guard, replace);
    }
    let prefix = if replace {
        format!("delete table inet {NFT_TABLE}\n")
    } else {
        String::new()
    };
    let mut result = format!("{prefix}table inet {NFT_TABLE} {{\n comment \"{OWNER}:{}\"\n set allow4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {} }} }}\n set allow6 {{ type ipv6_addr; flags interval; auto-merge; elements = {{ {} }} }}\n", policy.generation, list(policy.allowed4()), list(policy.allowed6()));
    for (chain, address) in [("output", "daddr"), ("input", "saddr")] {
        result.push_str(&format!(" chain {chain} {{ type filter hook {chain} priority -190; policy accept;\n  ip {address} != @allow4 counter drop\n  ip6 {address} != @allow6 counter drop\n }}\n"));
    }
    result.push_str(" chain forward { type filter hook forward priority -190; policy accept;\n  ip daddr != @allow4 counter drop\n  ip saddr != @allow4 counter drop\n  ip6 daddr != @allow6 counter drop\n  ip6 saddr != @allow6 counter drop\n }\n}\n");
    Ok(result)
}
fn nft_tunnel(policy: &Policy, guard: &TunnelGuard, replace: bool) -> Result<String, String> {
    if !super::tunnel::tun_name(&guard.interface) {
        return Err("TUN 设备名无效".into());
    }
    let prefix = if replace {
        format!("delete table inet {NFT_TABLE}\n")
    } else {
        String::new()
    };
    let iface = &guard.interface;
    let mut result = format!(
        "{prefix}table inet {NFT_TABLE} {{\n comment \"{OWNER}:{}\"\n chain output {{ type filter hook output priority -190; policy accept;\n  oifname \"lo\" accept\n  oifname \"{iface}\" accept\n  udp sport 68 udp dport 67 ip daddr 255.255.255.255 accept\n",
        policy.generation
    );
    for (address, port, protocols) in endpoint_rules(guard) {
        for protocol in protocols {
            result.push_str(&format!(
                "  ip daddr {address} {protocol} dport {port} accept\n"
            ));
        }
    }
    result.push_str(
        "  ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } accept\n  drop\n }\n",
    );
    result.push_str(&format!(
        " chain input {{ type filter hook input priority -190; policy accept;\n  iifname \"lo\" accept\n  iifname \"{iface}\" accept\n  udp sport 67 udp dport 68 accept\n"
    ));
    for (address, port, protocols) in endpoint_rules(guard) {
        for protocol in protocols {
            result.push_str(&format!(
                "  ip saddr {address} {protocol} sport {port} accept\n"
            ));
        }
    }
    result.push_str(
        "  ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } accept\n  drop\n }\n chain forward { type filter hook forward priority -190; policy accept;\n  drop\n }\n}\n",
    );
    Ok(result)
}
fn endpoint_rules(guard: &TunnelGuard) -> Vec<(Ipv4Addr, u16, &[String])> {
    let mut rules = Vec::new();
    rules.push((guard.addresses[0], guard.port, guard.protocols.as_slice()));
    // Every resolved address of the main node uses the same port and protocols.
    for ip in guard.addresses.iter().skip(1) {
        rules.push((*ip, guard.port, guard.protocols.as_slice()));
    }
    for pin in &guard.dns_pins {
        for ip in &pin.addresses {
            rules.push((*ip, pin.port, pin.protocols.as_slice()));
        }
    }
    rules
}
/// All variable strings in this script are validated numeric CIDRs or hex IDs.
/// Windows block rules take precedence: emit the exact complement, never a
/// blanket block with an allow-rule exception.
pub fn windows(policy: &Policy) -> Result<String, String> {
    policy.validate()?;
    if let Some(guard) = &policy.tunnel_guard {
        return windows_tunnel(policy, guard);
    }
    let mut script = windows_header();
    script.push_str("$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)\nif ($profiles.Count -ne 3 -or @($profiles | Where-Object { $_.Enabled -ne 'True' -or $_.AllowLocalFirewallRules -eq 'False' }).Count -gt 0) { throw 'Firewall profiles or local rule merging do not permit protection' }\n");
    let denied = policy.denied();
    let mut names = Vec::new();
    for (index, chunk) in denied.chunks(128).enumerate() {
        let addresses = chunk
            .iter()
            .map(|v| format!("'{v}'"))
            .collect::<Vec<_>>()
            .join(",");
        for direction in ["Inbound", "Outbound"] {
            let name = format!("Wujian-{}-{direction}-{index}", policy.generation);
            names.push(format!("'{name}'"));
            script.push_str(&format!("if (-not (Get-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -DisplayName '{name}' -Group '{WINDOWS_GROUP}' -Description '{OWNER}' -Enabled True -Profile Any -Direction {direction} -Action Block -Protocol Any -RemoteAddress @({addresses}) | Out-Null }}\n"));
        }
    }
    script.push_str(&format!("$expected = @({})\n", names.join(",")));
    script.push_str(&format!("$active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $expected -contains $_.Name -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }})\nif ($active.Count -ne $expected.Count) {{ throw 'Active firewall rules failed readback; restrictions retained' }}\nGet-NetFirewallRule -PolicyStore PersistentStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $expected -notcontains $_.Name -and $_.Description -eq '{OWNER}' }} | Remove-NetFirewallRule\n"));
    script.push_str("Write-Output 'WUJIAN_APPLY_OK'\n");
    Ok(script)
}
fn windows_tunnel(policy: &Policy, guard: &TunnelGuard) -> Result<String, String> {
    if !super::tunnel::tun_name(&guard.interface) {
        return Err("TUN 设备名无效".into());
    }
    let mut script = windows_header();
    script.push_str("$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)\nif ($profiles.Count -ne 3 -or @($profiles | Where-Object { $_.Enabled -ne 'True' -or $_.AllowLocalFirewallRules -eq 'False' }).Count -gt 0) { throw 'Firewall profiles or local rule merging do not permit protection' }\n");
    script.push_str(&format!(
        "$tun = '{}'\nif ($tun -notmatch '^(?:utun[0-9]{{1,5}}|Meta|Mihomo|mihomo|clash|tun0|tun1|tun2)$') {{ throw 'TUN name rejected' }}\n$phys = @(Get-NetAdapter | Where-Object {{ $_.Name -ne $tun }} | ForEach-Object {{ $_.Name }})\nif (@($phys).Count -lt 1) {{ throw 'No physical adapter to restrict' }}\n",
        guard.interface
    ));
    let exempt = quote_cidrs(&tunnel_exempt(guard));
    let blocked = quote_cidrs(&tunnel_blocked(guard));
    script.push_str(&format!(
        "$exempt = @({exempt})\n$block = @({blocked})\nif ($exempt.Count -lt 1 -or $block.Count -lt 1) {{ throw 'Address plan empty' }}\n"
    ));
    let mut names = Vec::new();
    for rule in tunnel_plan(guard) {
        let name = format!("Wujian-{}-{}", policy.generation, rule.suffix);
        names.push(format!("'{name}'"));
        let addresses = quote_cidrs(&rule.addresses);
        let ports = if rule.ports.is_empty() {
            String::new()
        } else {
            format!(
                " -RemotePort @({})",
                rule.ports
                    .iter()
                    .map(|port| format!("'{port}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        script.push_str(&format!(
            "if (-not (Get-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -DisplayName '{name}' -Group '{WINDOWS_GROUP}' -Description '{OWNER}' -Enabled True -Profile Any -Direction {direction} -Action Block -Protocol {protocol}{ports} -InterfaceAlias $phys -RemoteAddress @({addresses}) | Out-Null }}\n",
            direction = rule.direction,
            protocol = rule.protocol,
        ));
    }
    script.push_str(&format!("$expected = @({})\n", names.join(",")));
    script.push_str(&format!("$active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $expected -contains $_.Name -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }})\nif ($active.Count -ne $expected.Count) {{ throw 'Active firewall rules failed readback; restrictions retained' }}\nGet-NetFirewallRule -PolicyStore PersistentStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $expected -notcontains $_.Name -and $_.Description -eq '{OWNER}' }} | Remove-NetFirewallRule\n"));
    script.push_str("Write-Output 'WUJIAN_APPLY_OK'\n");
    Ok(script)
}
fn quote_cidrs(cidrs: &[Cidr]) -> String {
    cidrs
        .iter()
        .map(|cidr| format!("'{cidr}'"))
        .collect::<Vec<_>>()
        .join(",")
}
pub fn windows_header() -> String {
    "$ErrorActionPreference = 'Stop'\n[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n".into()
}
pub fn windows_remove() -> String {
    format!("{}Get-NetFirewallRule -PolicyStore PersistentStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $_.Description -eq '{OWNER}' }} | Remove-NetFirewallRule\nWrite-Output 'WUJIAN_REMOVE_OK'\n", windows_header())
}
pub fn windows_status() -> String {
    format!("{}$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Sort-Object Name | ForEach-Object {{ @{{name=[string]$_.Name;enabled=[string]$_.Enabled;localRules=[string]$_.AllowLocalFirewallRules}} }})\n$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {{ $port = $_ | Get-NetFirewallPortFilter; @{{name=$_.Name;description=$_.Description;enabled=[string]$_.Enabled;action=[string]$_.Action;direction=[string]$_.Direction;protocol=[string]$port.Protocol;addresses=@($_ | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress | Sort-Object);interfaces=@($_ | Get-NetFirewallInterfaceFilter | Select-Object -ExpandProperty InterfaceAlias | Sort-Object);ports=@($port.RemotePort)}} }})\n$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {{ [string]$_.Name }})\n@{{profiles=$profiles;rules=$rules;adapters=$adapters}} | ConvertTo-Json -Depth 6 -Compress\n", windows_header())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn global_tunnel_guard_has_no_fallback_or_state_bypass() {
        let mut p = Policy::isolation();
        p.lockdown = false;
        p.tunnel_guard = Some(super::super::tunnel::fixture());
        let text = pf(&p).unwrap();
        assert!(text.contains("pass quick on utun6 all no state"));
        assert!(text.contains("to 9.9.9.9 port 443 flags any no state"));
        assert!(text.contains("from 9.9.9.9 port 443 to any flags any no state"));
        assert!(text.contains("to 192.168.0.0/16 no state"));
        assert!(text.contains("from 10.0.0.0/8 to any no state"));
        assert!(text.contains("to 172.16.0.0/12 no state"));
        let lan_at = text.find("to 192.168.0.0/16").unwrap();
        let block_at = text.find("block drop out quick all").unwrap();
        assert!(lan_at < block_at);
        assert!(text.contains("block drop out quick all"));
        assert!(text.contains("block drop in quick all"));
        assert!(text
            .lines()
            .filter(|s| s.starts_with("pass "))
            .all(|s| s.contains("no state")));
        for forbidden in [
            "keep state",
            "user ",
            "utun+",
            "8.8.8.8",
            "1.1.1.1",
            "223.5.5.5",
            "198.18.",
            "100.64.",
            "<cn",
        ] {
            assert!(
                !text.contains(forbidden),
                "unexpected exception {forbidden}"
            );
        }
        let nft_text = nft(&p, false).unwrap();
        assert!(nft_text.contains("oifname \"utun6\" accept"));
        assert!(nft_text.contains("iifname \"lo\" accept"));
        assert!(nft_text.contains("ip daddr 9.9.9.9 tcp dport 443 accept"));
        assert!(nft_text.contains("ip saddr 9.9.9.9 tcp sport 443 accept"));
        assert!(nft_text.contains("10.0.0.0/8"));
        assert!(nft_text.contains("172.16.0.0/12"));
        assert!(nft_text.contains("192.168.0.0/16"));
        assert!(nft_text.contains("\n  drop\n"));
        assert!(nft_text.contains("hook forward"));
        assert!(nft_text.find("ip daddr 9.9.9.9").unwrap() < nft_text.find("\n  drop\n").unwrap());
        for forbidden in [
            "8.8.8.8",
            "1.1.1.1",
            "223.5.5.5",
            "198.18.",
            "100.64.",
            "ct state",
            "flush ruleset",
        ] {
            assert!(!nft_text.contains(forbidden), "nft leaked {forbidden}");
        }
        let win = windows(&p).unwrap();
        assert!(win.contains("$tun = 'utun6'"));
        assert!(win.contains("Get-NetAdapter"));
        assert!(win.contains("Where-Object"));
        assert!(win.contains("-InterfaceAlias $phys"));
        assert!(win.contains("-Action Block"));
        assert!(!win.contains("-Action Allow"));
        assert!(
            win.find("New-NetFirewallRule").unwrap() < win.find("Remove-NetFirewallRule").unwrap()
        );
        let exempt = win.split("$block").next().unwrap();
        assert!(exempt.contains("'9.9.9.9/32'"));
        assert!(exempt.contains("'10.0.0.0/8'"));
        assert!(exempt.contains("'192.168.0.0/16'"));
        assert!(exempt.contains("'::1/128'"));
        for forbidden in ["8.8.8.8", "1.1.1.1", "223.5.5.5", "198.18.", "100.64."] {
            assert!(
                !exempt.contains(forbidden),
                "windows exempt leaked {forbidden}"
            );
        }
        let broad = win
            .split("$block")
            .nth(1)
            .unwrap()
            .split("New-NetFirewallRule")
            .next()
            .unwrap();
        assert!(!broad.contains("'9.9.9.9/32'"));
        assert!(win.contains("-Protocol TCP"));
        assert!(win.contains("'1-442'"));
        assert!(win.contains("'444-65535'"));
        assert!(win.contains("-Protocol UDP"));
        assert!(win.contains("-Protocol ICMPv4"));
        let blocked = tunnel_blocked(p.tunnel_guard.as_ref().unwrap());
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "223.5.5.5",
            "198.18.0.1",
            "100.64.0.1",
        ] {
            let ip = ip.parse().unwrap();
            assert!(
                blocked.iter().any(|cidr| cidr.contains(ip)),
                "{ip} must be blocked"
            );
        }
        for ip in ["9.9.9.9", "192.168.10.1", "10.1.1.1", "127.0.0.1"] {
            let ip = ip.parse().unwrap();
            assert!(
                !blocked.iter().any(|cidr| cidr.contains(ip)),
                "{ip} must stay reachable"
            );
        }
        let mut pinned = super::super::tunnel::fixture();
        pinned.dns_pins.push(super::super::tunnel::PinnedEndpoint {
            server: "203.0.113.9".into(),
            port: 8443,
            protocols: vec!["tcp".into()],
            addresses: vec!["203.0.113.9".parse().unwrap()],
        });
        p.tunnel_guard = Some(pinned);
        let pinned_text = pf(&p).unwrap();
        assert!(pinned_text.contains("to 203.0.113.9 port 8443 flags any no state"));
        assert!(pinned_text.contains("wj-"));
        assert!(pinned_text.contains("-d0-0-tcp-out"));
        assert!(!pinned_text.contains("8.8.8.8"));
        assert!(!pinned_text.contains("1.1.1.1"));
        let block_at = pinned_text.find("block drop out quick all").unwrap();
        let pin_at = pinned_text.find("to 203.0.113.9 port 8443").unwrap();
        assert!(pin_at < block_at);
        let pinned_nft = nft(&p, true).unwrap();
        assert!(pinned_nft.starts_with("delete table inet wujian_guard\n"));
        assert!(pinned_nft.contains("ip daddr 203.0.113.9 tcp dport 8443 accept"));
        assert!(!pinned_nft.contains("flush ruleset"));
        let pinned_win = windows(&p).unwrap();
        let pinned_exempt = pinned_win.split("$block").next().unwrap();
        assert!(pinned_exempt.contains("'203.0.113.9/32'"));
        assert!(!pinned_win
            .split("$block")
            .nth(1)
            .unwrap()
            .split("New-NetFirewallRule")
            .next()
            .unwrap()
            .contains("'203.0.113.9/32'"));
        p.cn_networks.push("223.5.5.0/24".into());
        assert!(pf(&p).is_err());
    }
    fn policy() -> Policy {
        Policy {
            tunnel_guard: None,
            lockdown: false,
            ipv6_only: false,
            version: 1,
            generation: "b".repeat(32),
            cn_networks: vec!["223.5.5.0/24".into()],
            extra_allowed: vec![],
        }
    }
    #[test]
    fn pf_does_not_bypass_other_firewalls_or_scope_to_tcp() {
        let text = pf(&policy()).unwrap();
        assert_eq!(
            text.lines().filter(|v| v.starts_with("block drop")).count(),
            4
        );
        assert!(!text.lines().any(|v| v.starts_with("pass ")));
        assert!(!text.contains("proto tcp"));
        assert!(!text.contains("set skip"));
    }
    #[test]
    fn nft_replaces_only_owned_table_atomically_and_checks_existing_flows() {
        let text = nft(&policy(), true).unwrap();
        assert!(text.starts_with("delete table inet wujian_guard\n"));
        assert!(!text.contains("flush ruleset"));
        assert!(!text.contains("ct state established accept"));
        assert!(text.contains("hook output"));
        assert!(text.contains("hook input"));
        assert!(text.contains("hook forward"));
    }
    #[test]
    fn windows_uses_complement_and_creates_before_removing_old_rules() {
        let text = windows(&policy()).unwrap();
        assert!(!text.contains("-Action Allow"));
        assert!(!text.contains("'223.5.5.0/24'"));
        assert!(
            text.find("New-NetFirewallRule").unwrap()
                < text.find("Remove-NetFirewallRule").unwrap()
        );
        assert!(text.contains("-Direction Inbound"));
        assert!(text.contains("-Direction Outbound"));
        assert!(!windows_remove().contains("Reset"));
    }
}
