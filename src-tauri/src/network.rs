//! Read-only macOS route and IPv6 configuration inspection.
use crate::{models::CheckResult, platform::output};
use serde_json::Value;
use std::net::{IpAddr, Ipv6Addr};

pub(crate) fn dns_check(servers: &[String]) -> CheckResult {
    let mut labels = Vec::new();
    let mut details = Vec::new();
    for server in servers {
        let label = match server.as_str() {
            "100.100.100.100" | "fd7a:115c:a1e0::53" => "Tailscale DNS",
            _ => match server
                .split('%')
                .next()
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                Some(ip) if ip.is_loopback() => "本机 DNS",
                Some(IpAddr::V4(ip)) if ip.is_private() => "内网 DNS",
                Some(IpAddr::V6(ip)) if ip.is_unique_local() || ip.is_unicast_link_local() => {
                    "内网 DNS"
                }
                _ => "其他 DNS",
            },
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
        details.push(format!("{label}：{server}"));
    }
    let mut check = CheckResult::local(
        "dns-config", "系统 DNS", if servers.is_empty() { "unknown" } else { "observed" },
        if servers.is_empty() { "未取得 DNS 配置".into() } else { labels.join("、") },
        format!("{}。这些是本机配置的解析入口，不是泄露结论。Tailscale 的 IPv4/IPv6 DNS 地址本身不表示公网 IPv6 已开启或 DNS 泄露；是否走了错误上游需结合实际解析检测。", details.join("；")),
    );
    check.scope = "本机 DNS 配置识别".into();
    check
}

pub(crate) fn route_interface(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(str::trim)
            .filter(|s| !s.is_empty())
    })
}
fn tunnel(name: &str) -> bool {
    matches!(name, "Meta" | "Mihomo" | "mihomo" | "clash")
        || ["utun", "tun", "tap"].iter().any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|tail| !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()))
        })
}
fn route_check(first: Option<&str>, second: Option<&str>) -> CheckResult {
    let a = first.and_then(route_interface);
    let b = second.and_then(route_interface);
    let value = match (a, b) {
        (Some(a), Some(b)) if a == b && tunnel(a) => format!("公网采样路由经 TUN · {a}"),
        (Some(a), Some(b)) if a == b => format!("公网采样路由经 {a}"),
        (Some(a), Some(b)) => format!("检测到分流 · {a} / {b}"),
        _ => "公网采样路由未完整读到".into(),
    };
    let mut result = CheckResult::local("network-route", "国外网站访问路径", if a == b && a.is_some_and(tunnel) { "match" } else if a.is_some() && b.is_some() { "observed" } else { "unknown" }, value,
        format!("本机查询 1.1.1.1 → {}、8.8.8.8 → {}，只查询路由、不发送网络请求。TUN 可能通过更具体的路由接管公网流量，所以不能只检查 default。这里只说明这两个地址的选路，不把 Tailscale/其他 utun 接口的存在当作全局接管，也不据此推断出口国家。",a.unwrap_or("未确认"),b.unwrap_or("未确认")));
    result.scope = "两个固定公网地址的本机路由".into();
    result
}

fn interfaces(text: &str) -> Vec<(&str, bool, bool, Vec<Ipv6Addr>)> {
    let mut result: Vec<(&str, bool, bool, Vec<Ipv6Addr>)> = Vec::new();
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            if let Some((name, _)) = line.split_once(':') {
                result.push((name, false, false, vec![]));
            }
        } else if let Some((_, active, internet_v4, addresses)) = result.last_mut() {
            if line.trim() == "status: active" {
                *active = true;
            }
            if let Some(value) = line.trim().strip_prefix("inet ") {
                *internet_v4 = value
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                    .is_some_and(|ip| {
                        !ip.is_link_local() && !ip.is_loopback() && !ip.is_unspecified()
                    });
            }
            if let Some(value) = line.trim().strip_prefix("inet6 ") {
                if let Some(ip) = value
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.split('%').next())
                    .and_then(|s| s.parse().ok())
                {
                    addresses.push(ip);
                }
            }
        }
    }
    for (_, _, _, addresses) in &mut result {
        addresses.sort();
    }
    result
}
fn public_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xe000 == 0x2000
}

fn ipv6_check(
    ifconfig: Option<&str>,
    services: Option<&Value>,
    route: Option<&str>,
) -> CheckResult {
    let mut check = CheckResult::local(
        "ipv6-policy",
        "电脑 IPv6 状态",
        "unknown",
        "未完整取得 IPv6 设置",
        "需要读取活动网卡的 IPv6 设置、接口地址和公网 IPv6 路由；读取失败不等于已经关闭。",
    );
    check.scope = "当前活动网卡与公网 IPv6 配置；不修改设置".into();
    let (Some(text), Some(services), Some(route)) =
        (ifconfig, services.and_then(Value::as_object), route)
    else {
        return check;
    };
    let records = interfaces(text);
    let public_count = records
        .iter()
        .flat_map(|(_, _, _, ips)| ips)
        .filter(|ip| public_v6(ip))
        .count();
    let has_public_route = route_interface(route).is_some();
    let route_absent = route.contains("not in table")
        || route.contains("Network is unreachable")
        || route.contains("not found");
    let active: Vec<_> = records
        .iter()
        .filter(|(name, up, v4, ips)| {
            *up && (*v4 || ips.iter().any(public_v6)) && !tunnel(name) && name.starts_with("en")
        })
        .collect();
    let mut modes = vec![];
    for (name, _, _, _) in &active {
        let is_inactive = services
            .values()
            .find(|v| v["Interface"]["DeviceName"].as_str() == Some(*name))
            .and_then(|v| v["IPv6"]["__INACTIVE__"].as_bool())
            .unwrap_or(false);

        let raw_mode = services
            .values()
            .find(|v| v["Interface"]["DeviceName"].as_str() == Some(*name))
            .and_then(|v| v["IPv6"]["ConfigMethod"].as_str());

        let mode = if is_inactive { Some("Off") } else { raw_mode };
        modes.push((*name, mode));
    }
    if public_count > 0 || has_public_route {
        check.status = "review".into();
        check.value = "检测到公网 IPv6 地址或路由".into();
        check.detail = format!("当前有 {public_count} 个公网 IPv6 地址；公网 IPv6 采样路由：{}。Tailscale 内网地址及 fe80 链路本地地址不计为公网 IPv6。", route_interface(route).unwrap_or("未发现"));
        check.suggestion = Some("若你的使用策略要求停用公网 IPv6，请在当前联网网卡设置关闭 IPv6 或选择仅本地，然后重新检测。".into());
    } else if !modes.is_empty()
        && modes
            .iter()
            .all(|(_, mode)| matches!(mode, Some("LinkLocal" | "Off")))
        && route_absent
    {
        check.status = "match".into();
        check.value = "公网 IPv6 已停用（关闭或仅本地）".into();
        check.detail = "当前活动联网网卡均设为关闭或仅本地；未发现公网 IPv6 地址和该公网目标的 IPv6 路由。Tailscale 内网 IPv6 与链路本地地址可保留。网络切换后会重新检查。".into();
    } else if modes
        .iter()
        .any(|(_, mode)| matches!(mode, Some("Automatic" | "Manual")))
    {
        check.status = "review".into();
        check.value = "IPv6 仍为自动或手动模式".into();
        check.detail =
            "当前未发现公网 IPv6 地址，但活动网卡仍允许配置 IPv6；没有地址不等于已经关闭。".into();
        check.suggestion =
            Some("按你的要求，将当前联网网卡的 IPv6 设为关闭或仅本地，再重新检查。".into());
    }
    check
}

pub(crate) struct MacInspection {
    pub checks: Vec<CheckResult>,
    pub route_summary: String,
    pub signature: String,
}
pub(crate) async fn inspect_macos() -> MacInspection {
    let (first, second, ipv6, ifconfig, services) = tokio::join!(
        output("/sbin/route", &["-n", "get", "1.1.1.1"]),
        output("/sbin/route", &["-n", "get", "8.8.8.8"]),
        output(
            "/sbin/route",
            &["-n", "get", "-inet6", "2001:4860:4860::8888"]
        ),
        output("/sbin/ifconfig", &["-a"]),
        output(
            "/usr/bin/plutil",
            &[
                "-extract",
                "NetworkServices",
                "json",
                "-o",
                "-",
                "/Library/Preferences/SystemConfiguration/preferences.plist"
            ]
        )
    );
    // Counters/lifetimes change without a network change: do not hash raw ifconfig.
    let interface_signature = ifconfig
        .as_deref()
        .map(|text| format!("{:?}", interfaces(text)))
        .unwrap_or_default();
    let route_signature = |value: &Option<String>| {
        value.as_deref().map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| {
                    ["destination:", "mask:", "gateway:", "interface:"]
                        .iter()
                        .any(|key| line.starts_with(key))
                        || line.contains("not in table")
                        || line.contains("Network is unreachable")
                })
                .collect::<Vec<_>>()
                .join("|")
        })
    };
    let service_json = services
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    let services_signature = service_json
        .as_ref()
        .and_then(Value::as_object)
        .map(|obj| {
            let mut entries: Vec<String> = obj
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}:{}:{}:{}",
                        v["Interface"]["DeviceName"].as_str().unwrap_or(k),
                        v["IPv4"]["ConfigMethod"].as_str().unwrap_or(""),
                        v["IPv6"]["ConfigMethod"].as_str().unwrap_or(""),
                        v["IPv6"]["__INACTIVE__"].as_bool().unwrap_or(false),
                        v["DNS"]["ServerAddresses"]
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0),
                    )
                })
                .collect();
            entries.sort();
            entries.join("|")
        })
        .unwrap_or_default();
    let signature = format!(
        "{:?}{:?}{:?}{interface_signature}{services_signature}",
        route_signature(&first),
        route_signature(&second),
        route_signature(&ipv6)
    );
    let route = route_check(first.as_deref(), second.as_deref());
    let v6 = ipv6_check(ifconfig.as_deref(), service_json.as_ref(), ipv6.as_deref());
    MacInspection {
        route_summary: route.value.clone(),
        checks: vec![route, v6],
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tailscale_dns_is_information_not_a_leak() {
        let c = dns_check(&[
            "100.100.100.100".into(),
            "fd7a:115c:a1e0::53".into(),
            "127.0.0.1".into(),
        ]);
        assert_eq!(c.status, "observed");
        assert_eq!(c.value, "Tailscale DNS、本机 DNS");
        assert_eq!(dns_check(&[]).status, "unknown");
    }
    #[test]
    fn specific_routes_detect_tun_split_routes_and_read_failure() {
        let a = "route to: 1.1.1.1\n interface: utun6\n";
        assert!(route_check(Some(a), Some(a)).value.contains("经 TUN"));
        let named = "interface: Mihomo";
        assert!(route_check(Some(named), Some(named))
            .value
            .contains("经 TUN"));
        let ethernet = "interface: Ethernet";
        assert!(!route_check(Some(ethernet), Some(ethernet))
            .value
            .contains("经 TUN"));
        assert!(route_check(Some(a), Some("interface: en0"))
            .value
            .contains("分流"));
        assert_eq!(route_check(None, Some(a)).status, "unknown");
        assert_eq!(
            route_interface("route: writing to routing socket: not in table"),
            None
        );
    }
    fn services(mode: &str) -> Value {
        serde_json::json!({"service":{"Interface":{"DeviceName":"en0"},"IPv6":{"ConfigMethod":mode}}})
    }
    #[test]
    fn link_local_mode_and_tailscale_ula_do_not_trigger_public_ipv6_warning() {
        let config="en0: flags=8863<UP>\n\tinet 192.0.2.2 netmask 0xffffff00\n\tinet6 fe80::1%en0 prefixlen 64\n\tstatus: active\nutun8: flags=8051<UP>\n\tinet6 fd7a:115c:a1e0::12 prefixlen 48\n";
        assert_eq!(
            ipv6_check(
                Some(config),
                Some(&services("LinkLocal")),
                Some("route: not in table")
            )
            .status,
            "match"
        );
        assert_eq!(
            ipv6_check(
                Some(config),
                Some(&services("Automatic")),
                Some("route: not in table")
            )
            .status,
            "review"
        );
    }
    #[test]
    fn macos_inactive_flag_is_treated_as_off() {
        let config = "en0: flags=8863<UP>\n\tinet 192.0.2.2 netmask 0xffffff00\n\tstatus: active\n";
        let svc = serde_json::json!({
            "service": {
                "Interface": {"DeviceName": "en0"},
                "IPv6": {"__INACTIVE__": true, "ConfigMethod": "Automatic"}
            }
        });
        assert_eq!(
            ipv6_check(Some(config), Some(&svc), Some("route: not in table")).status,
            "match"
        );
    }
    #[test]
    fn auxiliary_link_local_only_adapter_does_not_require_internet_ipv6_configuration() {
        let config = "en0: flags=UP\n\tinet 192.0.2.2 netmask 0xffffff00\n\tstatus: active\nen11: flags=UP\n\tinet 169.254.1.1 netmask 0xffff0000\n\tstatus: active\n";
        assert_eq!(
            ipv6_check(
                Some(config),
                Some(&services("LinkLocal")),
                Some("not in table")
            )
            .status,
            "match"
        );
    }
    #[test]
    fn public_ipv6_or_route_requires_attention_even_if_link_local_configured() {
        let config = "en0: flags=8863<UP>\n\tinet 192.0.2.2 netmask 0xffffff00\n\tstatus: active\n\tinet6 2400:cb00::1 prefixlen 64\n";
        assert_eq!(
            ipv6_check(
                Some(config),
                Some(&services("LinkLocal")),
                Some("route: not in table")
            )
            .status,
            "review"
        );
        assert_eq!(
            ipv6_check(
                Some(config),
                Some(&services("LinkLocal")),
                Some("interface: utun6")
            )
            .status,
            "review"
        );
    }
    #[test]
    fn missing_or_ambiguous_ipv6_data_never_means_disabled() {
        assert_eq!(
            ipv6_check(
                None,
                Some(&services("LinkLocal")),
                Some("route: not in table")
            )
            .status,
            "unknown"
        );
        assert_eq!(
            ipv6_check(
                Some("en0: flags=UP\n\tinet 192.0.2.2 netmask 0xffffff00\n\tstatus: active\n"),
                Some(&services("LinkLocal")),
                Some("permission denied")
            )
            .status,
            "unknown"
        );
        assert_eq!(
            ipv6_check(
                Some("en0: flags=UP\n"),
                Some(&services("LinkLocal")),
                Some("not in table")
            )
            .status,
            "unknown"
        );
    }
}
