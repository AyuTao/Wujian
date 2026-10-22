//! Read-only Windows/Linux route and IPv6 inspection, separate from mutation.
use crate::models::CheckResult;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::platform::output;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use serde_json::Value;

pub(crate) fn route(first: Option<(&str, bool)>, second: Option<(&str, bool)>) -> CheckResult {
    let (status, value) = match (first, second) {
        (Some((a, true)), Some((b, true))) if a == b => {
            ("match", format!("两个采样目标经隧道接口 · {a}"))
        }
        (Some((a, _)), Some((b, _))) if a == b => (
            "observed",
            format!("两个采样目标经接口 · {a}（未验证为隧道）"),
        ),
        (Some((a, _)), Some((b, _))) => ("review", format!("检测到分流 · {a} / {b}")),
        _ => ("unknown", "未完整取得两个目标的路由".into()),
    };
    CheckResult::local(
        "network-route",
        "采样路由",
        status,
        value,
        "只读取 1.1.1.1 和 8.8.8.8 的当前选路，不据此推断代理全局模式或全部应用路径。",
    )
}
pub(crate) fn ipv6(disabled: Option<bool>, public_address: bool) -> CheckResult {
    let (status, value) = match (disabled, public_address) {
        (_, true) => ("review", "检测到公网 IPv6 地址"),
        (Some(true), false) => ("match", "当前活动物理接口的 IPv6 已停用"),
        (Some(false), false) => ("review", "IPv6 仍允许配置；无地址不代表已关闭"),
        (None, false) => ("unknown", "IPv6 配置读取不完整"),
    };
    CheckResult::local(
        "ipv6-policy",
        "IPv6 状态",
        status,
        value,
        "接口配置与本工具的防火墙 IPv6 阻断分别核验；不会用连接失败代替关闭证明。",
    )
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn public_v6(value: &str) -> bool {
    value
        .parse::<std::net::Ipv6Addr>()
        .is_ok_and(|ip| ip.segments()[0] & 0xe000 == 0x2000)
}

pub(crate) async fn inspect() -> (Vec<CheckResult>, String) {
    #[cfg(target_os = "linux")]
    {
        let mut routes = Vec::new();
        for target in ["1.1.1.1", "8.8.8.8"] {
            let text = output("ip", &["-j", "route", "get", target]).await;
            let v = text.and_then(|s| serde_json::from_str::<Value>(&s).ok());
            routes.push(
                v.as_ref()
                    .and_then(|v| v[0]["dev"].as_str())
                    .map(|s| s.to_string()),
            );
        }
        let is_tun = |s: &str| {
            std::path::Path::new("/sys/class/net")
                .join(s)
                .join("tun_flags")
                .exists()
                || s.starts_with("wg")
                || s.starts_with("tailscale")
        };
        let r = route(
            routes[0].as_deref().map(|s| (s, is_tun(s))),
            routes[1].as_deref().map(|s| (s, is_tun(s))),
        );
        let addresses = output("ip", &["-j", "-6", "addr", "show"])
            .await
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        let public = addresses
            .as_ref()
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter().any(|v| {
                    v["addr_info"].as_array().is_some_and(|a| {
                        a.iter().any(|v| v["local"].as_str().is_some_and(public_v6))
                    })
                })
            });
        let modes: Vec<_> = std::fs::read_dir("/sys/class/net")
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("device").exists())
            .map(|e| {
                let name = e.file_name();
                std::fs::read_to_string(
                    std::path::Path::new("/proc/sys/net/ipv6/conf")
                        .join(name)
                        .join("disable_ipv6"),
                )
                .ok()
                .map(|s| s.trim() == "1")
            })
            .collect();
        let disabled =
            (!modes.is_empty() && modes.iter().all(Option::is_some) && addresses.is_some())
                .then(|| modes.iter().all(|v| *v == Some(true)));
        let v6 = ipv6(disabled, public);
        return (
            vec![r.clone(), v6.clone()],
            format!("{}|{}|{}|{}", r.status, r.value, v6.status, v6.value),
        );
    }
    #[cfg(target_os = "windows")]
    {
        let script = r#"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
          $routes=@('1.1.1.1','8.8.8.8' | ForEach-Object {
            $r=Find-NetRoute -RemoteIPAddress $_ -ErrorAction Stop | Where-Object {$_.InterfaceIndex} | Select-Object -First 1;
            $a=Get-NetAdapter -ErrorAction Stop | Where-Object {$_.ifIndex -eq $r.InterfaceIndex} | Select-Object -First 1;
            if (-not $a) { throw 'Route adapter unavailable' };
            @{name=$a.Name; tunnel=([bool]($a.InterfaceDescription -match 'Wintun|WireGuard|TAP|Mihomo|Clash|VPN'))}
          });
          $bindings=@(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object {$_.Enabled});
          $addresses=@(Get-NetIPAddress -AddressFamily IPv6 | ForEach-Object {$_.IPAddress});
          @{routes=$routes; bindings=$bindings; addresses=$addresses} | ConvertTo-Json -Depth 5 -Compress"#;
        let value = output(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        )
        .await
        .and_then(|s| serde_json::from_str::<Value>(s.trim_start_matches('\u{feff}')).ok());
        if let Some(value) = value {
            let pair = |n: usize| {
                value["routes"][n]["name"]
                    .as_str()
                    .map(|s| (s, value["routes"][n]["tunnel"].as_bool() == Some(true)))
            };
            let r = route(pair(0), pair(1));
            let disabled = value["bindings"]
                .as_array()
                .filter(|a| !a.is_empty() && a.iter().all(Value::is_boolean))
                .map(|a| a.iter().all(|v| v.as_bool() == Some(false)));
            let public = value["addresses"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str().is_some_and(public_v6)));
            let v6 = ipv6(disabled, public);
            return (
                vec![r.clone(), v6.clone()],
                format!("{}|{}|{}|{}", r.status, r.value, v6.status, v6.value),
            );
        }
    }
    (
        vec![route(None, None), ipv6(None, false)],
        "network-inspection-unavailable".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_split_and_unverified_virtual_routes_never_match() {
        for r in [
            route(None, None),
            route(Some(("tun0", true)), Some(("eth0", false))),
            route(Some(("bridge0", false)), Some(("bridge0", false))),
        ] {
            assert_ne!(r.status, "match");
        }
        assert_eq!(
            route(Some(("tun0", true)), Some(("tun0", true))).status,
            "match"
        );
        assert_eq!(ipv6(None, false).status, "unknown");
        assert_ne!(ipv6(Some(false), false).status, "match");
        assert_ne!(ipv6(Some(true), true).status, "match");
    }
}
