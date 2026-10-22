//! Read-only, bounded inspection of the current user's Mihomo controller.
use crate::models::CheckResult;
use serde_json::Value;

pub(crate) fn config_check(value: &Value) -> CheckResult {
    let mode = value["mode"].as_str().unwrap_or("unknown");
    let tun = value["tun"]["enable"].as_bool() == Some(true);
    let (status, display) = match (mode, tun) {
        ("global", true) => ("match", "全局模式 · TUN 已开启"),
        ("global", false) => ("deviation", "全局模式 · 请在客户端开启 TUN 虚拟网卡"),
        ("rule", true) => ("observed", "规则模式 · TUN 已开启（需核对分流规则）"),
        ("rule", false) => ("deviation", "规则模式 · TUN 未确认开启"),
        ("direct", _) => ("deviation", "直连模式"),
        _ => ("unknown", "代理模式无法确认"),
    };
    CheckResult::local("proxy-mode", "代理运行模式", status, display,
        "运行模式只表示客户端配置。规则模式不等于泄漏，全局模式不保证 DNS 安全；请结合实际路由和浏览器检测核对。")
        .suggest("在代理客户端核对当前模式、TUN 和 DNS，再重新检测；本工具不会代替客户端切换模式。")
}

pub(crate) async fn inspect(route_tun_ok: bool) -> CheckResult {
    #[cfg(target_os = "macos")]
    {
        // 尝试读取本机当前用户的 Clash Verge / Mihomo 控制器
        if let Some(uid) = crate::platform::output("/usr/bin/id", &["-u"]).await {
            let uid = uid.trim();
            if !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()) {
                let socket = format!("/var/run/clash-verge-service/users/{uid}/verge-mihomo.sock");
                if std::path::Path::new(&socket).exists() {
                    if let Some(body) = crate::platform::output(
                        "/usr/bin/curl",
                        &[
                            "--silent",
                            "--show-error",
                            "--fail",
                            "--max-time",
                            "2",
                            "--unix-socket",
                            &socket,
                            "http://localhost/configs",
                        ],
                    )
                    .await
                    {
                        if let Ok(value) = serde_json::from_str::<Value>(&body) {
                            return config_check(&value);
                        }
                    }
                }
            }
        }
    }

    let _ = route_tun_ok;
    config_check(&Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_global_and_tun_match() {
        for v in [
            serde_json::json!({"mode":"rule","tun":{"enable":true}}),
            serde_json::json!({"mode":"direct","tun":{"enable":true}}),
            serde_json::json!({"mode":"global"}),
            Value::Null,
        ] {
            assert_ne!(config_check(&v).status, "match");
        }
        assert_eq!(
            config_check(&serde_json::json!({"mode":"global","tun":{"enable":true}})).status,
            "match"
        );
    }
}
