//! Read-only, bounded inspection of the current user's Mihomo controller.
use crate::models::CheckResult;
use serde_json::Value;

pub(crate) fn config_check(value: &Value) -> CheckResult {
    let mode = value["mode"].as_str().unwrap_or("unknown");
    let tun = value["tun"]["enable"].as_bool() == Some(true);
    let (status, display) = match (mode, tun) {
        ("global", true) => ("match", "全局模式 · TUN 已开启"),
        ("global", false) => ("deviation", "请开启 TUN"),
        ("rule", true) => ("observed", "请开启全局模式"),
        ("rule" | "direct", false) => ("deviation", "请开启全局模式和 TUN"),
        ("direct", true) => ("deviation", "请开启全局模式"),
        _ => ("unknown", "代理模式无法确认"),
    };
    CheckResult::local("proxy-mode", "代理运行模式", status, display,
        "运行模式只表示客户端配置。规则模式不等于泄漏，全局模式不保证 DNS 安全；请结合实际路由和浏览器检测核对。")
        .suggest("在代理客户端核对当前模式、TUN 和 DNS，再重新检测；本工具不会代替客户端切换模式。")
}

pub(crate) fn install_check(found: bool) -> CheckResult {
    if found {
        CheckResult::local(
            "clash-verge-app",
            "客户端",
            "match",
            "Clash Verge 已安装",
            "只确认本机有这个应用，不提供下载。",
        )
    } else {
        CheckResult::local(
            "clash-verge-app",
            "客户端",
            "unknown",
            "未发现 Clash Verge",
            "只确认本机有没有这个应用，不提供下载。",
        )
    }
}

pub(crate) fn clash_verge_candidates(
    home: &std::path::Path,
    local_app_data: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let local = local_app_data.unwrap_or(std::path::Path::new(r"C:\Users\Default\AppData\Local"));
    vec![
        "/Applications/Clash Verge.app/Contents/MacOS/clash-verge".into(),
        home.join("Applications/Clash Verge.app/Contents/MacOS/clash-verge"),
        "/usr/bin/clash-verge".into(),
        "/usr/bin/clash-verge-rev".into(),
        r"C:\Program Files\Clash Verge\clash-verge.exe".into(),
        local
            .join("Programs")
            .join("Clash Verge")
            .join("clash-verge.exe"),
    ]
}

pub(crate) fn clash_verge_present(home: &std::path::Path) -> bool {
    let local = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
    clash_verge_candidates(home, local.as_deref())
        .into_iter()
        .any(|path| path.is_file())
}

pub(crate) async fn inspect(route_tun_ok: bool) -> CheckResult {
    let _ = route_tun_ok;
    let uid = if cfg!(target_os = "windows") {
        Some(1)
    } else {
        crate::platform::output("/usr/bin/id", &["-u"])
            .await
            .and_then(|text| text.trim().parse::<u32>().ok())
            .filter(|uid| *uid > 0)
    };
    if let Some(uid) = uid {
        if let Ok(value) = crate::firewall::tunnel::read_controller(uid, "configs").await {
            return config_check(&value);
        }
    }
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

    #[test]
    fn install_check_names_clash_verge_without_a_download() {
        let present = install_check(true);
        let absent = install_check(false);
        assert_eq!(present.value, "Clash Verge 已安装");
        assert_eq!(present.status, "match");
        assert_eq!(absent.value, "未发现 Clash Verge");
        assert!(!present.detail.contains("http"));
        assert!(present.suggestion.is_none());
    }

    #[test]
    fn install_paths_cover_three_desktops_without_a_download() {
        let paths = clash_verge_candidates(
            std::path::Path::new("/tmp/wujian-home"),
            Some(std::path::Path::new(r"C:\Users\me\AppData\Local")),
        );
        let text = paths
            .iter()
            .map(|path| path.display().to_string().replace('\\', "/"))
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "/Applications/Clash Verge.app/Contents/MacOS/clash-verge",
            "wujian-home/Applications/Clash Verge.app/Contents/MacOS/clash-verge",
            "/usr/bin/clash-verge",
            "/usr/bin/clash-verge-rev",
        ] {
            assert!(text.contains(expected), "missing {expected}");
        }
        assert!(text.contains("clash-verge.exe"));
        assert!(text.contains("Program Files"));
        assert!(paths.iter().any(|path| {
            path.ends_with("clash-verge.exe")
                && path.components().any(|part| part.as_os_str() == "Programs")
                && path
                    .components()
                    .any(|part| part.as_os_str() == "Clash Verge")
        }));
        assert!(!text.contains("http"));
        assert!(!text.contains("github"));
    }
}
