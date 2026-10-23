use crate::models::{CheckResult, ToolInfo};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

pub struct NetworkInfo {
    pub dns_servers: Vec<String>,
    pub proxy_summary: String,
    pub checks: Vec<CheckResult>,
    pub fingerprint: u64,
    pub app_proxy_present: bool,
    pub proxy_readable: bool,
}
pub(crate) async fn run_cmd_checked(program: &str, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(args).kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(5), command.output()).await {
        Ok(Ok(out)) => {
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let code = out.status.code().unwrap_or(-1);
                Err(format!("命令 {program} 执行失败 (退出码 {code}): {err}"))
            }
        }
        Ok(Err(e)) => Err(format!("无法启动命令 {program}: {e}")),
        Err(_) => Err(format!("命令 {program} 执行超时 (超过 5 秒)")),
    }
}

pub(crate) async fn output(program: &str, args: &[&str]) -> Option<String> {
    let mut command = Command::new(program);
    command.args(args).kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(4), command.output()).await {
        Ok(Ok(out)) if out.status.success() && out.stdout.len() < 262_144 => {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            // macOS route can report "not in table" on stderr with exit code 0.
            if text.trim().is_empty() && program == "/sbin/route" && out.stderr.len() < 262_144 {
                let error = String::from_utf8_lossy(&out.stderr);
                if error.contains("not in table") || error.contains("Network is unreachable") {
                    return Some(error.into_owned());
                }
            }
            Some(text)
        }
        _ => None,
    }
}
fn parse_nameservers(text: &str) -> Vec<String> {
    let mut result = vec![];
    for line in text.lines() {
        let line = line.trim();
        let candidate = if line.starts_with("nameserver[") {
            line.split_once(':').map(|(_, value)| value.trim())
        } else {
            line.strip_prefix("nameserver ").map(str::trim)
        };
        if let Some(value) = candidate {
            let value = value.split_whitespace().next().unwrap_or("");
            let ip_part = value.split('%').next().unwrap_or(value);
            if ip_part.parse::<std::net::IpAddr>().is_ok() && !result.iter().any(|v| v == value) {
                result.push(value.to_string());
            }
        }
    }
    result
}
// Keep resolver scopes and options, excluding transient reachability/counter fields.
fn normalized_dns(text: &str) -> String {
    let mut blocks = vec![];
    let mut block = vec![];
    for line in text.lines().map(str::trim) {
        if line.starts_with("resolver #") || line.starts_with("DNS configuration") {
            if !block.is_empty() {
                blocks.push(block.join("\n"));
                block.clear();
            }
        } else if !line.is_empty() && !line.starts_with('#') && !line.starts_with("reach ") {
            block.push(line);
        }
    }
    if !block.is_empty() {
        blocks.push(block.join("\n"));
    }
    blocks.sort();
    blocks.join("\n--\n")
}
fn dns_policy_check(servers: &[String], configuration: Option<&str>) -> CheckResult {
    let value = configuration
        .filter(|s| !s.is_empty())
        .filter(|_| !servers.is_empty());
    let fingerprint = value.map(|s| {
        let mut hash = DefaultHasher::new();
        s.hash(&mut hash);
        format!("{:016x}", hash.finish())
    });
    CheckResult::local("dns-policy", "DNS 配置基线", if fingerprint.is_some() { "observed" } else { "unknown" },
        fingerprint.unwrap_or_else(|| "未完整读取解析配置".into()),
        "只锁定可读取的系统解析器、作用域及解析文件，不代表代理内部上游或应用自有 DoH 已核验；不会修改 DNS。")
}

fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}
fn executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        path.extension().is_some_and(|ext| {
            ext.eq_ignore_ascii_case("exe")
                || ext.eq_ignore_ascii_case("cmd")
                || ext.eq_ignore_ascii_case("bat")
        })
    }
}
pub fn validate_tool_path(raw: &str) -> Result<(PathBuf, bool), String> {
    if raw.len() > 4096 || raw.chars().any(char::is_control) {
        return Err("路径包含无效字符或过长".into());
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err("请提供完整绝对路径".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| "未找到该路径，请检查文件是否存在".to_string())?;
    let desktop = cfg!(target_os = "macos")
        && canonical.is_dir()
        && canonical.extension().is_some_and(|ext| ext == "app");
    if !desktop && !executable(&canonical) {
        return Err("此路径不是可执行文件或受支持的桌面应用".into());
    }
    Ok((canonical, desktop))
}
fn find_cli(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect())
        .unwrap_or_default();
    for path in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        dirs.push(path.into());
    }
    if let Some(home) = home() {
        for suffix in [
            ".local/bin",
            ".npm-global/bin",
            ".volta/bin",
            ".cargo/bin",
            "AppData/Roaming/npm",
        ] {
            dirs.push(home.join(suffix));
        }
        if let Ok(entries) = std::fs::read_dir(home.join(".nvm/versions/node")) {
            for entry in entries.flatten().take(20) {
                dirs.push(entry.path().join("bin"));
            }
        }
    }
    for dir in dirs {
        if cfg!(windows) {
            for ext in ["exe", "cmd", "bat"] {
                let path = dir.join(format!("{name}.{ext}"));
                if executable(&path) {
                    if let Ok(path) = path.canonicalize() {
                        return Some(path);
                    }
                }
            }
        } else {
            let path = dir.join(name);
            if executable(&path) {
                if let Ok(path) = path.canonicalize() {
                    return Some(path);
                }
            }
        }
    }
    None
}
fn tool(id: &str, name: &str, path: Option<PathBuf>, desktop: bool) -> ToolInfo {
    let installed = path.is_some();
    ToolInfo {
        id: id.into(),
        name: name.into(),
        kind: if desktop { "desktop" } else { "cli" }.into(),
        installed,
        path: path.map(|v| v.to_string_lossy().into_owned()),
        // Launch requires verified system protection, which is not available yet.
        can_launch: false,
        protection: "unsupported".into(),
        note: "系统级保护尚未实现；未开放受保护启动，其他入口仍不受本软件限制。".into(),
    }
}
pub fn discover(custom: &[ToolInfo]) -> Vec<ToolInfo> {
    let claude_app = [
        Some(PathBuf::from("/Applications/Claude.app")),
        home().map(|p| p.join("Applications/Claude.app")),
    ]
    .into_iter()
    .flatten()
    .find(|p| cfg!(target_os = "macos") && p.is_dir());
    let mut tools = vec![
        tool("claude-code", "Claude Code", find_cli("claude"), false),
        tool("codex-cli", "Codex CLI", find_cli("codex"), false),
        tool("claude-desktop", "Claude", claude_app, true),
    ];
    for custom_tool in custom {
        let mut item = custom_tool.clone();
        item.installed = item
            .path
            .as_ref()
            .is_some_and(|path| validate_tool_path(path).is_ok());
        // Never trust a persisted/UI-supplied launch or protection state.
        item.can_launch = false;
        item.protection = "unsupported".into();
        item.note = "系统级保护尚未实现；未开放受保护启动，其他入口仍不受本软件限制。".into();
        if let Some(index) = tools.iter().position(|t| t.id == item.id) {
            tools[index] = item;
        } else {
            tools.push(item);
        }
    }
    tools
}
pub fn new_tool(raw: &str) -> Result<ToolInfo, String> {
    let (path, desktop) = validate_tool_path(raw)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("手动添加工具");
    let (id, name) = match stem.to_ascii_lowercase().as_str() {
        "claude" if !desktop => ("claude-code".to_string(), "Claude Code".to_string()),
        "codex" => ("codex-cli".into(), "Codex CLI".into()),
        "claude" if desktop => ("claude-desktop".into(), "Claude".into()),
        _ => (
            format!("custom-{}", uuid::Uuid::new_v4()),
            stem.chars().take(80).collect(),
        ),
    };
    Ok(tool(&id, &name, Some(path), desktop))
}

fn evidence_fingerprint(signature: &str, checks: &[CheckResult]) -> u64 {
    // Observation times and command timing are not network configuration.
    let mut evidence: Vec<_> = checks
        .iter()
        .filter(|c| c.id != "proxy-mode")
        .map(|c| (&c.id, &c.status, &c.value))
        .collect();
    evidence.sort_unstable();
    let mut hasher = DefaultHasher::new();
    signature.hash(&mut hasher);
    evidence.hash(&mut hasher);
    hasher.finish()
}

pub async fn inspect() -> NetworkInfo {
    let env_proxy = [
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
    ]
    .iter()
    .any(|key| std::env::var(key).is_ok_and(|v| !v.trim().is_empty()));
    let mut dns_servers = vec![];
    let mut signature = String::new();
    let mut dns_configuration = None;
    let mut app_proxy_present = env_proxy;
    let mut proxy_readable = true;
    let mut checks = vec![];
    let mut route_summary = None;
    if cfg!(target_os = "macos") {
        let (dns, proxy, network) = tokio::join!(
            output("/usr/sbin/scutil", &["--dns"]),
            output("/usr/sbin/scutil", &["--proxy"]),
            crate::network::inspect_macos()
        );
        signature.push_str(&network.signature);
        route_summary = Some(network.route_summary);
        checks.extend(network.checks);
        if let Some(text) = dns {
            dns_servers = parse_nameservers(&text);
            signature.push_str(&dns_servers.join(","));
            dns_configuration = Some(normalized_dns(&text));
        }
        if let Some(text) = proxy {
            app_proxy_present |= text.lines().any(|line| {
                let line = line.trim();
                [
                    "HTTPEnable",
                    "HTTPSEnable",
                    "SOCKSEnable",
                    "ProxyAutoConfigEnable",
                    "ProxyAutoDiscoveryEnable",
                ]
                .iter()
                .any(|key| {
                    line.starts_with(key)
                        && line
                            .split_once(':')
                            .is_some_and(|(_, value)| value.trim() == "1")
                })
            });
            signature.push_str(&text);
        } else {
            proxy_readable = false;
        }
        let mut resolver_files = vec![];
        let mut scoped_ok = true;
        match std::fs::read_dir("/etc/resolver") {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) if entry.path().is_file() => match std::fs::read(entry.path()) {
                            Ok(bytes) if bytes.len() <= 262_144 => resolver_files.push((
                                entry.file_name(),
                                normalized_dns(&String::from_utf8_lossy(&bytes)),
                            )),
                            _ => scoped_ok = false,
                        },
                        Ok(_) => {}
                        Err(_) => scoped_ok = false,
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => scoped_ok = false,
        }
        resolver_files.sort();
        let count = resolver_files.len();
        if let Some(config) = dns_configuration.as_mut() {
            config.push_str(&format!("{resolver_files:?}"));
        }
        if !scoped_ok {
            dns_configuration = None;
        }
        checks.push(CheckResult::local("scoped-dns", "按域名解析设置", if count > 0 { "observed" } else { "not_applicable" },
            if count > 0 { format!("发现 {count} 个域名解析文件") } else { "未发现额外的解析文件".into() },
            "文件存在只说明配置存在，不能证明本地 DNS 服务可用，也不能替代缓存、DoH 或已有连接验证。"));
    } else if cfg!(target_os = "linux") {
        if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
            dns_servers = parse_nameservers(&text);
            signature.push_str(&text);
            dns_configuration = Some(normalized_dns(&text));
        }
        if Path::new("/run/systemd/resolve").exists() {
            let (dns, domains) = tokio::join!(
                output("resolvectl", &["dns"]),
                output("resolvectl", &["domain"])
            );
            dns_configuration = match (dns_configuration, dns, domains) {
                (Some(config), Some(dns), Some(domains)) => Some(format!(
                    "{config}\n{}\n{}",
                    normalized_dns(&dns),
                    normalized_dns(&domains)
                )),
                _ => None,
            };
        }
        if let Some(route) = output("ip", &["route", "show"]).await {
            signature.push_str(&route);
        }
        let proxy_mode = output("gsettings", &["get", "org.gnome.system.proxy", "mode"]).await;
        if let Some(mode) = proxy_mode {
            app_proxy_present |= !mode.contains("'none'");
            signature.push_str(&mode);
        }
        checks.push(CheckResult::local("resolver-scope", "解析管理器", "review", "读取 resolv.conf；作用域需核查", "systemd-resolved、NetworkManager 和应用自有解析可能使用其他路径；此版本不将文件内容视为全系统解析证明。"));
    } else if cfg!(windows) {
        let dns = output("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", "Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4 -Compress"]).await;
        if let Some(text) = dns {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                let rows = value.as_array().cloned().unwrap_or_else(|| vec![value]);
                for row in rows {
                    if let Some(servers) = row["ServerAddresses"].as_array() {
                        for server in servers.iter().filter_map(|v| v.as_str()) {
                            if server.parse::<std::net::IpAddr>().is_ok() {
                                dns_servers.push(server.to_owned());
                            }
                        }
                    }
                }
                dns_servers.sort();
                dns_servers.dedup();
                dns_configuration = Some(text.clone());
            }
            signature.push_str(&text);
        }
        if let Some(text) = output("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", "$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; $p | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress"]).await {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) { app_proxy_present |= value["ProxyEnable"].as_u64() == Some(1) || value["AutoConfigURL"].as_str().is_some_and(|v| !v.is_empty()); }
            else { proxy_readable = false; }
            signature.push_str(&text);
        } else { proxy_readable = false; }
        checks.push(CheckResult::local(
            "resolver-scope",
            "解析策略覆盖",
            "unknown",
            "尚未验证 NRPT 与应用自有 DNS",
            "本次只读取可获取的网卡地址；Windows 原生、WSL 与容器必须分别检查。",
        ));
    } else {
        proxy_readable = false;
    }
    if cfg!(target_os = "windows") || cfg!(target_os = "linux") {
        let (other, info) = crate::network_other::inspect().await;
        checks.extend(other);
        signature.push_str(&info);
    }
    let dns_policy = dns_policy_check(&dns_servers, dns_configuration.as_deref());
    signature.push_str(&dns_policy.value);
    checks.push(dns_policy);
    let timezone = get_system_timezone();
    checks.push(CheckResult::local(
        "timezone",
        "系统时区",
        if timezone.is_ok() {
            "observed"
        } else {
            "unknown"
        },
        timezone.unwrap_or_else(|_| "未能读取系统时区".into()),
        "时区由用户指定或在开启守护时锁定；不根据出口国家推断。",
    ));
    checks.insert(0, crate::network::dns_check(&dns_servers));
    let proxy_summary = if !proxy_readable {
        "部分代理设置无法读取"
    } else if app_proxy_present {
        "发现系统或终端代理配置"
    } else {
        route_summary
            .as_deref()
            .unwrap_or("未读到显式代理；当前平台的 TUN 选路尚未核实")
    }
    .to_string();
    checks.push(CheckResult::local("proxy-config", "代理与检测路径", if proxy_readable { "observed" } else { "unknown" }, proxy_summary.clone(),
        "留空时检测仅使用系统路由，不自动采用应用代理；若已发现代理配置，外部探测会要求明确指定代理，避免绕过。")
        .suggest("需要通过代理检测时，在设置填写现有代理地址，例如 http://127.0.0.1:7890。"));
    if !checks.iter().any(|c| c.id == "ipv6-policy") {
        checks.push(CheckResult::local(
            "ipv6-policy",
            "电脑 IPv6 状态",
            "unknown",
            "此平台的 IPv6 开关读取尚未适配",
            "需要检查当前联网网卡的 IPv6 设置；不把没有地址或请求失败当作已经关闭。",
        ));
    }
    signature.push_str(if env_proxy {
        "env-proxy-present"
    } else {
        "no-env-proxy"
    });
    for key in [
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
    ] {
        if let Ok(value) = std::env::var(key) {
            signature.push_str(&value);
        }
    }
    let route_tun_ok = checks
        .iter()
        .any(|c| c.id == "network-route" && c.status == "match");
    let home = home();
    let installed =
        crate::proxy_core::clash_verge_present(home.as_deref().unwrap_or(std::path::Path::new("")));
    checks.push(crate::proxy_core::install_check(installed));
    let mode = crate::proxy_core::inspect(route_tun_ok).await;
    checks.push(mode);
    let fingerprint = evidence_fingerprint(&signature, &checks);
    NetworkInfo {
        dns_servers,
        proxy_summary,
        checks,
        fingerprint,
        app_proxy_present,
        proxy_readable,
    }
}
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
pub async fn launch(tool: &ToolInfo) -> Result<(), String> {
    let raw = tool.path.as_ref().ok_or("未找到工具路径")?;
    let (path, desktop) = validate_tool_path(raw)?;
    if !cfg!(target_os = "macos") {
        return Err("当前平台的安全启动适配尚未完成".into());
    }
    let mut command;
    if desktop {
        command = Command::new("/usr/bin/open");
        command.arg("-a").arg(path);
    } else {
        command = Command::new("/usr/bin/osascript");
        command
            .args([
                "-e",
                "on run argv",
                "-e",
                "tell application \"Terminal\"",
                "-e",
                "activate",
                "-e",
                "do script (item 1 of argv)",
                "-e",
                "end tell",
                "-e",
                "end run",
                "--",
            ])
            .arg(shell_quote(&path.to_string_lossy()));
    }
    command.kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(15), command.output()).await {
        Ok(Ok(out)) if out.status.success() => Ok(()),
        Ok(Ok(_)) => Err("终端或应用未能启动，请核对系统自动化权限与工具路径".into()),
        _ => Err("启动请求未完成；可能正在等待系统授权，请检查终端状态".into()),
    }
}

pub fn get_system_timezone() -> Result<String, String> {
    #[cfg(unix)]
    {
        if let Ok(target) = std::fs::read_link("/etc/localtime") {
            let target_str = target.to_string_lossy();
            if let Some(pos) = target_str.find("zoneinfo/") {
                let tz = &target_str[pos + 9..];
                if !tz.is_empty() {
                    return Ok(tz.to_string());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/sbin/systemsetup")
            .arg("-gettimezone")
            .output();
        if let Ok(out) = out {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if let Some((_, tz)) = line.split_once(':') {
                    let clean = tz.trim();
                    if !clean.is_empty() {
                        return Ok(clean.to_string());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("timedatectl")
            .args(["show", "-p", "Timezone", "--value"])
            .output();
        if let Ok(out) = out {
            let clean = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !clean.is_empty() {
                return Ok(clean);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("tzutil").arg("/g").output();
        if let Ok(out) = out {
            let clean = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !clean.is_empty() {
                return Ok(clean);
            }
        }
    }

    Err("未能读取系统时区".into())
}

pub fn validate_timezone_name(tz: &str) -> Result<(), String> {
    if tz.is_empty()
        || tz.len() > 64
        || !tz.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '/' || c == '_' || c == '-' || c == '+' || c == ' '
        })
    {
        return Err("时区标识符格式无效".into());
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn iana_to_windows_timezone(iana: &str) -> Result<&'static str, String> {
    Ok(match iana {
        "America/Los_Angeles" => "Pacific Standard Time",
        "America/Denver" => "Mountain Standard Time",
        "America/Chicago" => "Central Standard Time",
        "America/New_York" => "Eastern Standard Time",
        "Asia/Shanghai" => "China Standard Time",
        "Asia/Tokyo" => "Tokyo Standard Time",
        "Asia/Singapore" => "Singapore Standard Time",
        "Asia/Hong_Kong" => "China Standard Time",
        "Europe/London" => "GMT Standard Time",
        "Europe/Berlin" => "W. Europe Standard Time",
        "UTC" => "UTC",
        _ => return Err("此 IANA 时区尚无 Windows 映射，请填写 Windows 时区 ID".into()),
    })
}

pub(crate) fn timezone_matches(current: &str, target: &str) -> bool {
    if current == target {
        return true;
    }
    #[cfg(target_os = "windows")]
    if target.contains('/') {
        return iana_to_windows_timezone(target).is_ok_and(|expected| current == expected);
    }
    false
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
pub async fn set_system_timezone(target_tz: &str) -> Result<(), String> {
    validate_timezone_name(target_tz)?;
    if get_system_timezone().is_ok_and(|current| timezone_matches(&current, target_tz)) {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let mut cmd = tokio::process::Command::new("/usr/sbin/systemsetup");
        cmd.args(["-settimezone", target_tz]).kill_on_drop(true);
        if let Ok(out) = cmd.output().await {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if out.status.success()
                && !stderr.contains("requires an administrator password")
                && !stderr.contains("You need administrator access")
            {
                if let Ok(verified) = get_system_timezone() {
                    if verified == target_tz {
                        return Ok(());
                    }
                }
            }
        }
        let script = format!(
            "do shell script \"/usr/sbin/systemsetup -settimezone {}\" with administrator privileges",
            shell_quote(target_tz)
        );
        let mut oscmd = tokio::process::Command::new("/usr/bin/osascript");
        oscmd.args(["-e", &script]).kill_on_drop(true);
        let out = oscmd
            .output()
            .await
            .map_err(|e| format!("执行时区设置失败: {e}"))?;
        if out.status.success() {
            if let Ok(verified) = get_system_timezone() {
                if verified == target_tz {
                    return Ok(());
                }
            }
        }
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!("修改系统时区未授权或失败: {}", err.trim()))
    }

    #[cfg(target_os = "windows")]
    {
        let win_tz = if target_tz.contains('/') {
            iana_to_windows_timezone(target_tz)?
        } else {
            target_tz
        };
        let mut cmd = tokio::process::Command::new("tzutil");
        cmd.args(["/s", win_tz]).kill_on_drop(true);
        let out = cmd
            .output()
            .await
            .map_err(|e| format!("执行时区设置失败: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        return Err("修改 Windows 时区失败".into());
    }

    #[cfg(target_os = "linux")]
    {
        let mut cmd = tokio::process::Command::new("pkexec");
        cmd.args(["timedatectl", "set-timezone", target_tz])
            .kill_on_drop(true);
        let out = cmd
            .output()
            .await
            .map_err(|e| format!("执行时区设置失败: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        return Err("修改 Linux 时区失败".into());
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    Err("不支持的时区修改平台".into())
}

#[allow(dead_code)]
pub async fn active_remote_ips() -> Vec<String> {
    let mut ips = std::collections::HashSet::new();
    #[cfg(unix)]
    {
        if let Some(text) = output("/usr/sbin/netstat", &["-n", "-p", "tcp"]).await {
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 && parts[5] == "ESTABLISHED" {
                    let remote = parts[4];
                    if let Some((ip, _)) = remote.rsplit_once('.') {
                        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                            if !addr.is_loopback() && !addr.is_private() {
                                ips.insert(format!("{addr}/32"));
                            }
                        }
                    }
                }
            }
        }
    }
    ips.into_iter().collect()
}

pub async fn restore_native_network(app_data_dir: &std::path::Path) -> Result<(), Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        use crate::recovery;
        let mut record = match recovery::load_recovery_record(app_data_dir) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()),
            Err(e) => return Err(vec![e]),
        };
        let mut tasks = vec![];
        let mut errors = vec![];
        for sb in &record.services {
            match recovery::service_tasks(sb) {
                Ok(v) => tasks.extend(v),
                Err(e) => errors.push(e),
            }
        }
        for (domain, original) in &record.browser_policies_original {
            let args = match original {
                Some(v) => vec![
                    "write".into(),
                    domain.clone(),
                    "WebRtcIPHandlingPolicy".into(),
                    "-string".into(),
                    v.clone(),
                ],
                None => vec![
                    "delete".into(),
                    domain.clone(),
                    "WebRtcIPHandlingPolicy".into(),
                ],
            };
            tasks.push(recovery::RestoreTask {
                id: format!("browser:{domain}"),
                program: "/usr/bin/defaults".into(),
                commands: vec![args],
            });
        }
        if let Err(e) = recovery::run_tasks(
            app_data_dir,
            &mut record,
            tasks,
            |program, args| async move {
                let refs: Vec<_> = args.iter().map(String::as_str).collect();
                run_cmd_checked(&program, &refs).await.map(|_| ())
            },
        )
        .await
        {
            errors.extend(e);
        }
        for (name, content) in record.clash_files_backup.clone() {
            let key = format!("clash:{name}");
            if record.completed.contains(&key) {
                continue;
            }
            let path = std::path::Path::new(&name);
            let temp = path.with_extension(format!("restore-{}", uuid::Uuid::new_v4().simple()));
            let result = std::fs::write(&temp, content).and_then(|_| std::fs::rename(&temp, path));
            match result {
                Ok(()) => {
                    record.completed.insert(key.clone());
                    if let Err(e) = recovery::save_recovery_record(app_data_dir, &record) {
                        record.completed.remove(&key);
                        errors.push(e);
                    }
                }
                Err(e) => {
                    let _ = std::fs::remove_file(temp);
                    errors.push(format!("恢复代理配置失败：{e}"));
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        recovery::clear_recovery_record(app_data_dir).map_err(|e| vec![e])
    }
    #[cfg(not(target_os = "macos"))]
    {
        match crate::recovery::load_recovery_record(app_data_dir) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(vec![
                "发现旧版本恢复记录，此平台不支持其格式；请保留记录并手动恢复，未报告成功".into(),
            ]),
            Err(e) => Err(vec![e]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_timezone_string_format() {
        assert!(validate_timezone_name("America/Los_Angeles").is_ok());
        assert!(validate_timezone_name("Asia/Shanghai").is_ok());
        assert!(validate_timezone_name("Pacific Standard Time").is_ok());
        assert!(validate_timezone_name("China Standard Time").is_ok());
        assert!(validate_timezone_name("UTC").is_ok());
        assert!(validate_timezone_name("Etc/GMT+8").is_ok());
        assert!(validate_timezone_name("").is_err());
        assert!(validate_timezone_name("America/Los_Angeles; rm -rf /").is_err());
        assert!(validate_timezone_name("Asia/Shanghai\" || whoami").is_err());
    }
    #[test]
    fn gets_local_timezone_without_panic() {
        let tz = get_system_timezone();
        assert!(tz.is_ok());
        assert!(!tz.unwrap().is_empty());
    }
    #[test]
    fn dns_baseline_tracks_scopes_and_options_without_treating_reachability_as_configuration() {
        let a = "DNS configuration\nresolver #1\n domain : example.cn\n nameserver[0] : 223.5.5.5\n reach : 0x00000002 (Reachable)\n order : 100\n";
        let b = a
            .replace("resolver #1", "resolver #8")
            .replace("0x00000002 (Reachable)", "0x00000000 (Not Reachable)");
        assert_eq!(normalized_dns(a), normalized_dns(&b));
        for changed in [
            a.replace("example.cn", "example.com"),
            a.replace("223.5.5.5", "1.1.1.1"),
            a.replace("100", "200"),
        ] {
            assert_ne!(normalized_dns(a), normalized_dns(&changed));
        }
        let servers = vec!["223.5.5.5".into()];
        assert_eq!(
            dns_policy_check(&servers, Some(&normalized_dns(a))).status,
            "observed"
        );
        assert_eq!(dns_policy_check(&servers, None).status, "unknown");
        assert_eq!(dns_policy_check(&[], Some(a)).status, "unknown");
    }
    #[test]
    fn an_optional_client_api_failure_does_not_invalidate_the_network_path() {
        let mut mode =
            CheckResult::local("proxy-mode", "模式", "match", "全局模式 · TUN 已开启", "");
        let before = evidence_fingerprint("same-network", &[mode.clone()]);
        mode.status = "unknown".into();
        mode.value = "代理模式无法确认".into();
        assert_eq!(before, evidence_fingerprint("same-network", &[mode]));
    }
    #[test]
    fn unknown_windows_timezone_never_defaults_to_california() {
        assert!(iana_to_windows_timezone("Unknown/City").is_err());
        assert_eq!(
            iana_to_windows_timezone("America/New_York").unwrap(),
            "Eastern Standard Time"
        );
    }

    #[test]
    fn parses_dns_ipv4_ipv6_without_duplicate() {
        assert_eq!(
            parse_nameservers(
                "nameserver[0] : 127.0.0.1\nnameserver[1] : 2001:db8::1\nnameserver 127.0.0.1\n"
            ),
            vec!["127.0.0.1", "2001:db8::1"]
        );
    }
    #[test]
    fn shell_arguments_are_single_quoted() {
        assert_eq!(
            shell_quote("/tmp/a'b $(touch bad)"),
            "'/tmp/a'\"'\"'b $(touch bad)'"
        );
    }
    #[test]
    fn persisted_launch_and_protection_flags_cannot_bypass_guard() {
        let custom = ToolInfo {
            id: "guard-regression-fixture".into(),
            name: "Fixture".into(),
            kind: "cli".into(),
            installed: true,
            path: Some(
                std::env::current_exe()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            ),
            can_launch: true,
            protection: "allowed_by_policy".into(),
            note: "untrusted persisted note".into(),
        };
        let tools = discover(&[custom]);
        let tool = tools
            .iter()
            .find(|t| t.id == "guard-regression-fixture")
            .unwrap();
        assert!(tool.installed);
        assert!(!tool.can_launch);
        assert_eq!(tool.protection, "unsupported");
        assert!(!tool.note.contains("untrusted persisted note"));
    }
    #[test]
    fn rejects_nonabsolute_and_control_paths() {
        assert!(validate_tool_path("claude").is_err());
        assert!(validate_tool_path("/tmp/a\nfoo").is_err());
    }
    #[test]
    fn fingerprint_ignores_observation_times_but_tracks_dns_route_and_read_failures() {
        let mut checks = vec![
            CheckResult::local(
                "network-route",
                "Route",
                "match",
                "tun0",
                "first observation",
            ),
            CheckResult::local("dns-config", "DNS", "observed", "本机 DNS", ""),
        ];
        let first = evidence_fingerprint("dns:127.0.0.1;proxy:local", &checks);
        for c in &mut checks {
            c.observed_at = (chrono::Utc::now() + chrono::Duration::seconds(5)).to_rfc3339();
            c.detail = "new observation".into();
        }
        checks.reverse();
        assert_eq!(
            first,
            evidence_fingerprint("dns:127.0.0.1;proxy:local", &checks)
        );
        assert_ne!(
            first,
            evidence_fingerprint("dns:192.0.2.53;proxy:local", &checks)
        );
        checks
            .iter_mut()
            .find(|c| c.id == "network-route")
            .unwrap()
            .value = "physical0".into();
        assert_ne!(
            first,
            evidence_fingerprint("dns:127.0.0.1;proxy:local", &checks)
        );
        let known = evidence_fingerprint("dns:127.0.0.1;proxy:local", &checks);
        checks
            .iter_mut()
            .find(|c| c.id == "network-route")
            .unwrap()
            .status = "unknown".into();
        assert_ne!(
            known,
            evidence_fingerprint("dns:127.0.0.1;proxy:local", &checks)
        );
    }
}
