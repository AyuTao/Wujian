//! Transactional DNS changes. Runs only inside the explicitly authorized native
//! helper. IPv6 protection uses packet filtering, never destructive adapter edits.
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub servers: Vec<IpAddr>,
}
pub(crate) fn overseas_system_dns() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1)),
    ]
}

/// Commit an explicit system DNS write.
/// Stopping protection must not put the previous resolvers back.
pub(crate) fn discard_recovery(dir: &Path) -> Result<(), String> {
    let path = dir.join("network-recovery.json");
    if path.exists() {
        std::fs::remove_file(&path).map_err(|_| "DNS 已写入，原始记录已保留")?;
    }
    Ok(())
}

impl Change {
    pub fn validate(&self) -> Result<(), String> {
        if self.servers.is_empty()
            || self.servers.len() > 4
            || self.servers.iter().any(|ip| {
                !ip.is_ipv4()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || *ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            })
        {
            return Err("请输入 1 至 4 个有效 IPv4 DNS 地址".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Backup {
    pub service: String,
    pub automatic: bool,
    pub servers: Vec<String>,
}
/// Read-only physical adapter state, distinct from the effective resolver stack
/// (which can also contain VPN/TUN and scoped resolvers).
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PhysicalDns {
    pub adapters: Vec<Backup>,
    pub observed_at: String,
    pub error: Option<String>,
    pub runtime_only: bool,
}

pub(crate) fn resolver_kind(servers: &[String]) -> &'static str {
    if servers.is_empty() {
        "empty"
    } else if servers.iter().any(|s| {
        matches!(
            s.split('%').next().unwrap_or(s),
            "114.114.114.114"
                | "114.114.115.115"
                | "223.5.5.5"
                | "223.6.6.6"
                | "119.29.29.29"
                | "119.28.28.28"
                | "182.254.116.116"
                | "182.254.118.118"
                | "180.76.76.76"
                | "1.2.4.8"
                | "210.2.4.8"
                | "101.226.4.6"
                | "123.125.81.6"
        )
    }) {
        "domestic"
    } else {
        "configured"
    }
}
impl PhysicalDns {
    fn kind(&self) -> &'static str {
        if self.error.is_some() {
            return "unavailable";
        }
        if self.adapters.is_empty() {
            return "empty";
        }
        if self.adapters.iter().all(|b| b.automatic) {
            return "automatic";
        }
        resolver_kind(
            &self
                .adapters
                .iter()
                .flat_map(|b| b.servers.clone())
                .collect::<Vec<_>>(),
        )
    }
}
pub(crate) async fn inspect() -> PhysicalDns {
    let result = tokio::time::timeout(Duration::from_secs(4), capture_mode(false))
        .await
        .unwrap_or_else(|_| Err("物理网卡 DNS 读取超时".into()));
    let (adapters, error) = match result {
        Ok(adapters) => (adapters, None),
        Err(error) => {
            crate::audit::transition("dns.physical_read", "error", Some(&error));
            (vec![], Some("物理网卡 DNS 读取失败，请重新核验".into()))
        }
    };
    let state = PhysicalDns {
        adapters,
        observed_at: chrono::Utc::now().to_rfc3339(),
        error,
        runtime_only: cfg!(target_os = "linux"),
    };
    // Classifications only: never export adapter names or resolver addresses.
    crate::audit::transition("dns.physical", state.kind(), None);
    state
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Journal {
    platform: String,
    original: Vec<Backup>,
    pending: Vec<usize>,
}

/// Require an actual DNS response, not just a listening TCP socket. This is
/// availability validation only; it never proves leak containment.
pub async fn probe(server: IpAddr) -> Result<(), String> {
    let id = uuid::Uuid::new_v4().as_bytes()[..2].to_vec();
    let mut query = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|_| "无法创建 DNS 验证请求")?;
    socket
        .connect(SocketAddr::new(server, 53))
        .await
        .map_err(|_| "无法连接指定 DNS")?;
    socket
        .send(&query)
        .await
        .map_err(|_| "DNS 验证请求发送失败")?;
    let mut reply = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut reply))
        .await
        .map_err(|_| "指定 DNS 未在 3 秒内响应；未修改系统配置")?
        .map_err(|_| "指定 DNS 不可用；未修改系统配置")?;
    if !valid_answer(&reply[..n], &id) {
        return Err("DNS 未返回有效解析答案；未修改系统配置".into());
    }
    Ok(())
}
fn valid_answer(reply: &[u8], id: &[u8]) -> bool {
    if reply.len() < 12
        || &reply[..2] != id
        || reply[2] & 0x82 != 0x80
        || reply[3] & 15 != 0
        || reply[4..6] != [0, 1]
    {
        return false;
    }
    let question = b"\x07example\x03com\x00\x00\x01\x00\x01";
    if reply.get(12..12 + question.len()) != Some(question) {
        return false;
    }
    let mut at = 12 + question.len();
    for _ in 0..u16::from_be_bytes([reply[6], reply[7]]) {
        loop {
            let Some(&n) = reply.get(at) else {
                return false;
            };
            at += 1;
            if n & 0xc0 == 0xc0 {
                if at >= reply.len() {
                    return false;
                }
                at += 1;
                break;
            }
            if n == 0 {
                break;
            }
            if n > 63 || at + n as usize > reply.len() {
                return false;
            }
            at += n as usize;
        }
        let Some(record) = reply.get(at..at + 10) else {
            return false;
        };
        let len = u16::from_be_bytes([record[8], record[9]]) as usize;
        at += 10;
        if at + len > reply.len() {
            return false;
        }
        if record[..4] == [0, 1, 0, 1] && len == 4 {
            return true;
        }
        at += len;
    }
    false
}
async fn cmd(program: &str, args: &[&str]) -> Result<String, String> {
    let operation = match (program, args.first().copied()) {
        ("/usr/sbin/networksetup", Some("-listnetworkserviceorder")) => "dns.services.read",
        ("/sbin/ifconfig", _) => "dns.interface.read",
        ("/usr/sbin/networksetup", Some("-getdnsservers")) => "dns.servers.read",
        ("/usr/sbin/networksetup", Some("-setdnsservers")) => "dns.servers.write",
        _ => "dns.platform.command",
    };
    crate::audit::record_async(
        operation,
        crate::firewall::command::run(Path::new(program), args, None),
    )
    .await
}
async fn read_cmd(program: &str, args: &[&str], audited: bool) -> Result<String, String> {
    if audited {
        cmd(program, args).await
    } else {
        crate::platform::run_cmd_checked(program, args).await
    }
}
#[cfg(target_os = "windows")]
async fn powershell(script: &str) -> Result<String, String> {
    powershell_mode(script, true).await
}
#[cfg(target_os = "windows")]
async fn powershell_mode(script: &str, audited: bool) -> Result<String, String> {
    let script = format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); {script}");
    let path = crate::firewall::system_powershell()?;
    let path = path.to_str().ok_or("PowerShell 路径无法读取")?;
    read_cmd(
        path,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        audited,
    )
    .await
}

#[cfg(target_os = "macos")]
fn service_order(text: &str) -> Vec<(String, String)> {
    let mut result = vec![];
    let mut name: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('(') && !line.starts_with("(Hardware") {
            name = line
                .split_once(") ")
                .filter(|(n, _)| {
                    let n = n.trim_start_matches('(');
                    n == "*" || n.parse::<u32>().is_ok()
                })
                .map(|(_, n)| n.to_string());
        } else if let Some((_, dev)) = line.split_once("Device: ") {
            if let Some(name) = name.take() {
                let dev = dev.trim_end_matches(')');
                if physical_nic(dev) {
                    result.push((name, dev.into()));
                }
            }
        }
    }
    result
}
#[cfg(target_os = "macos")]
fn physical_nic(dev: &str) -> bool {
    dev.strip_prefix("en")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(target_os = "macos")]
fn interface_missing(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("does not exist") || error.contains("不存在")
}

fn addresses(text: &str) -> Result<Vec<String>, String> {
    let values: Vec<_> = text.split_whitespace().map(str::to_string).collect();
    if values.iter().any(|s| {
        let mut parts = s.split('%');
        let invalid_ip = parts.next().unwrap_or(s).parse::<IpAddr>().is_err();
        let invalid_zone = parts.next().is_some_and(|z| {
            z.is_empty()
                || !z
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        });
        invalid_ip || invalid_zone || parts.next().is_some()
    }) {
        return Err("原 DNS 配置无法准确读取，拒绝修改".into());
    }
    Ok(values)
}
async fn capture() -> Result<Vec<Backup>, String> {
    capture_mode(true).await
}
async fn capture_mode(audited: bool) -> Result<Vec<Backup>, String> {
    #[cfg(target_os = "macos")]
    {
        let list = read_cmd(
            "/usr/sbin/networksetup",
            &["-listnetworkserviceorder"],
            audited,
        )
        .await?;
        let mut result = vec![];
        for (service, dev) in service_order(&list) {
            if !physical_nic(&dev) {
                continue;
            }
            match read_cmd("/sbin/ifconfig", &[&dev], audited).await {
                Ok(_) => {}
                Err(error) if interface_missing(&error) => {
                    if audited {
                        crate::audit::event("dns.interface.read", "skipped", None, None);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            }
            // DNS belongs to the saved network service, not its link state.
            // Include disconnected/disabled services without enabling them.
            let text = read_cmd(
                "/usr/sbin/networksetup",
                &["-getdnsservers", &service],
                audited,
            )
            .await?;
            let automatic = text.starts_with("There aren't any DNS Servers");
            let servers = if automatic { vec![] } else { addresses(&text)? };
            if !automatic && servers.is_empty() {
                return Err("原 DNS 数据缺失，拒绝修改".into());
            }
            result.push(Backup {
                service,
                automatic,
                servers,
            });
        }
        return Ok(result);
    }
    #[cfg(target_os = "windows")]
    {
        let script = r#"$a=@(Get-NetAdapter -Physical | ForEach-Object {
            $guid=[guid]$_.InterfaceGuid;
            $p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+$guid.ToString('B');
            $raw=(Get-ItemProperty -LiteralPath $p -ErrorAction Stop).NameServer;
            @{service=$guid.ToString('D'); automatic=[string]::IsNullOrWhiteSpace($raw); servers=@($raw -split '[,;\s]+' | Where-Object {$_})}
        }); ConvertTo-Json -InputObject $a -Depth 4 -Compress"#;
        let text = powershell_mode(script, audited).await?;
        let result: Vec<Backup> = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|_| "Windows DNS 原始配置解析失败")?;
        for b in &result {
            if uuid::Uuid::parse_str(&b.service).is_err() {
                return Err("网卡 GUID 无效".into());
            }
            addresses(&b.servers.join(" "))?;
        }
        return Ok(result);
    }
    #[cfg(target_os = "linux")]
    {
        let mut result = vec![];
        for entry in std::fs::read_dir("/sys/class/net")
            .map_err(|_| "无法读取网卡")?
            .flatten()
        {
            if !entry.path().join("device").exists()
                || !std::fs::read_to_string(entry.path().join("operstate"))
                    .is_ok_and(|s| s.trim() == "up")
            {
                continue;
            }
            let service = entry.file_name().to_string_lossy().into_owned();
            let text = read_cmd("/usr/bin/resolvectl", &["dns", &service], audited)
                .await
                .map_err(|e| format!("仅支持 systemd-resolved 管理的 DNS，未修改：{e}"))?;
            let tail = text.split_once(':').ok_or("无法读取原 DNS")?.1.trim();
            let servers = addresses(tail)?;
            result.push(Backup {
                service,
                automatic: servers.is_empty(),
                servers,
            });
        }
        return Ok(result);
    }
    #[allow(unreachable_code)]
    Err("此平台不支持 DNS 配置".into())
}
async fn set(backup: &Backup) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let mut args = vec!["-setdnsservers", backup.service.as_str()];
        if backup.automatic {
            args.push("Empty");
        } else {
            args.extend(backup.servers.iter().map(String::as_str));
        }
        cmd("/usr/sbin/networksetup", &args).await?;
    }
    #[cfg(target_os = "windows")]
    {
        let guid = uuid::Uuid::parse_str(&backup.service).map_err(|_| "网卡 GUID 无效")?;
        addresses(&backup.servers.join(" "))?;
        let parameter = if backup.automatic {
            "-ResetServerAddresses".into()
        } else {
            format!(
                "-ServerAddresses @({})",
                backup
                    .servers
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        powershell(&format!("$adapter=Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {{[guid]$_.InterfaceGuid -eq [guid]'{guid}'}} | Select-Object -First 1; if (-not $adapter) {{ throw 'Original adapter unavailable; recovery retained' }}; Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Set-DnsClientServerAddress {parameter} -ErrorAction Stop")).await?;
    }
    #[cfg(target_os = "linux")]
    {
        let mut args = vec!["dns", backup.service.as_str()];
        if backup.servers.is_empty() {
            args.push("");
        } else {
            args.extend(backup.servers.iter().map(String::as_str));
        }
        cmd("/usr/bin/resolvectl", &args).await?;
    }
    // A successful exit alone is insufficient. Compare the effective/static snapshot.
    let current = capture().await?;
    if current.iter().any(|b| b == backup) {
        Ok(())
    } else {
        Err("DNS 写入后的配置回读不匹配；恢复记录保留".into())
    }
}
fn save(dir: &Path, journal: &Journal) -> Result<(), String> {
    crate::firewall::write_private(
        &dir.join("network-recovery.json"),
        &serde_json::to_vec(journal).map_err(|e| e.to_string())?,
    )
}
async fn restore_with<F, Fut>(journal: &mut Journal, dir: &Path, mut apply: F) -> Result<(), String>
where
    F: FnMut(Backup) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut errors = vec![];
    for n in journal.pending.clone().into_iter().rev() {
        let backup = journal
            .original
            .get(n)
            .ok_or("DNS 恢复记录编号无效")?
            .clone();
        match crate::audit::record_async("dns.restore_adapter", apply(backup)).await {
            Ok(()) => {
                journal.pending.retain(|v| *v != n);
                save(dir, journal)?;
            }
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "部分 DNS 恢复失败，记录保留：{}",
            errors.join("；")
        ))
    }
}
/// Journal every adapter before mutation, including adapters newly present on
/// a retry. Only a fully verified explicit write becomes the new baseline.
async fn apply_with<F, Fut>(
    current: Vec<Backup>,
    change: &Change,
    keep: bool,
    dir: &Path,
    mut apply: F,
) -> Result<(), String>
where
    F: FnMut(Backup) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let path = dir.join("network-recovery.json");
    let mut journal = if path.exists() {
        if !keep {
            return Err("已有 DNS 修改等待恢复，请先还原后再修改".into());
        }
        let journal: Journal =
            serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|_| "DNS 恢复记录损坏，未修改")?;
        if journal.platform != std::env::consts::OS
            || journal.pending.iter().any(|n| *n >= journal.original.len())
        {
            return Err("DNS 恢复记录无效，未修改".into());
        }
        journal
    } else {
        Journal {
            platform: std::env::consts::OS.into(),
            original: vec![],
            pending: vec![],
        }
    };
    let servers: Vec<String> = change.servers.iter().map(ToString::to_string).collect();
    let written: std::collections::HashSet<_> = current.iter().map(|b| b.service.clone()).collect();
    for backup in current {
        let n = match journal
            .original
            .iter()
            .position(|b| b.service == backup.service)
        {
            Some(n) => {
                if !journal.pending.contains(&n) {
                    // An earlier restore completed for this adapter. Its current
                    // value is now the original for this new attempt.
                    journal.original[n] = backup.clone();
                }
                n
            }
            None => {
                journal.original.push(backup.clone());
                journal.original.len() - 1
            }
        };
        if !journal.pending.contains(&n) {
            journal.pending.push(n);
        }
        save(dir, &journal)?; // write-ahead original BEFORE each adapter mutation
        let next = Backup {
            service: backup.service,
            automatic: false,
            servers: servers.clone(),
        };
        if let Err(e) = crate::audit::record_async("dns.apply_adapter", apply(next)).await {
            return Err(format!(
                "DNS 配置未完成：{e}；请使用恢复按钮，原始记录已保留"
            ));
        }
    }
    // Never abandon recovery for an adapter no longer present. Let the user
    // reconnect it and retry/restore instead of reporting a partial success.
    if keep
        && journal
            .pending
            .iter()
            .any(|n| !written.contains(&journal.original[*n].service))
    {
        return Err(
            "部分旧网卡不可用，DNS 配置未完成；请重新连接后重试或恢复，原始记录已保留".into(),
        );
    }
    if keep {
        discard_recovery(dir)?;
        crate::audit::event("dns.commit", "ok", None, None);
    }
    Ok(())
}

pub(crate) async fn execute(
    action: &str,
    change: Option<&Change>,
    dir: &Path,
) -> Result<crate::firewall::Receipt, String> {
    let path = dir.join("network-recovery.json");
    if action == "network-apply" || action == "network-apply-keep" {
        let keep = action == "network-apply-keep";
        let change = change.ok_or("缺少 DNS 设置")?;
        change.validate()?;
        for server in &change.servers {
            probe(*server).await?;
        }
        let current = capture().await?;
        if current.is_empty() {
            return Err("没有可修改的物理网卡；Linux 需活动的 systemd-resolved 接口".into());
        }
        apply_with(current, change, keep, dir, |b| async move { set(&b).await }).await?;
        Ok(crate::firewall::Receipt::new(
            true,
            None,
            if keep {
                "系统 IPv4 DNS 已写入并回读；停止保护将保留新配置。"
            } else {
                "IPv4 DNS 已修改并回读；这是配置状态，不证明 DNS 无泄漏。"
            },
        ))
    } else if action == "network-release" {
        if !path.exists() {
            return Ok(crate::firewall::Receipt::new(
                false,
                None,
                "没有本工具的 DNS 修改记录。",
            ));
        }
        let mut journal: Journal =
            serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|_| "DNS 恢复记录损坏，未清除")?;
        if journal.platform != std::env::consts::OS {
            return Err("DNS 恢复记录平台不匹配".into());
        }
        restore_with(&mut journal, dir, |b| async move { set(&b).await }).await?;
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
        Ok(crate::firewall::Receipt::new(
            false,
            None,
            "已按原始记录恢复 DNS 并回读，未重置其他设置。",
        ))
    } else {
        Err("无效的 DNS 操作".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_dns_classifications_do_not_confuse_unknown_automatic_and_static() {
        let mut state = PhysicalDns::default();
        assert_eq!(state.kind(), "empty");
        state.adapters.push(Backup {
            service: "private adapter name".into(),
            automatic: true,
            servers: vec![],
        });
        assert_eq!(state.kind(), "automatic");
        state.adapters[0].automatic = false;
        state.adapters[0].servers = vec!["1.1.1.1".into()];
        assert_eq!(state.kind(), "configured");
        state.adapters[0].servers = vec!["114.114.114.114".into()];
        assert_eq!(state.kind(), "domestic");
        state.error = Some("fixture failure".into());
        assert_eq!(state.kind(), "unavailable");
        assert_eq!(resolver_kind(&["114.114.114.114".into()]), "domestic");
        assert_eq!(resolver_kind(&["127.0.0.1".into()]), "configured");
        assert_eq!(resolver_kind(&[]), "empty");
    }
    #[test]
    fn overseas_system_dns_is_cloudflare_and_sticks_after_the_journal_is_dropped() {
        let servers = overseas_system_dns();
        assert_eq!(
            servers,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "1.0.0.1".parse().unwrap()
            ]
        );
        assert!(Change {
            servers: servers.clone()
        }
        .validate()
        .is_ok());
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        save(
            &dir,
            &Journal {
                platform: std::env::consts::OS.into(),
                original: vec![Backup {
                    service: "Wi-Fi".into(),
                    automatic: false,
                    servers: vec!["114.114.114.114".into()],
                }],
                pending: vec![0],
            },
        )
        .unwrap();
        discard_recovery(&dir).unwrap();
        assert!(!dir.join("network-recovery.json").exists());
        discard_recovery(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn validation_never_accepts_commands_or_unknown_addresses() {
        assert!(Change { servers: vec![] }.validate().is_err());
        assert!(Change {
            servers: vec!["0.0.0.0".parse().unwrap()]
        }
        .validate()
        .is_err());
        assert!(addresses("127.0.0.1 ; rm file").is_err());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn disconnected_and_disabled_physical_services_are_selected_but_tunnels_are_not() {
        let text = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(*) Disabled\n(Hardware Port: Ethernet, Device: en1)\n(2) VPN\n(Hardware Port: VPN, Device: utun6)";
        assert_eq!(
            service_order(text),
            vec![
                ("Wi-Fi".into(), "en0".into()),
                ("Disabled".into(), "en1".into())
            ]
        );
        let ghost = "(3) iPhone USB\n(Hardware Port: iPhone USB, Device: en9)\n(4) Index\n(Hardware Port: USB, Device: 7)\n(5) LAN\n(Hardware Port: USB LAN, Device: en7)";
        assert_eq!(
            service_order(ghost),
            vec![
                ("iPhone USB".into(), "en9".into()),
                ("LAN".into(), "en7".into())
            ]
        );
        assert!(physical_nic("en0") && physical_nic("en7"));
        assert!(!physical_nic("7") && !physical_nic("en") && !physical_nic("utun6"));
        assert!(interface_missing(
            "系统操作失败：ifconfig: interface 7 does not exist"
        ));
        assert!(interface_missing("ifconfig: interface en9 does not exist"));
        assert!(interface_missing(
            "系统操作失败：ifconfig:interface en7 does not exist."
        ));
        assert!(interface_missing("接口不存在"));
        assert!(!interface_missing("系统操作失败：permission denied"));
    }
    #[tokio::test]
    async fn explicit_manual_and_preset_dns_survive_protection_release() {
        for servers in [
            vec!["1.1.1.1", "1.0.0.1"],
            vec!["8.8.8.8", "8.8.4.4"],
            vec!["192.0.2.53"],
        ] {
            let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            std::fs::create_dir_all(&dir).unwrap();
            let mut written = vec![];
            let change = Change {
                servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            };
            let original = vec![
                Backup {
                    service: "Wi-Fi".into(),
                    automatic: false,
                    servers: vec!["114.114.114.114".into()],
                },
                Backup {
                    service: "Offline Ethernet".into(),
                    automatic: true,
                    servers: vec![],
                },
            ];
            apply_with(original, &change, true, &dir, |b| {
                written.push(b);
                std::future::ready(Ok(()))
            })
            .await
            .unwrap();
            assert_eq!(written.len(), 2);
            assert!(written.iter().all(|b| !b.automatic && b.servers == servers));
            assert!(!dir.join("network-recovery.json").exists());
            // The real release dispatcher must have nothing to restore. If it
            // tried writing the OS here the fake service names would fail.
            assert!(
                !execute("network-release", None, &dir)
                    .await
                    .unwrap()
                    .configuration_active
            );
            assert!(written.iter().all(|b| b.servers == servers));
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn retry_journals_new_adapters_and_recovers_both_after_failure() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let wifi = Backup {
            service: "Wi-Fi".into(),
            automatic: false,
            servers: vec!["114.114.114.114".into()],
        };
        let ethernet = Backup {
            service: "Ethernet".into(),
            automatic: true,
            servers: vec![],
        };
        save(
            &dir,
            &Journal {
                platform: std::env::consts::OS.into(),
                original: vec![wifi.clone()],
                pending: vec![0],
            },
        )
        .unwrap();
        let current = vec![
            Backup {
                servers: vec!["8.8.8.8".into()],
                ..wifi.clone()
            },
            ethernet.clone(),
        ];
        let result = apply_with(
            current,
            &Change {
                servers: overseas_system_dns(),
            },
            true,
            &dir,
            |b| async move {
                if b.service == "Ethernet" {
                    Err("fixture readback failure".into())
                } else {
                    Ok(())
                }
            },
        )
        .await;
        assert!(result.is_err());
        let mut saved: Journal =
            serde_json::from_slice(&std::fs::read(dir.join("network-recovery.json")).unwrap())
                .unwrap();
        assert_eq!(saved.original, vec![wifi.clone(), ethernet.clone()]);
        assert_eq!(saved.pending, vec![0, 1]);
        let mut restored = vec![];
        restore_with(&mut saved, &dir, |b| {
            restored.push(b);
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert_eq!(restored, vec![ethernet, wifi]);
        assert!(saved.pending.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn commit_never_discards_recovery_for_a_disconnected_removed_adapter() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        save(
            &dir,
            &Journal {
                platform: std::env::consts::OS.into(),
                original: vec![Backup {
                    service: "Unplugged USB".into(),
                    automatic: true,
                    servers: vec![],
                }],
                pending: vec![0],
            },
        )
        .unwrap();
        let result = apply_with(
            vec![Backup {
                service: "Wi-Fi".into(),
                automatic: true,
                servers: vec![],
            }],
            &Change {
                servers: overseas_system_dns(),
            },
            true,
            &dir,
            |_| std::future::ready(Ok(())),
        )
        .await;
        assert!(result.unwrap_err().contains("原始记录已保留"));
        let saved: Journal =
            serde_json::from_slice(&std::fs::read(dir.join("network-recovery.json")).unwrap())
                .unwrap();
        assert_eq!(saved.pending, vec![0, 1]);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn malformed_empty_and_truncated_dns_responses_are_not_available() {
        let mut answer = vec![1, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        answer.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        assert!(!valid_answer(&answer, &[1, 2]));
        answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        assert!(valid_answer(&answer, &[1, 2]));
        assert!(!valid_answer(&answer, &[1, 3]));
        answer[2] |= 2;
        assert!(!valid_answer(&answer, &[1, 2]));
        assert!(addresses("fe80::1%zone';Write-Host").is_err());
    }
    #[tokio::test]
    async fn partial_restore_keeps_failed_adapter_and_retries_only_unfinished_work() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let original = vec![
            Backup {
                service: "manual".into(),
                automatic: false,
                servers: vec!["192.0.2.53".into()],
            },
            Backup {
                service: "dhcp".into(),
                automatic: true,
                servers: vec![],
            },
        ];
        let mut journal = Journal {
            platform: std::env::consts::OS.into(),
            original: original.clone(),
            pending: vec![0, 1],
        };
        save(&dir, &journal).unwrap();
        let result = restore_with(&mut journal, &dir, |b| async move {
            if b.service == "manual" {
                Err("fixture failure".into())
            } else {
                assert!(b.automatic);
                Ok(())
            }
        })
        .await;
        assert!(result.is_err());
        let mut saved: Journal =
            serde_json::from_slice(&std::fs::read(dir.join("network-recovery.json")).unwrap())
                .unwrap();
        assert_eq!(saved.pending, vec![0]);
        assert_eq!(saved.original, original);
        restore_with(&mut saved, &dir, |b| async move {
            assert_eq!(b.service, "manual");
            assert_eq!(b.servers, vec!["192.0.2.53"]);
            Ok(())
        })
        .await
        .unwrap();
        let saved: Journal =
            serde_json::from_slice(&std::fs::read(dir.join("network-recovery.json")).unwrap())
                .unwrap();
        assert!(saved.pending.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
