//! Accurate and atomic network recovery state management.
//!
//! Preserves original system DNS, IPv6 settings, proxy configurations,
//! browser policies, and Clash configuration backups prior to modification.
//! Restores ONLY what was modified and reports exact status.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxySetting {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceBackup {
    pub service_name: String,
    /// None means originally Empty (DHCP-assigned DNS)
    pub original_dns: Option<Vec<String>>,
    /// e.g. "Automatic", "Off", "LinkLocal"
    pub original_ipv6_mode: String,
    #[serde(default)]
    pub original_ipv6_manual: Option<ManualIpv6>,
    pub original_web_proxy: Option<ProxySetting>,
    pub original_secure_web_proxy: Option<ProxySetting>,
    pub original_socks_proxy: Option<ProxySetting>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManualIpv6 {
    pub address: String,
    pub prefix: u8,
    pub router: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryRecord {
    pub session_id: String,
    pub created_at: String,
    pub services: Vec<ServiceBackup>,
    #[serde(default)]
    pub completed: HashSet<String>,
    /// domain -> original_policy_value (None if not set)
    pub browser_policies_original: HashMap<String, Option<String>>,
    /// path -> original_file_content
    pub clash_files_backup: HashMap<String, String>,
}

impl RecoveryRecord {
    pub fn new() -> Self {
        Self {
            session_id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            services: Vec::new(),
            completed: HashSet::new(),
            browser_policies_original: HashMap::new(),
            clash_files_backup: HashMap::new(),
        }
    }
}

pub fn recovery_file_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("active_recovery.json")
}

pub fn save_recovery_record(app_data_dir: &Path, record: &RecoveryRecord) -> Result<(), String> {
    let target = recovery_file_path(app_data_dir);
    let temp = app_data_dir.join(format!(".recovery-{}.tmp", uuid::Uuid::new_v4().simple()));

    let json_bytes =
        serde_json::to_vec_pretty(record).map_err(|e| format!("序列化恢复记录失败: {e}"))?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|e| e.to_string())?;
    file.write_all(&json_bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    std::fs::rename(&temp, &target).map_err(|e| format!("保存恢复记录失败: {e}"))?;

    Ok(())
}

pub fn load_recovery_record(app_data_dir: &Path) -> Result<Option<RecoveryRecord>, String> {
    let target = recovery_file_path(app_data_dir);
    if !target.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(&target).map_err(|e| format!("读取恢复记录失败: {e}"))?;

    let record: RecoveryRecord =
        serde_json::from_slice(&bytes).map_err(|e| format!("反序列化恢复记录失败: {e}"))?;

    Ok(Some(record))
}

pub fn clear_recovery_record(app_data_dir: &Path) -> Result<(), String> {
    let target = recovery_file_path(app_data_dir);
    if target.exists() {
        std::fs::remove_file(&target).map_err(|e| format!("删除已完成的恢复记录失败: {e}"))?;
    }
    Ok(())
}

// 辅助解析函数（可在单测中隔离测试）
pub fn parse_networksetup_dns_output(output: &str) -> Option<Vec<String>> {
    let trimmed = output.trim();
    if trimmed.is_empty()
        || trimmed.contains("There aren't any DNS Servers")
        || trimmed.contains("aren't any DNS")
    {
        return None;
    }
    let servers: Vec<String> = trimmed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("Error"))
        .map(String::from)
        .collect();

    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}

pub fn parse_networksetup_ipv6_info(output: &str) -> String {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("IPv6:") {
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() >= 2 {
                return parts[1].trim().to_string();
            }
        }
    }
    "Unknown".to_string()
}

pub fn parse_networksetup_proxy_output(output: &str) -> Option<ProxySetting> {
    let mut enabled = false;
    let mut server = String::new();
    let mut port = 0u16;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Enabled:") {
            enabled = trimmed.contains("Yes") || trimmed.contains("true");
        } else if trimmed.starts_with("Server:") {
            server = trimmed
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
        } else if trimmed.starts_with("Port:") {
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() >= 2 {
                port = parts[1].trim().parse().unwrap_or(0);
            }
        }
    }

    if !output
        .lines()
        .any(|line| matches!(line.trim(), "Enabled: Yes" | "Enabled: No"))
    {
        return None;
    }
    Some(ProxySetting {
        enabled,
        server,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_servers_empty_and_valid() {
        let empty_output = "There aren't any DNS Servers set on Ethernet.";
        assert_eq!(parse_networksetup_dns_output(empty_output), None);

        let populated = "8.8.8.8\n1.1.1.1\n";
        assert_eq!(
            parse_networksetup_dns_output(populated),
            Some(vec!["8.8.8.8".into(), "1.1.1.1".into()])
        );
    }

    #[test]
    fn parses_ipv6_modes_correctly() {
        let info_off = "DHCP Configuration\nIPv6: Off\nRouter: 192.168.1.1\n";
        assert_eq!(parse_networksetup_ipv6_info(info_off), "Off");

        let info_auto = "DHCP Configuration\nIPv6: Automatic\n";
        assert_eq!(parse_networksetup_ipv6_info(info_auto), "Automatic");

        let info_missing = "DHCP Configuration\n";
        assert_eq!(parse_networksetup_ipv6_info(info_missing), "Unknown");
    }

    #[test]
    fn parses_proxy_settings_correctly() {
        let proxy_on =
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\nAuthenticated Proxy Enabled: 0\n";
        let parsed = parse_networksetup_proxy_output(proxy_on).unwrap();
        assert_eq!(parsed.enabled, true);
        assert_eq!(parsed.server, "127.0.0.1");
        assert_eq!(parsed.port, 7890);

        let proxy_off = "Enabled: No\nServer: \nPort: 0\n";
        let parsed_off = parse_networksetup_proxy_output(proxy_off).unwrap();
        assert_eq!(parsed_off.enabled, false);
        assert_eq!(parsed_off.server, "");
        assert_eq!(parsed_off.port, 0);
    }

    #[test]
    fn recovery_record_save_load_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("wujian-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut record = RecoveryRecord::new();
        record.services.push(ServiceBackup {
            service_name: "Ethernet".into(),
            original_dns: Some(vec!["192.168.1.1".into()]),
            original_ipv6_mode: "Automatic".into(),
            original_ipv6_manual: None,
            original_web_proxy: Some(ProxySetting {
                enabled: false,
                server: "".into(),
                port: 0,
            }),
            original_secure_web_proxy: None,
            original_socks_proxy: None,
        });
        record
            .browser_policies_original
            .insert("com.google.Chrome".into(), Some("default".into()));
        record
            .clash_files_backup
            .insert("/tmp/clash.yaml".into(), "port: 7890".into());

        save_recovery_record(&temp_dir, &record).unwrap();
        let loaded = load_recovery_record(&temp_dir)
            .unwrap()
            .expect("record must exist");
        assert_eq!(loaded, record);

        clear_recovery_record(&temp_dir).unwrap();
        assert_eq!(load_recovery_record(&temp_dir).unwrap(), None);

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}

#[derive(Debug)]
pub struct RestoreTask {
    pub id: String,
    pub program: String,
    pub commands: Vec<Vec<String>>,
}
pub fn service_tasks(sb: &ServiceBackup) -> Result<Vec<RestoreTask>, String> {
    let svc = &sb.service_name;
    let mut tasks = vec![];
    let mut dns = vec!["-setdnsservers".into(), svc.clone()];
    match &sb.original_dns {
        Some(servers)
            if !servers.is_empty()
                && servers
                    .iter()
                    .all(|s| s.parse::<std::net::IpAddr>().is_ok()) =>
        {
            dns.extend(servers.clone())
        }
        None => dns.push("Empty".into()),
        _ => {
            return Err(format!(
                "{svc} 的旧 DNS 备份无效，已保留记录，拒绝猜测恢复值"
            ))
        }
    }
    tasks.push(RestoreTask {
        id: format!("{svc}:dns"),
        program: "/usr/sbin/networksetup".into(),
        commands: vec![dns],
    });
    let v6 = match sb.original_ipv6_mode.as_str() {
        "Off" => vec!["-setv6off".into(), svc.clone()],
        "LinkLocal" => vec!["-setv6linklocal".into(), svc.clone()],
        "Automatic" => vec!["-setv6automatic".into(), svc.clone()],
        "Manual" => {
            let m = sb.original_ipv6_manual.as_ref().ok_or_else(|| {
                format!("{svc} 的旧版本备份缺少手动 IPv6 参数，请手动恢复；记录保留")
            })?;
            if m.address.parse::<std::net::Ipv6Addr>().is_err()
                || m.router.parse::<std::net::Ipv6Addr>().is_err()
                || m.prefix > 128
            {
                return Err("手动 IPv6 参数无效".into());
            }
            vec![
                "-setv6manual".into(),
                svc.clone(),
                m.address.clone(),
                m.prefix.to_string(),
                m.router.clone(),
            ]
        }
        _ => return Err(format!("{svc} 的 IPv6 原始模式未知，拒绝恢复为自动模式")),
    };
    tasks.push(RestoreTask {
        id: format!("{svc}:ipv6"),
        program: "/usr/sbin/networksetup".into(),
        commands: vec![v6],
    });
    for (kind, set, state, original) in [
        (
            "web",
            "-setwebproxy",
            "-setwebproxystate",
            &sb.original_web_proxy,
        ),
        (
            "secure",
            "-setsecurewebproxy",
            "-setsecurewebproxystate",
            &sb.original_secure_web_proxy,
        ),
        (
            "socks",
            "-setsocksfirewallproxy",
            "-setsocksfirewallproxystate",
            &sb.original_socks_proxy,
        ),
    ] {
        let p = original
            .as_ref()
            .ok_or_else(|| format!("{svc} 的 {kind} 代理备份缺失，拒绝猜测"))?;
        let mut commands = vec![];
        if !p.server.is_empty() && p.port != 0 {
            commands.push(vec![
                set.into(),
                svc.clone(),
                p.server.clone(),
                p.port.to_string(),
            ]);
        } else if p.enabled {
            return Err(format!("{svc} 的 {kind} 代理地址无效"));
        }
        commands.push(vec![
            state.into(),
            svc.clone(),
            if p.enabled { "on" } else { "off" }.into(),
        ]);
        tasks.push(RestoreTask {
            id: format!("{svc}:{kind}"),
            program: "/usr/sbin/networksetup".into(),
            commands,
        });
    }
    Ok(tasks)
}

pub async fn run_tasks<F, Fut>(
    dir: &Path,
    record: &mut RecoveryRecord,
    tasks: Vec<RestoreTask>,
    mut run: F,
) -> Result<(), Vec<String>>
where
    F: FnMut(String, Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut errors = vec![];
    for task in tasks {
        if record.completed.contains(&task.id) {
            continue;
        }
        let mut ok = true;
        for args in task.commands {
            if let Err(e) = run(task.program.clone(), args).await {
                errors.push(format!("{}: {e}", task.id));
                ok = false;
                break;
            }
        }
        if ok {
            record.completed.insert(task.id.clone());
            if let Err(e) = save_recovery_record(dir, record) {
                record.completed.remove(&task.id);
                errors.push(e);
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    #[tokio::test]
    async fn failed_proxy_task_is_retained_and_only_unfinished_work_retries() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let mut record = RecoveryRecord::new();
        let tasks = || {
            vec![
                RestoreTask {
                    id: "dns".into(),
                    program: "fixture".into(),
                    commands: vec![vec!["dns".into()]],
                },
                RestoreTask {
                    id: "proxy".into(),
                    program: "fixture".into(),
                    commands: vec![vec!["proxy".into()]],
                },
            ]
        };
        let first = run_tasks(&dir, &mut record, tasks(), |_, args| async move {
            if args[0] == "proxy" {
                Err("permission denied".into())
            } else {
                Ok(())
            }
        })
        .await;
        assert!(first.is_err());
        assert!(load_recovery_record(&dir).unwrap().is_some());
        assert!(record.completed.contains("dns"));
        assert!(!record.completed.contains("proxy"));
        run_tasks(&dir, &mut record, tasks(), |_, args| async move {
            assert_eq!(args[0], "proxy");
            Ok(())
        })
        .await
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn manual_ipv6_without_parameters_never_falls_back_to_automatic() {
        let sb = ServiceBackup {
            service_name: "fixture".into(),
            original_dns: None,
            original_ipv6_mode: "Manual".into(),
            original_ipv6_manual: None,
            original_web_proxy: None,
            original_secure_web_proxy: None,
            original_socks_proxy: None,
        };
        assert!(service_tasks(&sb).unwrap_err().contains("手动 IPv6"));
        assert!(parse_networksetup_proxy_output("").is_none());
        assert_eq!(
            parse_networksetup_proxy_output("Enabled: Yes\nServer: 2001:db8::1\nPort: 8080")
                .unwrap()
                .server,
            "2001:db8::1"
        );
    }
}
