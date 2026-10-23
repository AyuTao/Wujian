use super::{command, render, ManagedState, Receipt};
use serde_json::Value;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
pub fn powershell() -> Result<PathBuf, String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = [0u16; 32768];
    let size = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if size == 0 || size >= buffer.len() {
        return Err("无法定位 Windows 系统目录".into());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..size]))
        .join("WindowsPowerShell/v1.0/powershell.exe"))
}
#[cfg(not(target_os = "windows"))]
pub fn powershell() -> Result<PathBuf, String> {
    Err("当前不是 Windows".into())
}
async fn script(text: &str, dir: &Path) -> Result<String, String> {
    let path = dir.join(format!("operation-{}.ps1", uuid::Uuid::new_v4().simple()));
    // Windows PowerShell 5.1 requires a BOM for non-ASCII file contents.
    super::write_private(&path, format!("\u{feff}{text}").as_bytes())?;
    let result = command::run(
        &powershell()?,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            path.to_str().ok_or("脚本路径无效")?,
        ],
        None,
    )
    .await;
    let _ = std::fs::remove_file(path);
    result
}
async fn current(dir: &Path) -> Result<Value, String> {
    let text = script(&render::windows_status(), dir).await?;
    serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .map_err(|_| "无法解码 Windows 防火墙状态".into())
}
fn profiles_ok(v: &Value) -> bool {
    v["profiles"].as_array().is_some_and(|a| {
        a.len() == 3
            && a.iter()
                .all(|p| p["enabled"] == "True" && p["localRules"] != "False")
    })
}
fn address_condition(text: &str) -> Option<super::cidr::Cidr> {
    if let Ok(cidr) = super::cidr::Cidr::parse(text) {
        return Some(cidr);
    }
    // Windows may return an IPv4 subnet mask instead of a prefix length.
    let (address, mask) = text.split_once('/')?;
    let mask = u32::from(mask.parse::<std::net::Ipv4Addr>().ok()?);
    let prefix = mask.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if mask != expected {
        return None;
    }
    super::cidr::Cidr::parse(&format!("{address}/{prefix}")).ok()
}
fn generation_ok(v: &Value, state: &ManagedState) -> bool {
    let denied = state.policy.denied();
    let Some(rules) = v["rules"].as_array() else {
        return false;
    };
    if !profiles_ok(v) || rules.len() != denied.len().div_ceil(128) * 2 {
        return false;
    }
    for (index, chunk) in denied.chunks(128).enumerate() {
        for direction in ["Inbound", "Outbound"] {
            let name = format!("Wujian-{}-{direction}-{index}", state.policy.generation);
            let Some(rule) = rules.iter().find(|r| r["name"] == name) else {
                return false;
            };
            if rule["enabled"] != "True"
                || rule["action"] != "Block"
                || rule["description"] != render::OWNER
                || rule["direction"] != direction
            {
                return false;
            }
            let Some(addresses) = rule["addresses"].as_array() else {
                return false;
            };
            let Some(actual) = addresses
                .iter()
                .map(|v| v.as_str().and_then(address_condition))
                .collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            for v4 in [true, false] {
                if super::cidr::complement(&actual, v4) != super::cidr::complement(chunk, v4) {
                    return false;
                }
            }
        }
    }
    true
}
fn rules_match(v: &Value, state: &ManagedState) -> bool {
    if state.policy.tunnel_guard.is_some() {
        tunnel_rules_ok(v, state)
    } else {
        generation_ok(v, state)
    }
}
fn tunnel_rules_ok(v: &Value, state: &ManagedState) -> bool {
    let Some(guard) = state.policy.tunnel_guard.as_ref() else {
        return false;
    };
    if !profiles_ok(v) {
        return false;
    }
    let Some(rules) = v["rules"].as_array() else {
        return false;
    };
    let plan = render::tunnel_plan(guard);
    if rules.len() != plan.len() {
        return false;
    }
    let Some(adapters) = string_list(&v["adapters"]) else {
        return false;
    };
    if adapters.is_empty() {
        return false;
    }
    for planned in &plan {
        let name = format!("Wujian-{}-{}", state.policy.generation, planned.suffix);
        let Some(rule) = rules.iter().find(|rule| rule["name"] == name) else {
            return false;
        };
        if rule["enabled"] != "True"
            || rule["action"] != "Block"
            || rule["description"] != render::OWNER
            || rule["direction"] != planned.direction
            || !protocol_ok(rule["protocol"].as_str().unwrap_or(""), planned.protocol)
            || !ports_ok(&rule["ports"], &planned.ports)
        {
            return false;
        }
        let Some(addresses) = rule["addresses"].as_array() else {
            return false;
        };
        let Some(actual) = addresses
            .iter()
            .map(|value| value.as_str().and_then(address_condition))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        for v4 in [true, false] {
            if super::cidr::complement(&actual, v4)
                != super::cidr::complement(&planned.addresses, v4)
            {
                return false;
            }
        }
        let Some(interfaces) = string_list(&rule["interfaces"]) else {
            return false;
        };
        if interfaces.is_empty() || interfaces.iter().any(|name| name == &guard.interface) {
            return false;
        }
        for adapter in &adapters {
            if adapter != &guard.interface && !interfaces.iter().any(|name| name == adapter) {
                return false;
            }
        }
    }
    true
}
fn string_list(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect(),
        Value::String(text) => Some(vec![text.clone()]),
        Value::Number(number) => Some(vec![number.to_string()]),
        _ => None,
    }
}
fn protocol_ok(actual: &str, expected: &str) -> bool {
    let actual = actual.to_ascii_lowercase();
    match expected {
        "Any" => actual == "any" || actual == "256",
        "TCP" => actual == "tcp" || actual == "6",
        "UDP" => actual == "udp" || actual == "17",
        "ICMPv4" => actual == "icmpv4" || actual == "1" || actual == "icmp",
        _ => false,
    }
}
fn ports_ok(actual: &Value, expected: &[String]) -> bool {
    let Some(values) = string_list(actual) else {
        return expected.is_empty();
    };
    let normalize = |text: &str| text.replace(' ', "");
    if expected.is_empty() {
        return values.is_empty()
            || values.iter().all(|value| {
                let value = value.trim();
                value.eq_ignore_ascii_case("Any") || value == "*" || value.is_empty()
            });
    }
    values.len() == expected.len()
        && expected
            .iter()
            .all(|want| values.iter().any(|got| normalize(got) == normalize(want)))
}
pub fn check_plan(policy: &super::policy::Policy) -> Result<(), String> {
    let script = render::windows(policy)?;
    if script.contains("-Action Allow")
        || !script.contains("-Action Block")
        || !script.contains("WUJIAN_APPLY_OK")
    {
        return Err("Windows 规则草稿无效".into());
    }
    if policy.tunnel_guard.is_some()
        && (!script.contains("Get-NetAdapter") || !script.contains("-InterfaceAlias"))
    {
        return Err("Windows 隧道规则草稿无效".into());
    }
    #[cfg(target_os = "windows")]
    {
        powershell()?;
    }
    Ok(())
}
pub async fn apply(state: &mut ManagedState, dir: &Path) -> Result<Receipt, String> {
    let text = script(&render::windows(&state.policy)?, dir).await?;
    if !text.contains("WUJIAN_APPLY_OK") {
        return Err("Windows 防火墙未返回完成回执；请查询或解除当前规则".into());
    }
    let value = current(dir).await?;
    if !rules_match(&value, state) {
        return Err("Windows 活动规则核验失败；已建立的限制保持，请查询或解除".into());
    }
    state.fingerprint = Some(super::fingerprint(&value));
    super::save_state(dir, state)?;
    status(Some(state), dir).await
}
pub async fn release(dir: &Path) -> Result<Receipt, String> {
    script(&render::windows_remove(), dir).await?;
    let value = current(dir).await?;
    if value["rules"].as_array().is_none_or(|v| !v.is_empty()) {
        return Err("Windows 防火墙组仍有规则，解除核验未通过".into());
    }
    Ok(Receipt::new(
        false,
        None,
        "已核验本软件 Windows 防火墙组为空；其他规则未删除，请复测联网。",
    ))
}
pub async fn status(state: Option<&ManagedState>, dir: &Path) -> Result<Receipt, String> {
    let value = current(dir).await?;
    let active = state.is_some_and(|s| {
        rules_match(&value, s) && s.fingerprint == Some(super::fingerprint(&value))
    });
    let tunnel = state.is_some_and(|s| s.policy.tunnel_guard.is_some());
    Ok(Receipt::new(
        active,
        state.map(|s| s.policy.generation.clone()),
        if active && tunnel {
            "Windows 活动规则已按网卡回读：物理网卡上的公网被拦截，指定 TUN 不在拦截名单里。"
        } else if active {
            "Windows 活动规则、系统配置与地址条件回读匹配；已有流及隧道覆盖仍需实测。"
        } else {
            "Windows 防火墙未核验到完整受管隔断；不能将安装成功当作流量验收。"
        },
    ))
}
#[cfg(target_os = "windows")]
pub fn program_data() -> Result<PathBuf, String> {
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetFolderPathW(
            hwnd: *mut std::ffi::c_void,
            csidl: i32,
            token: *mut std::ffi::c_void,
            flags: u32,
            path: *mut u16,
        ) -> i32;
    }
    let mut buffer = [0u16; 260];
    let code = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            0x0023,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    if code < 0 {
        return Err("无法定位系统 ProgramData".into());
    }
    let length = buffer.iter().position(|&c| c == 0).ok_or("系统路径过长")?;
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..length])))
}
#[cfg(target_os = "windows")]
pub async fn secure_directory(dir: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(dir).map_err(|_| "无法核验防火墙状态目录")?;
    if meta.file_attributes() & 0x400 != 0 {
        return Err("隔断目录不得是 reparse point".into());
    }
    let path = super::ps_quote(dir.to_str().ok_or("系统路径无效")?);
    let script=format!("$ErrorActionPreference='Stop'; $acl=New-Object System.Security.AccessControl.DirectorySecurity; $acl.SetAccessRuleProtection($true,$false); foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {{ $id=New-Object System.Security.Principal.SecurityIdentifier($sid); $r=New-Object System.Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($r) }}; $owner=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'); $acl.SetOwner($owner); Set-Acl -LiteralPath {path} -AclObject $acl");
    command::run(
        &powershell()?,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        None,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_subnet_masks_are_decoded_without_accepting_arbitrary_conditions() {
        assert_eq!(
            address_condition("223.5.5.0/255.255.255.0"),
            address_condition("223.5.5.0/24")
        );
        assert!(address_condition("Any").is_none());
        assert!(address_condition("1.2.3.0/255.0.255.0").is_none());
    }
    #[test]
    fn readback_checks_addresses_and_both_directions_not_only_rule_count() {
        let state = ManagedState {
            policy: super::super::policy::Policy {
                tunnel_guard: None,
                lockdown: false,
                ipv6_only: false,
                version: 1,
                generation: "d".repeat(32),
                cn_networks: vec!["223.5.5.0/24".into()],
                extra_allowed: vec![],
            },
            resume: None,
            pf_token: None,
            fingerprint: None,
        };
        let mut rules = Vec::new();
        for (index, chunk) in state.policy.denied().chunks(128).enumerate() {
            for direction in ["Inbound", "Outbound"] {
                rules.push(serde_json::json!({"name":format!("Wujian-{}-{direction}-{index}",state.policy.generation),"enabled":"True","action":"Block","description":render::OWNER,"direction":direction,"addresses":chunk.iter().map(ToString::to_string).collect::<Vec<_>>() }));
            }
        }
        let mut v = serde_json::json!({"profiles":[{"enabled":"True"},{"enabled":"True"},{"enabled":"True"}],"rules":rules});
        assert!(generation_ok(&v, &state));
        v["rules"][0]["addresses"][0] = "223.5.5.0/24".into();
        assert!(!generation_ok(&v, &state));
    }
    #[test]
    fn tunnel_readback_requires_block_rules_on_every_adapter_except_the_tun() {
        let mut state = ManagedState {
            policy: super::super::policy::Policy::isolation(),
            resume: None,
            pf_token: None,
            fingerprint: None,
        };
        state.policy.lockdown = false;
        state.policy.tunnel_guard = Some(super::super::tunnel::fixture());
        let plan = render::tunnel_plan(state.policy.tunnel_guard.as_ref().unwrap());
        let rules: Vec<_> = plan
            .iter()
            .map(|rule| {
                serde_json::json!({
                    "name": format!("Wujian-{}-{}", state.policy.generation, rule.suffix),
                    "enabled": "True",
                    "action": "Block",
                    "description": render::OWNER,
                    "direction": rule.direction,
                    "protocol": rule.protocol,
                    "addresses": rule.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "interfaces": ["Ethernet"],
                    "ports": if rule.ports.is_empty() { vec!["Any".to_string()] } else { rule.ports.clone() },
                })
            })
            .collect();
        let value = serde_json::json!({
            "profiles": [{"enabled":"True"},{"enabled":"True"},{"enabled":"True"}],
            "adapters": ["Ethernet", "utun6"],
            "rules": rules,
        });
        assert!(tunnel_rules_ok(&value, &state));
        let mut exposed = value.clone();
        exposed["rules"][0]["interfaces"] = serde_json::json!(["Ethernet", "utun6"]);
        assert!(!tunnel_rules_ok(&exposed, &state));
        let mut missing = value.clone();
        missing["adapters"] = serde_json::json!(["Ethernet", "Wi-Fi", "utun6"]);
        assert!(!tunnel_rules_ok(&missing, &state));
        check_plan(&state.policy).unwrap();
    }
}
