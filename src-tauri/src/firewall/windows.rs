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
pub async fn apply(state: &mut ManagedState, dir: &Path) -> Result<Receipt, String> {
    let text = script(&render::windows(&state.policy)?, dir).await?;
    if !text.contains("WUJIAN_APPLY_OK") {
        return Err("Windows 防火墙未返回完成回执；请查询或解除当前规则".into());
    }
    let value = current(dir).await?;
    if !generation_ok(&value, state) {
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
        generation_ok(&value, s) && s.fingerprint == Some(super::fingerprint(&value))
    });
    Ok(Receipt::new(
        active,
        state.map(|s| s.policy.generation.clone()),
        if active {
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
                lockdown: false,
                ipv6_only: false,
                version: 1,
                generation: "d".repeat(32),
                cn_networks: vec!["223.5.5.0/24".into()],
                extra_allowed: vec![],
            },
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
}
