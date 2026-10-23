//! Ordinary desktop shortcuts, deliberately separate from guarded tool launch.
//! The frontend supplies only a catalogue ID; executable paths/arguments are resolved here.
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shortcut {
    pub id: String,
    pub name: String,
}
struct App {
    id: &'static str,
    name: &'static str,
    bundles: &'static [&'static str],
    binaries: &'static [&'static str],
    windows: &'static [&'static str],
}
const APPS: &[App] = &[
    App {
        id: "chatgpt",
        name: "ChatGPT",
        bundles: &["ChatGPT"],
        binaries: &[],
        windows: &["Programs/ChatGPT/ChatGPT.exe"],
    },
    App {
        id: "claude",
        name: "Claude",
        bundles: &["Claude"],
        binaries: &[],
        windows: &["AnthropicClaude/claude.exe", "Programs/Claude/Claude.exe"],
    },
    App {
        id: "codex",
        name: "Codex",
        bundles: &["Codex"],
        binaries: &[],
        windows: &["Programs/Codex/Codex.exe"],
    },
    App {
        id: "cursor",
        name: "Cursor",
        bundles: &["Cursor"],
        binaries: &["cursor"],
        windows: &["Programs/cursor/Cursor.exe", "Cursor/Cursor.exe"],
    },
    App {
        id: "windsurf",
        name: "Windsurf",
        bundles: &["Windsurf"],
        binaries: &["windsurf"],
        windows: &["Programs/Windsurf/Windsurf.exe", "Windsurf/Windsurf.exe"],
    },
    App {
        id: "antigravity",
        name: "Antigravity",
        bundles: &["Antigravity"],
        binaries: &["antigravity"],
        windows: &[
            "Programs/Antigravity/Antigravity.exe",
            "Antigravity/Antigravity.exe",
        ],
    },
    App {
        id: "zed",
        name: "Zed",
        bundles: &["Zed", "Zed Preview"],
        binaries: &["zed", "zeditor"],
        windows: &["Programs/Zed/zed.exe", "Zed/zed.exe"],
    },
];
#[derive(Clone)]
enum Target {
    #[allow(dead_code)]
    File(PathBuf),
    #[cfg(target_os = "windows")]
    Registered(String),
}
fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}
fn file_target(path: &Path) -> Option<Target> {
    crate::platform::validate_tool_path(&path.to_string_lossy())
        .ok()
        .map(|(p, _)| Target::File(p))
}
fn find_file(app: &App) -> Option<Target> {
    if cfg!(target_os = "macos") {
        let mut roots = vec![PathBuf::from("/Applications")];
        if let Some(home) = home() {
            roots.push(home.join("Applications"));
        }
        for root in roots {
            for name in app.bundles {
                if let Some(target) = file_target(&root.join(format!("{name}.app"))) {
                    return Some(target);
                }
            }
        }
    } else if cfg!(target_os = "windows") {
        for key in ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(root) = std::env::var_os(key).map(PathBuf::from) {
                for suffix in app.windows {
                    if let Some(target) = file_target(&root.join(suffix)) {
                        return Some(target);
                    }
                }
                // Claude's updater uses versioned app-* directories on some installations.
                if app.id == "claude" {
                    if let Ok(entries) = std::fs::read_dir(root.join("AnthropicClaude")) {
                        let mut paths: Vec<_> = entries
                            .flatten()
                            .take(100)
                            .map(|e| e.path())
                            .filter(|p| {
                                p.file_name()
                                    .is_some_and(|s| s.to_string_lossy().starts_with("app-"))
                            })
                            .collect();
                        paths.sort();
                        for path in paths.into_iter().rev() {
                            if let Some(target) = file_target(&path.join("claude.exe")) {
                                return Some(target);
                            }
                        }
                    }
                }
            }
        }
    } else if cfg!(target_os = "linux") {
        let mut roots: Vec<_> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        roots.extend([PathBuf::from("/usr/bin"), PathBuf::from("/usr/local/bin")]);
        if let Some(home) = home() {
            roots.extend([home.join(".local/bin"), home.join(".local/share/zed")]);
        }
        for name in app.binaries {
            for root in &roots {
                if let Some(target) = file_target(&root.join(name)) {
                    return Some(target);
                }
            }
            for path in [
                format!("/opt/{name}/{name}"),
                format!("/opt/{name}/bin/{name}"),
            ] {
                if let Some(target) = file_target(Path::new(&path)) {
                    return Some(target);
                }
            }
        }
    }
    // Portable AppImages are often kept outside PATH. Only inspect these shallow folders.
    if cfg!(target_os = "linux") {
        if let Some(home) = home() {
            for folder in ["Applications", "Downloads", ".local/bin"] {
                if let Ok(entries) = std::fs::read_dir(home.join(folder)) {
                    let mut paths: Vec<_> = entries
                        .flatten()
                        .take(1000)
                        .map(|e| e.path())
                        .filter(|p| {
                            let name = p
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_ascii_lowercase();
                            name.ends_with(".appimage")
                                && app.binaries.iter().any(|binary| {
                                    name.strip_prefix(binary).is_some_and(|suffix| {
                                        suffix.starts_with(['-', '_', '.', ' '])
                                    })
                                })
                        })
                        .collect();
                    paths.sort();
                    for path in paths.into_iter().rev() {
                        if let Some(target) = file_target(&path) {
                            return Some(target);
                        }
                    }
                }
            }
        }
    }

    None
}
fn catalogue(id: &str) -> Result<&'static App, String> {
    APPS.iter()
        .find(|app| app.id == id)
        .ok_or_else(|| "未登记的 AI 应用，请重新扫描".into())
}
#[cfg(any(target_os = "windows", test))]
fn registered_apps(text: &str) -> Result<Vec<(String, String)>, String> {
    let value: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .map_err(|_| "开始菜单应用列表读取失败")?;
    let entries = match &value {
        serde_json::Value::Array(items) => items.as_slice(),
        serde_json::Value::Null => &[],
        _ => std::slice::from_ref(&value),
    };
    Ok(entries
        .iter()
        .filter_map(|v| {
            let name = v.get("Name")?.as_str()?;
            let id = v.get("AppID")?.as_str()?;
            if id.is_empty()
                || id.len() > 512
                || id.chars().any(char::is_control)
                || id.contains(['"', '/', '\\'])
            {
                return None;
            }
            APPS.iter()
                .find(|app| app.name.eq_ignore_ascii_case(name))
                .map(|app| (app.id.to_owned(), id.to_owned()))
        })
        .collect())
}
async fn targets() -> Result<Vec<(&'static App, Target)>, String> {
    let mut found: Vec<_> = APPS
        .iter()
        .filter_map(|app| find_file(app).map(|target| (app, target)))
        .collect();
    #[cfg(target_os = "windows")]
    {
        let text = crate::platform::run_cmd_checked(crate::firewall::system_powershell()?.to_string_lossy().as_ref(), &["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'; [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); @(Get-StartApps | Select-Object Name,AppID) | ConvertTo-Json -Compress"]).await?;
        for (id, registered) in registered_apps(&text)? {
            if !found.iter().any(|(app, _)| app.id == id) {
                found.push((catalogue(&id)?, Target::Registered(registered)));
            }
        }
    }
    found.sort_by_key(|(app, _)| APPS.iter().position(|item| item.id == app.id));
    Ok(found)
}
pub async fn scan() -> Result<Vec<Shortcut>, String> {
    Ok(targets()
        .await?
        .into_iter()
        .map(|(app, _)| Shortcut {
            id: app.id.into(),
            name: app.name.into(),
        })
        .collect())
}
pub async fn launch(id: &str) -> Result<(), String> {
    catalogue(id)?;
    let (_, target) = targets()
        .await?
        .into_iter()
        .find(|(app, _)| app.id == id)
        .ok_or("应用已移动或卸载，请重新扫描")?;
    let mut command = match target {
        Target::File(path) => {
            #[cfg(target_os = "macos")]
            {
                let mut command = tokio::process::Command::new("/usr/bin/open");
                command.arg("-a").arg(path);
                command
            }
            #[cfg(not(target_os = "macos"))]
            {
                tokio::process::Command::new(path)
            }
        }
        #[cfg(target_os = "windows")]
        Target::Registered(id) => {
            let root = std::env::var_os("WINDIR")
                .map(PathBuf::from)
                .ok_or("找不到 Windows 目录")?;
            let mut command = tokio::process::Command::new(root.join("explorer.exe"));
            command.arg(format!("shell:AppsFolder\\{id}"));
            command
        }
    };
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(target_os = "macos")]
    {
        command.kill_on_drop(true);
        let status = tokio::time::timeout(std::time::Duration::from_secs(15), command.status())
            .await
            .map_err(|_| "启动应用超时，请检查系统提示")?
            .map_err(|_| "无法打开应用，请重新扫描")?;
        if !status.success() {
            return Err("应用未能打开，请重新扫描或检查系统权限".into());
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        command
            .spawn()
            .map_err(|_| "无法启动应用，请重新扫描或检查执行权限")?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_catalogue_ids_can_launch() {
        assert!(catalogue("cursor").is_ok());
        for id in ["/bin/sh", "cursor --help", "../Claude.app", "unknown"] {
            assert!(catalogue(id).is_err());
        }
    }
    #[test]
    fn start_menu_exact_names_single_array_and_invalid_ids() {
        assert_eq!(
            registered_apps(r#"{"Name":"ChatGPT","AppID":"OpenAI.ChatGPT_123!App"}"#)
                .unwrap()
                .len(),
            1
        );
        assert!(registered_apps("null").unwrap().is_empty());
        assert!(registered_apps("broken").is_err());
        let apps = registered_apps(r#"[{"Name":"Cursor","AppID":"Cursor"},{"Name":"Claude helper","AppID":"helper"},{"Name":"Claude","AppID":"C:\\evil.exe"}]"#).unwrap();
        assert_eq!(apps, vec![("cursor".into(), "Cursor".into())]);
    }
}
