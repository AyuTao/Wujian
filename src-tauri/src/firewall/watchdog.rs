//! A privileged helper performs fault isolation without another prompt.
//! The firewall itself, not this polling loop, prevents physical fallback.
use super::{command, policy::Policy, ManagedState, Receipt};
use std::path::{Path, PathBuf};
const LABEL: &str = "io.wujian.tunnel-guard";
const PLIST: &str = "/Library/LaunchDaemons/io.wujian.tunnel-guard.plist";
#[cfg(target_os = "linux")]
const UNIT: &str = "/etc/systemd/system/io.wujian.tunnel-guard.service";
#[cfg(target_os = "windows")]
const TASK: &str = r"\io.wujian.tunnel-guard";

fn mirror_path() -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    {
        return Ok(PathBuf::from("/var/run/io.wujian.tunnel-guard.json"));
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(PathBuf::from("/run/io.wujian.tunnel-guard.json"));
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(super::windows::program_data()?.join("io.wujian.tunnel-guard.json"));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("不支持该平台".into())
    }
}

pub async fn install(dir: &Path) -> Result<(), String> {
    crate::audit::record_async("watchdog.install", async {
        copy_helper(dir)?;
        #[cfg(target_os = "macos")]
        {
            return install_launchd().await;
        }
        #[cfg(target_os = "linux")]
        {
            return install_systemd(dir).await;
        }
        #[cfg(target_os = "windows")]
        {
            return install_task(dir).await;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = dir;
            Err("不支持该平台".into())
        }
    })
    .await
}

fn copy_helper(dir: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "无法定位隧道保护 helper")?;
    let dest_name = if cfg!(windows) {
        "tunnel-helper.exe"
    } else {
        "tunnel-helper"
    };
    let dest = dir.join(dest_name);
    let temp = dir.join(format!(".helper-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut source = std::fs::File::open(&exe).map_err(|_| "无法读取 helper")?;
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&temp)
                .map_err(|_| "无法创建 root helper")?;
            std::io::copy(&mut source, &mut target).map_err(|_| "无法复制 root helper")?;
            target.sync_all().map_err(|_| "无法同步 root helper")?;
        }
        #[cfg(windows)]
        {
            std::fs::copy(&exe, &temp).map_err(|_| "无法复制 root helper")?;
        }
        std::fs::rename(&temp, &dest).map_err(|_| "无法保存 root helper")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn helper_executable(dir: &Path) -> Result<String, String> {
    let name = if cfg!(windows) {
        "tunnel-helper.exe"
    } else {
        "tunnel-helper"
    };
    let path = dir.join(name);
    let text = path.to_str().ok_or("helper 路径无效")?.to_string();
    if !path.is_absolute()
        || text
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || "\"'".contains(ch))
    {
        return Err("helper 路径无效".into());
    }
    Ok(text)
}

#[cfg(target_os = "macos")]
async fn install_launchd() -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    {
        let expected = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array><string>/var/db/io.wujian.firewall/tunnel-helper</string><string>--tunnel-watchdog</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>3</integer><key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer></dict></plist>\n");
        if let Ok(meta) = std::fs::symlink_metadata(PLIST) {
            if !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || std::fs::read_to_string(PLIST).ok().as_deref() != Some(expected.as_str())
            {
                return Err("常驻 helper 的 launchd 配置归属或内容异常，拒绝覆盖".into());
            }
        }
        super::write_private(Path::new(PLIST), expected.as_bytes())?;
        std::fs::set_permissions(PLIST, std::fs::Permissions::from_mode(0o644))
            .map_err(|_| "无法设置 launchd 配置权限")?;
        let target = format!("system/{LABEL}");
        if command::run(Path::new("/bin/launchctl"), &["print", &target], None)
            .await
            .is_err()
        {
            command::run(
                Path::new("/bin/launchctl"),
                &["bootstrap", "system", PLIST],
                None,
            )
            .await
            .map_err(|_| "无法启动常驻保护 helper；规则可能已保留，请核验或停止保护")?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn install_systemd(dir: &Path) -> Result<(), String> {
    let exe = helper_executable(dir)?;
    let expected = format!(
        "[Unit]\nDescription=Wujian tunnel guard\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={exe} --tunnel-watchdog\nRestart=always\nRestartSec=3\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n"
    );
    if let Ok(text) = std::fs::read_to_string(UNIT) {
        if text != expected {
            return Err("常驻 helper 的 systemd 配置归属或内容异常，拒绝覆盖".into());
        }
    }
    super::write_private(Path::new(UNIT), expected.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(UNIT, std::fs::Permissions::from_mode(0o644))
            .map_err(|_| "无法设置 systemd 配置权限")?;
    }
    let bin = systemctl().ok_or("未安装 systemd，不能启动常驻保护")?;
    command::run(&bin, &["daemon-reload"], None)
        .await
        .map_err(|_| "无法重新加载 systemd")?;
    command::run(&bin, &["enable", "--now", LABEL], None)
        .await
        .map_err(|_| "无法启动常驻保护 helper；规则可能已保留，请核验或停止保护")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemctl() -> Option<PathBuf> {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

#[cfg(target_os = "windows")]
async fn install_task(dir: &Path) -> Result<(), String> {
    let exe = helper_executable(dir)?;
    let bin = schtasks()?;
    let command_line = format!("{exe} --tunnel-watchdog");
    command::run(
        &bin,
        &[
            "/Create",
            "/F",
            "/TN",
            TASK,
            "/SC",
            "ONSTART",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/TR",
            &command_line,
        ],
        None,
    )
    .await
    .map_err(|_| "无法登记常驻保护计划任务")?;
    command::run(&bin, &["/Run", "/TN", TASK], None)
        .await
        .map_err(|_| "无法启动常驻保护 helper；规则可能已保留，请核验或停止保护")?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn schtasks() -> Result<PathBuf, String> {
    let root = std::env::var_os("SystemRoot").ok_or("无法定位 SystemRoot")?;
    let path = PathBuf::from(root).join("System32").join("schtasks.exe");
    if path.is_file() {
        Ok(path)
    } else {
        Err("找不到 schtasks".into())
    }
}

pub async fn remove() -> Result<(), String> {
    crate::audit::record_async("watchdog.remove", async {
        #[cfg(target_os = "macos")]
        {
            remove_launchd().await?;
        }
        #[cfg(target_os = "linux")]
        {
            remove_systemd().await?;
        }
        #[cfg(target_os = "windows")]
        {
            remove_task().await?;
        }
        clear_status();
        Ok(())
    })
    .await
}

#[cfg(target_os = "macos")]
async fn remove_launchd() -> Result<(), String> {
    let target = format!("system/{LABEL}");
    if command::run(Path::new("/bin/launchctl"), &["print", &target], None)
        .await
        .is_ok()
    {
        command::run(Path::new("/bin/launchctl"), &["bootout", &target], None)
            .await
            .map_err(|_| "常驻保护 helper 尚未停止，拒绝宣称已解除")?;
    }
    if Path::new(PLIST).exists() {
        std::fs::remove_file(PLIST).map_err(|_| "无法删除本工具的 launchd 配置")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn remove_systemd() -> Result<(), String> {
    if Path::new(UNIT).exists() {
        let text = std::fs::read_to_string(UNIT).unwrap_or_default();
        if !text.contains("--tunnel-watchdog") || !text.contains("io.wujian") {
            return Err("常驻 helper 的 systemd 配置归属异常，拒绝删除".into());
        }
    }
    if let Some(bin) = systemctl() {
        let _ = command::run(&bin, &["disable", "--now", LABEL], None).await;
        if Path::new(UNIT).exists() {
            std::fs::remove_file(UNIT).map_err(|_| "无法删除本工具的 systemd 配置")?;
            let _ = command::run(&bin, &["daemon-reload"], None).await;
        }
        if command::run(&bin, &["is-active", LABEL], None)
            .await
            .is_ok()
        {
            return Err("常驻保护 helper 尚未停止，拒绝宣称已解除".into());
        }
    } else if Path::new(UNIT).exists() {
        return Err("无法停止常驻保护 helper".into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn remove_task() -> Result<(), String> {
    let bin = schtasks()?;
    if command::run(&bin, &["/Query", "/TN", TASK], None)
        .await
        .is_ok()
    {
        let _ = command::run(&bin, &["/End", "/TN", TASK], None).await;
        command::run(&bin, &["/Delete", "/F", "/TN", TASK], None)
            .await
            .map_err(|_| "常驻保护 helper 尚未停止，拒绝宣称已解除")?;
    }
    Ok(())
}

pub fn clear_status() {
    if let Ok(path) = mirror_path() {
        let _ = std::fs::remove_file(path);
    }
}

pub(crate) fn publish(mut receipt: Receipt) -> Result<(), String> {
    crate::audit::transition(
        "watchdog.state",
        if !receipt.configuration_active {
            "unconfirmed"
        } else {
            match receipt.policy_mode.as_str() {
                "tunnel" => "protected",
                "isolation" => "isolated",
                _ => "active",
            }
        },
        None,
    );
    // A public, minimal status file; never expose node names, hosts, or credentials.
    receipt.guard_policy = None;
    let bytes = serde_json::to_vec(&receipt).map_err(|_| "无法编码保护状态")?;
    let path = mirror_path()?;
    super::write_private(&path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|_| "无法发布只读保护状态")?;
    }
    Ok(())
}

pub fn read_status() -> Result<Receipt, String> {
    let path = mirror_path()?;
    let meta = std::fs::symlink_metadata(&path).map_err(|_| "保护状态还没有写好")?;
    if !meta.is_file() || meta.len() > 64 * 1024 {
        return Err("常驻保护状态文件无效".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("常驻保护状态不是可信 root 回执".into());
        }
    }
    let receipt: Receipt = super::read_json(&path, 64 * 1024)?;
    let at = chrono::DateTime::parse_from_rfc3339(&receipt.checked_at)
        .map_err(|_| "保护状态时间无效")?;
    let age = chrono::Utc::now().signed_duration_since(at).num_seconds();
    if !(0..20).contains(&age) {
        return Err("保护状态过期，正在重新确认".into());
    }
    Ok(receipt)
}

async fn apply_state(state: &mut ManagedState, dir: &Path) -> Result<Receipt, String> {
    #[cfg(target_os = "macos")]
    {
        return super::macos::apply(state, dir, true).await;
    }
    #[cfg(target_os = "linux")]
    {
        return super::linux::apply(state, dir).await;
    }
    #[cfg(target_os = "windows")]
    {
        return super::windows::apply(state, dir).await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (state, dir);
        Err("不支持该平台".into())
    }
}

async fn status_state(state: Option<&ManagedState>, dir: &Path) -> Result<Receipt, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = dir;
        return super::macos::status(state).await;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = dir;
        return super::linux::status(state).await;
    }
    #[cfg(target_os = "windows")]
    {
        return super::windows::status(state, dir).await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (state, dir);
        Err("不支持该平台".into())
    }
}

pub async fn run(dir: PathBuf) -> Result<(), String> {
    if !cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )) {
        return Err("不支持该平台".into());
    }
    loop {
        let operation = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("operation.lock"))
            .map_err(|_| "无法读取保护操作锁")?;
        if operation.try_lock().is_ok() {
            match super::load_state(&dir) {
                Ok(Some(mut state))
                    if state
                        .resume
                        .as_ref()
                        .is_some_and(|plan| plan.tunnel_guard.is_some()) =>
                {
                    let plan = state.resume.clone().unwrap();
                    let guard = plan.tunnel_guard.clone().unwrap();
                    match super::tunnel::resume_interface(&guard).await {
                        Ok(interface) => {
                            let mut restored = plan;
                            if let Some(guard) = restored.tunnel_guard.as_mut() {
                                guard.interface = interface;
                            }
                            restored.validate()?;
                            state.policy = restored;
                            state.resume = None;
                            super::save_state(&dir, &state)?;
                            let receipt = crate::audit::record_async(
                                "watchdog.resume",
                                apply_state(&mut state, &dir),
                            )
                            .await?;
                            publish(receipt)?;
                        }
                        Err(error) => hold(&mut state, &dir, &error).await?,
                    }
                }
                Ok(Some(mut state)) if state.policy.tunnel_guard.is_some() => {
                    let guard = state.policy.tunnel_guard.as_ref().unwrap().clone();
                    let verified = super::tunnel::verify(&guard).await;
                    let status = status_state(Some(&state), &dir).await;
                    if let (Ok(()), Ok(receipt)) = (&verified, &status) {
                        if receipt.configuration_active {
                            publish(receipt.clone())?;
                        } else {
                            hold(&mut state, &dir, "防回落规则回读不一致").await?;
                        }
                    } else {
                        let reason = verified
                            .err()
                            .unwrap_or_else(|| "全局模式、指定 TUN、节点或控制接口失效".into());
                        hold(&mut state, &dir, &reason).await?;
                    }
                }
                Ok(Some(mut state)) => {
                    let mut status = status_state(Some(&state), &dir).await?;
                    if state.policy.lockdown && !status.configuration_active {
                        status = crate::audit::record_async(
                            "watchdog.reapply",
                            apply_state(&mut state, &dir),
                        )
                        .await?;
                    }
                    publish(status)?;
                }
                Ok(None) => {
                    crate::audit::event("watchdog.stop", "released", None, None);
                    clear_status();
                    return Ok(());
                }
                Err(_) => {
                    // A damaged manifest cannot restore connectivity.
                    let mut state = ManagedState {
                        policy: Policy::isolation(),
                        resume: None,
                        pf_token: None,
                        fingerprint: None,
                    };
                    hold(&mut state, &dir, "保护状态文件损坏").await?;
                }
            }
        }
        drop(operation);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn hold(state: &mut ManagedState, dir: &Path, reason: &str) -> Result<(), String> {
    crate::audit::transition("watchdog.reason", "isolated", Some(reason));
    if state.resume.is_none() && state.policy.tunnel_guard.is_some() {
        state.resume = Some(state.policy.clone());
    }
    let waiting = state.resume.is_some();
    let detail = if waiting {
        format!("{reason}。网络已切断。同一节点恢复后会自动继续保护；节点变了请停止后重新确认。")
    } else {
        format!("{reason}。公网已切断，私网仍可通。请在无间道中停止保护后恢复。")
    };
    if state.policy.tunnel_guard.is_some() || !state.policy.lockdown {
        state.policy = Policy::isolation();
        super::save_state(dir, state)?;
        let mut receipt =
            crate::audit::record_async("watchdog.isolate", apply_state(state, dir)).await?;
        receipt.detail = detail;
        return publish(receipt);
    }
    let mut status = status_state(Some(state), dir).await?;
    if !status.configuration_active {
        status = crate::audit::record_async("watchdog.reapply", apply_state(state, dir)).await?;
    }
    status.detail = detail;
    publish(status)
}
