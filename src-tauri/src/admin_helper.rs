//! One administrator approval installs a resident root helper.
//! Later calls do not prompt when the helper answers.
//! An explicit action asks once if the helper does not respond.
//! Background calls pass `allow_prompt` false and stay silent.
//! The socket only accepts a timezone name or a typed firewall request. It never runs a shell command.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const LABEL: &str = "io.wujian.admin";
const PLIST: &str = "/Library/LaunchDaemons/io.wujian.admin.plist";
const DIR: &str = "/var/db/io.wujian.admin";
const HELPER: &str = "/var/db/io.wujian.admin/helper";
const SOCK: &str = "/var/db/io.wujian.admin/helper.sock";
const SOURCE: &str = "/var/db/io.wujian.admin/source";
const OLD_LABEL: &str = "io.wujian.timezone";
const OLD_PLIST: &str = "/Library/LaunchDaemons/io.wujian.timezone.plist";
const OLD_SOCK: &str = "/var/db/io.wujian.timezone/helper.sock";
const DECLINED: &str = "admin-auth-declined";
const MAX_BODY: usize = 4 * 1024 * 1024;
const PROTOCOL_VERSION: u32 = 5;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Job {
    Info {},
    Timezone { name: String },
    Firewall { request: crate::firewall::Request },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    component: Option<ComponentInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<crate::firewall::Receipt>,
}

#[derive(Clone, Debug)]
enum SubmitFail {
    Unavailable,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComponentInfo {
    protocol: u32,
    version: String,
    build_commit: Option<String>,
    arch: String,
}
impl ComponentInfo {
    fn current() -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
            build_commit: option_env!("WUJIAN_BUILD_COMMIT")
                .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(str::to_owned),
            arch: std::env::consts::ARCH.into(),
        }
    }
    #[cfg(any(unix, test))]
    fn matches(&self, expected: &Self) -> bool {
        self.protocol == expected.protocol
            && self.version == expected.version
            && expected
                .build_commit
                .as_ref()
                .is_none_or(|commit| self.build_commit.as_ref() == Some(commit))
        // Architecture can differ under Rosetta; it is not a protocol failure.
    }
}

/// Probe only read-only metadata. Never replay a mutating request to detect compatibility.
#[cfg(any(target_os = "macos", test))]
async fn ensure_component_with<P, PF, I, IF>(
    expected: &ComponentInfo,
    allow_prompt: bool,
    mut probe: P,
    install: I,
) -> Result<(), String>
where
    P: FnMut() -> PF,
    PF: std::future::Future<Output = Result<ComponentInfo, SubmitFail>>,
    I: FnOnce() -> IF,
    IF: std::future::Future<Output = Result<(), String>>,
{
    let outdated = match probe().await {
        Ok(info) if info.matches(expected) => {
            crate::audit::transition("admin.component", "current", None);
            return Ok(());
        }
        Ok(_) => true,
        Err(SubmitFail::Failed(error))
            if matches!(
                error.as_str(),
                "请求无效" | "不支持的隔断操作" | "管理组件没有返回版本"
            ) =>
        {
            true
        }
        Err(SubmitFail::Unavailable) => false,
        Err(SubmitFail::Failed(error)) => return Err(error),
    };
    crate::audit::transition(
        "admin.component",
        if outdated { "outdated" } else { "unavailable" },
        None,
    );
    if !allow_prompt {
        return Err(if outdated {
            "后台管理组件版本过旧。请在 App 中手动执行一次 DNS 修改或开启保护，授权更新后再试。"
        } else {
            "管理组件未响应；请在 App 中手动操作并授权修复"
        }
        .into());
    }
    // Existing firewall rules and DNS recovery records are retained by installation.
    install().await?;
    for _ in 0..20 {
        if probe().await.is_ok_and(|info| info.matches(expected)) {
            crate::audit::transition("admin.component", "updated", None);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    Err("管理组件更新未确认，尚未执行本次操作；请重新打开 App 后重试".into())
}

#[cfg(target_os = "macos")]
async fn ensure_component(app_data: &Path, allow_prompt: bool) -> Result<(), String> {
    ensure_component_with(
        &ComponentInfo::current(),
        allow_prompt,
        || async {
            spawn_submit(|| {
                submit_once(&Job::Info {})
                    .map_err(|error| match error {
                        SubmitFail::Failed(message)
                            if message.contains("传输中断") || message.contains("回执中断") =>
                        {
                            SubmitFail::Unavailable
                        }
                        other => other,
                    })?
                    .component
                    .ok_or_else(|| SubmitFail::Failed("管理组件没有返回版本".into()))
            })
            .await
            .map_err(SubmitFail::Failed)?
        },
        || prompt_install(app_data),
    )
    .await
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn declined(dir: &Path) -> bool {
    dir.join(DECLINED).is_file()
}

pub fn mark_declined(dir: &Path) {
    let _ = fs::File::create(dir.join(DECLINED));
}

pub fn clear_declined(dir: &Path) {
    let _ = fs::remove_file(dir.join(DECLINED));
}

pub fn ready() -> bool {
    Path::new(PLIST).is_file() && Path::new(SOCK).exists()
}

pub async fn apply(tz: &str, app_data: &Path, allow_prompt: bool) -> Result<(), String> {
    crate::platform::validate_timezone_name(tz)?;
    if crate::platform::get_system_timezone()
        .is_ok_and(|current| crate::platform::timezone_matches(&current, tz))
    {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        ensure_component(app_data, allow_prompt).await?;
        let name = tz.to_string();
        return match spawn_submit(move || submit_timezone(&name)).await? {
            Ok(()) => verified(tz),
            Err(SubmitFail::Failed(error)) => Err(error),
            Err(SubmitFail::Unavailable) => {
                Err("管理组件连接不可用；尚未提交时区修改，请重试".into())
            }
        };
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app_data;
        if !allow_prompt {
            return Err("管理组件尚未授权；未修改系统时区".into());
        }
        crate::platform::set_system_timezone(tz).await
    }
}

#[cfg(target_os = "macos")]
pub async fn firewall(
    request: crate::firewall::Request,
    app_data: &Path,
    allow_prompt: bool,
) -> Result<crate::firewall::Receipt, String> {
    request.validate()?;
    ensure_component(app_data, allow_prompt).await?;
    match spawn_submit(move || submit_firewall(&request)).await? {
        Ok(receipt) => Ok(receipt),
        Err(SubmitFail::Failed(error)) => Err(error),
        Err(SubmitFail::Unavailable) => Err("管理组件连接不可用；尚未提交本次操作，请重试".into()),
    }
}

#[cfg(target_os = "macos")]
pub async fn diagnostics(
    request: crate::firewall::Request,
) -> Result<crate::firewall::Receipt, String> {
    match spawn_submit(move || submit_firewall(&request)).await? {
        Ok(receipt) => Ok(receipt),
        Err(SubmitFail::Failed(error)) => Err(error),
        Err(SubmitFail::Unavailable) => Err("管理组件未安装或未响应；仅导出 App 日志".into()),
    }
}
pub fn install_as_root() -> Result<(), String> {
    if !is_root() {
        return Err("安装管理组件需要管理员权限".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        crate::audit::record("admin.install.directory", prepare_install_dir)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(format!("{DIR}/install.lock"))
            .map_err(|_| "无法锁定管理组件安装")?;
        protect_root_path(Path::new(&format!("{DIR}/install.lock")), 0o600)?;
        lock.try_lock()
            .map_err(|_| "管理组件正在安装，请稍后重试")?;
        // Older helpers watched this user-writable App path. Upgrades now require
        // explicit authorization and a protocol handshake, never an mtime reload.
        fs::remove_file(SOURCE)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|_| "无法移除旧管理组件来源记录")?;
        let exe = std::env::current_exe().map_err(|_| "无法定位当前程序")?;
        crate::audit::record("admin.install.binary", || copy_helper(&exe))?;
        crate::audit::record("admin.install.plist", write_launch_plist)?;
        retire_timezone_helper();
        crate::audit::record("admin.install.launchd", || {
            register_launchd(
                |args| launchctl(args),
                || {
                    std::thread::sleep(Duration::from_millis(100));
                },
            )
        })?;
        // A leftover socket is not evidence of a running, updated helper.
        crate::audit::record("admin.install.ready", || {
            for _ in 0..10 {
                if submit_once(&Job::Info {})
                    .ok()
                    .and_then(|r| r.component)
                    .is_some_and(|info| info.matches(&ComponentInfo::current()))
                {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            // Preserve files and recovery journals so the next repair can retry.
            Err("管理组件启动验证失败；安装文件已保留，请重试或导出日志".into())
        })
    }
    #[cfg(not(unix))]
    Err("当前平台不安装常驻管理组件".into())
}

pub fn serve() -> Result<(), String> {
    #[cfg(not(unix))]
    {
        return Err("当前平台没有常驻管理组件".into());
    }
    #[cfg(unix)]
    {
        if !is_root() {
            return Err("管理组件需要管理员权限".into());
        }
        let _ = fs::remove_file(SOCK);
        let listener =
            std::os::unix::net::UnixListener::bind(SOCK).map_err(|_| "无法监听管理组件")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(SOCK, fs::Permissions::from_mode(0o666))
                .map_err(|_| "无法开放管理组件连接")?;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "无法启动管理组件")?;
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else {
                crate::audit::transition("admin.connection", "error", Some("连接失败"));
                continue;
            };
            let _ = (|| -> Result<(), ()> {
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .map_err(|_| ())?;
                let body = read_frame(&mut stream).map_err(|e| {
                    crate::audit::event("admin.frame", "error", Some(&e), None);
                })?;
                let _ = stream.set_read_timeout(None);
                let reply = runtime.block_on(dispatch(&body));
                stream
                    .set_write_timeout(Some(Duration::from_secs(30)))
                    .map_err(|_| ())?;
                write_frame(&mut stream, &reply).map_err(|e| {
                    crate::audit::event("admin.reply", "error", Some(&e), None);
                })?;
                Ok(())
            })();
        }
        Ok(())
    }
}

async fn spawn_submit<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, SubmitFail> + Send + 'static,
) -> Result<Result<T, SubmitFail>, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| "管理组件调用失败".to_string())
}

#[cfg(target_os = "macos")]
async fn prompt_install(app_data: &Path) -> Result<(), String> {
    let result = crate::audit::record_async("admin.authorize", install_with_prompt()).await;
    result.map_err(|error| {
        if error.contains("-128") || error.to_ascii_lowercase().contains("cancel") {
            mark_declined(app_data);
            "管理员授权已取消".into()
        } else {
            error
        }
    })?;
    clear_declined(app_data);
    Ok(())
}

#[cfg(target_os = "macos")]
async fn install_with_prompt() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "无法定位当前程序")?;
    let exe = exe.to_str().ok_or("程序路径编码无效")?;
    let command = format!("{} --admin-install", crate::platform::shell_quote(exe));
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_quote(&command)
    );
    crate::firewall::command::run(Path::new("/usr/bin/osascript"), &["-e", &script], None).await?;
    Ok(())
}

#[cfg(unix)]
fn submit(job: &Job) -> Result<Reply, SubmitFail> {
    let existed = Path::new(SOCK).exists();
    match submit_once(job) {
        Ok(reply) => Ok(reply),
        Err(SubmitFail::Unavailable) if existed => {
            for _ in 0..80 {
                std::thread::sleep(Duration::from_millis(100));
                if let Ok(reply) = submit_once(job) {
                    return Ok(reply);
                }
            }
            Err(SubmitFail::Unavailable)
        }
        Err(other) => Err(other),
    }
}

#[cfg(unix)]
fn submit_once(job: &Job) -> Result<Reply, SubmitFail> {
    let mut stream =
        std::os::unix::net::UnixStream::connect(SOCK).map_err(|_| SubmitFail::Unavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| SubmitFail::Unavailable)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(if matches!(job, Job::Info {}) {
            3
        } else {
            130
        })))
        .map_err(|_| SubmitFail::Unavailable)?;
    let body = serde_json::to_vec(job).map_err(|_| SubmitFail::Failed("请求序列化失败".into()))?;
    write_frame(&mut stream, &body).map_err(|_| {
        SubmitFail::Failed("管理组件传输中断；操作结果未确认，请先核对当前状态".into())
    })?;
    let bytes = read_frame(&mut stream).map_err(|_| {
        SubmitFail::Failed("管理组件回执中断；操作结果未确认，请先核对当前状态".into())
    })?;
    let reply: Reply = serde_json::from_slice(&bytes)
        .map_err(|_| SubmitFail::Failed("管理组件回执无效".into()))?;
    if let Some(error) = reply.error.clone() {
        return Err(SubmitFail::Failed(error));
    }
    Ok(reply)
}

#[cfg(unix)]
fn submit_timezone(tz: &str) -> Result<(), SubmitFail> {
    accept_zone(tz).map_err(SubmitFail::Failed)?;
    submit(&Job::Timezone {
        name: tz.to_string(),
    })?;
    Ok(())
}

#[cfg(unix)]
fn submit_firewall(
    request: &crate::firewall::Request,
) -> Result<crate::firewall::Receipt, SubmitFail> {
    request.validate().map_err(SubmitFail::Failed)?;
    let job = Job::Firewall {
        request: request.clone(),
    };
    let reply = match submit(&job) {
        // Pre-diagnostics helpers reject the additional field before execution.
        // Retrying a transport timeout could repeat a mutation, so never do that here.
        Err(SubmitFail::Failed(error)) if error == "请求无效" && request.operation_id.is_some() =>
        {
            crate::audit::event("admin.protocol", "legacy", None, None);
            let mut legacy = request.clone();
            legacy.operation_id = None;
            submit(&Job::Firewall { request: legacy })?
        }
        result => result?,
    };
    reply
        .receipt
        .ok_or_else(|| SubmitFail::Failed("管理组件没有返回状态".into()))
}

async fn dispatch(bytes: &[u8]) -> Vec<u8> {
    let reply = match validate_job(bytes) {
        Ok(Job::Info {}) => Reply {
            component: Some(ComponentInfo::current()),
            error: None,
            receipt: None,
        },
        Ok(Job::Timezone { name }) => {
            match crate::audit::record("helper.timezone.apply", || apply_as_root(&name)) {
                Ok(()) => Reply {
                    component: None,
                    error: None,
                    receipt: None,
                },
                Err(error) => Reply {
                    component: None,
                    error: Some(error),
                    receipt: None,
                },
            }
        }
        Ok(Job::Firewall { request }) => match crate::firewall::execute(&request).await {
            Ok(receipt) => Reply {
                component: None,
                error: None,
                receipt: Some(receipt),
            },
            Err(error) => Reply {
                component: None,
                error: Some(error),
                receipt: None,
            },
        },
        Err(error) => {
            crate::audit::event("admin.request", "rejected", Some(&error), None);
            Reply {
                component: None,
                error: Some(error),
                receipt: None,
            }
        }
    };
    serde_json::to_vec(&reply)
        .unwrap_or_else(|_| br#"{"error":"reply serialization failed"}"#.to_vec())
}

fn validate_job(bytes: &[u8]) -> Result<Job, String> {
    let job: Job = serde_json::from_slice(bytes).map_err(|_| "请求无效".to_string())?;
    match &job {
        Job::Info {} => {}
        Job::Timezone { name } => accept_zone(name)?,
        Job::Firewall { request } => request.validate()?,
    }
    Ok(job)
}

fn apply_as_root(tz: &str) -> Result<(), String> {
    accept_zone(tz)?;
    if !is_root() {
        return Err("修改系统时区需要管理员权限".into());
    }
    let status = std::process::Command::new("/usr/sbin/systemsetup")
        .args(["-settimezone", tz])
        .status()
        .map_err(|_| "无法执行时区设置")?;
    if status.success() {
        Ok(())
    } else {
        Err("系统没有接受这个时区".into())
    }
}

fn verified(tz: &str) -> Result<(), String> {
    if crate::platform::get_system_timezone()
        .is_ok_and(|current| crate::platform::timezone_matches(&current, tz))
    {
        Ok(())
    } else {
        Err("管理组件已返回，但系统时区未改变".into())
    }
}

fn accept_zone(tz: &str) -> Result<(), String> {
    crate::platform::validate_timezone_name(tz)?;
    if tz.contains(' ')
        || tz.contains('.')
        || tz.split('/').any(|part| {
            part.is_empty()
                || !part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+')
        })
    {
        return Err("时区名称无效".into());
    }
    let path = Path::new("/usr/share/zoneinfo").join(tz);
    let canonical = path.canonicalize().map_err(|_| "系统没有这个时区")?;
    if !canonical.starts_with("/usr/share/zoneinfo")
        && !canonical.starts_with("/var/db/timezone")
        && !canonical.starts_with("/private/var/db/timezone")
    {
        return Err("时区路径无效".into());
    }
    if !canonical.is_file() {
        return Err("系统没有这个时区".into());
    }
    Ok(())
}

fn read_frame(mut input: impl Read) -> Result<Vec<u8>, String> {
    let mut len_buf = [0_u8; 4];
    input
        .read_exact(&mut len_buf)
        .map_err(|_| "管理组件连接中断".to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_BODY {
        return Err("请求大小无效".into());
    }
    let mut body = vec![0_u8; len];
    input
        .read_exact(&mut body)
        .map_err(|_| "管理组件请求不完整".to_string())?;
    Ok(body)
}

fn write_frame(mut output: impl Write, body: &[u8]) -> Result<(), String> {
    if body.is_empty() || body.len() > MAX_BODY {
        return Err("回执大小无效".into());
    }
    output
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|_| "无法写入管理组件连接".to_string())?;
    output
        .write_all(body)
        .map_err(|_| "无法写入管理组件连接".to_string())?;
    Ok(())
}

fn plist_body() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>AssociatedBundleIdentifiers</key><array><string>io.wujian.desktop</string></array><key>ProgramArguments</key><array><string>{HELPER}</string><string>--admin-helper</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>3</integer><key>ProcessType</key><string>Background</string></dict></plist>\n"
    )
}

#[cfg(unix)]
fn protect_root_path(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = fs::symlink_metadata(path).map_err(|_| "无法检查管理组件权限")?;
    if meta.file_type().is_symlink() || !(meta.is_file() || meta.is_dir()) {
        return Err("管理组件路径类型无效".into());
    }
    std::os::unix::fs::chown(path, Some(0), Some(0)).map_err(|_| "无法设置管理组件所有权")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| "无法设置管理组件权限")?;
    let meta = fs::symlink_metadata(path).map_err(|_| "无法核验管理组件权限")?;
    if meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o7777 != mode {
        return Err("管理组件所有权或权限核验失败".into());
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_install_dir() -> Result<(), String> {
    match fs::symlink_metadata(DIR) {
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
            return Err("管理组件目录类型无效".into())
        }
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(DIR).map_err(|_| "无法创建管理组件目录")?;
        }
        Err(_) => return Err("无法检查管理组件目录".into()),
    }
    protect_root_path(Path::new(DIR), 0o755)
}

/// The App executable's signature binds its Info.plist. A standalone copy must
/// get its own ad-hoc signature before launchd can execute it outside the bundle.
#[cfg(unix)]
fn sign_standalone(path: &Path) -> Result<(), String> {
    for args in [
        vec!["--force", "--sign", "-", "--identifier", LABEL],
        vec!["--verify", "--strict"],
    ] {
        let output = std::process::Command::new("/usr/bin/codesign")
            .args(&args)
            .arg(path)
            .output()
            .map_err(|_| "管理组件独立签名无法执行")?;
        if !output.status.success() {
            return Err(if args[0] == "--verify" {
                "管理组件独立签名验证失败"
            } else {
                "管理组件独立签名失败"
            }
            .into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_helper(from: &Path) -> Result<(), String> {
    let temp = PathBuf::from(format!("{DIR}/.helper-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        fs::copy(from, &temp).map_err(|_| "无法复制管理组件")?;
        crate::audit::record("admin.install.signature", || sign_standalone(&temp))?;
        protect_root_path(&temp, 0o755)?;
        fs::rename(&temp, HELPER).map_err(|_| "无法保存管理组件")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(unix)]
fn write_launch_plist() -> Result<(), String> {
    let temp = PathBuf::from(format!(
        "/Library/LaunchDaemons/.{LABEL}-{}.plist",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| {
        fs::write(&temp, plist_body()).map_err(|_| "无法写入管理组件启动项")?;
        protect_root_path(&temp, 0o644)?;
        let output = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&temp)
            .output()
            .map_err(|_| "无法核验管理组件启动项")?;
        if !output.status.success() {
            return Err("管理组件启动项格式无效".into());
        }
        fs::rename(&temp, PLIST).map_err(|_| "无法保存管理组件启动项")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(unix)]
fn launchctl(args: &[&str]) -> Result<i32, String> {
    let output = std::process::Command::new("/bin/launchctl")
        .args(args)
        .output()
        .map_err(|_| "无法执行管理组件启动命令")?;
    // Never forward stderr from benign bootout failures into the authorization
    // error. Persist only the command stage and numeric status.
    let code = output.status.code().unwrap_or(-1);
    crate::audit::event_kind(
        &format!("admin.launchd.{}", args[0]),
        if code == 0 { "ok" } else { "error" },
        (code != 0)
            .then_some(format!("launchctl_exit_{code}"))
            .as_deref(),
        None,
    );
    Ok(code)
}

#[cfg(unix)]
fn register_launchd(
    mut run: impl FnMut(&[&str]) -> Result<i32, String>,
    mut pause: impl FnMut(),
) -> Result<(), String> {
    let target = format!("system/{LABEL}");
    // Disabled overrides survive updates/reboots. Explicit user repair enables
    // only this helper's label before loading it.
    let code = run(&["enable", &target])?;
    if code != 0 {
        return Err(format!("管理组件启用失败（enable，退出码 {code}）"));
    }
    if run(&["print", &target])? == 0 {
        let code = run(&["bootout", &target])?;
        if code != 0 && code != 3 {
            return Err(format!("管理组件停止失败（bootout，退出码 {code}）"));
        }
        let mut unloaded = false;
        for _ in 0..50 {
            if run(&["print", &target])? != 0 {
                unloaded = true;
                break;
            }
            pause();
        }
        if !unloaded {
            return Err("管理组件停止验证失败，请稍后重试".into());
        }
    }
    let code = run(&["bootstrap", "system", PLIST])?;
    if code != 0 {
        return Err(format!(
            "管理组件启动注册失败（bootstrap，退出码 {code}）；请导出日志"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn retire_timezone_helper() {
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{OLD_LABEL}")])
        .output();
    let _ = fs::remove_file(OLD_PLIST);
    let _ = fs::remove_file(OLD_SOCK);
}

fn is_root() -> bool {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .is_some_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
}

fn applescript_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn component_info_is_read_only_and_does_not_accept_commands() {
        let reply: Reply = serde_json::from_slice(&dispatch(br#"{"op":"info"}"#).await).unwrap();
        assert!(reply.error.is_none() && reply.receipt.is_none());
        assert!(reply.component.unwrap().matches(&ComponentInfo::current()));
        assert!(validate_job(br#"{"op":"info","command":"id"}"#).is_err());
    }

    #[test]
    fn component_checks_build_and_protocol_but_allows_rosetta() {
        let mut expected = ComponentInfo::current();
        expected.build_commit = Some("a".repeat(40));
        expected.arch = "x86_64".into();
        let mut actual = expected.clone();
        actual.arch = "aarch64".into();
        assert!(actual.matches(&expected));
        actual.build_commit = None;
        assert!(!actual.matches(&expected));
        actual.build_commit = Some("b".repeat(40));
        assert!(!actual.matches(&expected));
        actual = expected.clone();
        actual.protocol += 1;
        assert!(!actual.matches(&expected));
    }

    #[tokio::test]
    async fn legacy_component_is_updated_once_before_proceeding() {
        let expected = ComponentInfo::current();
        let mut replies = std::collections::VecDeque::from([
            Err(SubmitFail::Failed("请求无效".into())),
            Ok(expected.clone()),
        ]);
        let installed = std::sync::atomic::AtomicUsize::new(0);
        let result = ensure_component_with(
            &expected,
            true,
            || std::future::ready(replies.pop_front().expect("no extra probes")),
            || async {
                installed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(installed.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(replies.is_empty());
    }

    #[tokio::test]
    async fn background_never_prompts_and_cancelled_upgrade_never_proceeds() {
        let expected = ComponentInfo::current();
        let installed = std::sync::atomic::AtomicBool::new(false);
        let result = ensure_component_with(
            &expected,
            false,
            || std::future::ready(Err(SubmitFail::Failed("请求无效".into()))),
            || async {
                installed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.unwrap_err().contains("版本过旧"));
        assert!(!installed.load(std::sync::atomic::Ordering::SeqCst));
        let mut probes = 0;
        let result = ensure_component_with(
            &expected,
            true,
            || {
                probes += 1;
                std::future::ready(Err(SubmitFail::Failed("请求无效".into())))
            },
            || async { Err("用户取消授权".into()) },
        )
        .await;
        assert_eq!(result.unwrap_err(), "用户取消授权");
        assert_eq!(probes, 1);
    }

    #[tokio::test]
    async fn current_component_does_not_require_another_authorization() {
        let expected = ComponentInfo::current();
        let result = ensure_component_with(
            &expected,
            true,
            || std::future::ready(Ok(expected.clone())),
            || async { panic!("matching component must not be reinstalled") },
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reported_install_success_is_not_accepted_without_a_current_reply() {
        let expected = ComponentInfo::current();
        let mut old = expected.clone();
        old.protocol = 0;
        let result = ensure_component_with(
            &expected,
            true,
            || std::future::ready(Ok(old.clone())),
            || async { Ok(()) },
        )
        .await;
        assert!(result.unwrap_err().contains("更新未确认"));
    }

    #[test]
    fn declined_marker_blocks_only_until_cleared() {
        let dir =
            std::env::temp_dir().join(format!("wujian-admin-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        assert!(!declined(&dir));
        mark_declined(&dir);
        assert!(declined(&dir));
        clear_declined(&dir);
        assert!(!declined(&dir));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn frames_roundtrip_and_reject_bad_lengths() {
        let body = br#"{"op":"noop"}"#;
        let mut buf = Vec::new();
        write_frame(&mut buf, body).unwrap();
        assert_eq!(read_frame(buf.as_slice()).unwrap(), body);
        assert!(read_frame((0_u32).to_be_bytes().as_slice()).is_err());
        assert!(read_frame(((MAX_BODY as u32) + 1).to_be_bytes().as_slice()).is_err());
        assert!(write_frame(&mut Vec::new(), b"").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn jobs_only_accept_a_timezone_or_a_typed_firewall_request() {
        assert!(validate_job(br#"{"op":"timezone","name":"America/Los_Angeles"}"#).is_ok());
        assert!(validate_job(br#"{"op":"timezone","name":"Etc/UTC"}"#).is_ok());
        assert!(validate_job(br#"{"op":"exec","command":"id"}"#).is_err());
        assert!(
            validate_job(br#"{"op":"timezone","name":"America/Los_Angeles","command":"id"}"#)
                .is_err()
        );
        assert!(validate_job(br#"{"op":"timezone","name":"America/Los_Angeles;reboot"}"#).is_err());
        assert!(validate_job(br#"{"op":"timezone","name":"../America/Los_Angeles"}"#).is_err());
        assert!(validate_job(
            br#"{"op":"firewall","request":{"action":"status","policy":null,"acknowledgeConnectionReset":false}}"#
        )
        .is_ok());
        assert!(validate_job(
            br#"{"op":"firewall","request":{"action":"release; rm -rf","policy":null,"acknowledgeConnectionReset":false}}"#
        )
        .is_err());
    }

    #[cfg(unix)]
    fn simulate_registration(script: &[(&str, i32)]) -> Result<(), String> {
        let mut expected = script.iter();
        let result = register_launchd(
            |args| {
                let (command, code) = expected.next().expect("unexpected launchctl call");
                assert_eq!(args[0], *command);
                assert!(args
                    .iter()
                    .any(|arg| *arg == PLIST || *arg == "system/io.wujian.admin"));
                Ok(*code)
            },
            || {},
        );
        assert!(
            expected.next().is_none(),
            "registration did not follow expected stages"
        );
        result
    }

    #[cfg(unix)]
    #[test]
    fn install_handles_missing_job_and_waits_for_old_job_to_unload() {
        simulate_registration(&[("enable", 0), ("print", 113), ("bootstrap", 0)]).unwrap();
        simulate_registration(&[
            ("enable", 0),
            ("print", 0),
            ("bootout", 0),
            ("print", 0),
            ("print", 113),
            ("bootstrap", 0),
        ])
        .unwrap();
        // Service may exit between print and bootout; no-such-process is benign.
        simulate_registration(&[
            ("enable", 0),
            ("print", 0),
            ("bootout", 3),
            ("print", 113),
            ("bootstrap", 0),
        ])
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn install_preserves_bootstrap_error_and_does_not_run_destructive_cleanup() {
        let error =
            simulate_registration(&[("enable", 0), ("print", 113), ("bootstrap", 5)]).unwrap_err();
        assert_eq!(crate::audit::error_kind(&error), "helper_bootstrap_exit_5");
        assert!(simulate_registration(&[("enable", 1)])
            .unwrap_err()
            .contains("enable"));
        assert!(
            simulate_registration(&[("enable", 0), ("print", 0), ("bootout", 5)])
                .unwrap_err()
                .contains("bootout")
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_never_bootstraps_while_old_job_is_still_loaded() {
        let mut script = vec![("enable", 0), ("print", 0), ("bootout", 0)];
        script.extend(std::iter::repeat_n(("print", 0), 50));
        assert!(simulate_registration(&script)
            .unwrap_err()
            .contains("停止验证失败"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copied_app_executable_gets_a_valid_standalone_signature() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "wujian-sign-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let bundle = root.join("Fixture.app");
        let contents = bundle.join("Contents");
        fs::create_dir_all(contents.join("MacOS")).unwrap();
        let exe = contents.join("MacOS/fixture");
        fs::copy("/usr/bin/true", &exe).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(contents.join("Info.plist"), r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>fixture</string><key>CFBundleIdentifier</key><string>io.wujian.signature-test</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>"#).unwrap();
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&bundle)
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let standalone = root.join("helper");
        fs::copy(&exe, &standalone).unwrap();
        let verify = || {
            std::process::Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict"])
                .arg(&standalone)
                .output()
                .unwrap()
        };
        assert!(
            !verify().status.success(),
            "fixture must reproduce invalid bundle-bound signature"
        );
        sign_standalone(&standalone).unwrap();
        assert!(verify().status.success());
        assert!(std::process::Command::new(&standalone)
            .status()
            .unwrap()
            .success());
        fs::remove_dir_all(root).unwrap();
    }
}
