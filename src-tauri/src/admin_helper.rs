//! One administrator approval installs a resident root helper.
//! Timezone changes, protection, DNS, and IPv6 then use its socket and do not prompt again.
//! The socket only accepts a timezone name or a typed firewall request. It never runs a shell command.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Job {
    Timezone { name: String },
    Firewall { request: crate::firewall::Request },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<crate::firewall::Receipt>,
}

enum SubmitFail {
    Unavailable,
    Failed(String),
}

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
        let name = tz.to_string();
        match spawn_submit(move || submit_timezone(&name)).await? {
            Ok(()) => return verified(tz),
            Err(SubmitFail::Failed(error)) => return Err(error),
            Err(SubmitFail::Unavailable) if Path::new(PLIST).is_file() => {
                return Err("管理组件未响应；未再次请求授权".into());
            }
            Err(SubmitFail::Unavailable) => {}
        }
        if !allow_prompt {
            return Err("管理组件尚未授权；未修改系统时区".into());
        }
        crate::audit::event(
            "admin.connection",
            "unavailable",
            Some("管理组件未响应"),
            None,
        );
        prompt_install(app_data).await?;
        let name = tz.to_string();
        return match spawn_submit(move || submit_timezone(&name)).await? {
            Ok(()) => verified(tz),
            Err(SubmitFail::Failed(error)) => Err(error),
            Err(SubmitFail::Unavailable) => Err("授权已完成，但管理组件没有响应".into()),
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
) -> Result<crate::firewall::Receipt, String> {
    request.validate()?;
    let probe = request.clone();
    match spawn_submit(move || submit_firewall(&probe)).await? {
        Ok(receipt) => return Ok(receipt),
        Err(SubmitFail::Failed(error)) => return Err(error),
        Err(SubmitFail::Unavailable) if Path::new(PLIST).is_file() => {
            return Err("管理组件未响应；未再次请求授权".into());
        }
        Err(SubmitFail::Unavailable) => {}
    }
    prompt_install(app_data).await?;
    match spawn_submit(move || submit_firewall(&request)).await? {
        Ok(receipt) => Ok(receipt),
        Err(SubmitFail::Failed(error)) => Err(error),
        Err(SubmitFail::Unavailable) => Err("授权已完成，但管理组件没有响应".into()),
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
        use std::os::unix::fs::PermissionsExt;
        retire_timezone_helper();
        fs::create_dir_all(DIR).map_err(|_| "无法创建管理组件目录")?;
        fs::set_permissions(DIR, fs::Permissions::from_mode(0o755))
            .map_err(|_| "无法设置管理组件目录权限")?;
        let exe = std::env::current_exe().map_err(|_| "无法定位当前程序")?;
        copy_helper(&exe)?;
        if exe != Path::new(HELPER) {
            let path = exe.to_str().ok_or("程序路径编码无效")?;
            if path.contains('\n') || path.contains('\r') {
                return Err("程序路径无效".into());
            }
            fs::write(SOURCE, format!("{path}\n")).map_err(|_| "无法记录管理组件来源")?;
            fs::set_permissions(SOURCE, fs::Permissions::from_mode(0o644))
                .map_err(|_| "无法保护管理组件来源")?;
        }
        fs::write(PLIST, plist_body()).map_err(|_| "无法写入管理组件启动项")?;
        fs::set_permissions(PLIST, fs::Permissions::from_mode(0o644))
            .map_err(|_| "无法设置管理组件启动项权限")?;
        let _ = std::process::Command::new("/bin/launchctl")
            .args(["bootout", &format!("system/{LABEL}")])
            .status();
        let status = std::process::Command::new("/bin/launchctl")
            .args(["bootstrap", "system", PLIST])
            .status()
            .map_err(|_| "无法启动管理组件")?;
        if !status.success() {
            remove_install();
            return Err("管理组件没有启动".into());
        }
        for _ in 0..50 {
            if Path::new(SOCK).exists() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        remove_install();
        return Err("管理组件已安装但尚未就绪".into());
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
            relaunch_if_source_changed();
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
    if !Path::new(SOCK).exists() {
        return Err("授权已完成，但管理组件没有启动".into());
    }
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
        .set_read_timeout(Some(Duration::from_secs(130)))
        .map_err(|_| SubmitFail::Unavailable)?;
    let body = serde_json::to_vec(job).map_err(|_| SubmitFail::Failed("请求序列化失败".into()))?;
    write_frame(&mut stream, &body).map_err(|_| SubmitFail::Unavailable)?;
    let bytes = read_frame(&mut stream).map_err(|_| SubmitFail::Unavailable)?;
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
        Ok(Job::Timezone { name }) => {
            match crate::audit::record("helper.timezone.apply", || apply_as_root(&name)) {
                Ok(()) => Reply {
                    error: None,
                    receipt: None,
                },
                Err(error) => Reply {
                    error: Some(error),
                    receipt: None,
                },
            }
        }
        Ok(Job::Firewall { request }) => match crate::firewall::execute(&request).await {
            Ok(receipt) => Reply {
                error: None,
                receipt: Some(receipt),
            },
            Err(error) => Reply {
                error: Some(error),
                receipt: None,
            },
        },
        Err(error) => {
            crate::audit::event("admin.request", "rejected", Some(&error), None);
            Reply {
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
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array><string>{HELPER}</string><string>--admin-helper</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>3</integer><key>ProcessType</key><string>Background</string></dict></plist>\n"
    )
}

#[cfg(unix)]
fn copy_helper(from: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let temp = PathBuf::from(format!("{DIR}/.helper-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        fs::copy(from, &temp).map_err(|_| "无法复制管理组件")?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))
            .map_err(|_| "无法设置管理组件权限")?;
        fs::rename(&temp, HELPER).map_err(|_| "无法保存管理组件")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.map_err(str::to_string)
}

#[cfg(unix)]
fn retire_timezone_helper() {
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{OLD_LABEL}")])
        .status();
    let _ = fs::remove_file(OLD_PLIST);
    let _ = fs::remove_file(OLD_SOCK);
}

#[cfg(unix)]
fn remove_install() {
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{LABEL}")])
        .status();
    let _ = fs::remove_file(PLIST);
    let _ = fs::remove_file(SOCK);
}

#[cfg(unix)]
fn relaunch_if_source_changed() {
    let Ok(text) = fs::read_to_string(SOURCE) else {
        return;
    };
    let source = PathBuf::from(text.trim());
    if source.as_os_str().is_empty() {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(&source) else {
        return;
    };
    let Ok(helper_meta) = fs::metadata(HELPER) else {
        return;
    };
    let Ok(helper_modified) = helper_meta.modified() else {
        return;
    };
    if !source_may_replace(&meta, helper_modified) {
        return;
    }
    if let Err(error) = copy_helper(&source) {
        crate::audit::event("admin.refresh", "error", Some(&error), None);
        return;
    }
    crate::audit::event("admin.refresh", "restarting", None, None);
    // kickstart -k waits until this process dies. Waiting here blocks the click
    // for about a minute and then the new helper never starts. If spawn fails,
    // keep handling this request with the process that is already running.
    if std::process::Command::new("/bin/launchctl")
        .args(["kickstart", "-k", &format!("system/{LABEL}")])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
    {
        std::process::exit(0);
    }
}

fn source_may_replace(meta: &fs::Metadata, helper_modified: SystemTime) -> bool {
    if !meta.is_file() || meta.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 || meta.len() == 0 || meta.len() > 200 * 1024 * 1024 {
            return false;
        }
    }
    meta.modified()
        .ok()
        .is_some_and(|modified| modified > helper_modified)
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
    #[test]
    fn helper_refresh_rejects_writable_or_indirect_binaries() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("wujian-helper-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wujian");
        fs::write(&path, b"bin").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(source_may_replace(&meta, SystemTime::UNIX_EPOCH));
        assert!(!source_may_replace(&meta, meta.modified().unwrap()));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
        let writable = fs::symlink_metadata(&path).unwrap();
        assert!(!source_may_replace(&writable, SystemTime::UNIX_EPOCH));
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let linked = fs::symlink_metadata(&link).unwrap();
        assert!(!source_may_replace(&linked, SystemTime::UNIX_EPOCH));
        let _ = fs::remove_dir_all(dir);
    }
}
