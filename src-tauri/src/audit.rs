//! Bounded, local diagnostics. Never persist raw errors, addresses, paths or settings.
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::Instant,
};

const LIMIT: u64 = 512 * 1024;
const FILES: usize = 4;
static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);
static TRANSITIONS: OnceLock<Mutex<HashMap<String, (String, Option<String>)>>> = OnceLock::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub at: String,
    pub session: String,
    pub operation: String,
    pub outcome: String,
    pub error_kind: Option<String>,
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub build_commit: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    pub initialized: bool,
    pub dropped_events: u64,
    pub unreadable_files: u64,
    pub invalid_lines: u64,
    pub entries: Vec<Entry>,
}
struct Logger {
    dir: PathBuf,
    session: String,
    source: String,
}
fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
}
impl Logger {
    fn new(dir: &Path, source: &str) -> Result<Self, String> {
        if !safe_name(source) {
            return Err("诊断来源无效".into());
        }
        std::fs::create_dir_all(dir).map_err(|_| "无法创建诊断目录")?;
        let metadata = std::fs::symlink_metadata(dir).map_err(|_| "无法读取诊断目录")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("诊断目录类型无效".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "无法保护诊断目录")?;
        }
        Ok(Self {
            dir: dir.into(),
            session: uuid::Uuid::new_v4().to_string(),
            source: source.into(),
        })
    }
    // Helpers are separate processes. A shared file lock serializes rotation;
    // never wait indefinitely on logging in the firewall execution path.
    fn file_lock(&self) -> Result<std::fs::File, String> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(self.dir.join("write.lock"))
            .map_err(|_| "无法打开日志锁")?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(_) if started.elapsed().as_millis() < 30 => {
                    std::thread::sleep(std::time::Duration::from_millis(2))
                }
                Err(_) => return Err("日志正在写入".into()),
            }
        }
    }
    fn write(
        &self,
        operation: &str,
        outcome: &str,
        kind: Option<&str>,
        duration_ms: Option<u64>,
        id: Option<&str>,
    ) -> Result<(), String> {
        if !safe_name(operation)
            || !safe_name(outcome)
            || kind.is_some_and(|s| !safe_name(s))
            || id.is_some_and(|s| uuid::Uuid::parse_str(s).is_err())
        {
            return Err("诊断事件名称无效".into());
        }
        let _lock = self.file_lock()?;
        let current = self.dir.join("diagnostic.jsonl");
        if std::fs::metadata(&current).is_ok_and(|m| m.len() >= LIMIT) {
            match std::fs::remove_file(self.dir.join(format!("diagnostic.{}.jsonl", FILES - 1))) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("无法轮转诊断日志".into()),
            }
            for n in (1..FILES - 1).rev() {
                let from = self.dir.join(format!("diagnostic.{n}.jsonl"));
                if from.exists() {
                    std::fs::rename(from, self.dir.join(format!("diagnostic.{}.jsonl", n + 1)))
                        .map_err(|_| "无法轮转诊断日志")?;
                }
            }
            std::fs::rename(&current, self.dir.join("diagnostic.1.jsonl"))
                .map_err(|_| "无法轮转诊断日志")?;
        }
        let entry = Entry {
            at: chrono::Utc::now().to_rfc3339(),
            session: self.session.clone(),
            operation: operation.into(),
            outcome: outcome.into(),
            error_kind: kind.map(str::to_owned),
            duration_ms,
            operation_id: id.map(str::to_owned),
            source: self.source.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            platform: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            build_commit: option_env!("WUJIAN_BUILD_COMMIT")
                .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(str::to_owned),
        };
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(current).map_err(|_| "无法写入诊断日志")?;
        let mut bytes = serde_json::to_vec(&entry).map_err(|_| "日志编码失败")?;
        bytes.push(b'\n');
        file.write_all(&bytes)
            .map_err(|_| "无法写入诊断日志".into())
    }
    fn bundle(&self) -> Bundle {
        let mut bundle = Bundle {
            initialized: true,
            dropped_events: DROPPED.load(Ordering::Relaxed),
            ..Default::default()
        };
        let Ok(_lock) = self.file_lock() else {
            bundle.unreadable_files += 1;
            return bundle;
        };
        for n in (0..FILES).rev() {
            let name = if n == 0 {
                "diagnostic.jsonl".into()
            } else {
                format!("diagnostic.{n}.jsonl")
            };
            let path = self.dir.join(name);
            // Bound imported data even if a damaged or replaced file grows unexpectedly.
            match std::fs::metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Ok(m) if m.len() <= LIMIT + 16 * 1024 => {}
                _ => {
                    bundle.unreadable_files += 1;
                    continue;
                }
            }
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    for line in contents.lines() {
                        match serde_json::from_str::<Entry>(line) {
                            Ok(entry) => bundle.entries.push(entry),
                            Err(_) => bundle.invalid_lines += 1,
                        }
                    }
                }
                Err(_) => bundle.unreadable_files += 1,
            }
        }
        bundle
    }
}
/// Classify locally; the input itself is never serialized.
pub fn error_kind(error: &str) -> &'static str {
    let lower = error.to_lowercase();
    if error == "前端异常" {
        return "frontend_exception";
    }
    if lower.contains("节点端点发生变化") {
        return "tunnel_plan_changed";
    }
    if lower.contains("请开启 tun") || lower.contains("未经过该 tun") {
        return "tunnel_unavailable";
    }
    if lower.contains("全局模式") && !lower.contains("未完整确认") {
        return "proxy_mode_changed";
    }
    if lower.contains("dns")
        && (lower.contains("直连") || lower.contains("劫持") || lower.contains("路径"))
    {
        return "dns_path_invalid";
    }
    if lower.contains("代理状态") || lower.contains("控制接口") {
        return "controller_unavailable";
    }
    if lower.contains("秒内响应") {
        return "timeout";
    }
    if lower.contains("cancel") || lower.contains("取消") || lower.contains("-128") {
        "admin_cancelled"
    } else if lower.contains("timeout") || lower.contains("超时") {
        "timeout"
    } else if lower.contains("未响应") || lower.contains("没有响应") || lower.contains("没有启动")
    {
        "helper_unavailable"
    } else if lower.contains("过期") || lower.contains("不同步") || lower.contains("已变化")
    {
        "stale_evidence"
    } else if lower.contains("回读")
        || lower.contains("核验")
        || lower.contains("未确认")
        || lower.contains("未完整确认")
    {
        "verification_failed"
    } else if lower.contains("permission")
        || lower.contains("授权")
        || lower.contains("denied")
        || lower.contains("not authorized")
        || lower.contains("权限")
    {
        "permission"
    } else if lower.contains("http ") {
        "http_status"
    } else if lower.contains("tls") || lower.contains("连接") || lower.contains("代理或") {
        "connection_or_tls_failed"
    } else if lower.contains("未安装") || lower.contains("找不到") || lower.contains("未找到")
    {
        "dependency_missing"
    } else if lower.contains("json")
        || lower.contains("格式")
        || lower.contains("无效")
        || lower.contains("损坏")
        || lower.contains("编码")
    {
        "invalid_data"
    } else if lower.contains("写入")
        || lower.contains("保存")
        || lower.contains("读取")
        || lower.contains("目录")
    {
        "storage_failed"
    } else if lower.contains("请先")
        || lower.contains("拒绝")
        || lower.contains("不支持")
        || lower.contains("必须")
        || lower.contains("不能")
    {
        "precondition_failed"
    } else {
        "operation_failed"
    }
}
pub fn init(dir: &Path) -> Result<(), String> {
    init_source(dir, "app")
}
pub fn init_source(dir: &Path, source: &str) -> Result<(), String> {
    if LOGGER.get().is_some() {
        return Ok(());
    }
    let logger = Logger::new(&dir.join("logs"), source)?;
    if source == "app" {
        let marker = logger.dir.join("session.state");
        let interrupted = std::fs::read_to_string(&marker).is_ok_and(|v| v == "running");
        // No free-form state or user path is persisted in the marker.
        write_marker(&marker, "running")?;
        LOGGER.set(Mutex::new(logger)).map_err(|_| "日志已初始化")?;
        if interrupted {
            event_kind(
                "app.previous_session",
                "interrupted",
                Some("unclean_exit"),
                None,
            );
        }
    } else {
        LOGGER.set(Mutex::new(logger)).map_err(|_| "日志已初始化")?;
    }
    event("process.start", "ok", None, None);
    Ok(())
}
fn write_marker(path: &Path, value: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut f| f.write_all(value.as_bytes()))
        .map_err(|_| "无法写入诊断会话标记".into())
}
pub fn shutdown() {
    event("app.exit", "ok", None, None);
    if let Some(lock) = LOGGER.get() {
        if let Ok(logger) = lock.lock() {
            if write_marker(&logger.dir.join("session.state"), "clean").is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
pub fn install_panic_hook() {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Panic payloads and stacks may contain credentials. Never forward them.
            // Avoid acquiring an in-process logger lock already held by a panicking thread.
            let written = LOGGER
                .get()
                .and_then(|l| l.try_lock().ok())
                .is_some_and(|l| {
                    l.write("process.panic", "error", Some("rust_panic"), None, None)
                        .is_ok()
                });
            if !written {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
            previous(info);
        }));
    });
}
fn write_event(
    operation: &str,
    outcome: &str,
    kind: Option<&str>,
    duration: Option<u64>,
    id: Option<&str>,
) {
    let written = LOGGER
        .get()
        .and_then(|l| l.lock().ok())
        .is_some_and(|l| l.write(operation, outcome, kind, duration, id).is_ok());
    if !written {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}
pub fn event(operation: &str, outcome: &str, error: Option<&str>, duration: Option<u64>) {
    event_kind(operation, outcome, error.map(error_kind), duration);
}
pub fn event_kind(operation: &str, outcome: &str, kind: Option<&str>, duration: Option<u64>) {
    write_event(operation, outcome, kind, duration, None);
}
/// State transitions only: a healthy three-second poll must not flood history.
pub fn transition(operation: &str, outcome: &str, error: Option<&str>) {
    transition_kind(operation, outcome, error.map(error_kind));
}
pub fn transition_kind(operation: &str, outcome: &str, kind: Option<&str>) {
    if LOGGER.get().is_none() {
        return;
    }
    let value = (outcome.to_string(), kind.map(str::to_owned));
    let lock = TRANSITIONS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut states) = lock.lock() {
        if states.get(operation) != Some(&value) {
            states.insert(operation.into(), value.clone());
            event_kind(operation, outcome, value.1.as_deref(), None);
        }
    }
}
/// A timed heartbeat at most once per minute per probe, independent of state changes.
pub fn timed_observation(operation: &str, duration: u64) {
    if LOGGER.get().is_none() {
        return;
    }
    static LAST: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    if let Ok(mut last) = LAST.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        if last
            .get(operation)
            .is_none_or(|at| at.elapsed().as_secs() >= 60)
        {
            last.insert(operation.into(), Instant::now());
            event_kind(operation, "heartbeat", None, Some(duration));
        }
    }
}
pub struct Span {
    operation: &'static str,
    id: String,
    started: Instant,
    finished: bool,
}
impl Span {
    pub fn new(operation: &'static str) -> Self {
        Self::with_id(operation, None)
    }
    pub fn with_id(operation: &'static str, id: Option<&str>) -> Self {
        let id = id
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or_else(uuid::Uuid::new_v4)
            .to_string();
        write_event(operation, "start", None, None, Some(&id));
        Self {
            operation,
            id,
            started: Instant::now(),
            finished: false,
        }
    }
    pub fn id(&self) -> String {
        self.id.clone()
    }
    pub fn finish<T>(&mut self, result: &Result<T, String>) {
        write_event(
            self.operation,
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err().map(|e| error_kind(e)),
            Some(self.started.elapsed().as_millis() as u64),
            Some(&self.id),
        );
        self.finished = true;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            write_event(
                self.operation,
                "interrupted",
                Some("operation_interrupted"),
                Some(self.started.elapsed().as_millis() as u64),
                Some(&self.id),
            );
        }
    }
}
pub fn record<T>(
    operation: &'static str,
    work: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let mut span = Span::new(operation);
    let result = work();
    span.finish(&result);
    result
}
pub async fn record_async<T>(
    operation: &'static str,
    work: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let mut span = Span::new(operation);
    let result = work.await;
    span.finish(&result);
    result
}
pub fn bundle() -> Bundle {
    LOGGER
        .get()
        .and_then(|l| l.lock().ok())
        .map(|l| l.bundle())
        .unwrap_or_else(|| Bundle {
            dropped_events: DROPPED.load(Ordering::Relaxed),
            ..Default::default()
        })
}
pub fn entries() -> Vec<Entry> {
    bundle().entries
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> PathBuf {
        std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
    }
    #[test]
    fn logs_exclude_sensitive_payload_and_reject_untrusted_fields() {
        let dir = temp();
        let logger = Logger::new(&dir, "test").unwrap();
        let raw = "failed 203.0.113.1 /Users/private token=secret proxy://credential";
        logger
            .write(
                "probe.dns",
                "error",
                Some(error_kind(raw)),
                Some(42),
                Some(&uuid::Uuid::new_v4().to_string()),
            )
            .unwrap();
        let log = std::fs::read_to_string(dir.join("diagnostic.jsonl")).unwrap();
        for secret in ["203.0.113.1", "private", "secret", "credential"] {
            assert!(!log.contains(secret));
        }
        assert!(logger
            .write("203.0.113.1:8080", "ok", None, None, None)
            .is_err());
        assert!(logger
            .write("probe.dns", "ok", Some(raw), None, None)
            .is_err());
        assert!(logger
            .write("probe.dns", "ok", None, None, Some(raw))
            .is_err());
        assert_eq!(logger.bundle().entries.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rotation_keeps_four_files_and_reports_corruption() {
        let dir = temp();
        let logger = Logger::new(&dir, "test").unwrap();
        for _ in 0..6 {
            std::fs::write(dir.join("diagnostic.jsonl"), "x".repeat(LIMIT as usize)).unwrap();
            logger.write("app.rotate", "ok", None, None, None).unwrap();
        }
        assert!(dir.join("diagnostic.3.jsonl").is_file());
        assert!(!dir.join("diagnostic.4.jsonl").exists());
        let bundle = logger.bundle();
        assert_eq!(bundle.invalid_lines, 3);
        assert_eq!(bundle.entries.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn cross_process_lock_and_unwritable_destination_are_reported() {
        let dir = temp();
        let logger = Logger::new(&dir, "test").unwrap();
        let other = Logger::new(&dir, "watchdog").unwrap();
        let lock = logger.file_lock().unwrap();
        assert!(other.write("guard.state", "ok", None, None, None).is_err());
        assert_eq!(other.bundle().unreadable_files, 1);
        drop(lock);
        std::fs::create_dir(dir.join("diagnostic.jsonl")).unwrap();
        assert!(logger.write("guard.state", "ok", None, None, None).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn operations_pair_errors_cancellation_and_concurrent_writers_without_payloads() {
        let dir = temp();
        init(&dir).unwrap();
        let error: Result<(), String> =
            record("test.early", || Err("HTTP 503 secret 203.0.113.8".into()));
        assert!(error.is_err());
        let task = tokio::spawn(record_async(
            "test.cancel",
            std::future::pending::<Result<(), String>>(),
        ));
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        let workers: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| record("test.concurrent", || Ok(()))))
            .collect();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let entries = bundle().entries;
        let early: Vec<_> = entries
            .iter()
            .filter(|e| e.operation == "test.early")
            .collect();
        assert_eq!(early.len(), 2);
        assert_eq!(early[0].operation_id, early[1].operation_id);
        assert_eq!(early[1].error_kind.as_deref(), Some("http_status"));
        let cancel: Vec<_> = entries
            .iter()
            .filter(|e| e.operation == "test.cancel")
            .collect();
        assert_eq!(cancel.len(), 2);
        assert_eq!(cancel[1].outcome, "interrupted");
        assert_eq!(cancel[0].operation_id, cancel[1].operation_id);
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.operation == "test.concurrent")
                .count(),
            16
        );
        transition_kind("test.transition", "error", Some("tunnel_unavailable"));
        transition_kind("test.transition", "error", Some("tunnel_unavailable"));
        transition_kind("test.transition", "ok", None);
        assert_eq!(
            bundle()
                .entries
                .iter()
                .filter(|e| e.operation == "test.transition")
                .count(),
            2
        );
        let text = std::fs::read_to_string(dir.join("logs/diagnostic.jsonl")).unwrap();
        assert!(!text.contains("203.0.113.8") && !text.contains("secret"));
        shutdown();
        assert_eq!(
            std::fs::read_to_string(dir.join("logs/session.state")).unwrap(),
            "clean"
        );
        // The process-global logger remains valid for other concurrently running unit tests.
    }
    #[test]
    fn legacy_entries_and_specific_error_categories() {
        let entry: Entry = serde_json::from_str(r#"{"at":"time","session":"old","operation":"probe.dns","outcome":"unavailable","errorKind":null,"durationMs":null}"#).unwrap();
        assert!(entry.operation_id.is_none());
        assert_eq!(error_kind("管理员授权已取消"), "admin_cancelled");
        assert_eq!(error_kind("管理组件未响应"), "helper_unavailable");
        assert_eq!(error_kind("HTTP 503"), "http_status");
        assert_eq!(error_kind("请求超时"), "timeout");
    }
}
