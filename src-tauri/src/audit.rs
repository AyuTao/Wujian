//! Local diagnostic logs deliberately exclude command arguments, addresses,
//! paths, account names, settings, and raw remote responses.
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

const LIMIT: u64 = 512 * 1024;
const FILES: usize = 4;
static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub at: String,
    pub session: String,
    pub operation: String,
    pub outcome: String,
    pub error_kind: Option<String>,
    pub duration_ms: Option<u64>,
}
struct Logger {
    dir: PathBuf,
    session: String,
}
impl Logger {
    fn new(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        Ok(Self {
            dir: dir.into(),
            session: uuid::Uuid::new_v4().to_string(),
        })
    }
    fn write(
        &self,
        operation: &str,
        outcome: &str,
        error: Option<&str>,
        duration_ms: Option<u64>,
    ) -> Result<(), String> {
        // Call sites supply static event names. Reject accidental free-form data.
        let safe = |s: &str| {
            !s.is_empty()
                && s.len() <= 80
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
        };
        if !safe(operation) || !safe(outcome) {
            return Err("诊断事件名称无效".into());
        }
        let current = self.dir.join("diagnostic.jsonl");
        if std::fs::metadata(&current).is_ok_and(|m| m.len() >= LIMIT) {
            let _ = std::fs::remove_file(self.dir.join(format!("diagnostic.{}.jsonl", FILES - 1)));
            for n in (1..FILES - 1).rev() {
                let from = self.dir.join(format!("diagnostic.{n}.jsonl"));
                if from.exists() {
                    std::fs::rename(from, self.dir.join(format!("diagnostic.{}.jsonl", n + 1)))
                        .map_err(|e| e.to_string())?;
                }
            }
            std::fs::rename(&current, self.dir.join("diagnostic.1.jsonl"))
                .map_err(|e| e.to_string())?;
        }
        let entry = Entry {
            at: chrono::Utc::now().to_rfc3339(),
            session: self.session.clone(),
            operation: operation.into(),
            outcome: outcome.into(),
            error_kind: error.map(error_kind),
            duration_ms,
        };
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(current).map_err(|e| e.to_string())?;
        let mut bytes = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        file.write_all(&bytes).map_err(|e| e.to_string())
    }
    fn entries(&self) -> Vec<Entry> {
        let mut entries = Vec::new();
        for n in (0..FILES).rev() {
            let name = if n == 0 {
                "diagnostic.jsonl".into()
            } else {
                format!("diagnostic.{n}.jsonl")
            };
            if let Ok(contents) = std::fs::read_to_string(self.dir.join(name)) {
                entries.extend(
                    contents
                        .lines()
                        .filter_map(|line| serde_json::from_str::<Entry>(line).ok()),
                );
            }
        }
        entries
    }
}
fn error_kind(error: &str) -> String {
    let lower = error.to_lowercase();
    if lower.contains("timeout") || lower.contains("超时") {
        "timeout"
    } else if lower.contains("permission") || lower.contains("授权") || lower.contains("denied") {
        "permission"
    } else if lower.contains("json") || lower.contains("格式") {
        "invalid_data"
    } else {
        "operation_failed"
    }
    .into()
}
pub fn init(dir: &Path) -> Result<(), String> {
    let logger = Logger::new(&dir.join("logs"))?;
    LOGGER
        .set(Mutex::new(logger))
        .map_err(|_| "日志已初始化".to_string())?;
    event("app.start", "ok", None, None);
    Ok(())
}
pub fn event(operation: &str, outcome: &str, error: Option<&str>, duration_ms: Option<u64>) {
    if let Some(logger) = LOGGER.get() {
        if let Ok(logger) = logger.lock() {
            let _ = logger.write(operation, outcome, error, duration_ms);
        }
    }
}
pub fn entries() -> Vec<Entry> {
    LOGGER
        .get()
        .and_then(|l| l.lock().ok())
        .map(|l| l.entries())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn log_excludes_sensitive_error_payload_and_rejects_free_text() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let logger = Logger::new(&dir).unwrap();
        logger
            .write(
                "probe.dns",
                "error",
                Some("failed 203.0.113.1 /Users/private token=secret proxy://credential"),
                Some(42),
            )
            .unwrap();
        let log = std::fs::read_to_string(dir.join("diagnostic.jsonl")).unwrap();
        for secret in ["203.0.113.1", "private", "secret", "credential"] {
            assert!(!log.contains(secret));
        }
        assert!(logger.write("203.0.113.1:8080", "ok", None, None).is_err());
        assert_eq!(logger.entries().len(), 1);
        // Verify bounded rotation without generating real network activity.
        std::fs::write(dir.join("diagnostic.jsonl"), "x".repeat(LIMIT as usize)).unwrap();
        logger.write("app.rotate", "ok", None, None).unwrap();
        assert!(dir.join("diagnostic.1.jsonl").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
