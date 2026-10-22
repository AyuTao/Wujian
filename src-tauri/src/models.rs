use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub theme: String,
    pub external_ip_consent: bool,
    pub dns_http_consent: bool,
    pub proxy_url: String,
    pub monitor_interval_sec: u64,
    pub history_days: u64,
    pub pinned_egress_ip: Option<String>,
    pub original_timezone: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            external_ip_consent: false,
            dns_http_consent: false,
            proxy_url: String::new(),
            monitor_interval_sec: 0,
            history_days: 7,
            pinned_egress_ip: None,
            original_timezone: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimezoneInfo {
    pub current: String,
    pub original: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolInfo {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub installed: bool,
    pub path: Option<String>,
    pub can_launch: bool,
    pub protection: String,
    pub note: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: String,
    pub label: String,
    pub status: String,
    pub value: String,
    pub detail: String,
    pub suggestion: Option<String>,
    pub scope: String,
    pub source: String,
    pub observed_at: String,
    pub integrity: String,
}
impl CheckResult {
    pub fn local(
        id: &str,
        label: &str,
        status: &str,
        value: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            status: status.into(),
            value: value.into(),
            detail: detail.into(),
            suggestion: None,
            scope: "本机配置，未覆盖 AI 工具实际流量".into(),
            source: "操作系统只读检查".into(),
            observed_at: chrono::Utc::now().to_rfc3339(),
            integrity: "local_verified".into(),
        }
    }
    pub fn suggest(mut self, text: &str) -> Self {
        self.suggestion = Some(text.into());
        self
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEvent {
    pub id: String,
    pub at: String,
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub level: String,
}
impl HistoryEvent {
    pub fn new(kind: &str, title: &str, detail: &str, warning: bool) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            at: chrono::Utc::now().to_rfc3339(),
            kind: kind.into(),
            title: title.into(),
            detail: detail.into(),
            level: if warning { "warning" } else { "info" }.into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub value: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerReport {
    pub all_passed: bool,
    pub is_tripped: bool,
    pub tripped_reason: Option<String>,
    pub gates: Vec<GateCheck>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub tools: Vec<ToolInfo>,
    pub checks: Vec<CheckResult>,
    pub platform: String,
    pub version: String,
    pub network_epoch: u64,
    pub observed_at: String,
    pub proxy_summary: String,
    pub dns_servers: Vec<String>,
    pub settings: Settings,
    pub events: Vec<HistoryEvent>,
    pub is_disguised: bool,
    pub protection: crate::protection::ProtectionStatus,
    pub circuit_breaker: CircuitBreakerReport,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckReport {
    pub checks: Vec<CheckResult>,
    pub observed_at: String,
    pub network_epoch: u64,
    pub proxy_summary: String,
    pub dns_servers: Vec<String>,
    pub circuit_breaker: CircuitBreakerReport,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredData {
    pub schema_version: u32,
    pub settings: Settings,
    pub custom_tools: Vec<ToolInfo>,
    pub events: Vec<HistoryEvent>,
}
impl Default for StoredData {
    fn default() -> Self {
        Self {
            schema_version: 1,
            settings: Settings::default(),
            custom_tools: vec![],
            events: vec![],
        }
    }
}
