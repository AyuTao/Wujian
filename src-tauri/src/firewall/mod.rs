//! One policy and command protocol, with small native firewall adapters.
//! A configuration receipt is NOT a guarantee about remote service identity.
pub mod cidr;
pub(crate) mod command;
mod linux;
mod macos;
pub mod policy;
pub mod render;
mod windows;
use policy::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    hash::{Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub backend: String,
    pub configuration_active: bool,
    pub enforcement_verified: bool,
    pub generation: Option<String>,
    pub checked_at: String,
    pub detail: String,
}
impl Receipt {
    pub(crate) fn new(active: bool, generation: Option<String>, detail: &str) -> Self {
        Self {
            backend: backend().into(),
            configuration_active: active,
            enforcement_verified: false,
            generation,
            checked_at: chrono::Utc::now().to_rfc3339(),
            detail: detail.into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    #[serde(default)]
    pub dns: Option<crate::network_dns::Change>,
    pub action: String,
    pub policy: Option<Policy>,
    pub acknowledge_connection_reset: bool,
}
impl Request {
    pub fn validate(&self) -> Result<(), String> {
        match self.action.as_str() {
            "network-apply" if self.policy.is_none() => {
                self.dns.as_ref().ok_or("缺少 DNS 设置")?.validate()
            }
            "network-release" if self.policy.is_none() && self.dns.is_none() => Ok(()),
            "apply" if self.dns.is_none() => self.policy.as_ref().ok_or("缺少规则策略")?.validate(),
            "release" | "status" if self.policy.is_none() && self.dns.is_none() => Ok(()),
            _ => Err("不支持的隔断操作".into()),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManagedState {
    policy: Policy,
    pf_token: Option<String>,
    fingerprint: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response {
    receipt: Option<Receipt>,
    error: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared {
    pub id: String,
    pub backend: String,
    pub cn_network_count: usize,
    pub denied_network_count: usize,
    pub resets_connections: bool,
    pub summary: String,
    pub rules: String,
}
pub async fn probe_executor() -> Result<String, String> {
    #[cfg(unix)]
    {
        command::run(Path::new("/usr/bin/id"), &["-u"], None).await
    }
    #[cfg(target_os = "windows")]
    {
        command::run(
            &windows::powershell()?,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Write-Output WUJIAN_EXECUTOR_OK",
            ],
            None,
        )
        .await
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        Err("不支持该平台".into())
    }
}
pub fn backend() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS PF"
    } else if cfg!(target_os = "windows") {
        "Windows Firewall"
    } else if cfg!(target_os = "linux") {
        "Linux nftables"
    } else {
        "unsupported"
    }
}
pub fn prepare(
    database: Option<&Path>,
    extra_allowed: Vec<String>,
) -> Result<(Prepared, Policy), String> {
    if backend() == "unsupported" {
        return Err("当前操作系统尚无隔断适配器".into());
    }
    let path = database
        .map(PathBuf::from)
        .or_else(crate::geo::default_database)
        .ok_or("未找到 Country.mmdb，请在本机配置数据库文件")?;
    let mut policy = Policy::from_database(&path)?;
    policy.extra_allowed = extra_allowed;
    let rules = if cfg!(target_os = "macos") {
        render::pf(&policy)?
    } else if cfg!(target_os = "windows") {
        render::windows(&policy)?
    } else {
        render::nft(&policy, false)?
    };
    Ok((
        Prepared {
            id: policy.generation.clone(),
            backend: backend().into(),
            cn_network_count: policy.cn_networks.len(),
            denied_network_count: policy.denied().len(),
            resets_connections: cfg!(target_os = "macos"),
            summary:
                "无间伪装安全防护：已全面放行代理隧道 (TUN/Fake-IP) 与 DNS，拦截物理直连海外泄露。"
                    .into(),
            rules,
        },
        policy,
    ))
}
pub fn export_plan(policy: &Policy, dir: &Path) -> Result<(), String> {
    policy.validate()?;
    std::fs::create_dir(dir).map_err(|_| "输出目录必须是尚不存在的新目录")?;
    for (name, text) in [
        (
            "policy.json",
            serde_json::to_string_pretty(policy).map_err(|_| "策略序列化失败")?,
        ),
        ("macos.conf", render::pf(policy)?),
        ("linux.nft", render::nft(policy, false)?),
        ("windows.ps1", render::windows(policy)?),
        (
            "denied-networks.json",
            serde_json::to_string(
                &policy
                    .denied()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| "地址序列化失败")?,
        ),
    ] {
        write_private(&dir.join(name), text.as_bytes())?;
    }
    for action in ["apply", "release", "status"] {
        let request = Request {
            dns: None,
            action: action.into(),
            policy: if action == "apply" {
                Some(policy.clone())
            } else {
                None
            },
            acknowledge_connection_reset: true,
        };
        write_private(
            &dir.join(format!("request-{action}.json")),
            &serde_json::to_vec_pretty(&request).map_err(|_| "请求序列化失败")?,
        )?;
    }
    Ok(())
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path, limit: u64) -> Result<T, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("无法读取本地隔断文件：{e}"))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("隔断文件类型或大小无效".into());
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|_| "读取隔断文件失败")?)
        .map_err(|_| "隔断文件格式无效".into())
}
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("本地路径无效")?;
    let temp = parent.join(format!(".wujian-{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|_| "无法创建隔断临时文件")?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| "写入隔断文件失败")?;
        file.sync_all().map_err(|_| "同步隔断文件失败")?;
        std::fs::rename(&temp, path).map_err(|_| "保存隔断文件失败")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
fn save_state(dir: &Path, state: &ManagedState) -> Result<(), String> {
    write_private(
        &dir.join("state.json"),
        &serde_json::to_vec(state).map_err(|_| "隔断状态序列化失败")?,
    )
}
fn load_state(dir: &Path) -> Result<Option<ManagedState>, String> {
    let path = dir.join("state.json");
    if !path.exists() {
        return Ok(None);
    }
    let state: ManagedState = read_json(&path, 8 * 1024 * 1024)?;
    state.policy.validate()?;
    Ok(Some(state))
}
fn fingerprint(value: &Value) -> u64 {
    fn clean(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .filter(|(key, _)| {
                        !matches!(key.as_str(), "metainfo" | "handle" | "packets" | "bytes")
                    })
                    .map(|(key, value)| (key.clone(), clean(value)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .filter(|v| v.get("metainfo").is_none())
                    .map(clean)
                    .collect(),
            ),
            _ => value.clone(),
        }
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    clean(value).to_string().hash(&mut h);
    h.finish()
}
async fn require_administrator() -> Result<(), String> {
    #[cfg(unix)]
    {
        if command::run(Path::new("/usr/bin/id"), &["-u"], None)
            .await?
            .trim()
            != "0"
        {
            return Err("系统隔断操作需要本机管理员授权；未修改规则".into());
        }
    }
    #[cfg(target_os = "windows")]
    {
        let check="$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 1 }; Write-Output 'WUJIAN_ADMIN'";
        command::run(
            &windows::powershell()?,
            &["-NoProfile", "-NonInteractive", "-Command", check],
            None,
        )
        .await
        .map_err(|_| "系统隔断操作需要 Windows 管理员授权")?;
    }
    Ok(())
}
async fn state_directory() -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    let dir = PathBuf::from("/var/db/io.wujian.firewall");
    #[cfg(target_os = "linux")]
    let dir = PathBuf::from("/var/lib/io.wujian.firewall");
    #[cfg(target_os = "windows")]
    let dir = windows::program_data()?.join("io.wujian.firewall");
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err("当前平台不支持系统隔断".into());
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        if !dir.exists() {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&dir).map_err(|_| "无法创建系统隔断目录")?;
        }
        let meta = std::fs::symlink_metadata(&dir).map_err(|_| "无法核验隔断目录")?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("系统隔断目录类型异常".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err("隔断目录必须由 root 拥有且不可被其他用户修改".into());
            }
        }
        #[cfg(target_os = "windows")]
        windows::secure_directory(&dir).await?;
        Ok(dir)
    }
}
async fn execute_request(request: &Request) -> Result<Receipt, String> {
    request.validate()?;
    require_administrator().await?;
    let dir = state_directory().await?;
    let operation_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("operation.lock"))
        .map_err(|_| "无法打开隔断操作锁")?;
    operation_lock
        .try_lock()
        .map_err(|_| "已有系统隔断操作正在执行，请稍后核验")?;
    if request.action.starts_with("network-") {
        return crate::network_dns::execute(&request.action, request.dns.as_ref(), &dir).await;
    }
    let previous = load_state(&dir);
    // A corrupt manifest must not make the local emergency release unavailable.
    let state = if request.action == "release" {
        previous.unwrap_or(None)
    } else {
        previous?
    };
    match request.action.as_str() {
        "apply" => {
            let mut state = ManagedState {
                policy: request.policy.clone().ok_or("规则缺失")?,
                pf_token: state.and_then(|s| s.pf_token),
                fingerprint: None,
            };
            save_state(&dir, &state)?;
            let result = if cfg!(target_os = "macos") {
                macos::apply(&mut state, &dir, request.acknowledge_connection_reset).await
            } else if cfg!(target_os = "linux") {
                linux::apply(&mut state, &dir).await
            } else if cfg!(target_os = "windows") {
                windows::apply(&mut state, &dir).await
            } else {
                Err("不支持的平台".into())
            };
            result.map_err(|error| {
                format!("{error}。操作失败不代表规则已解除，可使用本机的解除隔断。")
            })
        }
        "release" => {
            let result = if cfg!(target_os = "macos") {
                macos::release(state.as_ref()).await
            } else if cfg!(target_os = "linux") {
                linux::release().await
            } else {
                windows::release(&dir).await
            }?;
            let path = dir.join("state.json");
            if path.exists() {
                std::fs::remove_file(path)
                    .map_err(|_| "规则已清除，但本地状态文件未删除；请重新核验")?;
            }
            Ok(result)
        }
        "status" => {
            if cfg!(target_os = "macos") {
                macos::status(state.as_ref()).await
            } else if cfg!(target_os = "linux") {
                linux::status(state.as_ref()).await
            } else {
                windows::status(state.as_ref(), &dir).await
            }
        }
        _ => Err("无效操作".into()),
    }
}
/// Called only by the native executable's explicit helper entry point.
/// It never starts the UI as administrator.
pub async fn helper(request_path: &Path, result_file: bool) -> Result<(), String> {
    let request: Request = read_json(request_path, 4 * 1024 * 1024)?;
    let response = match execute_request(&request).await {
        Ok(receipt) => Response {
            receipt: Some(receipt),
            error: None,
        },
        Err(error) => Response {
            receipt: None,
            error: Some(error),
        },
    };
    let text = serde_json::to_string(&response).map_err(|_| "系统回执序列化失败")?;
    if result_file {
        // Windows UAC cannot redirect stdout. Exclusive creation prevents an
        // elevated helper from following/truncating an existing response file.
        let path = request_path
            .parent()
            .ok_or("请求路径无效")?
            .join("result.json");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| "无法新建管理员操作回执")?;
        file.write_all(text.as_bytes())
            .map_err(|_| "写入管理员操作回执失败")?;
    } else {
        println!("{text}");
    }
    Ok(())
}
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
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
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn windows_argument(value: &str) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            result.push_str(&"\\".repeat(slashes * 2 + 1));
            result.push('"');
        } else {
            result.push_str(&"\\".repeat(slashes));
            result.push(ch);
        }
        slashes = 0;
    }
    result.push_str(&"\\".repeat(slashes * 2));
    result.push('"');
    result
}
/// Interactive OS authorization is triggered only by the user's explicit action.
/// The request contains typed policy data, never arbitrary executable commands.
pub async fn elevated(request: Request, app_data: &Path) -> Result<Receipt, String> {
    request.validate()?;
    let dir = app_data
        .join("firewall-requests")
        .join(uuid::Uuid::new_v4().simple().to_string());
    std::fs::create_dir_all(&dir).map_err(|_| "无法准备管理员请求目录")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "无法保护请求目录")?;
    }
    let path = dir.join("request.json");
    write_private(
        &path,
        &serde_json::to_vec(&request).map_err(|_| "请求序列化失败")?,
    )?;
    let exe = std::env::current_exe().map_err(|_| "无法定位原生程序")?;
    let exe = exe.to_str().ok_or("程序路径编码无效")?;
    let request_path = path.to_str().ok_or("请求路径编码无效")?;
    let output = if cfg!(target_os = "macos") {
        let command = format!(
            "{} --firewall-helper {}",
            shell_quote(exe),
            shell_quote(request_path)
        );
        let script = format!(
            "do shell script {} with administrator privileges",
            applescript_quote(&command)
        );
        command::run(Path::new("/usr/bin/osascript"), &["-e", &script], None).await?
    } else if cfg!(target_os = "linux") {
        let pkexec = ["/usr/bin/pkexec", "/bin/pkexec"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or("需要安装 polkit/pkexec 才能在桌面授权；也可使用 sudo 运行原生 helper 请求")?;
        command::run(&pkexec, &[exe, "--firewall-helper", request_path], None).await?
    } else if cfg!(target_os = "windows") {
        let arguments = ["--firewall-helper", request_path, "--result-file"]
            .map(windows_argument)
            .join(" ");
        let script=format!("$ErrorActionPreference='Stop'; $p=Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -Wait -PassThru; if ($p.ExitCode -ne 0) {{ throw 'Administrator helper failed' }}",ps_quote(exe),ps_quote(&arguments));
        command::run(
            &windows::powershell()?,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            None,
        )
        .await?;
        std::fs::read_to_string(dir.join("result.json")).map_err(|_| "未收到管理员操作回执")?
    } else {
        return Err("当前平台不支持管理员隔断操作".into());
    };
    let response: Response = serde_json::from_str(output.trim())
        .map_err(|_| "管理员操作回执格式无效；请核验当前规则，不要假定已经解除")?;
    if let Some(error) = response.error {
        return Err(error);
    }
    response.receipt.ok_or("管理员操作没有返回状态".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_typed_actions_are_authorized() {
        assert!(Request {
            dns: None,
            action: "status".into(),
            policy: None,
            acknowledge_connection_reset: false
        }
        .validate()
        .is_ok());
        assert!(Request {
            dns: None,
            action: "apply".into(),
            policy: None,
            acknowledge_connection_reset: true
        }
        .validate()
        .is_err());
        assert!(Request {
            dns: None,
            action: "release; rm -rf".into(),
            policy: None,
            acknowledge_connection_reset: false
        }
        .validate()
        .is_err());
    }
    #[test]
    fn counter_changes_do_not_mask_changed_addresses() {
        let a = serde_json::json!({"expr":[{"counter":{"packets":1,"bytes":20}},{"addr":"223.5.5.0/24"}]});
        let mut b = a.clone();
        b["expr"][0]["counter"]["packets"] = 99.into();
        assert_eq!(fingerprint(&a), fingerprint(&b));
        b["expr"][1]["addr"] = "8.8.8.0/24".into();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }
    #[test]
    fn shell_and_windows_quoting_keep_paths_literal() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(windows_argument("C:\\some path\\"), "\"C:\\some path\\\\\"");
        assert_eq!(ps_quote("a'b"), "'a''b'");
    }
}
