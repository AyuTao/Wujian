mod audit;
pub mod firewall;
pub mod geo;
mod guard;
mod models;
mod network;
mod network_dns;
mod network_other;
mod platform;
mod probes;
mod protection;
mod proxy_core;
pub mod recovery;
mod safety;
mod store;
pub mod yaml_sanitizer;

use models::*;
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder},
    Emitter, Manager, State,
};

pub static FIREWALL_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

struct Runtime {
    data: StoredData,
    tools: Vec<ToolInfo>,
    checks: Vec<CheckResult>,
    fingerprint: Option<u64>,
    epoch: u64,
    settings_revision: u64,
    running: bool,
    init_error: Option<String>,
    #[allow(dead_code)]
    firewall_policies: std::collections::HashMap<String, firewall::policy::Policy>,
    #[allow(dead_code)]
    firewall_running: bool,
    protection: protection::ProtectionStatus,
}
struct AppState {
    inner: Mutex<Runtime>,
    dir: PathBuf,
    op_lock: tokio::sync::Mutex<()>,
    probe_lock: tokio::sync::Mutex<()>,
}
impl AppState {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Runtime>, String> {
        self.inner
            .lock()
            .map_err(|_| "本地服务状态异常，请重新打开程序".into())
    }
}
fn update_network(runtime: &mut Runtime, network: &platform::NetworkInfo) {
    if runtime
        .fingerprint
        .is_some_and(|old| old != network.fingerprint)
    {
        runtime.epoch += 1;
        // Invalidate existing evidence immediately, including during an in-flight probe.
        {
            for check in &mut runtime.checks {
                if check.status != "not_run" {
                    check.status = "stale".into();
                }
            }
        }
        runtime.data.events.insert(
            0,
            HistoryEvent::new(
                "network",
                "网络配置发生变化",
                "旧检测结果已过期，请按当前路径重新检查。",
                true,
            ),
        );
    }
    runtime.fingerprint = Some(network.fingerprint);
}
fn evaluate_circuit_breaker(checks: &[CheckResult], settings: &Settings) -> CircuitBreakerReport {
    safety::evaluate(checks, settings)
}

fn snapshot(runtime: &Runtime, network: &platform::NetworkInfo) -> AppSnapshot {
    let mut effective_checks = if runtime.checks.is_empty() {
        network.checks.clone()
    } else {
        runtime.checks.clone()
    };
    native_ipv6_evidence(&mut effective_checks, &runtime.protection);
    let circuit_breaker = evaluate_circuit_breaker(&effective_checks, &runtime.data.settings);
    AppSnapshot {
        tools: runtime.tools.clone(),
        checks: effective_checks,
        platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        version: env!("CARGO_PKG_VERSION").into(),
        network_epoch: runtime.epoch,
        observed_at: chrono::Utc::now().to_rfc3339(),
        proxy_summary: network.proxy_summary.clone(),
        dns_servers: network.dns_servers.clone(),
        settings: runtime.data.settings.clone(),
        events: runtime.data.events.clone(),
        is_disguised: FIREWALL_ACTIVE.load(Ordering::SeqCst),
        circuit_breaker,
        protection: runtime.protection.clone(),
    }
}
#[tauri::command]
async fn get_snapshot(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    let network = platform::inspect().await;
    let mut runtime = state.lock()?;
    if let Some(error) = &runtime.init_error {
        return Err(error.clone());
    }
    update_network(&mut runtime, &network);
    runtime.tools = platform::discover(&runtime.data.custom_tools);
    store::prune(&mut runtime.data);
    Ok(snapshot(&runtime, &network))
}
#[tauri::command]
fn discover_tools(state: State<'_, AppState>) -> Result<Vec<ToolInfo>, String> {
    let mut runtime = state.lock()?;
    runtime.tools = platform::discover(&runtime.data.custom_tools);
    let count = runtime.tools.iter().filter(|tool| tool.installed).count();
    let mut data = runtime.data.clone();
    data.events.insert(
        0,
        HistoryEvent::new(
            "scan",
            "工具扫描完成",
            &format!("发现 {count} 个已安装工具；未启动任何工具。"),
            false,
        ),
    );
    store::save(&state.dir, &mut data)?;
    runtime.data = data;
    Ok(runtime.tools.clone())
}
#[tauri::command]
fn save_settings(mut settings: Settings, state: State<'_, AppState>) -> Result<Settings, String> {
    settings.proxy_url = settings.proxy_url.trim().to_string();
    probes::validate_settings(&settings)?;
    let mut runtime = state.lock()?;
    if settings.original_timezone.is_none() && runtime.data.settings.original_timezone.is_some() {
        settings.original_timezone = runtime.data.settings.original_timezone.clone();
    }
    if settings.pinned_egress_ip.is_none() && runtime.data.settings.pinned_egress_ip.is_some() {
        settings.pinned_egress_ip = runtime.data.settings.pinned_egress_ip.clone();
    }
    if runtime.data.settings == settings {
        return Ok(settings);
    }
    let path_changed = runtime.data.settings.proxy_url != settings.proxy_url;
    let evidence_changed = path_changed
        || runtime.data.settings.external_ip_consent != settings.external_ip_consent
        || runtime.data.settings.dns_http_consent != settings.dns_http_consent;
    let mut data = runtime.data.clone();
    data.settings = settings.clone();
    data.events.insert(
        0,
        HistoryEvent::new(
            "settings",
            "检测设置已更新",
            "外部请求仅按已保存的授权范围执行。",
            false,
        ),
    );
    store::save(&state.dir, &mut data)?;
    runtime.data = data;
    if evidence_changed {
        runtime.settings_revision += 1;
    }
    if path_changed {
        runtime.epoch += 1;
    }
    if evidence_changed {
        for check in &mut runtime.checks {
            if check.status != "not_run" {
                check.status = "stale".into();
            }
        }
    }
    Ok(settings)
}
struct RunningGuard<'a>(&'a AppState);
impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut runtime) = self.0.inner.lock() {
            runtime.running = false;
        }
    }
}
fn native_ipv6_evidence(checks: &mut Vec<CheckResult>, status: &protection::ProtectionStatus) {
    if status.ipv6_filtering
        && status
            .receipt
            .as_ref()
            .is_some_and(|r| r.configuration_active)
        && status.error.is_none()
    {
        checks.retain(|c| c.id != "ipv6-policy");
        let mut c = CheckResult::local("ipv6-policy", "IPv6 防护", "match", "本工具的公网 IPv6 阻断规则已回读", "这是原生规则配置证据，不等于实机断流验收；不会修改或清除网卡 IPv6 地址。外部管理员修改防火墙后需重新核验。");
        c.integrity = "native_configuration".into();
        if let Some(r) = &status.receipt {
            c.observed_at = r.checked_at.clone();
        }
        checks.push(c);
    }
}
fn current_decision(rt: &Runtime) -> CircuitBreakerReport {
    let mut checks = rt.checks.clone();
    native_ipv6_evidence(&mut checks, &rt.protection);
    evaluate_circuit_breaker(&checks, &rt.data.settings)
}
async fn native_request(
    state: &AppState,
    request: firewall::Request,
) -> Result<firewall::Receipt, String> {
    let started = std::time::Instant::now();
    let event = match request.action.as_str() {
        "apply" => "firewall.apply",
        "release" => "firewall.release",
        "status" => "firewall.verify",
        "network-apply" => "dns.apply",
        _ => "dns.restore",
    };
    audit::event(event, "start", None, None);
    let result = firewall::elevated(request, &state.dir).await;
    audit::event(
        event,
        if result.is_ok() { "ok" } else { "error" },
        result.as_ref().err().map(String::as_str),
        Some(started.elapsed().as_millis() as u64),
    );
    result
}
async fn enforce_current(state: &AppState, retry: bool) -> Result<(), String> {
    let _op = state.op_lock.lock().await;
    {
        let mut rt = state.lock()?;
        let tripped = current_decision(&rt).is_tripped;
        if !rt.protection.should_isolate(tripped)
            && !(retry && rt.protection.armed && rt.protection.isolation_pending)
        {
            return Ok(());
        }
        rt.protection.isolation_pending = true;
        rt.protection.filter_may_exist = true;
        rt.protection.ipv6_filtering = false;
        rt.protection.receipt = None;
        rt.protection.error = Some("等待管理员授权；授权完成前隔离未确认。".into());
        rt.protection.save(&state.dir)?;
    }
    let result = native_request(
        state,
        firewall::Request {
            dns: None,
            action: "apply".into(),
            policy: Some(firewall::policy::Policy::isolation()),
            acknowledge_connection_reset: true,
        },
    )
    .await;
    let mut rt = state.lock()?;
    match result {
        Ok(receipt) => {
            let active = receipt.configuration_active;
            rt.protection.ipv6_filtering = active;
            rt.protection.receipt = Some(receipt);
            rt.protection.error = if active {
                None
            } else {
                Some("隔离规则回读未通过；请授权核验或重试。".into())
            };
        }
        Err(e) => rt.protection.error = Some(format!("隔离未确认：{e}。请手动重试或停止防护。")),
    }
    rt.protection.save(&state.dir)
}
async fn configure_ipv6_filter(state: &AppState) -> Result<(), String> {
    let _op = state.op_lock.lock().await;
    {
        let mut rt = state.lock()?;
        if rt.protection.isolation_pending {
            return Err("隔离期间不能用 IPv6 规则覆盖整机隔离；请先明确停止防护。".into());
        }
        rt.protection.filter_may_exist = true;
        rt.protection.ipv6_filtering = false;
        rt.protection.save(&state.dir)?;
    }
    let result = native_request(
        state,
        firewall::Request {
            dns: None,
            action: "apply".into(),
            policy: Some(firewall::policy::Policy::ipv6_block()),
            acknowledge_connection_reset: true,
        },
    )
    .await;
    let mut rt = state.lock()?;
    match result {
        Ok(r) if r.configuration_active => {
            rt.protection.ipv6_filtering = true;
            rt.protection.receipt = Some(r);
            rt.protection.error = None;
        }
        Ok(_) => {
            rt.protection.error = Some("IPv6 阻断规则回读未通过".into());
        }
        Err(e) => {
            rt.protection.error = Some(e);
        }
    }
    rt.protection.save(&state.dir)?;
    if let Some(e) = &rt.protection.error {
        Err(e.clone())
    } else {
        Ok(())
    }
}

#[tauri::command]
async fn run_checks(
    expected_epoch: u64,
    state: State<'_, AppState>,
) -> Result<CheckReport, String> {
    let _probe = state.probe_lock.lock().await;
    let started = std::time::Instant::now();
    audit::event("checks.manual", "start", None, None);
    let (settings, revision) = {
        let mut rt = state.lock()?;
        if let Some(e) = &rt.init_error {
            return Err(e.clone());
        }
        rt.running = true;
        (rt.data.settings.clone(), rt.settings_revision)
    };
    let _running = RunningGuard(state.inner());
    let network = platform::inspect().await;
    let epoch = {
        let mut rt = state.lock()?;
        update_network(&mut rt, &network);
        if expected_epoch > rt.epoch {
            return Err("网络版本不同步，请刷新".into());
        }
        for c in &network.checks {
            rt.checks.retain(|old| old.id != c.id);
            rt.checks.push(c.clone());
        }
        rt.epoch
    };
    enforce_current(state.inner(), false).await?;
    let isolated = state.lock()?.protection.isolation_pending;
    let mut checks = network.checks.clone();
    if !isolated {
        checks.extend(probes::run(&settings, &network).await);
    } else {
        checks.push(CheckResult::local("egress-ipv4", "公网出口", "not_run", "隔离期间暂停外部采样", "请先在代理客户端检查规则或全局模式、TUN 和远端 DNS；授权解除隔离会停止防护并恢复联网，然后才能重新采样。"));
    }
    let latest = platform::inspect().await;
    let report = {
        let mut rt = state.lock()?;
        let stale = rt.epoch != epoch
            || rt.settings_revision != revision
            || network.fingerprint != latest.fingerprint;
        update_network(&mut rt, &latest);
        if stale {
            for c in &mut checks {
                c.status = "stale".into();
            }
        }
        rt.checks = checks.clone();
        CheckReport {
            checks,
            observed_at: chrono::Utc::now().to_rfc3339(),
            network_epoch: rt.epoch,
            proxy_summary: latest.proxy_summary.clone(),
            dns_servers: latest.dns_servers.clone(),
            circuit_breaker: current_decision(&rt),
        }
    };
    enforce_current(state.inner(), false).await?;
    audit::event(
        "checks.manual",
        if report.circuit_breaker.is_tripped {
            "restricted"
        } else {
            "observed"
        },
        None,
        Some(started.elapsed().as_millis() as u64),
    );
    Ok(report)
}

#[tauri::command]
async fn prepare_firewall(
    database_path: Option<String>,
    _state: State<'_, AppState>,
) -> Result<firewall::Prepared, String> {
    let _ = database_path;
    let policy = firewall::policy::Policy::isolation();
    let rules = if cfg!(target_os = "macos") {
        firewall::render::pf(&policy)?
    } else if cfg!(target_os = "linux") {
        firewall::render::nft(&policy, false)?
    } else if cfg!(target_os = "windows") {
        firewall::render::windows(&policy)?
    } else {
        return Err("此平台尚不支持原生隔离".into());
    };
    let denied_network_count = policy.denied().len();
    Ok(firewall::Prepared { id: policy.generation, backend: firewall::backend().into(), cn_network_count: 0,
        denied_network_count, resets_connections: true,
        summary: "严格隔离仅保留本机回环通信，将中断整机互联网与局域网访问；现有连接可能断开。必须管理员授权，不会自动解除。".into(), rules })
}

#[tauri::command]
async fn firewall_action(
    action: String,
    plan_id: Option<String>,
    acknowledge: bool,
    state: State<'_, AppState>,
) -> Result<firewall::Receipt, String> {
    let _ = plan_id;
    if action == "apply" {
        if !acknowledge {
            return Err("请确认整机隔离可能中断所有现有连接，并需管理员授权。".into());
        }
        {
            let _op = state.op_lock.lock().await;
            let mut rt = state.lock()?;
            if let Some(e) = &rt.init_error {
                return Err(e.clone());
            }
            rt.protection.armed = true;
            rt.protection.save(&state.dir)?;
            FIREWALL_ACTIVE.store(true, Ordering::SeqCst);
        }
        let pending_isolation = state.lock()?.protection.isolation_pending;
        if !pending_isolation {
            configure_ipv6_filter(state.inner()).await?;
        }
        // Fresh local mode/route evidence; IPC cannot bypass the guard using an old UI plan.
        let network = platform::inspect().await;
        {
            let mut rt = state.lock()?;
            update_network(&mut rt, &network);
            for nc in &network.checks {
                rt.checks.retain(|c| c.id != nc.id);
                rt.checks.push(nc.clone());
            }
        }
        enforce_current(state.inner(), true).await?;
    } else if action == "release" || action == "verify" {
        let _op = state.op_lock.lock().await;
        if action == "release" && !acknowledge {
            return Err("解除隔离将停止防护并恢复联网，请明确确认。".into());
        }
        let pending = state.lock()?.protection.isolation_pending;
        let filter_may_exist = state.lock()?.protection.filter_may_exist;
        if pending || filter_may_exist || action == "verify" {
            let receipt = native_request(
                state.inner(),
                firewall::Request {
                    dns: None,
                    action: if action == "release" {
                        "release"
                    } else {
                        "status"
                    }
                    .into(),
                    policy: None,
                    acknowledge_connection_reset: false,
                },
            )
            .await;
            let mut rt = state.lock()?;
            match receipt {
                Ok(r) => {
                    if action == "release" && r.configuration_active {
                        return Err("规则仍存在，解除未确认".into());
                    }
                    rt.protection.ipv6_filtering = r.configuration_active;
                    rt.protection.error = None;
                    rt.protection.receipt = Some(r);
                }
                Err(e) => {
                    rt.protection.error = Some(e.clone());
                    rt.protection.save(&state.dir)?;
                    return Err(e);
                }
            }
        }
        if action == "release" {
            let dns_modified = state.lock()?.protection.dns_modified;
            if dns_modified {
                if let Err(e) = native_request(
                    state.inner(),
                    firewall::Request {
                        dns: None,
                        action: "network-release".into(),
                        policy: None,
                        acknowledge_connection_reset: false,
                    },
                )
                .await
                {
                    let mut rt = state.lock()?;
                    rt.protection.error = Some(e.clone());
                    rt.protection.save(&state.dir)?;
                    return Err(e);
                }
            }
            // Explicit cleanup of legacy application-side backups only.
            if let Err(errors) = platform::restore_native_network(&state.dir).await {
                let error = format!("旧版本配置尚未完全恢复：{}", errors.join("；"));
                let mut rt = state.lock()?;
                rt.protection.error = Some(error.clone());
                rt.protection.save(&state.dir)?;
                return Err(error);
            }
            let mut rt = state.lock()?;
            rt.protection = protection::ProtectionStatus::default();
            rt.protection.save(&state.dir)?;
            FIREWALL_ACTIVE.store(false, Ordering::SeqCst);
        } else {
            state.lock()?.protection.save(&state.dir)?;
        }
    } else if action != "status" {
        return Err("未知的防护操作".into());
    }
    let rt = state.lock()?;
    // Only the native executor supplies receipts. A diagnostic pass never fabricates one.
    let mut receipt = rt.protection.receipt.clone().unwrap_or(firewall::Receipt {
        backend: firewall::backend().into(),
        configuration_active: false,
        enforcement_verified: false,
        generation: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
        detail: "未验证系统隔离；请以管理员规则回读及实际断流验收为准。".into(),
    });
    if let Some(error) = &rt.protection.error {
        receipt.detail = error.clone();
        receipt.enforcement_verified = false;
    }
    Ok(receipt)
}
#[tauri::command]
fn add_tool(path: String, state: State<'_, AppState>) -> Result<ToolInfo, String> {
    let mut tool = platform::new_tool(&path)?;
    let mut runtime = state.lock()?;
    if let Some(existing) = runtime
        .data
        .custom_tools
        .iter()
        .find(|t| t.path == tool.path)
    {
        tool.id = existing.id.clone();
    }
    let mut data = runtime.data.clone();
    data.custom_tools
        .retain(|t| t.id != tool.id && t.path != tool.path);
    if data.custom_tools.len() >= 50 {
        return Err("最多添加 50 个工具，请先整理配置".into());
    }
    data.custom_tools.push(tool.clone());
    data.events.insert(
        0,
        HistoryEvent::new(
            "scan",
            "已添加工具",
            "已验证可执行路径；未启动程序或修改网络设置。",
            false,
        ),
    );
    store::save(&state.dir, &mut data)?;
    runtime.data = data;
    runtime.tools = platform::discover(&runtime.data.custom_tools);
    Ok(tool)
}
#[tauri::command]
async fn launch_tool(tool_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let tool = {
        let runtime = state.lock()?;
        runtime
            .tools
            .iter()
            .find(|t| t.id == tool_id)
            .cloned()
            .ok_or("工具未登记，请先扫描或添加")?
    };
    if !tool.installed {
        return Err("当前工具不存在，请重新扫描或添加".into());
    }
    guard::require_current_protection(&tool.id)?;
    if !tool.can_launch {
        return Err("此平台的受保护启动适配尚未完成".into());
    }
    platform::launch(&tool).await
}
#[tauri::command]
fn export_report(report_json: String, state: State<'_, AppState>) -> Result<String, String> {
    if report_json.len() > 1_048_576 {
        return Err("报告超出大小限制".into());
    }
    let report: serde_json::Value =
        serde_json::from_str(&report_json).map_err(|_| "报告格式无效".to_string())?;
    let folder = state.dir.join("reports");
    std::fs::create_dir_all(&folder).map_err(|_| "无法创建报告目录".to_string())?;
    let path = folder.join(format!(
        "无间道报告-{}-{}.json",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| "无法写入报告".to_string())?;
    let bytes = serde_json::to_vec_pretty(&report).map_err(|_| "报告序列化失败".to_string())?;
    file.write_all(&bytes)
        .map_err(|_| "保存报告失败".to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

#[tauri::command]
fn get_system_timezone(state: State<'_, AppState>) -> Result<TimezoneInfo, String> {
    let current = platform::get_system_timezone()?;
    let runtime = state.lock()?;
    Ok(TimezoneInfo {
        current,
        original: runtime.data.settings.original_timezone.clone(),
    })
}

#[tauri::command]
fn pin_egress_ip(ip: Option<String>, state: State<'_, AppState>) -> Result<Option<String>, String> {
    let clean_ip = ip.and_then(|v| {
        let trimmed = v.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let mut runtime = state.lock()?;
    let mut data = runtime.data.clone();
    data.settings.pinned_egress_ip = clean_ip.clone();
    data.events.insert(
        0,
        HistoryEvent::new(
            "settings",
            if clean_ip.is_some() {
                "已锁定安全出口 IP"
            } else {
                "已解除出口 IP 锁定"
            },
            match &clean_ip {
                Some(ip) => format!("已锚定安全出口 {ip}，检测偏离将告警。"),
                None => "已取消出口 IP 锁定。".into(),
            }
            .as_str(),
            false,
        ),
    );
    store::save(&state.dir, &mut data)?;
    runtime.data = data;
    Ok(clean_ip)
}

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    if !matches!(
        url.as_str(),
        "https://browserleaks.com/dns" | "https://browserleaks.com/webrtc"
    ) {
        return Err("仅允许打开列出的浏览器检测页面".into());
    }
    #[cfg(target_os = "macos")]
    {
        let _ = tokio::process::Command::new("/usr/bin/open")
            .arg(&url)
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = tokio::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", &url])
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = tokio::process::Command::new("xdg-open").arg(&url).spawn();
    }
    Ok(())
}

#[tauri::command]
async fn optimize_all_gates(state: State<'_, AppState>) -> Result<CheckReport, String> {
    configure_ipv6_filter(state.inner()).await?;
    run_checks(0, state).await
}
#[tauri::command]
async fn restore_all_network(state: State<'_, AppState>) -> Result<CheckReport, String> {
    firewall_action("release".into(), None, true, state.clone()).await?;
    run_checks(0, state).await
}
#[tauri::command]
async fn configure_dns(servers: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    let change = network_dns::Change {
        servers: servers
            .iter()
            .map(|s| s.parse().map_err(|_| "DNS 地址无效".to_string()))
            .collect::<Result<_, _>>()?,
    };
    change.validate()?;
    // Probe before ANY mutation; a missing local resolver cannot take down DNS.
    for server in &change.servers {
        network_dns::probe(*server).await?;
    }
    let _op = state.op_lock.lock().await;
    {
        let mut rt = state.lock()?;
        if rt.protection.isolation_pending {
            return Err("隔离期间请先恢复网络，再修改 DNS".into());
        }
        rt.protection.dns_modified = true;
        rt.protection.save(&state.dir)?;
    }
    let result = native_request(
        state.inner(),
        firewall::Request {
            dns: Some(change),
            action: "network-apply".into(),
            policy: None,
            acknowledge_connection_reset: false,
        },
    )
    .await;
    if let Err(e) = result {
        let mut rt = state.lock()?;
        rt.protection.error = Some(e.clone());
        rt.protection.save(&state.dir)?;
        return Err(e);
    }
    let mut rt = state.lock()?;
    rt.protection.error = None;
    rt.protection.save(&state.dir)?;
    Ok(())
}
#[tauri::command]
async fn toggle_gate(
    gate_id: String,
    enable: bool,
    state: State<'_, AppState>,
) -> Result<CheckReport, String> {
    if gate_id != "gate-ipv6" {
        return Err("DNS 请使用独立设置；时区仅供参考，不自动按国家改写".into());
    }
    if enable {
        configure_ipv6_filter(state.inner()).await?;
    } else {
        firewall_action("release".into(), None, true, state.clone()).await?;
    }
    run_checks(0, state).await
}
#[tauri::command]
fn get_diagnostic_logs() -> Vec<audit::Entry> {
    let mut entries = audit::entries();
    let start = entries.len().saturating_sub(100);
    entries.drain(..start);
    entries
}
#[tauri::command]
fn export_diagnostic_logs(state: State<'_, AppState>) -> Result<String, String> {
    let folder = state.dir.join("reports");
    std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    let path = folder.join(format!(
        "wujian-diagnostics-{}.json",
        uuid::Uuid::new_v4().simple()
    ));
    let data = serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "platform": std::env::consts::OS, "arch": std::env::consts::ARCH, "exportedAt": chrono::Utc::now().to_rfc3339(), "note": "不含原始命令参数、IP、代理端点、账户、恢复记录或路径。", "entries": audit::entries() });
    firewall::write_private(
        &path,
        &serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?,
    )?;
    audit::event("logs.export", "ok", None, None);
    Ok(path.to_string_lossy().into_owned())
}

#[tauri::command]
async fn exit_app(state: State<'_, AppState>) -> Result<(), String> {
    let _op = state.op_lock.lock().await;
    let rt = state.lock()?;
    if rt.protection.armed
        || rt.protection.isolation_pending
        || rt.protection.filter_may_exist
        || rt.protection.dns_modified
    {
        return Err("请先明确停止防护并授权解除隔离；退出程序不会解除系统规则。".into());
    }
    drop(rt);
    if recovery::load_recovery_record(&state.dir)?.is_some() {
        return Err("有旧版本配置等待恢复，请先点击解除隔离并停止防护。".into());
    }
    std::process::exit(0);
}

#[cfg(target_os = "macos")]
mod macos_event_filter {
    use std::os::raw::c_void;

    extern "C" {
        fn objc_getClass(name: *const std::os::raw::c_char) -> *mut c_void;
        fn sel_registerName(name: *const std::os::raw::c_char) -> *mut c_void;
        fn class_getInstanceMethod(cls: *mut c_void, name: *mut c_void) -> *mut c_void;
        fn method_getImplementation(m: *mut c_void) -> *mut c_void;
        fn method_setImplementation(m: *mut c_void, imp: *mut c_void) -> *mut c_void;
        fn objc_msgSend(receiver: *mut c_void, op: *mut c_void, ...) -> *mut c_void;
    }

    static mut ORIGINAL_SEND_EVENT: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void)> =
        None;

    extern "C" fn custom_send_event(this: *mut c_void, cmd: *mut c_void, event: *mut c_void) {
        unsafe {
            if !event.is_null() {
                let msg_send_usize: unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize =
                    std::mem::transmute(objc_msgSend as *const ());
                let type_sel = sel_registerName(b"type\0".as_ptr() as _);
                let event_type: usize = msg_send_usize(event, type_sel);
                // NSEventTypeKeyDown = 10
                if event_type == 10 {
                    let modifier_sel = sel_registerName(b"modifierFlags\0".as_ptr() as _);
                    let flags: usize = msg_send_usize(event, modifier_sel);
                    let cmd_flag = 1 << 20; // NSEventModifierFlagCommand
                    if (flags & cmd_flag) != 0 {
                        let chars_sel =
                            sel_registerName(b"charactersIgnoringModifiers\0".as_ptr() as _);
                        let chars_obj: *mut c_void = objc_msgSend(event, chars_sel);
                        if !chars_obj.is_null() {
                            let utf8_sel = sel_registerName(b"UTF8String\0".as_ptr() as _);
                            let msg_send_cstr: unsafe extern "C" fn(
                                *mut c_void,
                                *mut c_void,
                            )
                                -> *const std::os::raw::c_char =
                                std::mem::transmute(objc_msgSend as *const ());
                            let cstr: *const std::os::raw::c_char =
                                msg_send_cstr(chars_obj, utf8_sel);
                            if !cstr.is_null() {
                                let s = std::ffi::CStr::from_ptr(cstr).to_string_lossy();
                                if s == "q" || s == "Q" || s == "w" || s == "W" {
                                    eprintln!(
                                        "[wujian-filter] >>> TRAPPED Cmd+{}! Dropping event! <<<",
                                        s
                                    );
                                    if let Some(app) = super::APP_HANDLE.get() {
                                        use tauri::{Emitter, Manager};
                                        if let Some(window) = app.get_webview_window("main") {
                                            let is_armed = super::FIREWALL_ACTIVE
                                                .load(std::sync::atomic::Ordering::SeqCst);
                                            let msg = if is_armed {
                                                "无间伪装保护中！必须先点击【卸下伪装】停止后台保护后，才能安全退出应用。"
                                            } else {
                                                "快捷键已拦截锁定。若要退出应用，请在界面操作栏点击【🚪 退出程序】。"
                                            };
                                            let _ = window.emit("disguise-prevent-exit", msg);
                                            let _ = window.set_focus();
                                        }
                                    }
                                    // 彻底丢弃此事件！绝不分发给 Cocoa 菜单系统！
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            if let Some(orig) = ORIGINAL_SEND_EVENT {
                orig(this, cmd, event);
            }
        }
    }

    pub fn install() {
        unsafe {
            let ns_app_cls = objc_getClass(b"NSApplication\0".as_ptr() as _);
            if ns_app_cls.is_null() {
                return;
            }
            let send_event_sel = sel_registerName(b"sendEvent:\0".as_ptr() as _);
            let method = class_getInstanceMethod(ns_app_cls, send_event_sel);
            if method.is_null() {
                return;
            }
            let orig = method_getImplementation(method);
            ORIGINAL_SEND_EVENT = Some(std::mem::transmute(orig));
            method_setImplementation(method, custom_send_event as *mut c_void);
            eprintln!("[wujian-filter] Installed NSApplication sendEvent: filter successfully!");
        }
    }
}

pub fn run() {
    tauri::Builder::default()
        .menu(|app| {
            let safe_quit = MenuItemBuilder::with_id("safe_quit", "退出无间道").build(app)?;
            let safe_close = MenuItemBuilder::with_id("safe_close", "关闭窗口").build(app)?;
            let app_menu = SubmenuBuilder::new(app, "无间道")
                .item(&safe_close)
                .item(&safe_quit)
                .build()?;
            let menu = MenuBuilder::new(app).item(&app_menu).build()?;
            Ok(menu)
        })
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            audit::init(&dir).map_err(std::io::Error::other)?;
            let (data, init_error) = match store::load(&dir) {
                Ok(data) => (data, None),
                Err(error) => (StoredData::default(), Some(error)),
            };
            let protection = protection::ProtectionStatus::load(&dir);
            FIREWALL_ACTIVE.store(
                protection.armed || protection.isolation_pending,
                Ordering::SeqCst,
            );
            let tools = platform::discover(&data.custom_tools);
            let _ = APP_HANDLE.set(app.handle().clone());
            #[cfg(target_os = "macos")]
            macos_event_filter::install();
            app.manage(AppState {
                inner: Mutex::new(Runtime {
                    data,
                    tools,
                    checks: vec![],
                    fingerprint: None,
                    epoch: 0,
                    settings_revision: 0,
                    running: false,
                    init_error,
                    firewall_policies: std::collections::HashMap::new(),
                    firewall_running: false,
                    protection,
                }),
                dir,
                op_lock: tokio::sync::Mutex::new(()),
                probe_lock: tokio::sync::Mutex::new(()),
            });

            // Local inspection comes before remote probes; expired or changed evidence
            // triggers a latched native incident. Never automatically release rules.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut last_probe = std::time::Instant::now();
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let state = handle.state::<AppState>();
                    let Ok(_probe) = state.probe_lock.try_lock() else {
                        continue;
                    };
                    let network = platform::inspect().await;
                    let settings = if let Ok(mut rt) = state.lock() {
                        update_network(&mut rt, &network);
                        for nc in &network.checks {
                            rt.checks.retain(|c| c.id != nc.id);
                            rt.checks.push(nc.clone());
                        }
                        rt.data.settings.clone()
                    } else {
                        continue;
                    };
                    if let Err(e) = enforce_current(state.inner(), false).await {
                        audit::event("checks.background", "error", Some(&e), None);
                        if let Ok(mut rt) = state.lock() {
                            rt.protection.error = Some(e);
                        }
                    }
                    let isolated = state
                        .lock()
                        .map(|rt| rt.protection.isolation_pending)
                        .unwrap_or(true);
                    let armed = state.lock().map(|rt| rt.protection.armed).unwrap_or(false);
                    let interval = if armed {
                        10
                    } else {
                        settings.monitor_interval_sec.max(60)
                    };
                    if !isolated
                        && (armed || settings.monitor_interval_sec > 0)
                        && last_probe.elapsed().as_secs() >= interval
                    {
                        last_probe = std::time::Instant::now();
                        let start_rev = state
                            .lock()
                            .map(|rt| rt.settings_revision)
                            .unwrap_or(u64::MAX);
                        let mut checks = network.checks.clone();
                        checks.extend(probes::run(&settings, &network).await);
                        let latest = platform::inspect().await;
                        if let Ok(mut rt) = state.lock() {
                            let stale = latest.fingerprint != network.fingerprint
                                || rt.settings_revision != start_rev;
                            update_network(&mut rt, &latest);
                            if stale {
                                for c in &mut checks {
                                    c.status = "stale".into();
                                }
                            }
                            rt.checks = checks;
                        }
                        if let Err(e) = enforce_current(state.inner(), false).await {
                            audit::event("checks.background", "error", Some(&e), None);
                            if let Ok(mut rt) = state.lock() {
                                rt.protection.error = Some(e);
                            }
                        }
                    }
                    let current = if let Ok(rt) = state.lock() {
                        Some(snapshot(&rt, &network))
                    } else {
                        None
                    };
                    if let Some(current) = current {
                        let _ = handle.emit("snapshot-updated", current);
                    }
                }
            });

            Ok(())
        })
        .on_menu_event(|app, event| {
            if event.id() == "safe_quit" || event.id() == "safe_close" {
                if let Some(window) = app.get_webview_window("main") {
                    let is_armed = FIREWALL_ACTIVE.load(Ordering::SeqCst);
                    let msg = if is_armed {
                        "无间伪装保护中！必须先点击【卸下伪装】停止后台保护后，才能安全退出应用。"
                    } else {
                        "快捷键已拦截锁定。若要退出应用，请在界面操作栏点击【🚪 退出程序】。"
                    };
                    let _ = window.emit("disguise-prevent-exit", msg);
                    let _ = window.set_focus();
                }
            }
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let is_armed = FIREWALL_ACTIVE.load(Ordering::SeqCst);
                let msg = if is_armed {
                    "无间伪装保护中！必须先点击【卸下伪装】停止后台保护后，才能安全关闭窗口。"
                } else {
                    "窗口关闭已拦截锁定。若要退出应用，请在界面操作栏点击【🚪 退出程序】。"
                };
                let _ = window.emit("disguise-prevent-exit", msg);
                let _ = window.set_focus();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            discover_tools,
            save_settings,
            run_checks,
            add_tool,
            launch_tool,
            export_report,
            prepare_firewall,
            firewall_action,
            get_system_timezone,
            pin_egress_ip,
            configure_dns,
            get_diagnostic_logs,
            export_diagnostic_logs,
            open_url,
            optimize_all_gates,
            restore_all_network,
            toggle_gate,
            exit_app
        ])
        .build(tauri::generate_context!())
        .expect("无法启动无间道桌面程序")
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                api.prevent_exit();
                if let Some(window) = app_handle.get_webview_window("main") {
                    let is_armed = FIREWALL_ACTIVE.load(Ordering::SeqCst);
                    let msg = if is_armed {
                        "无间伪装保护中！必须先点击【卸下伪装】停止后台保护后，才能安全退出应用。"
                    } else {
                        "无间道应用守护中；若要退出请在界面操作。"
                    };
                    let _ = window.emit("disguise-prevent-exit", msg);
                    let _ = window.set_focus();
                }
            }
        });
}

#[cfg(test)]
mod circuit_breaker_regression_tests {
    use super::*;

    #[test]
    fn empty_checks_fails_all_gates_and_trips() {
        let settings = Settings::default();
        let report = evaluate_circuit_breaker(&[], &settings);
        assert!(!report.all_passed);
        assert!(report.is_tripped);
        assert_eq!(report.gates.len(), 6);
        for g in &report.gates {
            assert!(!g.passed, "关卡 {} 在缺失证据时不应放行", g.name);
        }
    }

    #[test]
    fn unknown_country_or_missing_region_rejects_gate_1_and_2() {
        let settings = Settings::default();
        let checks = vec![
            CheckResult::local("egress-ipv4", "出口 IP", "match", "1.2.3.4", "公网 IP"),
            CheckResult::local(
                "egress-region",
                "出口国家",
                "unknown",
                "未知国家",
                "未知归属",
            ),
        ];
        let report = evaluate_circuit_breaker(&checks, &settings);
        let g1 = report.gates.iter().find(|g| g.id == "gate-ip").unwrap();
        assert!(!g1.passed, "出口国家未知不得视为海外合规");

        let g2 = report
            .gates
            .iter()
            .find(|g| g.id == "gate-timezone")
            .unwrap();
        assert!(!g2.passed, "出口国家未知无法对齐时区，必须拒绝放行");
    }

    #[test]
    fn not_run_dns_never_passes() {
        let settings = Settings::default();
        let checks = vec![CheckResult::local(
            "dns-observation",
            "DNS 解析",
            "not_run",
            "待采样",
            "尚未采样",
        )];
        let report = evaluate_circuit_breaker(&checks, &settings);
        let g3 = report.gates.iter().find(|g| g.id == "gate-dns").unwrap();
        assert!(!g3.passed, "未采样 DNS 绝不可判定为通过");
    }

    #[test]
    fn dns_leak_triggers_immediate_trip() {
        let settings = Settings::default();
        let checks = vec![CheckResult::local(
            "dns-observation",
            "DNS 解析",
            "observed",
            "183.232.250.152 · China Mobile",
            "解析命中移动",
        )];
        let report = evaluate_circuit_breaker(&checks, &settings);
        let g3 = report.gates.iter().find(|g| g.id == "gate-dns").unwrap();
        assert!(!g3.passed);
        assert!(g3.detail.contains("泄漏至国内运营商"));
    }

    #[test]
    fn ipv6_automatic_mode_is_not_considered_disabled() {
        let settings = Settings::default();
        let checks = vec![CheckResult::local(
            "ipv6-policy",
            "IPv6 状态",
            "review",
            "IPv6 仍为自动模式",
            "未停用",
        )];
        let report = evaluate_circuit_breaker(&checks, &settings);
        let g4 = report.gates.iter().find(|g| g.id == "gate-ipv6").unwrap();
        assert!(!g4.passed, "IPv6 自动模式绝不可视为已停用");
    }

    #[test]
    fn physical_en_route_rejects_tunnel_gate() {
        let settings = Settings::default();
        let checks = vec![CheckResult::local(
            "network-route",
            "出口路由",
            "observed",
            "公网采样路由经 en0",
            "直连网卡",
        )];
        let report = evaluate_circuit_breaker(&checks, &settings);
        let g5 = report.gates.iter().find(|g| g.id == "gate-tunnel").unwrap();
        assert!(!g5.passed, "物理网卡 en0 绝不可判定为 TUN 接管");
    }

    #[test]
    fn stale_check_evidence_is_rejected() {
        let settings = Settings::default();
        let checks = vec![
            CheckResult::local("egress-ipv4", "出口 IP", "stale", "1.2.3.4", "过期证据"),
            CheckResult::local("egress-region", "出口国家", "stale", "US", "过期证据"),
            CheckResult::local(
                "dns-observation",
                "DNS 解析",
                "stale",
                "8.8.8.8",
                "过期证据",
            ),
            CheckResult::local("ipv6-policy", "IPv6 状态", "stale", "已关闭", "过期证据"),
            CheckResult::local("network-route", "出口路由", "stale", "utun3", "过期证据"),
        ];
        let report = evaluate_circuit_breaker(&checks, &settings);
        assert!(!report.all_passed);
        for g in &report.gates {
            assert!(!g.passed, "过期证据 (stale) 绝不得判定通过: {}", g.name);
        }
    }
}
