mod admin_helper;
pub mod audit;
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
mod timezone_follow;

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

pub fn admin_install() -> Result<(), String> {
    init_helper_diagnostics("admin_installer");
    audit::record("admin.install", admin_helper::install_as_root)
}
pub fn init_helper_diagnostics(source: &str) {
    if let Ok(runtime) = tokio::runtime::Runtime::new() {
        let _ = runtime.block_on(firewall::initialize_diagnostics(source));
    }
}
pub fn admin_serve() -> Result<(), String> {
    init_helper_diagnostics("admin_helper");
    audit::record("admin.serve", admin_helper::serve)
}
pub static FIREWALL_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

struct Runtime {
    timezone_follow: timezone_follow::FollowState,
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
    lifecycle_lock: tokio::sync::Mutex<()>,
}
impl AppState {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Runtime>, String> {
        self.inner
            .lock()
            .map_err(|_| "本地服务状态异常，请重新打开程序".into())
    }
}
fn log_check_states(checks: &[CheckResult]) {
    for check in checks {
        let operation = format!("check.{}", check.id.replace('-', "_"));
        let error = matches!(check.status.as_str(), "unknown" | "deviation")
            .then_some(check.detail.as_str());
        audit::transition(&operation, &check.status, error);
    }
}
fn update_network(runtime: &mut Runtime, network: &platform::NetworkInfo) {
    if runtime
        .fingerprint
        .is_some_and(|old| old != network.fingerprint)
    {
        audit::event("network.changed", "observed", None, None);
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

fn snapshot(runtime: &Runtime, network: &platform::NetworkInfo) -> AppSnapshot {
    let mut effective_checks = if runtime.checks.is_empty() {
        network.checks.clone()
    } else {
        runtime.checks.clone()
    };
    native_ipv6_evidence(&mut effective_checks, &runtime.protection);
    native_timezone_evidence(&mut effective_checks, runtime);
    let circuit_breaker = if !runtime.protection.armed || runtime.protection.tunnel_policy.is_some()
    {
        safety::global_report(
            &effective_checks,
            &runtime.data.settings,
            &runtime.protection,
        )
    } else {
        safety::evaluate(
            &effective_checks,
            &runtime.data.settings,
            runtime.protection.baseline.as_ref(),
            runtime.protection.armed,
        )
    };
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
    let result: Result<_, String> = async {
        let network = platform::inspect().await;
        log_check_states(&network.checks);
        let mut runtime = state.lock()?;
        sync_tunnel_status(&mut runtime);
        if let Some(error) = &runtime.init_error {
            return Err(error.clone());
        }
        update_network(&mut runtime, &network);
        runtime.tools = platform::discover(&runtime.data.custom_tools);
        store::prune(&mut runtime.data);
        Ok(snapshot(&runtime, &network))
    }
    .await;
    audit::transition(
        "snapshot.read",
        if result.is_ok() { "ok" } else { "error" },
        result.as_ref().err().map(String::as_str),
    );
    result
}
#[tauri::command]
fn discover_tools(state: State<'_, AppState>) -> Result<Vec<ToolInfo>, String> {
    audit::record("tools.discover", || {
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
    })
}
#[tauri::command]
fn save_settings(mut settings: Settings, state: State<'_, AppState>) -> Result<Settings, String> {
    audit::record("settings.save", || {
        settings.proxy_url = settings.proxy_url.trim().to_string();
        settings.target_timezone = settings
            .target_timezone
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        settings.geoip_database_path = settings
            .geoip_database_path
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        probes::validate_settings(&settings)?;
        let mut runtime = state.lock()?;
        if settings.original_timezone.is_none() && runtime.data.settings.original_timezone.is_some()
        {
            settings.original_timezone = runtime.data.settings.original_timezone.clone();
        }
        if settings.pinned_egress_ip.is_none() && runtime.data.settings.pinned_egress_ip.is_some() {
            settings.pinned_egress_ip = runtime.data.settings.pinned_egress_ip.clone();
        }
        if runtime.data.settings == settings {
            return Ok(settings);
        }
        if runtime.protection.armed || runtime.protection.isolation_pending {
            return Err("请先停止守护并解除隔离，再修改检测设置或目标时区".into());
        }
        let path_changed = runtime.data.settings.proxy_url != settings.proxy_url;
        let evidence_changed = path_changed
            || runtime.data.settings.timezone_mode != settings.timezone_mode
            || runtime.data.settings.external_ip_consent != settings.external_ip_consent
            || runtime.data.settings.dns_http_consent != settings.dns_http_consent
            || runtime.data.settings.target_timezone != settings.target_timezone
            || runtime.data.settings.geoip_database_path != settings.geoip_database_path;
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
        if path_changed || runtime.data.settings.timezone_mode != settings.timezone_mode {
            runtime.timezone_follow = timezone_follow::FollowState::default();
        }
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
    })
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
    native_timezone_evidence(&mut checks, rt);
    if !rt.protection.armed || rt.protection.tunnel_policy.is_some() {
        return safety::global_report(&checks, &rt.data.settings, &rt.protection);
    }
    safety::evaluate(
        &checks,
        &rt.data.settings,
        rt.protection.baseline.as_ref(),
        rt.protection.armed,
    )
}
fn native_timezone_evidence(checks: &mut Vec<CheckResult>, rt: &Runtime) {
    checks.retain(|c| c.id != "timezone-follow");
    if rt.data.settings.timezone_mode == "egress" {
        checks.push(rt.timezone_follow.check(checks));
    }
}
fn sync_tunnel_status(rt: &mut Runtime) {
    let Some(policy) = rt.protection.tunnel_policy.as_ref() else {
        return;
    };
    match firewall::guard_status() {
        Ok(receipt)
            if receipt.configuration_active
                && receipt.policy_mode == "tunnel"
                && receipt.generation.as_deref() == Some(policy.generation.as_str()) =>
        {
            audit::transition("guard.state", "protected", None);
            rt.protection.isolation_pending = false;
            rt.protection.incident_reason = None;
            rt.protection.tunnel_guard_confirmed = true;
            rt.protection.ipv6_filtering = true;
            rt.protection.error = None;
            rt.protection.receipt = Some(receipt);
        }
        Ok(receipt) => {
            rt.protection.tunnel_guard_confirmed = false;
            if receipt.configuration_active && receipt.policy_mode == "isolation" {
                rt.protection.isolation_pending = true;
                rt.protection.incident_reason.get_or_insert_with(|| {
                    "TUN 或节点暂不可用，网络已切断。同一节点恢复后会自动继续。".into()
                });
                rt.protection.error = None;
            } else {
                rt.protection.error = Some("保护规则还没对上，正在重新确认。".into());
            }
            audit::transition(
                "guard.state",
                if rt.protection.isolation_pending {
                    "isolated"
                } else {
                    "unconfirmed"
                },
                rt.protection.error.as_deref(),
            );
            rt.protection.receipt = Some(receipt);
        }
        Err(error) => {
            audit::transition("guard.state", "error", Some(&error));
            rt.protection.tunnel_guard_confirmed = false;
            rt.protection.error = Some(error);
        }
    }
}
async fn native_request(
    state: &AppState,
    request: firewall::Request,
) -> Result<firewall::Receipt, String> {
    let event = match request.action.as_str() {
        "apply" => match request.policy.as_ref() {
            Some(p) if p.tunnel_guard.is_some() => "native.tunnel.apply",
            Some(p) if p.lockdown => "native.isolation.apply",
            _ => "native.ipv6.apply",
        },
        "release" => "native.firewall.release",
        "status" => "native.firewall.verify",
        "guard-plan" => "native.guard.prepare",
        "network-apply" => "native.dns.apply",
        "network-release" => "native.dns.restore",
        _ => "native.diagnostics",
    };
    let mut span = audit::Span::new(event);
    let mut request = request;
    request.operation_id = Some(span.id());
    let result = firewall::elevated(request, &state.dir).await;
    span.finish(&result);
    result
}
async fn enforce_current(state: &AppState, retry: bool) -> Result<(), String> {
    let _op = state.op_lock.lock().await;
    {
        let mut rt = state.lock()?;
        if rt.protection.tunnel_policy.is_some() {
            sync_tunnel_status(&mut rt);
            return rt.protection.save(&state.dir);
        }
        let decision = current_decision(&rt);
        if !rt
            .protection
            .begin_isolation(decision.is_tripped, decision.tripped_reason, retry)
        {
            return Ok(());
        }
        rt.protection.save(&state.dir)?;
    }
    let result = native_request(
        state,
        firewall::Request {
            operation_id: None,
            guard_user: None,
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
            rt.protection.ipv6_filtering = false;
            rt.protection.receipt = Some(receipt);
            rt.protection.error = if active {
                None
            } else {
                Some("隔离规则还没对上，请再试一次或停止保护。".into())
            };
        }
        Err(e) => rt.protection.error = Some(format!("隔离未确认：{e}。请手动重试或停止防护。")),
    }
    rt.protection.save(&state.dir)
}
async fn configure_ipv6_filter(state: &AppState) -> Result<(), String> {
    audit::record_async("ipv6.configure", async {
        let _op = state.op_lock.lock().await;
        {
            let mut rt = state.lock()?;
            if rt.protection.isolation_pending {
                return Err("隔离期间不能用 IPv6 规则覆盖整机隔离；请先明确停止防护。".into());
            }
            if rt.protection.tunnel_policy.is_some() {
                return Err("全局保护已包含隧道外 IPv6 阻断，不能用单独规则覆盖。".into());
            }
            rt.protection.filter_may_exist = true;
            rt.protection.ipv6_filtering = false;
            rt.protection.save(&state.dir)?;
        }
        let result = native_request(
            state,
            firewall::Request {
                operation_id: None,
                guard_user: None,
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
    })
    .await
}

#[tauri::command]
async fn run_checks(
    expected_epoch: u64,
    trigger: Option<String>,
    state: State<'_, AppState>,
) -> Result<CheckReport, String> {
    let operation = match trigger.as_deref() {
        Some("startup") => "checks.startup",
        Some("settings") => "checks.settings",
        Some("background") => "checks.background",
        Some("operation") => "checks.after_operation",
        _ => "checks.manual",
    };
    audit::record_async(operation, run_checks_inner(expected_epoch, state)).await
}
async fn run_checks_inner(
    expected_epoch: u64,
    state: State<'_, AppState>,
) -> Result<CheckReport, String> {
    let _probe = state.probe_lock.lock().await;
    let started = std::time::Instant::now();
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
    log_check_states(&network.checks);
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
        if rt.protection.tunnel_policy.is_some() {
            let previous = rt
                .checks
                .iter()
                .find(|c| c.id == "egress-ipv4" && c.integrity == "tls_verified");
            let next = checks.iter().find(|c| {
                c.id == "egress-ipv4"
                    && c.integrity == "tls_verified"
                    && safety::fresh(c, chrono::Utc::now())
            });
            if previous.zip(next).is_some_and(|(a, b)| {
                a.value != b.value && a.value.parse::<std::net::Ipv4Addr>().is_ok()
            }) {
                rt.data.events.insert(0, HistoryEvent::new("network", "出口 IP 发生变化", "已记录出口变化；全局防回落规则继续保留，不因出口观测变化自动切换节点或解除保护。", true));
                let mut data = rt.data.clone();
                store::save(&state.dir, &mut data)?;
                rt.data = data;
            }
        }
        rt.checks = checks.clone();
        native_ipv6_evidence(&mut checks, &rt.protection);
        native_timezone_evidence(&mut checks, &rt);
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
    log_check_states(&report.checks);
    audit::event(
        "checks.summary",
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
    state: State<'_, AppState>,
) -> Result<firewall::Prepared, String> {
    audit::record_async("guard.prepare", async {
    let _ = database_path;
    let _lifecycle = state.lifecycle_lock.lock().await;
    let _op = state.op_lock.lock().await;
    if state.lock()?.protection.armed {
        return Err("请先停止当前保护，再重新准备节点计划".into());
    }
    if !cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )) {
        return Err("当前系统暂不支持全局 TUN 保护".into());
    }
    let mode = proxy_core::inspect(false).await;
    if !matches!(mode.status.as_str(), "match" | "unknown") {
        return Err(mode.value);
    }
    let uid: u32 = if cfg!(target_os = "windows") {
        1
    } else {
        platform::output("/usr/bin/id", &["-u"])
            .await
            .ok_or("无法读取桌面用户")?
            .trim()
            .parse()
            .map_err(|_| "桌面用户无效")?
    };
    let receipt = native_request(
        state.inner(),
        firewall::Request {
            operation_id: None,
            guard_user: Some(uid),
            dns: None,
            action: "guard-plan".into(),
            policy: None,
            acknowledge_connection_reset: false,
        },
    )
    .await?;
    let policy = receipt.guard_policy.ok_or("未返回可核验的隧道计划")?;
    policy.validate()?;
    let guard = policy.tunnel_guard.as_ref().ok_or("未确认全局 TUN")?;
    let dns_path = if guard.dns_pins.is_empty() {
        "国外 DNS 走该节点。"
    } else {
        "国外 DNS 使用了另一个节点，其地址和端口一并放行。"
    };
    let mut summary = format!(
        "节点 {}，{}。全局模式，{} 已劫持 53 端口，{dns_path}只放行 {} 端口 {}（{}），以及回环、DHCP 和私网。192.168、10 和 172.16 继续可通。不放行公共 DNS、国内公网或其他 VPN。国内直连 DNS 开启后会被防火墙阻断。出口 IP 变化不会断开保护。",
        guard.node,
        guard.country,
        guard.interface,
        guard
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("、"),
        guard.port,
        guard.protocols.join("/")
    );
    if cfg!(target_os = "macos") {
        summary.push_str("开启会重置已有连接。");
    } else if cfg!(target_os = "windows") {
        summary.push_str("物理网卡上，节点地址除该端口外也会被拦住；指定 TUN 不在拦截名单里。");
    } else if cfg!(target_os = "linux") {
        summary.push_str("已经建立的连接也会被这套规则拦住。");
    }
    if !guard.dns_note.is_empty() {
        summary.push_str(&guard.dns_note);
    }
    let rules = if cfg!(target_os = "windows") {
        firewall::render::windows(&policy)?
    } else if cfg!(target_os = "linux") {
        firewall::render::nft(&policy, false)?
    } else {
        firewall::render::pf(&policy)?
    };
    let prepared = firewall::Prepared {
        id: policy.generation.clone(),
        backend: firewall::backend().into(),
        cn_network_count: 0,
        denied_network_count: 0,
        resets_connections: cfg!(target_os = "macos"),
        summary,
        rules,
    };
    let mut rt = state.lock()?;
    rt.firewall_policies.clear();
    rt.firewall_policies
        .insert(policy.generation.clone(), policy);
    Ok(prepared)
    }).await
}

#[tauri::command]
async fn firewall_action(
    action: String,
    plan_id: Option<String>,
    acknowledge: bool,
    state: State<'_, AppState>,
) -> Result<firewall::Receipt, String> {
    let operation = match action.as_str() {
        "apply" => "guard.enable",
        "release" => "guard.release",
        "verify" => "guard.verify",
        "isolate" => "guard.isolate",
        _ => "guard.status",
    };
    audit::record_async(operation, async {
        let _lifecycle = state.lifecycle_lock.lock().await;
        if action == "isolate" {
            if !acknowledge {
                return Err("整机隔断会中断互联网，私网仍可通，请明确确认。".into());
            }
            let _op = state.op_lock.lock().await;
            {
                let mut rt = state.lock()?;
                rt.protection.armed = true;
                rt.protection.isolation_pending = true;
                rt.protection.filter_may_exist = true;
                rt.protection.tunnel_guard_confirmed = false;
                rt.protection.receipt = None;
                rt.protection.error = Some("等待管理员确认整机隔断".into());
                rt.protection.save(&state.dir)?;
                FIREWALL_ACTIVE.store(true, Ordering::SeqCst);
            }
            let result = native_request(
                state.inner(),
                firewall::Request {
                    operation_id: None,
                    guard_user: None,
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
                    rt.protection.error =
                        (!receipt.configuration_active).then(|| "整机隔断规则未确认".into());
                    rt.protection.receipt = Some(receipt);
                }
                Err(error) => {
                    rt.protection.error = Some(error.clone());
                    rt.protection.save(&state.dir)?;
                    return Err(error);
                }
            }
            rt.protection.save(&state.dir)?;
        } else if action == "apply" {
            if !acknowledge {
                return Err("请先核对节点计划，确认重置连接并安装常驻保护 helper。".into());
            }
            let _op = state.op_lock.lock().await;
            let policy = {
                let mut rt = state.lock()?;
                if rt.protection.armed {
                    return Err("保护已开启；请核验或明确停止，不能直接替换出口计划。".into());
                }
                let id = plan_id.ok_or("必须先准备并确认全局 TUN 节点计划")?;
                let policy = rt
                    .firewall_policies
                    .remove(&id)
                    .ok_or("节点计划不存在或已使用，请重新检查")?;
                let guard = policy
                    .tunnel_guard
                    .as_ref()
                    .ok_or("没有可核验的 TUN 计划")?;
                let at = chrono::DateTime::parse_from_rfc3339(&guard.prepared_at)
                    .map_err(|_| "计划时间无效")?;
                if !(0..120).contains(&chrono::Utc::now().signed_duration_since(at).num_seconds()) {
                    return Err("节点计划已过期，请重新检查".into());
                }
                rt.protection.filter_may_exist = true;
                rt.protection.tunnel_policy = Some(policy.clone());
                rt.protection.tunnel_guard_confirmed = false;
                rt.protection.save(&state.dir)?;
                policy
            };
            let result = native_request(
                state.inner(),
                firewall::Request {
                    operation_id: None,
                    guard_user: None,
                    dns: None,
                    action: "apply".into(),
                    policy: Some(policy.clone()),
                    acknowledge_connection_reset: true,
                },
            )
            .await;
            let mut rt = state.lock()?;
            match result {
                Ok(receipt)
                    if receipt.configuration_active
                        && receipt.policy_mode == "tunnel"
                        && receipt.generation.as_deref() == Some(policy.generation.as_str()) =>
                {
                    rt.protection.armed = true;
                    rt.protection.baseline = None;
                    rt.protection.tunnel_guard_confirmed = true;
                    rt.protection.ipv6_filtering = true;
                    rt.protection.error = None;
                    rt.protection.receipt = Some(receipt);
                    FIREWALL_ACTIVE.store(true, Ordering::SeqCst);
                }
                Ok(receipt) => {
                    rt.protection.receipt = Some(receipt);
                    rt.protection.error =
                        Some("未完整确认全局保护；规则可能已保留，请核验或明确停止保护。".into());
                    rt.protection.save(&state.dir)?;
                    return Err(rt.protection.error.clone().unwrap());
                }
                Err(error) => {
                    rt.protection.error = Some(error.clone());
                    rt.protection.save(&state.dir)?;
                    return Err(error);
                }
            }
            rt.protection.save(&state.dir)?;
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
                        operation_id: None,
                        guard_user: None,
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
                        rt.protection.ipv6_filtering = r.configuration_active && !pending;
                        rt.protection.error = None;
                        if let Some(policy) = rt.protection.tunnel_policy.as_ref() {
                            rt.protection.tunnel_guard_confirmed = r.configuration_active
                                && r.policy_mode == "tunnel"
                                && r.generation.as_deref() == Some(policy.generation.as_str());
                            if r.configuration_active && r.policy_mode == "isolation" {
                                rt.protection.isolation_pending = true;
                            }
                            if !r.configuration_active && action == "verify" {
                                rt.protection.error =
                                    Some("规则未通过当前核验；请检查或明确停止保护。".into());
                            }
                        }
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
                            operation_id: None,
                            guard_user: None,
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
            diagnostic_logs: None,
            policy_mode: "unknown".into(),
            guard_policy: None,
            backend: firewall::backend().into(),
            configuration_active: false,
            enforcement_verified: false,
            generation: None,
            checked_at: chrono::Utc::now().to_rfc3339(),
            detail: "还没有系统隔离回读。".into(),
        });
        if let Some(error) = &rt.protection.error {
            receipt.detail = error.clone();
            receipt.enforcement_verified = false;
        }
        Ok(receipt)
    })
    .await
}
#[tauri::command]
fn add_tool(path: String, state: State<'_, AppState>) -> Result<ToolInfo, String> {
    audit::record("tools.add", || {
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
    })
}
#[tauri::command]
async fn launch_tool(tool_id: String, state: State<'_, AppState>) -> Result<(), String> {
    audit::record_async("tools.launch", async {
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
    })
    .await
}
#[tauri::command]
fn export_report(report_json: String, state: State<'_, AppState>) -> Result<String, String> {
    audit::record("report.export", || {
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
    })
}

#[tauri::command]
fn get_system_timezone(state: State<'_, AppState>) -> Result<TimezoneInfo, String> {
    let result: Result<_, String> = (|| {
        let current = platform::get_system_timezone()?;
        let runtime = state.lock()?;
        Ok(TimezoneInfo {
            current,
            original: runtime.data.settings.original_timezone.clone(),
        })
    })();
    audit::transition(
        "timezone.read",
        if result.is_ok() { "ok" } else { "error" },
        result.as_ref().err().map(String::as_str),
    );
    result
}

#[tauri::command]
async fn set_system_timezone(
    target_tz: String,
    state: State<'_, AppState>,
) -> Result<TimezoneInfo, String> {
    audit::record_async("timezone.manual", async {
        admin_helper::clear_declined(&state.dir);
        apply_timezone(target_tz, state.inner(), None, None, true).await
    })
    .await
}

#[tauri::command]
async fn follow_egress_timezone(state: State<'_, AppState>) -> Result<TimezoneInfo, String> {
    audit::record_async("timezone.follow_manual", async {
        let _lifecycle = state.lifecycle_lock.lock().await;
        let _probe = state.probe_lock.lock().await;
        follow_timezone(state.inner(), true)
            .await?
            .ok_or("未开启时区跟随".into())
    })
    .await
}

async fn follow_timezone(state: &AppState, force: bool) -> Result<Option<TimezoneInfo>, String> {
    let (settings, revision, cached) = {
        let mut rt = state.lock()?;
        if rt.protection.isolation_pending
            || rt.protection.armed && rt.protection.tunnel_policy.is_none()
        {
            audit::transition("timezone.follow_state", "paused", None);
            return if force {
                Err("请先停止守护，再跟随出口时区".into())
            } else {
                Ok(None)
            };
        }
        if !force && rt.data.settings.timezone_mode != "egress" {
            audit::transition("timezone.follow_state", "disabled", None);
            return Ok(None);
        }
        audit::transition("timezone.follow_state", "enabled", None);
        let ip = rt
            .checks
            .iter()
            .find(|c| {
                c.id == "egress-ipv4"
                    && c.integrity == "tls_verified"
                    && safety::fresh(c, chrono::Utc::now())
            })
            .map(|c| c.value.clone());
        let current = rt
            .checks
            .iter()
            .find(|c| c.id == "timezone")
            .map(|c| c.value.as_str())
            .unwrap_or("");
        if !force
            && (rt.running
                || ip
                    .as_deref()
                    .is_none_or(|ip| !rt.timezone_follow.due(ip, current)))
        {
            return Ok(None);
        }
        let cached = if !force && rt.timezone_follow.ip == ip {
            ip.clone()
                .zip(rt.timezone_follow.target.clone())
                .map(|(ip, timezone)| probes::EgressTimezone { ip, timezone })
        } else {
            None
        };
        rt.timezone_follow.begin(ip.as_deref().unwrap_or(""));
        (rt.data.settings.clone(), rt.settings_revision, cached)
    };
    audit::event(
        "timezone.follow",
        if cached.is_some() { "cached" } else { "lookup" },
        None,
        None,
    );
    let result = audit::record_async("timezone.follow", async {
        let before = platform::inspect().await;
        let lookup = match cached {
            Some(cached) => match probes::verified_egress_ip(&settings, &before).await {
                Ok(ip) if ip.to_string() == cached.ip => Ok(cached),
                Ok(_) => Err("出口 IP 已变化，保留当前时区；等待重新匹配".into()),
                Err(error) => Err(error),
            },
            None => probes::egress_timezone(&settings, &before).await,
        };
        let target = match lookup {
            Ok(target) => target,
            Err(error) => {
                let mut rt = state.lock()?;
                if rt.settings_revision == revision {
                    rt.timezone_follow.error = Some(error.clone());
                }
                return Err(error);
            }
        };
        let after = platform::inspect().await;
        if before.fingerprint != after.fingerprint {
            let error = "查询期间网络配置已变化，保留当前时区；稍后重试".to_string();
            let mut rt = state.lock()?;
            if rt.settings_revision == revision {
                rt.timezone_follow.error = Some(error.clone());
            }
            return Err(error);
        }
        // The first privileged change asks once and installs the resident admin helper.
        // Later timezone, protection, DNS, and IPv6 calls use it and do not prompt.
        let app_data = state.dir.clone();
        if !force && !admin_helper::ready() && admin_helper::declined(&app_data) {
            let mut rt = state.lock()?;
            if rt.settings_revision == revision && rt.data.settings.timezone_mode == "egress" {
                rt.timezone_follow.bind(target.ip, target.timezone);
            }
            return Ok(None);
        }
        if force {
            admin_helper::clear_declined(&app_data);
        }
        let result = apply_timezone(
            target.timezone.clone(),
            state,
            Some(revision),
            Some(target.ip.clone()),
            force || !admin_helper::ready(),
        )
        .await;
        if let Err(error) = &result {
            let mut rt = state.lock()?;
            if rt.data.settings.timezone_mode == "egress" {
                rt.timezone_follow.error = Some(error.clone());
                if !error.contains("未响应") {
                    rt.timezone_follow.application_blocked = true;
                }
            }
        }
        result.map(Some)
    })
    .await;
    result
}

async fn apply_timezone(
    target_tz: String,
    state: &AppState,
    expected_revision: Option<u64>,
    following_ip: Option<String>,
    allow_prompt: bool,
) -> Result<TimezoneInfo, String> {
    audit::record_async("timezone.apply", async {
        let _op = state.op_lock.lock().await;
        platform::validate_timezone_name(&target_tz)?;
        {
            let mut rt = state.lock()?;
            if rt.protection.isolation_pending
                || rt.protection.armed
                    && (following_ip.is_none() || rt.protection.tunnel_policy.is_none())
            {
                return Err("请先停止守护，再修改系统时区".into());
            }
            if expected_revision.is_some_and(|revision| rt.settings_revision != revision) {
                return Err("查询期间检测设置已变化，请重试；未修改时区".into());
            }
            let mut data = rt.data.clone();
            let current = platform::get_system_timezone()?;
            if data.settings.original_timezone.is_none()
                && !platform::timezone_matches(&current, &target_tz)
            {
                data.settings.original_timezone = Some(current);
            }
            if following_ip.is_some() {
                data.settings.timezone_mode = "egress".into();
            } else {
                data.settings.timezone_mode = "manual".into();
                data.settings.target_timezone = Some(target_tz.clone());
                rt.timezone_follow = timezone_follow::FollowState::default();
            }
            store::save(&state.dir, &mut data)?;
            rt.data = data;
            rt.settings_revision += 1;
        }
        admin_helper::apply(&target_tz, &state.dir, allow_prompt).await?;
        let current = platform::get_system_timezone()?;
        let mut rt = state.lock()?;
        if let Some(ip) = following_ip {
            if rt.data.settings.timezone_mode == "egress" {
                rt.timezone_follow.bind(ip, target_tz);
            }
        }
        rt.checks.retain(|c| c.id != "timezone");
        rt.checks.push(CheckResult::local(
            "timezone",
            "系统时区",
            "observed",
            current.clone(),
            "当前系统时区",
        ));
        Ok(TimezoneInfo {
            current,
            original: rt.data.settings.original_timezone.clone(),
        })
    })
    .await
}

#[tauri::command]
async fn restore_system_timezone(state: State<'_, AppState>) -> Result<TimezoneInfo, String> {
    audit::record_async("timezone.restore", async {
        let _op = state.op_lock.lock().await;
        let original = {
            let mut rt = state.lock()?;
            if rt.protection.armed || rt.protection.isolation_pending {
                return Err("请先停止守护，再恢复系统时区".into());
            }
            let mut data = rt.data.clone();
            data.settings.timezone_mode = "manual".into();
            store::save(&state.dir, &mut data)?;
            rt.data = data;
            rt.settings_revision += 1;
            rt.timezone_follow = timezone_follow::FollowState::default();
            rt.data.settings.original_timezone.clone()
        };
        if let Some(original) = original {
            admin_helper::apply(&original, &state.dir, true).await?;
            let mut rt = state.lock()?;
            let mut data = rt.data.clone();
            data.settings.original_timezone = None;
            data.settings.target_timezone = Some(original);
            store::save(&state.dir, &mut data)?;
            rt.data = data;
        }
        Ok(TimezoneInfo {
            current: platform::get_system_timezone()?,
            original: None,
        })
    })
    .await
}

#[tauri::command]
fn pin_egress_ip(ip: Option<String>, state: State<'_, AppState>) -> Result<Option<String>, String> {
    audit::record("egress.pin", || {
        let clean_ip = ip.and_then(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        let mut runtime = state.lock()?;
        if runtime.protection.armed || runtime.protection.isolation_pending {
            return Err("请先停止守护，再修改出口锁定".into());
        }
        if let Some(ip) = &clean_ip {
            ip.parse::<std::net::Ipv4Addr>()
                .map_err(|_| "出口 IP 格式无效")?;
        }
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
                    Some(ip) => format!("已锚定安全出口 {ip}，守护期间检测偏离将触发整机隔离。"),
                    None => "已取消出口 IP 锁定。".into(),
                }
                .as_str(),
                false,
            ),
        );
        store::save(&state.dir, &mut data)?;
        runtime.data = data;
        Ok(clean_ip)
    })
}

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    audit::record_async("browser.open", async {
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
                .spawn()
                .map_err(|_| "无法打开浏览器检测页面".to_string())?;
        }
        #[cfg(target_os = "windows")]
        {
            let _ = tokio::process::Command::new("rundll32.exe")
                .args(["url.dll,FileProtocolHandler", &url])
                .spawn()
                .map_err(|_| "无法打开浏览器检测页面".to_string())?;
        }
        #[cfg(target_os = "linux")]
        {
            tokio::process::Command::new("xdg-open")
                .arg(&url)
                .spawn()
                .map_err(|_| "无法打开浏览器检测页面".to_string())?;
        }
        Ok(())
    })
    .await
}

#[tauri::command]
async fn optimize_all_gates(state: State<'_, AppState>) -> Result<CheckReport, String> {
    audit::record_async("network.optimize", async {
        configure_ipv6_filter(state.inner()).await?;
        run_checks(0, Some("operation".into()), state).await
    })
    .await
}
#[tauri::command]
async fn restore_all_network(state: State<'_, AppState>) -> Result<CheckReport, String> {
    audit::record_async("network.restore", async {
        firewall_action("release".into(), None, true, state.clone()).await?;
        restore_system_timezone(state.clone()).await?;
        run_checks(0, Some("operation".into()), state).await
    })
    .await
}
#[tauri::command]
async fn configure_dns(servers: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    audit::record_async("dns.configure", async {
        {
            let rt = state.lock()?;
            if rt.protection.armed || rt.protection.isolation_pending {
                return Err("请先停止守护，再修改系统 DNS；代理上游请在客户端中配置".into());
            }
        }
        let change = network_dns::Change {
            servers: servers
                .iter()
                .map(|s| s.parse().map_err(|_| "DNS 地址无效".to_string()))
                .collect::<Result<_, _>>()?,
        };
        change.validate()?;
        // Probe before ANY mutation; a missing local resolver cannot take down DNS.
        for server in &change.servers {
            audit::record_async("dns.preflight", network_dns::probe(*server)).await?;
        }
        let _op = state.op_lock.lock().await;
        {
            let mut rt = state.lock()?;
            if rt.protection.armed || rt.protection.isolation_pending {
                return Err("请先停止守护并恢复网络，再修改 DNS".into());
            }
            rt.protection.dns_modified = true;
            rt.protection.save(&state.dir)?;
        }
        let result = native_request(
            state.inner(),
            firewall::Request {
                operation_id: None,
                guard_user: None,
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
    })
    .await
}
#[tauri::command]
async fn toggle_gate(
    gate_id: String,
    enable: bool,
    state: State<'_, AppState>,
) -> Result<CheckReport, String> {
    audit::record_async("gate.toggle", async {
        match gate_id.as_str() {
            "gate-timezone" => {
                if enable {
                    let target = state
                        .lock()?
                        .data
                        .settings
                        .target_timezone
                        .clone()
                        .ok_or("请先在设置中填写目标时区；不根据出口国家自动猜测")?;
                    set_system_timezone(target, state.clone()).await?;
                } else {
                    restore_system_timezone(state.clone()).await?;
                }
            }
            "gate-ipv6" => {
                let guarded = {
                    let rt = state.lock()?;
                    rt.protection.armed || rt.protection.isolation_pending
                };
                if guarded {
                    return Err("请先停止守护，再调整 IPv6 防护".into());
                }
                if enable {
                    configure_ipv6_filter(state.inner()).await?;
                } else {
                    firewall_action("release".into(), None, true, state.clone()).await?;
                }
            }
            // DNS button now rechecks; never overwrite a client's resolver policy.
            "gate-dns" => {}
            _ => return Err("未知的检查项".into()),
        }
        run_checks(0, Some("operation".into()), state).await
    })
    .await
}
#[tauri::command]
fn get_diagnostic_logs() -> Result<Vec<audit::Entry>, String> {
    let bundle = audit::bundle();
    if !bundle.initialized || bundle.unreadable_files > 0 {
        return Err("诊断日志无法完整读取；请导出查看日志健康信息".into());
    }
    let mut entries = bundle.entries;
    let start = entries.len().saturating_sub(100);
    entries.drain(..start);
    Ok(entries)
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticExport {
    path: String,
    system_logs: String,
    app_healthy: bool,
}
#[tauri::command]
async fn export_diagnostic_logs(state: State<'_, AppState>) -> Result<DiagnosticExport, String> {
    audit::record_async("logs.export", async {
        let system = firewall::diagnostic_bundle(&state.dir).await;
        let system_status = match &system {
            Ok(bundle) if !bundle.initialized => "unavailable",
            Ok(bundle) if bundle.dropped_events > 0 || bundle.unreadable_files > 0 || bundle.invalid_lines > 0 => "partial",
            Ok(_) => "included", Err(_) => "unavailable",
        };
        audit::event("logs.system_collect", system_status, system.as_ref().err().map(String::as_str), None);
        let app = audit::bundle();
        let app_healthy = app.initialized && app.dropped_events == 0 && app.unreadable_files == 0 && app.invalid_lines == 0;
        let mut entries = app.entries.clone();
        if let Ok(system) = &system { entries.extend(system.entries.clone()); }
        entries.sort_by(|a, b| a.at.cmp(&b.at));
        let system_error = system.as_ref().err().map(|e| audit::error_kind(e));
        let folder = state.dir.join("reports");
        std::fs::create_dir_all(&folder).map_err(|_| "无法创建日志导出目录".to_string())?;
        let path = folder.join(format!("wujian-diagnostics-{}.json", uuid::Uuid::new_v4().simple()));
        let data = serde_json::json!({
            "formatVersion": 2, "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "exportedAt": chrono::Utc::now().to_rfc3339(),
            "note": "不含原始命令参数、错误、IP、代理端点、账户、恢复记录或用户路径。",
            "appHealth": { "initialized": app.initialized, "droppedEvents": app.dropped_events, "unreadableFiles": app.unreadable_files, "invalidLines": app.invalid_lines },
            "system": { "status": system_status, "errorKind": system_error,
                "health": system.as_ref().ok().map(|s| serde_json::json!({ "initialized": s.initialized, "droppedEvents": s.dropped_events, "unreadableFiles": s.unreadable_files, "invalidLines": s.invalid_lines })) },
            "entries": entries,
        });
        firewall::write_private(&path, &serde_json::to_vec_pretty(&data).map_err(|_| "日志导出编码失败".to_string())?)?;
        Ok(DiagnosticExport { path: path.to_string_lossy().into_owned(), system_logs: system_status.into(), app_healthy })
    }).await
}
#[tauri::command]
fn record_frontend_event(operation: String) -> Result<(), String> {
    if !matches!(
        operation.as_str(),
        "frontend.render"
            | "frontend.error"
            | "frontend.unhandled_rejection"
            | "frontend.event_subscription"
            | "frontend.ipc_failure"
    ) {
        return Err("未知的前端诊断事件".into());
    }
    // Accept event identifiers only, never arbitrary JS messages, stacks or URLs.
    audit::event_kind(&operation, "error", Some("frontend_exception"), None);
    Ok(())
}

#[tauri::command]
async fn exit_app(state: State<'_, AppState>) -> Result<(), String> {
    let mut span = audit::Span::new("app.exit_request");
    let _op = state.op_lock.lock().await;
    let result: Result<(), String> = (|| {
        let rt = state.lock()?;
        if rt.protection.armed
            || rt.protection.isolation_pending
            || rt.protection.filter_may_exist
            || rt.protection.dns_modified
        {
            return Err(
                "请先停止守护或点击“恢复本工具配置”并授权解除规则；退出程序不会解除系统规则。"
                    .into(),
            );
        }
        drop(rt);
        if recovery::load_recovery_record(&state.dir)?.is_some() {
            return Err("有旧版本配置等待恢复，请先点击解除隔离并停止防护。".into());
        }
        Ok(())
    })();
    span.finish(&result);
    result?;
    audit::shutdown();
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
                                                "无间伪装保护中！必须先点击【停止卧底防护】停止后台保护后，才能安全退出应用。"
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
            if audit::init(&dir).is_err() {
                eprintln!("Diagnostic logging unavailable; export will include health status");
            }
            audit::install_panic_hook();
            let (data, init_error) = match store::load(&dir) {
                Ok(data) => (data, None),
                Err(error) => (StoredData::default(), Some(error)),
            };
            audit::transition("settings.load", if init_error.is_some() { "error" } else { "ok" }, init_error.as_deref());
            let protection = protection::ProtectionStatus::load(&dir);
            audit::transition("protection.load", if protection.error.is_some() { "error" } else { "ok" }, protection.error.as_deref());
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
                    timezone_follow: timezone_follow::FollowState::default(),
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
                lifecycle_lock: tokio::sync::Mutex::new(()),
            });

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    let state = handle.state::<AppState>();
                    let Ok(_lifecycle) = state.lifecycle_lock.try_lock() else { continue; };
                    let Ok(_probe) = state.probe_lock.try_lock() else { continue; };
                    if let Err(error) = follow_timezone(state.inner(), false).await {
                        audit::event("timezone.follow", "error", Some(&error), None);
                    }
                }
            });

            // Local monitoring must continue while a slow external probe holds probe_lock.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let state = handle.state::<AppState>();
                    let network = platform::inspect().await;
    log_check_states(&network.checks);
                    if let Ok(mut rt) = state.lock() {
                        sync_tunnel_status(&mut rt);
                        update_network(&mut rt, &network);
                        for nc in &network.checks {
                            rt.checks.retain(|c| c.id != nc.id);
                            rt.checks.push(nc.clone());
                        }
                    }
                    if let Err(e) = enforce_current(state.inner(), false).await {
                        audit::event("checks.background", "error", Some(&e), None);
                    }
                    let current = state.lock().ok().map(|rt| snapshot(&rt, &network));
                    if let Some(current) = current {
                        let _ = handle.emit("snapshot-updated", current);
                    }
                }
            });
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut last_probe = std::time::Instant::now();
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let state = handle.state::<AppState>();
                    let should_probe = state.lock().is_ok_and(|rt| {
                        let interval = probes::refresh_interval(&rt.data.settings, rt.protection.armed);
                        !rt.protection.isolation_pending && !rt.running
                            && interval.is_some_and(|seconds| last_probe.elapsed().as_secs() >= seconds)
                    });
                    if should_probe {
                        last_probe = std::time::Instant::now();
                        if let Err(e) = run_checks(0, Some("background".into()), state).await {
                            audit::event("checks.background", "error", Some(&e), None);
                        }
                    }
                }
            });

            audit::event("app.ready", "ok", None, None);
            Ok(())
        })
        .on_menu_event(|app, event| {
            if event.id() == "safe_quit" || event.id() == "safe_close" {
                audit::event("app.close", "blocked", None, None);
                if let Some(window) = app.get_webview_window("main") {
                    let is_armed = FIREWALL_ACTIVE.load(Ordering::SeqCst);
                    let msg = if is_armed {
                        "无间伪装保护中！必须先点击【停止卧底防护】停止后台保护后，才能安全退出应用。"
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
                audit::event("app.close", "blocked", None, None);
                let is_armed = FIREWALL_ACTIVE.load(Ordering::SeqCst);
                let msg = if is_armed {
                    "无间伪装保护中！必须先点击【停止卧底防护】停止后台保护后，才能安全关闭窗口。"
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
            follow_egress_timezone,
            set_system_timezone,
            restore_system_timezone,
            pin_egress_ip,
            configure_dns,
            record_frontend_event,
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
                audit::event("app.exit", "blocked", None, None);
                if let Some(window) = app_handle.get_webview_window("main") {
                    let is_armed = FIREWALL_ACTIVE.load(Ordering::SeqCst);
                    let msg = if is_armed {
                        "无间伪装保护中！必须先点击【停止卧底防护】停止后台保护后，才能安全退出应用。"
                    } else {
                        "无间道应用守护中；若要退出请在界面操作。"
                    };
                    let _ = window.emit("disguise-prevent-exit", msg);
                    let _ = window.set_focus();
                }
            }
        });
}
