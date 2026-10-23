//! Global TUN guard for macOS, Linux, and Windows.
//! The macOS service socket stays the first candidate. Other systems use the
//! same Clash Verge service layout and fail closed when it cannot be read.
//! Node country is checked once while preparing the plan. The firewall itself
//! has no country, process-user, or public-DNS bypass.
use super::{command, policy::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
};

const FOREIGN_DNS_LEAK: &str = "国外域名的 DNS 仍走直连或未确认路径，查询会从本机出去";
const FOREIGN_DNS_SHAPE: &str = "国外 DNS 必须写成 https://公网IPv4/…#策略组，不能直连";
const DOMESTIC_DNS_OTHER: &str = "国内 DNS 指向了其他节点，无法确认解析路径";
const DOMESTIC_DNS_NOTE: &str =
    "当前国内域名策略仍是直连，开启后这些查询会被阻断，国内网站可能打不开。";
const HIJACK_MISSING: &str = "TUN 没有劫持 53 端口，系统 DNS 可能绕过代理直连";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelGuard {
    pub uid: u32,
    pub interface: String,
    pub node: String,
    pub server: String,
    pub port: u16,
    pub protocols: Vec<String>,
    pub addresses: Vec<Ipv4Addr>,
    pub selected_chain: Vec<String>,
    pub prepared_at: String,
    /// Display label from the one-time Country.mmdb check. Empty in synthetic fixtures.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    /// Shown when domestic geosite policies still dial DIRECT. Not an arming failure.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dns_note: String,
    /// Other proxy nodes used by DNS. Their addresses stay allowed so DNS does not fall back to direct.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_pins: Vec<PinnedEndpoint>,
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let a = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a[0] == 0
        || a[0] >= 240
        || (a[0] == 100 && a[1] & 0xc0 == 64)
        || (a[0] == 198 && a[1] & 0xfe == 18))
}

pub fn tun_name(name: &str) -> bool {
    const NAMED: &[&str] = &["Meta", "Mihomo", "mihomo", "clash", "tun0", "tun1", "tun2"];
    if NAMED.contains(&name) {
        return true;
    }
    let Some(tail) = name.strip_prefix("utun") else {
        return false;
    };
    !tail.is_empty() && tail.len() <= 5 && tail.bytes().all(|b| b.is_ascii_digit())
}

impl TunnelGuard {
    pub fn validate(&self) -> Result<(), String> {
        if self.uid == 0
            || !tun_name(&self.interface)
            || self.port == 0
            || matches!(self.port, 53 | 853)
            || self.addresses.is_empty()
            || self.addresses.len() > 16
            || self.addresses.iter().any(|ip| !public_v4(*ip))
            || self.protocols.is_empty()
            || self.protocols.len() > 2
            || self.protocols.iter().any(|p| p != "tcp" && p != "udp")
            || self.node.is_empty()
            || self.node.len() > 256
            || self.node.chars().any(char::is_control)
            || self.server.is_empty()
            || self.server.len() > 253
            || !self
                .server
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
            || self.selected_chain.is_empty()
            || self.selected_chain.len() > 16
            || self
                .selected_chain
                .iter()
                .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
            || chrono::DateTime::parse_from_rfc3339(&self.prepared_at).is_err()
            || !note_ok(&self.country)
            || !note_ok(&self.dns_note)
            || self.dns_pins.len() > 8
            || self.dns_pins.iter().any(|pin| !pin_ok(pin))
        {
            return Err("隧道计划无效：需要指定受支持的 TUN、有效单节点及精确公网 IPv4/端口；不接受 DNS 端口或宽泛放行".into());
        }
        Ok(())
    }
}

fn note_ok(text: &str) -> bool {
    text.len() <= 180 && !text.chars().any(char::is_control)
}

fn pin_ok(pin: &PinnedEndpoint) -> bool {
    !pin.addresses.is_empty()
        && pin.addresses.len() <= 8
        && pin.addresses.iter().all(|ip| public_v4(*ip))
        && pin.port != 0
        && !matches!(pin.port, 53 | 853)
        && !pin.protocols.is_empty()
        && pin.protocols.len() <= 2
        && pin
            .protocols
            .iter()
            .all(|protocol| protocol == "tcp" || protocol == "udp")
        && !pin.server.is_empty()
        && pin.server.len() <= 253
        && pin
            .server
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
}

fn same_endpoint(
    server: &str,
    port: u16,
    protocols: &[String],
    other_server: &str,
    other_port: u16,
    other_protocols: &[String],
) -> bool {
    if server != other_server || port != other_port {
        return false;
    }
    let mut left = protocols.to_vec();
    let mut right = other_protocols.to_vec();
    left.sort();
    right.sort();
    left == right
}

/// Skip a DNS node that is the same endpoint as GLOBAL. A different port on
/// the same server still has to be pinned, or that DNS dial is blackholed.
fn consider_pin(
    pins: &mut Vec<PinnedEndpoint>,
    main_server: &str,
    main_port: u16,
    main_protocols: &[String],
    server: String,
    port: u16,
    protocols: Vec<String>,
) {
    if same_endpoint(
        &server,
        port,
        &protocols,
        main_server,
        main_port,
        main_protocols,
    ) {
        return;
    }
    if pins.iter().any(|pin| {
        same_endpoint(
            &server,
            port,
            &protocols,
            &pin.server,
            pin.port,
            &pin.protocols,
        )
    }) {
        return;
    }
    pins.push(PinnedEndpoint {
        server,
        port,
        protocols,
        addresses: vec![],
    });
}

fn pin_keys(pins: &[PinnedEndpoint]) -> Vec<(String, u16, Vec<String>)> {
    let mut keys: Vec<_> = pins
        .iter()
        .map(|pin| {
            let mut protocols = pin.protocols.clone();
            protocols.sort();
            (pin.server.clone(), pin.port, protocols)
        })
        .collect();
    keys.sort();
    keys
}

async fn resolve_public(server: &str, port: u16) -> Result<Vec<Ipv4Addr>, String> {
    let mut addresses: Vec<Ipv4Addr> = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((server, port)),
    )
    .await
    .map_err(|_| "节点地址解析超时")?
    .map_err(|_| "节点地址解析失败")?
    .filter_map(|addr| match addr.ip() {
        std::net::IpAddr::V4(ip) if public_v4(ip) => Some(ip),
        _ => None,
    })
    .collect();
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

/// Follow the actual GLOBAL selection, never infer it from a group's name.
fn selected(proxies: &Value) -> Result<Vec<String>, String> {
    selected_from(proxies, "GLOBAL")
}
fn selected_from(proxies: &Value, start: &str) -> Result<Vec<String>, String> {
    let entries = proxies["proxies"]
        .as_object()
        .ok_or("客户端没有返回代理信息")?;
    let mut chain = vec![];
    let mut name = start.to_string();
    for _ in 0..16 {
        if chain.contains(&name) {
            return Err("代理策略存在循环，不能开启保护".into());
        }
        let entry = entries.get(&name).ok_or("无法展开当前代理策略")?;
        chain.push(name.clone());
        match entry["type"].as_str().unwrap_or("") {
            "Selector" | "URLTest" | "Fallback" => {
                name = entry["now"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .ok_or("策略组当前选择未知")?
                    .into();
            }
            "DIRECT" | "Direct" | "REJECT" | "Reject" | "RejectDrop" | "Compatible" | "Pass"
            | "LoadBalance" | "Relay" => {
                return Err(
                    "GLOBAL 必须最终选择单个代理节点；直连、负载均衡及链式代理暂不支持".into(),
                );
            }
            "Shadowsocks" | "Vmess" | "VMess" | "Vless" | "VLESS" | "Trojan" | "Hysteria"
            | "Hysteria2" | "Tuic" | "TUIC" | "Http" | "HTTP" => return Ok(chain),
            _ => return Err("当前节点类型尚未适配，不能猜测节点出站协议".into()),
        }
    }
    Err("代理策略层级过深".into())
}

fn domestic_policy_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "geosite:cn" | "geosite:geolocation-cn" | "geosite:category-cn"
    )
}

enum Route {
    Direct,
    Same,
    Proxy(String),
    Unclear,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedEndpoint {
    pub server: String,
    pub port: u16,
    pub protocols: Vec<String>,
    pub addresses: Vec<Ipv4Addr>,
}

fn route_of(proxies: &Value, group: &str, node: &str) -> Result<Route, String> {
    if group.is_empty() || group.contains('&') {
        return Ok(Route::Unclear);
    }
    if matches!(group, "DIRECT" | "Direct" | "direct") {
        return Ok(Route::Direct);
    }
    if let Some(entry) = proxies["proxies"].get(group) {
        if matches!(entry["type"].as_str(), Some("DIRECT" | "Direct")) {
            return Ok(Route::Direct);
        }
    }
    let chain = selected_from(proxies, group)?;
    let Some(last) = chain.last() else {
        return Ok(Route::Unclear);
    };
    if last == node {
        Ok(Route::Same)
    } else {
        Ok(Route::Proxy(last.clone()))
    }
}

fn foreign_literal_doh(url_text: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url_text) else {
        return false;
    };
    let literal_ip = url
        .host_str()
        .and_then(|host| host.parse::<Ipv4Addr>().ok())
        .is_some_and(public_v4);
    url.scheme() == "https" && url.username().is_empty() && url.password().is_none() && literal_ip
}

struct UpstreamHit {
    domestic_direct: bool,
    extra_node: Option<String>,
}

/// Foreign resolvers may use another concrete proxy node. DIRECT still leaks.
fn audit_upstream(
    text: &str,
    domestic: bool,
    proxies: &Value,
    node: &str,
) -> Result<UpstreamHit, String> {
    let Some((url, group)) = text.rsplit_once('#') else {
        return if domestic {
            Ok(UpstreamHit {
                domestic_direct: true,
                extra_node: None,
            })
        } else {
            Err(FOREIGN_DNS_LEAK.into())
        };
    };
    if !domestic && !foreign_literal_doh(url) {
        return Err(FOREIGN_DNS_SHAPE.into());
    }
    match (route_of(proxies, group, node)?, domestic) {
        (Route::Same, _) => Ok(UpstreamHit {
            domestic_direct: false,
            extra_node: None,
        }),
        (Route::Direct, true) => Ok(UpstreamHit {
            domestic_direct: true,
            extra_node: None,
        }),
        (Route::Proxy(name), _) => Ok(UpstreamHit {
            domestic_direct: false,
            extra_node: Some(name),
        }),
        (Route::Unclear, true) => Err(DOMESTIC_DNS_OTHER.into()),
        (Route::Direct | Route::Unclear, false) => Err(FOREIGN_DNS_LEAK.into()),
    }
}

struct DnsReport {
    note: Option<String>,
    extra_nodes: Vec<String>,
}

fn check_dns(config: &Value, proxies: &Value, node: &str) -> Result<DnsReport, String> {
    let dns = &config["dns"];
    if dns["enable"] != true {
        return Err("请先开启代理 DNS，再准备整机保护".into());
    }
    let primary = dns["nameserver"]
        .as_array()
        .filter(|v| !v.is_empty())
        .ok_or("DNS 主解析上游未确认")?;
    let mut upstreams = Vec::new();
    for value in primary {
        upstreams.push((value, false));
    }
    match dns.get("nameserver-policy") {
        None | Some(Value::Null) => {}
        Some(Value::Object(policies)) => {
            for (key, value) in policies {
                let domestic = domestic_policy_key(key);
                if let Some(list) = value.as_array() {
                    upstreams.extend(list.iter().map(|item| (item, domestic)));
                } else {
                    upstreams.push((value, domestic));
                }
            }
        }
        Some(_) => return Err("DNS 域名策略无法核对".into()),
    }
    match dns.get("fallback") {
        None | Some(Value::Null) => {}
        Some(Value::Array(fallbacks)) => {
            upstreams.extend(fallbacks.iter().map(|item| (item, false)));
        }
        Some(_) => return Err("DNS fallback 无法核对".into()),
    }
    let mut domestic_direct = false;
    let mut extra_nodes = Vec::new();
    for (value, domestic) in upstreams {
        let text = value.as_str().ok_or("DNS 上游配置无法核对")?;
        let hit = audit_upstream(text, domestic, proxies, node)?;
        domestic_direct |= hit.domestic_direct;
        if let Some(name) = hit.extra_node {
            if name != node && !extra_nodes.iter().any(|item| item == &name) {
                extra_nodes.push(name);
            }
        }
    }
    Ok(DnsReport {
        note: domestic_direct.then(|| DOMESTIC_DNS_NOTE.to_string()),
        extra_nodes,
    })
}

fn hijacks_port_53(tun: &Value) -> Option<bool> {
    let list = tun.get("dns-hijack").or_else(|| tun.get("dns_hijack"))?;
    let texts: Vec<&str> = if let Some(items) = list.as_array() {
        if items.is_empty() {
            return Some(false);
        }
        items.iter().filter_map(Value::as_str).collect()
    } else if let Some(text) = list.as_str() {
        vec![text]
    } else {
        return Some(false);
    };
    if texts.is_empty() {
        return Some(false);
    }
    Some(texts.iter().any(|text| {
        let text = text.trim().to_ascii_lowercase();
        text == "any:53" || text.ends_with(":53")
    }))
}

fn endpoint(config: &Value, node: &str) -> Result<(String, u16, Vec<String>), String> {
    let candidates: Vec<_> = config["proxies"]
        .as_array()
        .ok_or("无法读取运行配置中的节点；订阅 provider 节点暂不支持")?
        .iter()
        .filter(|p| p["name"].as_str() == Some(node))
        .collect();
    if candidates.len() != 1 {
        return Err("当前节点不在运行配置的唯一内联节点中；暂不支持 provider 或重名节点".into());
    }
    let p = candidates[0];
    for key in ["dialer-proxy", "plugin", "smux", "obfs", "obfs-password"] {
        if p.get(key)
            .is_some_and(|v| !v.is_null() && v != false && v != "")
        {
            return Err("该节点含额外拨号、插件或混淆设置，暂不能确定唯一出站端点".into());
        }
    }
    if p.get("ports").is_some() || p.get("hop-interval").is_some() {
        return Err("暂不支持节点端口跳跃".into());
    }
    let kind = p["type"].as_str().unwrap_or("");
    let network = p["network"].as_str().unwrap_or("tcp");
    if !matches!(network, "tcp" | "ws" | "grpc" | "http" | "h2") {
        return Err("暂不支持该节点传输方式".into());
    }
    let protocols = match kind {
        "ss" => vec!["tcp".into(), "udp".into()],
        "vmess" | "vless" | "trojan" | "http" => vec!["tcp".into()],
        "hysteria" | "hysteria2" | "tuic" => vec!["udp".into()],
        _ => return Err("该节点协议暂未适配".into()),
    };
    let server = p["server"]
        .as_str()
        .ok_or("节点没有服务器地址")?
        .to_string();
    let port = p["port"]
        .as_u64()
        .or_else(|| p["port"].as_str()?.parse().ok())
        .filter(|p| *p > 0 && *p <= u16::MAX as u64)
        .ok_or("节点端口无效")? as u16;
    Ok((server, port, protocols))
}

pub(crate) fn unix_service_sockets(uid: u32) -> Vec<String> {
    vec![
        format!("/var/run/clash-verge-service/users/{uid}/verge-mihomo.sock"),
        format!("/var/run/clash-verge-service-dev/users/{uid}/verge-mihomo.sock"),
        format!("/run/clash-verge-service/users/{uid}/verge-mihomo.sock"),
        format!("/run/clash-verge-service-dev/users/{uid}/verge-mihomo.sock"),
    ]
}

pub(crate) fn service_runtime_yaml(uid: u32) -> Vec<PathBuf> {
    vec![
        PathBuf::from(format!(
            "/Library/Application Support/clash-verge-service/users/{uid}/runtime/config.yaml"
        )),
        PathBuf::from(format!(
            "/Library/Application Support/clash-verge-service-dev/users/{uid}/runtime/config.yaml"
        )),
        PathBuf::from(format!(
            "/var/lib/clash-verge-service/users/{uid}/runtime/config.yaml"
        )),
        PathBuf::from(format!(
            "/var/lib/clash-verge-service-dev/users/{uid}/runtime/config.yaml"
        )),
    ]
}

fn user_runtime_yaml(home: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for id in [
        "io.github.clash-verge-rev.clash-verge-rev",
        "io.github.clash-verge-rev.clash-verge-rev.dev",
    ] {
        paths.push(
            home.join("Library/Application Support")
                .join(id)
                .join("config.yaml"),
        );
        paths.push(home.join(".local/share").join(id).join("config.yaml"));
        paths.push(home.join("AppData/Roaming").join(id).join("config.yaml"));
    }
    paths
}

fn user_sidecar_sockets(home: &Path) -> Vec<String> {
    let mut sockets = Vec::new();
    for id in [
        "io.github.clash-verge-rev.clash-verge-rev",
        "io.github.clash-verge-rev.clash-verge-rev.dev",
    ] {
        for name in ["verge-mihomo.sock", "verge-mihomo-dev.sock"] {
            sockets.push(
                home.join(".local/share")
                    .join(id)
                    .join(name)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    sockets
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn windows_pipe_ok(name: &str) -> bool {
    if name == "verge-mihomo" {
        return true;
    }
    const PREFIXES: &[&str] = &[
        "verge-mihomo-production-",
        "verge-mihomo-development-",
        "verge-mihomo-sidecar-release-",
        "verge-mihomo-sidecar-dev-",
    ];
    PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|tail| {
            (1..=64).contains(&tail.len()) && tail.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn pipe_rank(name: &str) -> u8 {
    if name.contains("verge-mihomo-production-") {
        0
    } else if name.contains("verge-mihomo-development-") {
        1
    } else if name.contains("verge-mihomo-sidecar-release-") {
        2
    } else if name.contains("verge-mihomo-sidecar-dev-") {
        3
    } else {
        4
    }
}

pub(crate) fn windows_runtime_from_pipe(pipe: &str, program_data: &Path) -> Option<PathBuf> {
    let name = pipe.rsplit(['\\', '/']).next().unwrap_or(pipe);
    let (slug, key) = if let Some(key) = name.strip_prefix("verge-mihomo-production-") {
        ("clash-verge-service", key)
    } else if let Some(key) = name.strip_prefix("verge-mihomo-development-") {
        ("clash-verge-service-dev", key)
    } else {
        return None;
    };
    if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        program_data
            .join(slug)
            .join("users")
            .join(key)
            .join("runtime")
            .join("config.yaml"),
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_route_dev(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    value
        .get(0)
        .and_then(|item| item.get("dev"))
        .and_then(|dev| dev.as_str())
        .or_else(|| value.get("dev").and_then(|dev| dev.as_str()))
        .map(str::to_string)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_link_up(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let flags = &value[0]["flags"];
    let has = |name: &str| {
        flags
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == name))
    };
    has("UP") && has("POINTOPOINT")
}

fn curl_program() -> PathBuf {
    if cfg!(target_os = "windows") {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("curl.exe")
    } else {
        PathBuf::from("/usr/bin/curl")
    }
}

async fn curl_json(socket: &str, endpoint: &str) -> Result<Value, String> {
    let url = format!("http://localhost/{endpoint}");
    let text = command::run(
        &curl_program(),
        &[
            "--noproxy",
            "*",
            "--silent",
            "--fail",
            "--max-time",
            "3",
            "--unix-socket",
            socket,
            &url,
        ],
        None,
    )
    .await
    .map_err(|_| "无法读取代理状态，暂不能开启保护")?;
    serde_json::from_str(&text).map_err(|_| "代理控制接口返回无效数据".into())
}

struct Controller {
    socket: String,
    configs: Value,
}

pub(crate) async fn read_controller(uid: u32, endpoint: &str) -> Result<Value, String> {
    let controller = open_controller(uid).await?;
    if endpoint == "configs" {
        return Ok(controller.configs);
    }
    curl_json(&controller.socket, endpoint).await
}

async fn open_controller(uid: u32) -> Result<Controller, String> {
    if uid == 0 {
        return Err("必须选择桌面用户的代理，不能使用 root 会话".into());
    }
    for socket in controller_candidates(uid).await? {
        if let Ok(configs) = curl_json(&socket, "configs").await {
            return Ok(Controller { socket, configs });
        }
    }
    Err("无法读取代理状态，暂不能开启保护".into())
}

async fn controller_candidates(uid: u32) -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        let _ = uid;
        return windows_pipes();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut sockets = unix_service_sockets(uid);
        let ready: Vec<_> = sockets
            .iter()
            .filter(|path| Path::new(path).exists())
            .cloned()
            .collect();
        if !ready.is_empty() {
            return Ok(ready);
        }
        if let Ok(home) = desktop_home(uid).await {
            sockets.extend(user_sidecar_sockets(&home));
        }
        let sockets: Vec<_> = sockets
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .collect();
        if sockets.is_empty() {
            return Err("无法读取代理状态，暂不能开启保护".into());
        }
        Ok(sockets)
    }
}

#[cfg(target_os = "windows")]
fn windows_pipes() -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(Path::new(r"\\.\pipe"))
        .map_err(|_| "无法读取代理状态，暂不能开启保护")?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if windows_pipe_ok(&name) {
            names.push(format!(r"\\.\pipe\{name}"));
        }
    }
    names.sort_by(|left, right| pipe_rank(left).cmp(&pipe_rank(right)).then(left.cmp(right)));
    if names.is_empty() {
        return Err("无法读取代理状态，暂不能开启保护".into());
    }
    Ok(names)
}

fn program_data_root() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(path) = super::windows::program_data() {
            return path;
        }
    }
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

struct Observed {
    interface: String,
    chain: Vec<String>,
    server: String,
    port: u16,
    protocols: Vec<String>,
    dns_note: String,
    dns_pins: Vec<PinnedEndpoint>,
}

async fn current(uid: u32) -> Result<Observed, String> {
    if uid == 0 {
        return Err("必须选择桌面用户的代理，不能使用 root 会话".into());
    }
    let controller = open_controller(uid).await?;
    let configs = controller.configs;
    if configs["tun"]["enable"] != true {
        return Err("请开启 TUN".into());
    }
    if configs["mode"] != "global" {
        return Err("请开启全局模式".into());
    }
    let api_hijack = hijacks_port_53(&configs["tun"]);
    if api_hijack == Some(false) {
        return Err(HIJACK_MISSING.into());
    }
    let device = configs["tun"]["device"]
        .as_str()
        .filter(|s| tun_name(s))
        .ok_or("控制接口没有返回受支持的 TUN 设备，不能确认隧道归属")?
        .to_string();
    interface_up(&device).await?;
    for destination in ["1.1.1.1", "8.8.8.8"] {
        if route_device(destination).await?.as_str() != device {
            return Err("公网采样路由未经过该 TUN，不能开启保护".into());
        }
    }
    let proxies = curl_json(&controller.socket, "proxies").await?;
    let chain = selected(&proxies)?;
    let config = load_runtime(uid, &controller.socket).await?;
    let node = chain.last().ok_or("没有选中节点")?;
    let (server, port, protocols) = endpoint(&config, node)?;
    if api_hijack != Some(true) && hijacks_port_53(&config["tun"]) != Some(true) {
        return Err(HIJACK_MISSING.into());
    }
    let dns = check_dns(&config, &proxies, node)?;
    let mut dns_pins = Vec::new();
    for name in dns.extra_nodes {
        let (pin_server, pin_port, pin_protocols) = endpoint(&config, &name)
            .map_err(|error| format!("国外 DNS 的节点无法确定出站地址：{error}"))?;
        consider_pin(
            &mut dns_pins,
            &server,
            port,
            &protocols,
            pin_server,
            pin_port,
            pin_protocols,
        );
    }
    Ok(Observed {
        interface: device,
        chain,
        server,
        port,
        protocols,
        dns_note: dns.note.unwrap_or_default(),
        dns_pins,
    })
}

async fn interface_up(device: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let iface = command::run(Path::new("/sbin/ifconfig"), &[device], None)
            .await
            .map_err(|_| "请开启 TUN")?;
        if !iface
            .lines()
            .next()
            .is_some_and(|line| line.contains("UP") && line.contains("POINTOPOINT"))
        {
            return Err("请开启 TUN".into());
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let text = command::run(&linux_ip()?, &["-j", "link", "show", "dev", device], None)
            .await
            .map_err(|_| "请开启 TUN")?;
        if linux_link_up(&text) {
            return Ok(());
        }
        if text.contains("\"UP\"")
            && Path::new("/sys/class/net")
                .join(device)
                .join("tun_flags")
                .is_file()
        {
            return Ok(());
        }
        return Err("请开启 TUN".into());
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "$ErrorActionPreference='Stop'; $a=Get-NetAdapter -Name '{device}' -ErrorAction Stop; if ($a.Status -ne 'Up') {{ exit 1 }}; Write-Output 'WUJIAN_TUN_UP'"
        );
        let text = command::run(
            &super::windows::powershell()?,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            None,
        )
        .await
        .map_err(|_| "请开启 TUN")?;
        return if text.contains("WUJIAN_TUN_UP") {
            Ok(())
        } else {
            Err("请开启 TUN".into())
        };
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = device;
        Err("当前系统暂不支持全局 TUN 保护".into())
    }
}

async fn route_device(destination: &str) -> Result<String, String> {
    if destination != "1.1.1.1" && destination != "8.8.8.8" {
        return Err("公网采样路由未经过该 TUN，不能开启保护".into());
    }
    #[cfg(target_os = "macos")]
    {
        let route = command::run(
            Path::new("/sbin/route"),
            &["-n", "get", "-inet", destination],
            None,
        )
        .await?;
        return crate::network::route_interface(&route)
            .map(str::to_string)
            .ok_or("公网采样路由未经过该 TUN，不能开启保护".into());
    }
    #[cfg(target_os = "linux")]
    {
        let text = command::run(&linux_ip()?, &["-j", "route", "get", destination], None).await?;
        return linux_route_dev(&text).ok_or("公网采样路由未经过该 TUN，不能开启保护".into());
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "$ErrorActionPreference='Stop'; $r=Find-NetRoute -RemoteIPAddress '{destination}' | Where-Object {{ $_.InterfaceIndex }} | Select-Object -First 1; $a=Get-NetAdapter | Where-Object {{ $_.ifIndex -eq $r.InterfaceIndex }} | Select-Object -First 1; if (-not $a) {{ throw 'route missing' }}; Write-Output $a.Name"
        );
        let text = command::run(
            &super::windows::powershell()?,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            None,
        )
        .await?;
        return text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_string)
            .ok_or("公网采样路由未经过该 TUN，不能开启保护".into());
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = destination;
        Err("当前系统暂不支持全局 TUN 保护".into())
    }
}

#[cfg(target_os = "linux")]
fn linux_ip() -> Result<PathBuf, String> {
    ["/usr/sbin/ip", "/sbin/ip", "/bin/ip", "/usr/bin/ip"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or("无法读取路由".into())
}

async fn load_runtime(uid: u32, socket: &str) -> Result<Value, String> {
    let mut paths = Vec::new();
    if let Some(path) = windows_runtime_from_pipe(socket, &program_data_root()) {
        paths.push(path);
    }
    paths.extend(service_runtime_yaml(uid));
    match read_runtime_yaml(&paths) {
        Ok(value) => Ok(value),
        Err(error) if error == "无法读取代理运行配置" => {
            paths.extend(user_runtime_yaml(&desktop_home(uid).await?));
            read_runtime_yaml(&paths)
        }
        Err(error) => Err(error),
    }
}

fn read_runtime_yaml(paths: &[PathBuf]) -> Result<Value, String> {
    for path in paths {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
            return Err("代理运行配置类型或大小无效".into());
        }
        // Never log, return, or persist the raw configuration (it includes secrets).
        let text = std::fs::read_to_string(path).map_err(|_| "代理运行配置读取失败")?;
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&text).map_err(|_| "代理运行配置无法解析")?;
        return serde_json::to_value(yaml).map_err(|_| "代理运行配置格式无效".to_string());
    }
    Err("无法读取代理运行配置".into())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn home_from_passwd(text: &str, uid: u32) -> Result<String, String> {
    let mut matched = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let mut parts = line.split(':');
        let _name = parts.next();
        let _password = parts.next();
        let id = parts.next().unwrap_or("");
        let _gid = parts.next();
        let _gecos = parts.next();
        let dir = parts.next().unwrap_or("");
        if id.parse::<u32>().ok() == Some(uid) {
            matched.push(dir.to_string());
        }
    }
    if matched.len() != 1 {
        return Err("无法确认桌面用户主目录".into());
    }
    let dir = matched.pop().unwrap();
    validate_home(&dir)?;
    Ok(dir)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn validate_home(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);
    if dir == "/"
        || dir.is_empty()
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || dir.to_ascii_lowercase().contains("systemprofile")
    {
        return Err("桌面用户主目录无效".into());
    }
    Ok(())
}

fn home_from_directory_service(text: &str, uid: u32) -> Result<String, String> {
    let mut matched = Vec::new();
    let mut record_uid = None;
    let mut record_dir = None;
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if record_uid == Some(uid) {
                if let Some(dir) = record_dir.take() {
                    matched.push(dir);
                }
            }
            record_uid = None;
            record_dir = None;
            continue;
        }
        if let Some(value) = line.strip_prefix("uid:") {
            record_uid = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("dir:") {
            record_dir = Some(value.trim().to_string());
        }
    }
    if matched.len() != 1 {
        return Err("无法确认桌面用户主目录".into());
    }
    let dir = matched.pop().unwrap();
    let path = Path::new(&dir);
    if dir == "/"
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("桌面用户主目录无效".into());
    }
    Ok(dir)
}

async fn desktop_home(uid: u32) -> Result<PathBuf, String> {
    if uid == 0 {
        return Err("必须使用桌面用户的国家库".into());
    }
    #[cfg(target_os = "linux")]
    {
        let text = command::run(
            Path::new("/usr/bin/getent"),
            &["passwd", &uid.to_string()],
            None,
        )
        .await
        .map_err(|_| "无法确认桌面用户主目录")?;
        let dir = home_from_passwd(&text, uid)?;
        return owned_home(uid, PathBuf::from(dir));
    }
    #[cfg(target_os = "windows")]
    {
        let dir = std::env::var("USERPROFILE").map_err(|_| "无法确认桌面用户主目录")?;
        validate_home(&dir)?;
        let path = PathBuf::from(&dir);
        if !path.is_dir() {
            return Err("桌面用户主目录无效".into());
        }
        return Ok(path);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        return Err("必须使用桌面用户的国家库".into());
    }
    #[cfg(target_os = "macos")]
    {
        let text = command::run(
            Path::new("/usr/bin/dscacheutil"),
            &["-q", "user", "-a", "uid", &uid.to_string()],
            None,
        )
        .await
        .map_err(|_| "无法确认桌面用户主目录")?;
        let dir = home_from_directory_service(&text, uid)?;
        owned_home(uid, PathBuf::from(dir))
    }
}

fn owned_home(uid: u32, path: PathBuf) -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "无法核验桌面用户主目录")?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
            return Err("桌面用户主目录无效".into());
        }
        let _ = uid;
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        if !path.is_dir() {
            return Err("桌面用户主目录无效".into());
        }
    }
    Ok(path)
}

pub async fn prepare(uid: u32) -> Result<Policy, String> {
    let observed = current(uid).await?;
    let node = observed.chain.last().cloned().ok_or("没有选中节点")?;
    // Validate before DNS lookup: no arbitrary URLs, ports, or address ranges.
    let mut guard = TunnelGuard {
        uid,
        interface: observed.interface,
        node,
        server: observed.server,
        port: observed.port,
        protocols: observed.protocols,
        addresses: vec![Ipv4Addr::new(1, 1, 1, 1)],
        selected_chain: observed.chain,
        prepared_at: chrono::Utc::now().to_rfc3339(),
        country: String::new(),
        dns_note: observed.dns_note,
        dns_pins: observed
            .dns_pins
            .into_iter()
            .map(|mut pin| {
                pin.addresses = vec![Ipv4Addr::new(1, 1, 1, 1)];
                pin
            })
            .collect(),
    };
    guard.validate()?;
    guard.addresses = resolve_public(&guard.server, guard.port).await?;
    if guard.addresses.is_empty() {
        return Err("节点没有公网 IPv4".into());
    }
    for pin in &mut guard.dns_pins {
        pin.addresses = resolve_public(&pin.server, pin.port)
            .await
            .map_err(|error| format!("国外 DNS 的节点无法确定出站地址：{error}"))?;
        if pin.addresses.is_empty() {
            return Err("DNS 节点没有公网 IPv4".into());
        }
    }
    guard.validate()?;
    let home = desktop_home(uid).await?;
    let database =
        crate::geo::database_in_home(&home).ok_or("找不到 Country.mmdb，无法确认节点在国外")?;
    let db = crate::geo::CountryDb::open(&database)?;
    let mut ips = guard.addresses.clone();
    for pin in &guard.dns_pins {
        ips.extend(pin.addresses.iter().copied());
    }
    ips.sort();
    ips.dedup();
    let mut found = Vec::with_capacity(ips.len());
    for ip in ips {
        found.push(db.place(std::net::IpAddr::V4(ip))?);
    }
    guard.country = crate::geo::require_places(&found)?;
    guard.validate()?;
    let mut policy = Policy::isolation();
    policy.lockdown = false;
    policy.tunnel_guard = Some(guard);
    policy.validate()?;
    Ok(policy)
}

fn endpoint_matches(guard: &TunnelGuard, live: &Observed) -> Result<(), String> {
    if live.chain != guard.selected_chain
        || live.server != guard.server
        || live.port != guard.port
        || live.protocols != guard.protocols
        || pin_keys(&live.dns_pins) != pin_keys(&guard.dns_pins)
    {
        return Err("TUN、全局代理选择或节点端点发生变化，需要停止保护后重新确认".into());
    }
    Ok(())
}

async fn live_guard(guard: &TunnelGuard) -> Result<Observed, String> {
    guard.validate()?;
    let live = current(guard.uid).await?;
    endpoint_matches(guard, &live)?;
    Ok(live)
}

pub async fn verify(guard: &TunnelGuard) -> Result<(), String> {
    let live = live_guard(guard).await?;
    if live.interface != guard.interface {
        return Err("TUN、全局代理选择或节点端点发生变化，需要停止保护后重新确认".into());
    }
    Ok(())
}

/// Same saved node, DNS pins, and proxy choice. The utun name may change after
/// TUN restarts; the caller writes that name back into the plan before reload.
pub async fn resume_interface(guard: &TunnelGuard) -> Result<String, String> {
    Ok(live_guard(guard).await?.interface)
}

#[cfg(test)]
pub fn fixture() -> TunnelGuard {
    TunnelGuard {
        uid: 501,
        interface: "utun6".into(),
        node: "test node".into(),
        server: "9.9.9.9".into(),
        port: 443,
        protocols: vec!["tcp".into()],
        addresses: vec!["9.9.9.9".parse().unwrap()],
        selected_chain: vec!["GLOBAL".into(), "test node".into()],
        prepared_at: chrono::Utc::now().to_rfc3339(),
        country: String::new(),
        dns_note: String::new(),
        dns_pins: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_dns_must_use_the_selected_node_and_domestic_direct_is_only_a_warning() {
        let proxies = serde_json::json!({"proxies":{"GLOBAL":{"type":"Selector","now":"node"},"node":{"type":"Shadowsocks"},"DIRECT":{"type":"DIRECT"},"other":{"type":"Trojan"}}});
        let config = serde_json::json!({"dns":{"enable":true,"nameserver":["https://1.1.1.1/dns-query#GLOBAL"],"nameserver-policy":{},"fallback":[]}});
        let ok = check_dns(&config, &proxies, "node").unwrap();
        assert!(ok.note.is_none());
        assert!(ok.extra_nodes.is_empty());
        for key in [
            "geosite:cn",
            "geosite:geolocation-cn",
            "GEOSITE:category-cn",
        ] {
            let mut domestic = config.clone();
            domestic["dns"]["nameserver-policy"] =
                serde_json::json!({key:["https://223.5.5.5/dns-query#DIRECT"]});
            let note = check_dns(&domestic, &proxies, "node").unwrap();
            assert!(note.note.unwrap().contains("直连"));
            assert!(note.extra_nodes.is_empty());
            domestic["dns"]["nameserver-policy"] = serde_json::json!({key:["223.5.5.5"]});
            assert!(check_dns(&domestic, &proxies, "node")
                .unwrap()
                .note
                .is_some());
            domestic["dns"]["nameserver-policy"] =
                serde_json::json!({key:["https://223.5.5.5/dns-query#GLOBAL"]});
            let same = check_dns(&domestic, &proxies, "node").unwrap();
            assert!(same.note.is_none());
            assert!(same.extra_nodes.is_empty());
            domestic["dns"]["nameserver-policy"] =
                serde_json::json!({key:["https://1.1.1.1/dns-query#other"]});
            let other = check_dns(&domestic, &proxies, "node").unwrap();
            assert!(other.note.is_none());
            assert_eq!(other.extra_nodes, ["other"]);
        }
        for resolver in [
            "https://1.1.1.1/dns-query",
            "https://223.5.5.5/dns-query#DIRECT",
            "https://dns.example/dns-query#GLOBAL",
            "https://1.1.1.1/dns-query#group&node",
        ] {
            let mut bad = config.clone();
            bad["dns"]["nameserver"] = serde_json::json!([resolver]);
            assert!(check_dns(&bad, &proxies, "node").is_err(), "{resolver}");
            bad["dns"]["nameserver"] = config["dns"]["nameserver"].clone();
            bad["dns"]["nameserver-policy"] =
                serde_json::json!({"geosite:geolocation-!cn":[resolver]});
            assert!(
                check_dns(&bad, &proxies, "node").is_err(),
                "policy {resolver}"
            );
            bad["dns"]["nameserver-policy"] = serde_json::json!({});
            bad["dns"]["fallback"] = serde_json::json!([resolver]);
            assert!(
                check_dns(&bad, &proxies, "node").is_err(),
                "fallback {resolver}"
            );
        }
        let mut via_other = config.clone();
        via_other["dns"]["nameserver"] = serde_json::json!(["https://1.1.1.1/dns-query#other"]);
        via_other["dns"]["fallback"] = serde_json::json!(["https://1.0.0.1/dns-query#other"]);
        via_other["dns"]["nameserver-policy"] =
            serde_json::json!({"geosite:geolocation-!cn":["https://8.8.8.8/dns-query#other"]});
        assert_eq!(
            check_dns(&via_other, &proxies, "node").unwrap().extra_nodes,
            ["other"]
        );
    }
    #[test]
    fn dns_pin_keeps_a_different_port_on_the_same_server() {
        let main = vec!["tcp".to_string()];
        let mut pins = Vec::new();
        consider_pin(
            &mut pins,
            "9.9.9.9",
            443,
            &main,
            "9.9.9.9".into(),
            443,
            vec!["tcp".into()],
        );
        assert!(pins.is_empty());
        consider_pin(
            &mut pins,
            "9.9.9.9",
            443,
            &main,
            "9.9.9.9".into(),
            8443,
            vec!["tcp".into()],
        );
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].port, 8443);
        consider_pin(
            &mut pins,
            "9.9.9.9",
            443,
            &main,
            "9.9.9.9".into(),
            8443,
            vec!["tcp".into()],
        );
        assert_eq!(pins.len(), 1);
    }
    #[test]
    fn resume_keeps_the_saved_endpoint_when_the_tun_name_changes() {
        let guard = fixture();
        let mut live = Observed {
            interface: "utun7".into(),
            chain: guard.selected_chain.clone(),
            server: guard.server.clone(),
            port: guard.port,
            protocols: guard.protocols.clone(),
            dns_note: String::new(),
            dns_pins: vec![],
        };
        endpoint_matches(&guard, &live).unwrap();
        live.port = 8443;
        assert!(endpoint_matches(&guard, &live).is_err());
    }
    #[test]
    fn tun_must_hijack_port_53() {
        assert_eq!(hijacks_port_53(&serde_json::json!({})), None);
        assert_eq!(
            hijacks_port_53(&serde_json::json!({"dns-hijack":[]})),
            Some(false)
        );
        assert_eq!(
            hijacks_port_53(&serde_json::json!({"dns-hijack":["any:53"]})),
            Some(true)
        );
        assert_eq!(
            hijacks_port_53(&serde_json::json!({"dns-hijack":["0.0.0.0:53"]})),
            Some(true)
        );
        assert_eq!(
            hijacks_port_53(&serde_json::json!({"dns_hijack":"any:853"})),
            Some(false)
        );
    }
    #[cfg(unix)]
    #[test]
    fn directory_service_home_is_the_matching_user_only() {
        let text = "name: ayu\nuid: 501\ndir: /Users/ayu\n\nname: root\nuid: 0\ndir: /var/root\n";
        assert_eq!(
            home_from_directory_service(text, 501).unwrap(),
            "/Users/ayu"
        );
        assert!(home_from_directory_service("uid: 501\ndir: ../etc\n", 501).is_err());
        assert!(home_from_directory_service("uid: 501\ndir: relative\n", 501).is_err());
        assert!(home_from_directory_service("uid: 501\n", 501).is_err());
    }
    #[test]
    fn follows_nested_selection_and_rejects_direct_cycles_and_unknown() {
        let p = serde_json::json!({"proxies": {"GLOBAL":{"type":"Selector","now":"group"},"group":{"type":"Fallback","now":"node"},"node":{"type":"Shadowsocks"}}});
        assert_eq!(selected(&p).unwrap(), ["GLOBAL", "group", "node"]);
        for entry in [
            serde_json::json!({"type":"DIRECT"}),
            serde_json::json!({"type":"Selector","now":"GLOBAL"}),
            serde_json::json!({"type":"LoadBalance"}),
            serde_json::json!({"type":"mystery"}),
        ] {
            assert!(selected(&serde_json::json!({"proxies":{"GLOBAL":entry}})).is_err());
        }
    }
    #[test]
    fn endpoint_does_not_guess_plugins_chains_or_hopping() {
        let p = serde_json::json!({"proxies":[{"name":"node","type":"ss","server":"9.9.9.9","port":443}]});
        assert_eq!(endpoint(&p, "node").unwrap().1, 443);
        for (k, v) in [
            ("plugin", serde_json::json!("obfs")),
            ("dialer-proxy", serde_json::json!("other")),
            ("ports", serde_json::json!("1-65535")),
        ] {
            let mut bad = p.clone();
            bad["proxies"][0][k] = v;
            assert!(endpoint(&bad, "node").is_err());
        }
        assert!(endpoint(&p, "missing").is_err());
    }
    #[test]
    fn rejects_interface_injection_private_fakeip_and_dns_exceptions() {
        fixture().validate().unwrap();
        for name in [
            "utun+",
            "utun6\npass all",
            "en0",
            "utun",
            "Ethernet",
            "eth0",
            "lo",
            "enp0s3",
            "wlan0",
            "Meta tun",
        ] {
            let mut p = fixture();
            p.interface = name.into();
            assert!(p.validate().is_err(), "{name}");
        }
        for name in ["utun6", "Meta", "Mihomo", "mihomo", "clash", "tun0", "tun2"] {
            let mut p = fixture();
            p.interface = name.into();
            p.validate().unwrap();
        }
        for ip in [
            "127.0.0.1",
            "192.168.1.2",
            "198.18.0.1",
            "100.64.0.1",
            "224.0.0.1",
        ] {
            let mut p = fixture();
            p.addresses = vec![ip.parse().unwrap()];
            assert!(p.validate().is_err());
        }
        let mut p = fixture();
        p.port = 53;
        assert!(p.validate().is_err());
        let mut noted = fixture();
        noted.country = "美国 (US)".into();
        noted.dns_note = DOMESTIC_DNS_NOTE.into();
        noted.validate().unwrap();
        noted.country = "美国\nUS".into();
        assert!(noted.validate().is_err());
    }
    #[test]
    fn clash_paths_keep_the_macos_service_first_and_reject_foreign_pipes() {
        let sockets = unix_service_sockets(501);
        assert_eq!(
            sockets[0],
            "/var/run/clash-verge-service/users/501/verge-mihomo.sock"
        );
        assert_eq!(
            service_runtime_yaml(501)[0],
            PathBuf::from(
                "/Library/Application Support/clash-verge-service/users/501/runtime/config.yaml"
            )
        );
        assert!(windows_pipe_ok("verge-mihomo"));
        assert!(windows_pipe_ok(&format!(
            "verge-mihomo-production-{}",
            "ab".repeat(32)
        )));
        assert!(!windows_pipe_ok("verge-mihomo-production-ab;calc"));
        assert!(!windows_pipe_ok("Ethernet"));
        assert!(
            pipe_rank(r"\\.\pipe\verge-mihomo-production-aa")
                < pipe_rank(r"\\.\pipe\verge-mihomo-development-aa")
        );
        let yaml = windows_runtime_from_pipe(
            &format!(r"\\.\pipe\verge-mihomo-production-{}", "cd".repeat(32)),
            Path::new(r"C:\ProgramData"),
        )
        .unwrap();
        assert!(
            yaml.ends_with(format!(
                "clash-verge-service/users/{}/runtime/config.yaml",
                "cd".repeat(32)
            )) || yaml.ends_with(format!(
                "clash-verge-service\\users\\{}\\runtime\\config.yaml",
                "cd".repeat(32)
            ))
        );
        assert!(windows_runtime_from_pipe(r"\\.\pipe\verge-mihomo", Path::new("x")).is_none());
        assert_eq!(
            linux_route_dev(r#"[{"dst":"1.1.1.1","dev":"Mihomo"}]"#).as_deref(),
            Some("Mihomo")
        );
        assert!(linux_link_up(r#"[{"flags":["POINTOPOINT","UP"]}]"#));
        assert!(!linux_link_up(r#"[{"flags":["UP"]}]"#));
        #[cfg(unix)]
        {
            assert!(home_from_passwd("ayu:x:1000:1000:Ayu:/home/ayu:/bin/zsh", 1000).is_ok());
            assert!(home_from_passwd("root:x:0:0:root:/root:/bin/zsh", 1000).is_err());
        }
        assert!(validate_home(r"C:\Windows\system32\config\systemprofile").is_err());
    }
}
