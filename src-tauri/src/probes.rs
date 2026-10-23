use crate::{
    models::{CheckResult, EndpointObservation, Settings},
    platform::NetworkInfo,
};
use reqwest::{Client, Proxy, Url};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub fn validate_proxy(raw: &str) -> Result<Option<Url>, String> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    if raw.len() > 2048 || raw.chars().any(char::is_control) {
        return Err("代理地址包含无效字符或过长".into());
    }
    let url = Url::parse(raw.trim())
        .map_err(|_| "代理地址格式无效，请包含 http://、https:// 或 socks5h://".to_string())?;
    if !["http", "https", "socks5h"].contains(&url.scheme()) || url.host_str().is_none() {
        return Err("只支持 HTTP、HTTPS 或远端解析的 SOCKS5H 代理".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("当前版本不接收 URL 中的代理账户或密码".into());
    }
    if !["", "/"].contains(&url.path()) || url.query().is_some() || url.fragment().is_some() {
        return Err("代理地址只能包含协议、主机和端口".into());
    }
    Ok(Some(url))
}
/// Display refresh is independent of arming the firewall. Consent still gates requests.
pub(crate) fn refresh_interval(settings: &Settings, armed: bool) -> Option<u64> {
    if armed {
        return Some(10);
    }
    if !settings.external_ip_consent && !settings.dns_http_consent {
        return None;
    }
    Some(if settings.monitor_interval_sec == 0 {
        15
    } else {
        settings.monitor_interval_sec
    })
}

pub fn validate_settings(settings: &Settings) -> Result<(), String> {
    if !matches!(settings.timezone_mode.as_str(), "manual" | "egress") {
        return Err("未知的时区模式".into());
    }
    if settings.timezone_mode == "egress" && !settings.external_ip_consent {
        return Err("跟随出口时区需要允许 HTTPS 出口查询".into());
    }
    if !["system", "light", "dark"].contains(&settings.theme.as_str()) {
        return Err("未知的主题选项".into());
    }
    if settings.monitor_interval_sec != 0 && !(60..=3600).contains(&settings.monitor_interval_sec) {
        return Err("检查间隔应为 60 至 3600 秒，或设为 0 使用默认刷新间隔".into());
    }
    if !(1..=90).contains(&settings.history_days) {
        return Err("记录保留时间应为 1 至 90 天".into());
    }
    validate_proxy(&settings.proxy_url)?;
    if let Some(ip) = &settings.pinned_egress_ip {
        ip.parse::<std::net::Ipv4Addr>()
            .map_err(|_| "锁定出口必须是有效 IPv4 地址")?;
    }
    if let Some(tz) = &settings.target_timezone {
        crate::platform::validate_timezone_name(tz)?;
    }
    if let Some(path) = &settings.geoip_database_path {
        if !std::path::Path::new(path).is_absolute() || path.chars().any(char::is_control) {
            return Err("GeoIP 数据库需要有效的本机绝对路径".into());
        }
    }
    Ok(())
}
fn client(settings: &Settings, dns_override: Option<(&str, SocketAddr)>) -> Result<Client, String> {
    let mut builder = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Wujian/0.1 local-network-inspection");
    if let Some(proxy) = validate_proxy(&settings.proxy_url)? {
        builder =
            builder.proxy(Proxy::all(proxy.as_str()).map_err(|_| "代理地址无法使用".to_string())?);
    }
    if let Some((host, address)) = dns_override {
        builder = builder.resolve(host, address);
    }
    builder.build().map_err(|_| "无法建立检测客户端".into())
}
async fn json_request(client: &Client, url: &str) -> Result<serde_json::Value, String> {
    let mut response = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            "请求超时；未改为直连"
        } else {
            "连接、代理或 TLS 校验失败；未回退其他路径"
        }
        .to_string()
    })?;
    if !response.status().is_success() {
        return Err(format!(
            "检测服务返回 HTTP {}，本次无法确认",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > 65_536)
    {
        return Err("检测响应超出大小限制".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "读取检测响应失败".to_string())?
    {
        if bytes.len() + chunk.len() > 65_536 {
            return Err("检测响应超出大小限制".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "检测响应不是有效 JSON".into())
}
fn external_result(
    id: &str,
    label: &str,
    status: &str,
    value: &str,
    detail: &str,
    proxy: bool,
    http: bool,
) -> CheckResult {
    let mut check = CheckResult::local(id, label, status, value, detail);
    check.scope = if proxy {
        "显式代理路径；不代表 AI 请求出口"
    } else {
        "系统路由检测路径；不代表 AI 请求出口"
    }
    .into();
    check.source = if http { "ip-api DNS" } else { "ipify IPv4" }.into();
    check.integrity = if http {
        "http_unverified"
    } else if ["review", "match"].contains(&status) {
        "tls_verified"
    } else {
        "unverified"
    }
    .into();
    check
}
pub async fn run(settings: &Settings, network: &NetworkInfo) -> Vec<CheckResult> {
    // An optional, untrusted DNS service cannot invalidate a successful HTTPS probe.
    let (egress, dns) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(12), probe_egress(settings, network)),
        tokio::time::timeout(Duration::from_secs(10), probe_dns(settings, network)),
    );
    let proxy = !settings.proxy_url.is_empty();
    let mut results = egress.unwrap_or_else(|_| {
        vec![external_result(
            "egress-ipv4",
            "公网 IPv4 出口",
            "unknown",
            "出口检测超时",
            "出口检测超过 12 秒，未回退直连；守护期间将触发隔离。",
            proxy,
            false,
        )]
    });
    results.extend(dns.unwrap_or_else(|_| {
        vec![external_result(
            "dns-observation",
            "DNS 辅助观测",
            "unknown",
            "辅助观测超时",
            "HTTP 辅助观测仅供参考，不控制断网。",
            proxy,
            true,
        )]
    }));
    log_probe_results(&results);

    results
}
fn log_probe_results(results: &[CheckResult]) {
    for result in results {
        let operation = match result.id.as_str() {
            "egress-ipv4" => "probe.ipv4",
            "dns-observation" => "probe.dns",
            "egress-region" => "probe.geoip",
            _ => continue,
        };
        let outcome = match result.status.as_str() {
            "not_run" => "skipped",
            "unknown" => "unavailable",
            "deviation" => "deviation",
            _ => "observed",
        };
        let kind = if result.status == "unknown" {
            Some(if result.value.contains("明确检测代理") {
                "proxy_path_required"
            } else {
                crate::audit::error_kind(&result.detail)
            })
        } else {
            None
        };
        // State changes include failures and recovery; repeated healthy probes
        // retain an occasional timed heartbeat instead of flooding the ring.
        crate::audit::transition_kind(operation, outcome, kind);
    }
}
async fn probe_egress(settings: &Settings, network: &NetworkInfo) -> Vec<CheckResult> {
    let started = std::time::Instant::now();
    let results = async {
    let proxy = !settings.proxy_url.trim().is_empty();
    let mut results = vec![];
    let unsafe_default = !proxy && (network.app_proxy_present || !network.proxy_readable);
    if !settings.external_ip_consent {
        results.push(external_result(
            "egress-ipv4",
            "公网 IPv4 出口",
            "not_run",
            "尚未授权外部查询",
            "可在设置中允许向 ipify 发起 HTTPS 请求。当前没有发起该请求。",
            proxy,
            false,
        ));
    } else if unsafe_default {
        results.push(external_result("egress-ipv4", "公网 IPv4 出口", "unknown", "请先明确检测代理", "检测到应用代理或无法读取相关配置；为避免绕过现有设置，本次未发起请求。请在设置填写要使用的代理。", proxy, false));
    } else {
        let observed = async {
            let client = client(settings, None)?;
            let urls = ["https://api.ipify.org?format=json"];
            let mut last_err = "无法获取公网 IP".to_string();
            for url in urls {
                match json_request(&client, url).await {
                    Ok(val) => {
                        let raw = val["ip"].as_str().or_else(|| val["ip_addr"].as_str());
                        if let Some(raw) = raw {
                            if let Ok(ip) = raw.parse::<std::net::Ipv4Addr>() {
                                if !ip.is_private()
                                    && !ip.is_loopback()
                                    && !ip.is_unspecified()
                                    && !ip.is_multicast()
                                    && !ip.is_link_local()
                                {
                                    return Ok::<_, String>(ip.to_string());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        last_err = e;
                    }
                }
            }
            Err(last_err)
        }
        .await;
        match observed {
            Ok(ip) => {
                results.push(external_result("egress-ipv4", "公网 IPv4 出口", "review", &ip, "已观测本次请求出口。尚未设定出口白名单，请确认是否符合你的预期；不能由此推定 AI 服务看到相同地址。", proxy, false));
                let country = ip
                    .parse()
                    .map_err(|_| "IP 无效".to_string())
                    .and_then(|ip| lookup_country(settings, ip));
                let mut region = match country {
                    Ok(country) => CheckResult::local("egress-region", "出口 IP 地区", "observed", format!("{} ({})", country.name, country.code), "使用本机 Country.mmdb 离线查询本次公网出口。GeoIP 标签可能有误差，不单独证明路径安全、DNS 无泄露或出口稳定。"),
                    Err(error) => CheckResult::local("egress-region", "出口 IP 地区", "unknown", "地区待确认", error),
                };
                region.source = "本机 Country.mmdb".into();
                region.scope = "本次公网 IPv4 的离线国家分类".into();
                results.push(region);
            }
            Err(error) => results.push(external_result(
                "egress-ipv4",
                "公网 IPv4 出口",
                "unknown",
                "本次出口未确认",
                &error,
                proxy,
                false,
            )),
        }
    }
    results
    }.await;
    log_probe_results(&results);
    crate::audit::timed_observation("probe.ipv4", started.elapsed().as_millis() as u64);
    results
}

fn lookup_country(settings: &Settings, ip: IpAddr) -> Result<crate::geo::Country, String> {
    let result: Result<_, String> = (|| {
        settings
            .geoip_database_path
            .as_ref()
            .map(std::path::PathBuf::from)
            .or_else(crate::geo::default_database)
            .ok_or_else(|| {
                "未找到 Country.mmdb，请在设置中填写本机数据库路径（无需使用 Clash）".to_string()
            })
            .and_then(|path| crate::geo::CountryDb::open(&path))
            .and_then(|db| db.lookup(ip))
            .and_then(|country| country.ok_or("GeoIP 没有此地址的国家记录".to_string()))
    })();
    crate::audit::transition(
        "geoip.lookup",
        if result.is_ok() { "ok" } else { "error" },
        result.as_ref().err().map(String::as_str),
    );
    result
}

pub(crate) struct EgressTimezone {
    pub ip: String,
    pub timezone: String,
}
pub(crate) async fn verified_egress_ip(
    settings: &Settings,
    network: &NetworkInfo,
) -> Result<IpAddr, String> {
    probe_egress(settings, network)
        .await
        .into_iter()
        .find(|c| c.id == "egress-ipv4" && c.integrity == "tls_verified")
        .and_then(|c| c.value.parse().ok())
        .ok_or_else(|| "出口未确认，请先授权 HTTPS 出口查询并核对代理路径；未修改时区".into())
}

/// Queried on explicit follow or after an IP change when follow mode is enabled.
/// ipinfo's timezone matched the measured Seattle facility for this egress.
/// ipwho.is registered that same address in Buffalo and is only a fallback.
pub(crate) async fn egress_timezone(
    settings: &Settings,
    network: &NetworkInfo,
) -> Result<EgressTimezone, String> {
    let ip = verified_egress_ip(settings, network).await?;
    let http = client(settings, None)?;
    let timezone = match crate::audit::record_async("timezone.lookup.ipinfo", async {
        let response = json_request(&http, &format!("https://ipinfo.io/{ip}/json")).await?;
        timezone_from_ipinfo(&response, ip)
    })
    .await
    {
        Ok(timezone) => timezone,
        Err(_) => {
            crate::audit::event("timezone.lookup", "fallback", None, None);
            crate::audit::record_async("timezone.lookup.ipwho", timezone_from_ipwho(&http, ip))
                .await?
        }
    };
    if verified_egress_ip(settings, network).await? != ip {
        return Err("查询期间出口 IP 已变化，请重试；未修改时区".into());
    }
    Ok(EgressTimezone {
        ip: ip.to_string(),
        timezone,
    })
}

async fn timezone_from_ipwho(client: &Client, ip: IpAddr) -> Result<String, String> {
    let response = json_request(client, &format!("https://ipwho.is/{ip}"))
        .await
        .map_err(|e| format!("城市时区查询失败：{e}；未修改时区"))?;
    timezone_from_response(&response, ip)
}

fn timezone_from_ipinfo(value: &serde_json::Value, ip: IpAddr) -> Result<String, String> {
    if value.get("error").is_some()
        || value["ip"]
            .as_str()
            .and_then(|value| value.parse::<IpAddr>().ok())
            != Some(ip)
    {
        return Err("城市查询未返回当前出口 IP 的有效记录；未修改时区".into());
    }
    let tz = value["timezone"]
        .as_str()
        .ok_or("出口城市没有时区信息；请在设置中手动指定，未修改时区")?;
    accept_iana_timezone(tz)
}

fn timezone_from_response(value: &serde_json::Value, ip: IpAddr) -> Result<String, String> {
    if value["success"].as_bool() != Some(true)
        || value["ip"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) != Some(ip)
    {
        return Err("城市查询未返回当前出口 IP 的有效记录；未修改时区".into());
    }
    let tz = value["timezone"]["id"]
        .as_str()
        .ok_or("出口城市没有时区信息；请在设置中手动指定，未修改时区")?;
    accept_iana_timezone(tz)
}

fn accept_iana_timezone(tz: &str) -> Result<String, String> {
    crate::platform::validate_timezone_name(tz)?;
    if tz.starts_with('/') || tz.split('/').any(str::is_empty) || tz.contains(' ') {
        return Err("城市查询未返回有效的 IANA 时区；未修改时区".into());
    }
    // Accept an installed IANA name, not an offset or a guessed country default.
    #[cfg(unix)]
    if !std::path::Path::new("/usr/share/zoneinfo")
        .join(tz)
        .is_file()
    {
        return Err("城市查询返回了系统不支持的时区；未修改时区".into());
    }
    #[cfg(target_os = "windows")]
    crate::platform::iana_to_windows_timezone(tz)?;
    Ok(tz.to_string())
}

async fn probe_dns(settings: &Settings, network: &NetworkInfo) -> Vec<CheckResult> {
    let started = std::time::Instant::now();
    let results = async {
    let proxy = !settings.proxy_url.trim().is_empty();
    let mut results = vec![];
    let unsafe_default = !proxy && (network.app_proxy_present || !network.proxy_readable);
    if !settings.dns_http_consent {
        results.push(external_result(
            "dns-observation",
            "DNS 解析出口观测",
            "not_run",
            "尚未授权 HTTP DNS 观测",
            "该非商业接口使用随机测试域名；服务会看到解析与请求相关信息。当前没有发起该请求。",
            proxy,
            true,
        ));
    } else if unsafe_default {
        results.push(external_result(
            "dns-observation",
            "DNS 解析出口观测",
            "unknown",
            "请先明确检测代理",
            "为避免绕过已有代理设置，本次未发起 DNS 观测。",
            proxy,
            true,
        ));
    } else {
        let observed = async {
            let host = format!("{}.edns.ip-api.com", uuid::Uuid::new_v4().simple());
            // The explicitly selected proxy may resolve remotely. Do not secretly
            // issue a direct OS lookup that bypasses the selected path.
            let http_client = if proxy { client(settings, None)? } else {
                let mut addresses = tokio::time::timeout(Duration::from_secs(8), tokio::net::lookup_host((host.as_str(), 80))).await
                    .map_err(|_| "系统解析测试域名超时".to_string())?.map_err(|_| "系统无法解析测试域名".to_string())?;
                let address = addresses.find(|a| matches!(a.ip(), IpAddr::V4(ip) if !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_link_local())).ok_or("系统没有返回有效 IPv4 地址")?;
                client(settings, Some((&host, address)))?
            };
            let value = json_request(&http_client, &format!("http://{host}/json")).await?;
            let dns: IpAddr = value["dns"]["ip"]
                .as_str()
                .ok_or("接口缺少 DNS 观测字段")?
                .parse()
                .map_err(|_| "接口返回了无效的 DNS 地址")?;
            let ecs = value["edns"]["ip"]
                .as_str()
                .map(|v| v.chars().take(80).collect::<String>());
            let geo_label = |field: &str| {
                value[field]["geo"]
                    .as_str()
                    .map(|v| {
                        v.chars()
                            .filter(|c| !c.is_control())
                            .take(160)
                            .collect::<String>()
                    })
                    .filter(|v| !v.trim().is_empty())
            };
            Ok::<_, String>((dns.to_string(), ecs, geo_label("dns"), geo_label("edns")))
        }
        .await;
        match observed {
            Ok((dns, _ecs, dns_geo, _ecs_geo)) => {
                let dns_geo_str = dns_geo.as_deref().unwrap_or("接口未提供归属");
                let status = "observed";
                let detail = format!("HTTP 辅助采样：{dns_geo_str}；明文结果可被篡改，仅供参考，不控制断网。国内服务按分流规则使用国内 DNS 属于正常行为；本次观测不覆盖其他域名、浏览器安全 DNS 或全系统路径。");
                let display = format!("{dns} · {dns_geo_str}");
                let mut result = external_result(
                    "dns-observation",
                    "DNS 解析出口观测",
                    status,
                    &display,
                    &detail,
                    proxy,
                    true,
                );
                result.integrity = "http_unverified".into();
                let country = dns
                    .parse()
                    .ok()
                    .and_then(|ip| lookup_country(settings, ip).ok());
                result.endpoint = Some(EndpointObservation {
                    address: dns,
                    country_code: country.as_ref().map(|c| c.code.clone()),
                    location: country
                        .map(|c| c.name)
                        .or(dns_geo)
                        .unwrap_or_else(|| "地区未知".into()),
                });
                results.push(result);
            }
            Err(error) => results.push(external_result(
                "dns-observation",
                "DNS 解析出口观测",
                "unknown",
                "本次解析出口未确认",
                &error,
                proxy,
                true,
            )),
        }
    }
    results
    }.await;
    log_probe_results(&results);
    crate::audit::timed_observation("probe.dns", started.elapsed().as_millis() as u64);
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timezone_lookup_requires_the_exact_egress_and_an_iana_city_record() {
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let response = serde_json::json!({"success":true,"ip":"203.0.113.10","country_code":"US","timezone":{"id":"America/New_York"}});
        assert_eq!(
            timezone_from_response(&response, ip).unwrap(),
            "America/New_York"
        );
        let pacific = "203.0.113.15".parse().unwrap();
        assert_eq!(
            timezone_from_ipinfo(
                &serde_json::json!({"ip":"203.0.113.15","city":"Seattle","timezone":"America/Los_Angeles"}),
                pacific
            )
            .unwrap(),
            "America/Los_Angeles"
        );
        assert!(timezone_from_ipinfo(
            &serde_json::json!({"ip":"203.0.113.16","timezone":"America/Los_Angeles"}),
            pacific
        )
        .is_err());
        assert!(timezone_from_ipinfo(
            &serde_json::json!({"error":{"title":"Wrong"},"ip":"203.0.113.15"}),
            pacific
        )
        .is_err());
        for response in [
            serde_json::json!({"success":false,"ip":"203.0.113.10"}),
            serde_json::json!({"success":true,"ip":"203.0.113.11","timezone":{"id":"America/New_York"}}),
            serde_json::json!({"success":true,"ip":"203.0.113.10","country_code":"US"}),
            serde_json::json!({"success":true,"ip":"203.0.113.10","timezone":{"id":"/etc/localtime"}}),
            serde_json::json!({"success":true,"ip":"203.0.113.10","timezone":{"id":"Unknown/City"}}),
        ] {
            assert!(timezone_from_response(&response, ip).is_err());
        }
    }
    #[test]
    fn authorized_observations_refresh_even_without_firewall_monitoring() {
        let mut settings = Settings::default();
        assert_eq!(refresh_interval(&settings, false), None);
        settings.external_ip_consent = true;
        assert_eq!(refresh_interval(&settings, false), Some(15));
        settings.external_ip_consent = false;
        settings.dns_http_consent = true;
        assert_eq!(refresh_interval(&settings, false), Some(15));
        settings.monitor_interval_sec = 60;
        assert_eq!(refresh_interval(&settings, false), Some(60));
        assert_eq!(refresh_interval(&settings, true), Some(10));
    }
    #[test]
    fn rejects_credentials_unsupported_schemes_and_extra_urls() {
        for value in [
            "http://user:secret@127.0.0.1:7890",
            "file:///tmp/a",
            "https://a/path",
            "http://a?x=1",
            "socks5://127.0.0.1:1080",
        ] {
            assert!(validate_proxy(value).is_err(), "{value}");
        }
        assert!(validate_proxy("http://127.0.0.1:7890").is_ok());
        assert!(validate_proxy("socks5h://127.0.0.1:1080").is_ok());
    }
    #[test]
    fn validates_monitoring_and_retention() {
        let mut settings = Settings::default();
        assert!(validate_settings(&settings).is_ok());
        settings.monitor_interval_sec = 1;
        assert!(validate_settings(&settings).is_err());
        settings.monitor_interval_sec = 60;
        settings.history_days = 0;
        assert!(validate_settings(&settings).is_err());
    }
    #[tokio::test]
    async fn no_consent_returns_without_contacting_any_endpoint() {
        let settings = Settings {
            proxy_url: "http://127.0.0.1:1".into(),
            external_ip_consent: false,
            dns_http_consent: false,
            ..Settings::default()
        };
        let network = NetworkInfo {
            dns_servers: vec![],
            proxy_summary: String::new(),
            checks: vec![],
            fingerprint: 0,
            app_proxy_present: false,
            proxy_readable: true,
        };
        let results = tokio::time::timeout(Duration::from_millis(100), run(&settings, &network))
            .await
            .expect("without consent there must be no network wait");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|check| check.status == "not_run"));
    }

    async fn fixture(status: u16, body: &str, extra: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len());
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0_u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{address}/fixture")
    }
    #[tokio::test]
    async fn accepts_bounded_json_fixture() {
        let url = fixture(200, r#"{"ip":"203.0.113.1"}"#, "").await;
        let result = json_request(&client(&Settings::default(), None).unwrap(), &url)
            .await
            .unwrap();
        assert_eq!(result["ip"], "203.0.113.1");
    }
    #[tokio::test]
    async fn rejects_redirect_instead_of_contacting_another_host() {
        let url = fixture(
            302,
            "",
            "Location: http://should-not-be-contacted.invalid/\r\n",
        )
        .await;
        let error = json_request(&client(&Settings::default(), None).unwrap(), &url)
            .await
            .unwrap_err();
        assert!(error.contains("302"));
    }
    #[tokio::test]
    async fn rejects_invalid_json_fixture() {
        let url = fixture(200, "not-json", "").await;
        assert!(
            json_request(&client(&Settings::default(), None).unwrap(), &url)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn rejects_oversized_body_fixture() {
        let url = fixture(200, &"x".repeat(65_537), "").await;
        let error = json_request(&client(&Settings::default(), None).unwrap(), &url)
            .await
            .unwrap_err();
        assert!(error.contains("大小限制"));
    }

    #[test]
    fn failed_probe_cannot_claim_verified_tls_evidence() {
        let failed = external_result("egress", "IP", "unknown", "", "TLS failed", false, false);
        assert_eq!(failed.integrity, "unverified");
        let skipped = external_result("egress", "IP", "not_run", "", "no consent", false, false);
        assert_eq!(skipped.integrity, "unverified");
    }
}
