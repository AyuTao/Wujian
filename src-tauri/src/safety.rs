use crate::models::*;

pub(crate) fn fresh(c: &CheckResult, now: chrono::DateTime<chrono::Utc>) -> bool {
    matches!(c.status.as_str(), "match" | "observed" | "review")
        && chrono::DateTime::parse_from_rfc3339(&c.observed_at).is_ok_and(|at| {
            let age = now.signed_duration_since(at).num_milliseconds();
            (0..30_000).contains(&age)
        })
}

pub(crate) fn evaluate(checks: &[CheckResult], settings: &Settings) -> CircuitBreakerReport {
    let now = chrono::Utc::now();
    let find = |id: &str| checks.iter().find(|c| c.id == id);
    let valid =
        |id: &str, integrity: &str| find(id).filter(|c| fresh(c, now) && c.integrity == integrity);
    let mut gates = Vec::new();
    let mut gate = |id: &str, name: &str, passed: bool, c: Option<&CheckResult>, detail: &str| {
        gates.push(GateCheck {
            id: id.into(),
            name: name.into(),
            passed,
            value: c
                .map(|c| c.value.clone())
                .unwrap_or_else(|| "未确认".into()),
            detail: detail.into(),
        });
    };
    let ip = valid("egress-ipv4", "tls_verified");
    let country = valid("egress-region", "local_verified");
    // ISO code is taken from our offline lookup, never guessed from an ISP name.
    let code = country
        .and_then(|c| c.value.rsplit_once('('))
        .and_then(|(_, s)| s.strip_suffix(')'));
    let ip_ok = ip.is_some_and(|c| {
        c.value.parse::<std::net::Ipv4Addr>().is_ok()
            && settings
                .pinned_egress_ip
                .as_ref()
                .is_none_or(|p| p == &c.value)
    });
    let country_ok = code
        .is_some_and(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase()) && s != "CN");
    gate(
        "gate-ip",
        "出口 IP",
        ip_ok && country_ok,
        ip,
        "需要当前 HTTPS 出口与离线国家证据；不代表所有应用走相同路径。",
    );
    let tz = crate::platform::get_system_timezone().ok();
    // Country data does not identify a city's timezone. Do not modify the clock.
    let tz_check = CheckResult::local(
        "timezone",
        "时区",
        "observed",
        tz.as_deref().unwrap_or("未知"),
        "",
    );
    gate(
        "gate-timezone",
        "系统时区",
        tz.is_some() && country_ok,
        Some(&tz_check),
        "时区只作为环境信息，国家级数据库不能证明与节点所在城市一致。",
    );
    let dns = valid("dns-observation", "enforced_path");
    gate("gate-dns", "DNS 路径", dns.is_some_and(|d| d.status == "match"), find("dns-observation"),
        "HTTP 采样仅作辅助。采样显示泄漏至国内运营商时提示风险；未建立可信的全路径 DNS 约束前，不据此自动解除隔离。请检查客户端远端 DNS 和浏览器安全 DNS。");
    let v6 = valid("ipv6-policy", "local_verified");
    gate(
        "gate-ipv6",
        "IPv6 配置",
        v6.is_some_and(|c| c.status == "match")
            || find("ipv6-policy")
                .is_some_and(|c| c.status == "match" && c.integrity == "native_configuration"),
        find("ipv6-policy"),
        "需要接口停用证据或本工具的 IPv6 阻断规则回读；配置证据不能代替实机断流验收。",
    );
    let route = valid("network-route", "local_verified");
    gate(
        "gate-tunnel",
        "采样路由",
        route.is_some_and(|c| c.status == "match"),
        find("network-route"),
        "两个采样目标必须经过相同 TUN；分流和未知不通过，采样不能证明全系统接管。",
    );
    let mode = valid("proxy-mode", "local_verified");
    gate(
        "gate-mode",
        "代理模式",
        mode.is_some_and(|c| c.status == "match" || c.status == "observed"),
        find("proxy-mode"),
        "模式未知时展示未知，不用采样路由猜测客户端模式。规则模式和全局模式均需验证实际路径。",
    );
    let all_passed = gates.iter().all(|g| g.passed);
    // Diagnostic completeness is separate from an isolation trigger. An HTTP
    // DNS observation never authorizes release, and an unreadable client mode
    // alone does not establish a real leak. Native incidents remain latched.
    let required =
        |g: &&GateCheck| matches!(g.id.as_str(), "gate-ip" | "gate-ipv6" | "gate-tunnel");
    let critical_missing = gates.iter().filter(required).any(|g| !g.passed);
    let dns_deviation = find("dns-observation").is_some_and(|c| c.status == "deviation");
    let direct_mode =
        find("proxy-mode").is_some_and(|c| c.status == "deviation" && c.value == "直连模式");
    let tripped = critical_missing || dns_deviation || direct_mode;
    let reason = tripped.then(|| {
        gates
            .iter()
            .filter(|g| !g.passed)
            .map(|g| format!("{}：{}", g.name, g.value))
            .collect::<Vec<_>>()
            .join("；")
    });
    CircuitBreakerReport {
        all_passed,
        is_tripped: tripped,
        tripped_reason: reason,
        gates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_future_and_untrusted_evidence_do_not_allow() {
        let mut c = CheckResult::local("dns-observation", "DNS", "match", "US", "");
        let now = chrono::Utc::now();
        c.observed_at = (now - chrono::Duration::seconds(31)).to_rfc3339();
        assert!(!fresh(&c, now));
        c.observed_at = (now + chrono::Duration::seconds(1)).to_rfc3339();
        assert!(!fresh(&c, now));
        c.observed_at = now.to_rfc3339();
        c.integrity = "http_unverified".into();
        assert!(
            !evaluate(&[c], &Settings::default())
                .gates
                .iter()
                .find(|g| g.id == "gate-dns")
                .unwrap()
                .passed
        );
    }
    #[test]
    fn split_routes_trip_even_when_rule_mode_is_valid() {
        let checks = [
            CheckResult::local(
                "network-route",
                "路由",
                "observed",
                "检测到分流 · utun6 / en0",
                "",
            ),
            crate::proxy_core::config_check(
                &serde_json::json!({"mode":"rule","tun":{"enable":true}}),
            ),
        ];
        let r = evaluate(&checks, &Settings::default());
        assert!(
            !r.gates
                .iter()
                .find(|g| g.id == "gate-tunnel")
                .unwrap()
                .passed
        );
        assert!(r.gates.iter().find(|g| g.id == "gate-mode").unwrap().passed);
        assert!(r.is_tripped);
    }
    #[test]
    fn healthy_recheck_does_not_trip_from_http_dns_or_unknown_client_mode() {
        let mut ip = CheckResult::local("egress-ipv4", "IP", "observed", "203.0.113.8", "");
        ip.integrity = "tls_verified".into();
        let mut checks = vec![
            ip,
            CheckResult::local("egress-region", "国家", "observed", "Japan (JP)", ""),
            CheckResult::local("network-route", "路由", "match", "tun0", ""),
            CheckResult::local("ipv6-policy", "IPv6", "match", "disabled", ""),
            CheckResult::local("proxy-mode", "模式", "unknown", "未知", ""),
        ];
        let mut dns = CheckResult::local("dns-observation", "DNS", "observed", "US", "");
        dns.integrity = "http_unverified".into();
        checks.push(dns);
        let result = evaluate(&checks, &Settings::default());
        assert!(!result.is_tripped);
        assert!(!result.all_passed); // HTTP DNS is never full-path proof.
        checks[0].observed_at = (chrono::Utc::now() - chrono::Duration::seconds(31)).to_rfc3339();
        assert!(evaluate(&checks, &Settings::default()).is_tripped);
    }
}
