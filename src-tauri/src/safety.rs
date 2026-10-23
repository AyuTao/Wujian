use crate::{models::*, protection::Baseline};

pub(crate) const EVIDENCE_TTL_SECONDS: i64 = 30;

/// Global tunnel protection is enforced by PF, independently of IP/TZ samples.
pub(crate) fn global_report(
    checks: &[CheckResult],
    settings: &Settings,
    status: &crate::protection::ProtectionStatus,
) -> CircuitBreakerReport {
    let mut settings = settings.clone();
    settings.pinned_egress_ip = None;
    let mut report = evaluate(checks, &settings, None, false);
    for gate in &mut report.gates {
        match gate.id.as_str() {
            "gate-ip" => {
                gate.passed = checks.iter().any(|c| {
                    c.id == "egress-ipv4"
                        && c.integrity == "tls_verified"
                        && fresh(c, chrono::Utc::now())
                });
                gate.detail = "出口观测供参考；变化会记录提醒，不用出口 IP 轮询决定防回落。".into();
            }
            "gate-timezone" => {
                if settings.timezone_mode == "egress" {
                    let follow = checks.iter().find(|c| c.id == "timezone-follow");
                    gate.passed =
                        follow.is_some_and(|c| c.status == "match" && fresh(c, chrono::Utc::now()));
                    gate.detail = follow
                        .map(|c| c.detail.clone())
                        .unwrap_or_else(|| "等待查询出口城市时区".into());
                } else {
                    gate.passed = checks.iter().any(|c| {
                        c.id == "timezone"
                            && fresh(c, chrono::Utc::now())
                            && settings.target_timezone.as_deref().is_none_or(|target| {
                                crate::platform::timezone_matches(&c.value, target)
                            })
                    });
                    gate.detail =
                        "手动时区模式；有自定义目标时按目标核对，不作为全局保护的断网条件。".into();
                }
            }
            "gate-dns" => {
                gate.detail =
                    "系统解析配置供参考；全局保护禁止物理出口直连 DNS，实际解析由代理处理。".into();
            }
            "gate-ipv6" => {
                gate.passed |= status.tunnel_guard_confirmed;
                gate.detail =
                    "全局保护直接阻断隧道外 IPv6；无需通过关闭所有网卡 IPv6 建立保护。".into();
            }
            "gate-tunnel" => {
                gate.name = "指定 TUN".into();
                gate.detail =
                    "开启计划时由特权 helper 核对客户端返回的具体 utun 和公网采样路由。".into();
            }
            "gate-mode" => {
                gate.name = "全局代理".into();
                gate.passed = checks.iter().any(|c| {
                    c.id == "proxy-mode" && c.status == "match" && fresh(c, chrono::Utc::now())
                });
                gate.detail =
                    "必须为全局模式，GLOBAL 最终选择有效单节点；规则模式、直连和未知不允许开启。"
                        .into();
            }
            _ => {}
        }
    }
    report.all_passed = if status.armed {
        status.tunnel_guard_confirmed && !status.isolation_pending
    } else {
        report
            .gates
            .iter()
            .filter(|g| g.id == "gate-tunnel" || g.id == "gate-mode")
            .all(|g| g.passed)
    };
    report.is_tripped = !report.all_passed;
    report.tripped_reason = (!report.all_passed).then(|| {
        status
            .error
            .clone()
            .unwrap_or_else(|| "全局模式、指定 TUN 或当前规则尚未确认".into())
    });
    report
}

pub(crate) fn fresh(c: &CheckResult, now: chrono::DateTime<chrono::Utc>) -> bool {
    matches!(c.status.as_str(), "match" | "observed" | "review")
        && chrono::DateTime::parse_from_rfc3339(&c.observed_at).is_ok_and(|at| {
            let age = now.signed_duration_since(at).num_milliseconds();
            (0..EVIDENCE_TTL_SECONDS * 1000).contains(&age)
        })
}

pub(crate) fn evaluate(
    checks: &[CheckResult],
    settings: &Settings,
    baseline: Option<&Baseline>,
    armed: bool,
) -> CircuitBreakerReport {
    let now = chrono::Utc::now();
    let find = |id: &str| checks.iter().find(|c| c.id == id);
    let valid =
        |id: &str, integrity: &str| find(id).filter(|c| fresh(c, now) && c.integrity == integrity);
    let mut gates = Vec::new();
    let mut gate = |id: &str, name: &str, passed: bool, value: String, detail: String| {
        gates.push(GateCheck {
            id: id.into(),
            name: name.into(),
            passed,
            value,
            detail,
        });
    };
    let value = |id: &str| {
        find(id)
            .map(|c| c.value.clone())
            .unwrap_or_else(|| "未确认".into())
    };
    let ip = valid("egress-ipv4", "tls_verified");
    let country = valid("egress-region", "local_verified");
    let code = country
        .and_then(|c| c.value.rsplit_once('('))
        .and_then(|(_, s)| s.strip_suffix(')'));
    let expected_ip = baseline
        .map(|b| b.egress_ip.as_str())
        .or(settings.pinned_egress_ip.as_deref());
    let country_ok = code
        .is_some_and(|s| s.len() == 2 && s.bytes().all(|c| c.is_ascii_uppercase()) && s != "CN");
    let ip_ok = ip.is_some_and(|c| {
        c.value.parse::<std::net::Ipv4Addr>().is_ok()
            && expected_ip.is_none_or(|expected| c.value == expected)
    }) && country_ok
        && baseline.is_none_or(|b| b.proxy_url == settings.proxy_url);
    gate(
        "gate-ip",
        "出口 IP",
        ip_ok && (!armed || baseline.is_some()),
        value("egress-ipv4"),
        match expected_ip {
            Some(ip) => format!(
                "锁定出口 {ip}；变化、检测失败或证据超过 30 秒将触发整机隔离。仅覆盖所选检测路径。"
            ),
            None => "开启守护时锁定当前已核验的海外出口；未知地区不能建立基线。".into(),
        },
    );
    let timezone = valid("timezone", "local_verified");
    let is_china_tz = timezone.as_ref().is_some_and(|c| {
        let val = c.value.to_lowercase();
        val.contains("shanghai")
            || val.contains("chongqing")
            || val.contains("beijing")
            || val.contains("harbin")
            || val.contains("prc")
            || val.contains("china")
            || val.contains("cst")
    });
    let expected_tz = baseline
        .map(|b| b.timezone.as_str())
        .or(settings.target_timezone.as_deref());
    let tz_ok = timezone.is_some_and(|c| {
        if c.value.is_empty() {
            return false;
        }
        // 出口为海外节点时，中国时区属于明显属地破绽，不可通过
        if country_ok && is_china_tz {
            return false;
        }
        expected_tz.is_none_or(|tz| crate::platform::timezone_matches(&c.value, tz))
    });
    gate(
        "gate-timezone",
        "系统时区",
        tz_ok && (!armed || baseline.is_some()),
        value("timezone"),
        format!(
            "目标：{}。未指定时，在开启守护时锁定当前时区；不根据国家猜测城市时区。",
            expected_tz.unwrap_or("开启时确认的当前时区")
        ),
    );
    // DNS is a local configuration baseline, not the geolocation of a recursive resolver.
    // A China resolver is legitimate in a split policy. HTTP samples are advisory only.
    let dns = valid("dns-policy", "local_verified");
    let dns_ok = dns.is_some_and(|c| baseline.is_none_or(|b| b.dns_fingerprint == c.value));
    gate("gate-dns", "DNS 配置", dns_ok && (!armed || baseline.is_some()),
        if dns_ok { if baseline.is_some() { "已锁定配置" } else { "待开启时锁定" }.into() } else { "配置变化或未确认".into() },
        "锁定可读取的系统解析配置；变化或读取失败触发隔离。保留国内外分流，不改写代理 DNS；不覆盖应用内 DoH 或未暴露的客户端上游。".into());
    let v6 = find("ipv6-policy");
    let v6_ok = v6.is_some_and(|c| {
        c.status == "match"
            && ((c.integrity == "local_verified" && fresh(c, now))
                || c.integrity == "native_configuration")
    });
    gate(
        "gate-ipv6",
        "IPv6 配置",
        v6_ok,
        value("ipv6-policy"),
        "要求公网 IPv6 已停用或本工具阻断规则已回读；保留链路本地 IPv6。规则回读不是实际断流证明。"
            .into(),
    );
    let route = valid("network-route", "local_verified");
    gate(
        "gate-tunnel",
        "采样路由（参考）",
        route.is_some_and(|c| c.status == "match"),
        value("network-route"),
        "仅供参考；显式 HTTP/SOCKS 代理无需 TUN，分流路由不单独触发隔离。".into(),
    );
    let mode = valid("proxy-mode", "local_verified");
    gate(
        "gate-mode",
        "客户端模式（参考）",
        mode.is_some(),
        value("proxy-mode"),
        "仅供参考；未适配的代理模式可能无法确认。".into(),
    );
    let all_passed = gates[..4].iter().all(|g| g.passed);
    let is_tripped = !all_passed;
    let tripped_reason = is_tripped.then(|| {
        gates[..4]
            .iter()
            .filter(|g| !g.passed)
            .map(|g| format!("{}：{}", g.name, g.value))
            .collect::<Vec<_>>()
            .join("；")
    });
    CircuitBreakerReport {
        all_passed,
        is_tripped,
        tripped_reason,
        gates,
    }
}

#[cfg(test)]
pub(crate) fn capture(checks: &[CheckResult], settings: &Settings) -> Result<Baseline, String> {
    let report = evaluate(checks, settings, None, false);
    if !report.all_passed {
        return Err(report
            .tripped_reason
            .unwrap_or_else(|| "守护条件未满足".into()));
    }
    let get = |id: &str| {
        checks
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.value.clone())
            .ok_or("基线证据缺失")
    };
    Ok(Baseline {
        egress_ip: get("egress-ipv4")?,
        dns_fingerprint: get("dns-policy")?,
        timezone: get("timezone")?,
        proxy_url: settings.proxy_url.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timezone_pass_requires_the_selected_mode_to_match() {
        let checks = vec![CheckResult::local(
            "timezone",
            "TZ",
            "observed",
            "Asia/Shanghai",
            "",
        )];
        let mut settings = Settings {
            target_timezone: Some("America/New_York".into()),
            ..Settings::default()
        };
        let status = crate::protection::ProtectionStatus::default();
        assert!(
            !global_report(&checks, &settings, &status)
                .gates
                .iter()
                .find(|g| g.id == "gate-timezone")
                .unwrap()
                .passed
        );
        settings.timezone_mode = "egress".into();
        assert!(
            !global_report(&checks, &settings, &status)
                .gates
                .iter()
                .find(|g| g.id == "gate-timezone")
                .unwrap()
                .passed
        );
        let mut verified = checks;
        verified.push(CheckResult::local(
            "timezone-follow",
            "follow",
            "match",
            "已跟随",
            "",
        ));
        assert!(
            global_report(&verified, &settings, &status)
                .gates
                .iter()
                .find(|g| g.id == "gate-timezone")
                .unwrap()
                .passed
        );
    }
    #[test]
    fn global_guard_requires_global_tun_and_keeps_ip_timezone_diagnostics_advisory() {
        let mut status = crate::protection::ProtectionStatus::default();
        let settings = Settings::default();
        let mut checks = vec![
            CheckResult::local("network-route", "route", "match", "TUN", ""),
            CheckResult::local("proxy-mode", "mode", "unknown", "unknown", ""),
        ];
        assert!(!global_report(&checks, &settings, &status).all_passed);
        checks[1].status = "match".into();
        assert!(global_report(&checks, &settings, &status).all_passed);
        status.armed = true;
        assert!(!global_report(&checks, &settings, &status).all_passed);
        status.tunnel_guard_confirmed = true;
        checks.push(CheckResult::local(
            "egress-ipv4",
            "IP",
            "stale",
            "changed",
            "",
        ));
        checks.push(CheckResult::local(
            "timezone",
            "TZ",
            "deviation",
            "Asia/Shanghai",
            "",
        ));
        assert!(global_report(&checks, &settings, &status).all_passed);
        status.isolation_pending = true;
        assert!(!global_report(&checks, &settings, &status).all_passed);
    }
    fn fixture() -> (Vec<CheckResult>, Settings, Baseline) {
        let mut ip = CheckResult::local("egress-ipv4", "IP", "observed", "203.0.113.8", "");
        ip.integrity = "tls_verified".into();
        let checks = vec![
            ip,
            CheckResult::local("egress-region", "地区", "observed", "日本 (JP)", ""),
            CheckResult::local("timezone", "时区", "observed", "Asia/Tokyo", ""),
            CheckResult::local("dns-policy", "DNS", "observed", "config-a", ""),
            CheckResult::local("ipv6-policy", "IPv6", "match", "仅本地", ""),
            CheckResult::local("proxy-mode", "模式", "unknown", "未知", ""),
            CheckResult::local("network-route", "路由", "observed", "en0", ""),
        ];
        let settings = Settings::default();
        let baseline = capture(&checks, &settings).unwrap();
        (checks, settings, baseline)
    }
    #[test]
    fn supports_non_mihomo_and_split_or_explicit_proxy_without_tun() {
        let (checks, settings, baseline) = fixture();
        assert!(evaluate(&checks, &settings, Some(&baseline), true).all_passed);
    }
    #[test]
    fn each_required_change_trips_independently() {
        let (checks, settings, baseline) = fixture();
        for (id, new_value) in [
            ("egress-ipv4", "203.0.113.9"),
            ("timezone", "Asia/Shanghai"),
            ("dns-policy", "config-b"),
        ] {
            let mut changed = checks.clone();
            changed.iter_mut().find(|c| c.id == id).unwrap().value = new_value.into();
            let report = evaluate(&changed, &settings, Some(&baseline), true);
            assert!(report.is_tripped, "{id}");
            let mut protection = crate::protection::ProtectionStatus {
                armed: true,
                baseline: Some(baseline.clone()),
                ..Default::default()
            };
            assert!(
                protection.begin_isolation(report.is_tripped, report.tripped_reason, false),
                "{id} must reach native dispatch"
            );
            assert!(protection.isolation_pending && protection.filter_may_exist);
        }
        let mut changed = checks.clone();
        changed
            .iter_mut()
            .find(|c| c.id == "ipv6-policy")
            .unwrap()
            .status = "review".into();
        assert!(evaluate(&changed, &settings, Some(&baseline), true).is_tripped);
    }
    #[test]
    fn missing_unknown_expired_future_and_wrong_integrity_fail_closed() {
        let (checks, settings, baseline) = fixture();
        for id in [
            "egress-ipv4",
            "egress-region",
            "timezone",
            "dns-policy",
            "ipv6-policy",
        ] {
            let mut missing = checks.clone();
            missing.retain(|c| c.id != id);
            assert!(
                evaluate(&missing, &settings, Some(&baseline), true).is_tripped,
                "missing {id}"
            );
            for state in ["stale", "unknown", "not_run"] {
                let mut changed = checks.clone();
                changed.iter_mut().find(|c| c.id == id).unwrap().status = state.into();
                assert!(
                    evaluate(&changed, &settings, Some(&baseline), true).is_tripped,
                    "{id} {state}"
                );
            }
            for seconds in [-31, 1] {
                let mut changed = checks.clone();
                changed.iter_mut().find(|c| c.id == id).unwrap().observed_at =
                    (chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339();
                assert!(
                    evaluate(&changed, &settings, Some(&baseline), true).is_tripped,
                    "expired {id}"
                );
            }
        }
        let mut changed = checks.clone();
        changed[0].integrity = "http_unverified".into();
        assert!(evaluate(&changed, &settings, Some(&baseline), true).is_tripped);
    }
    #[test]
    fn http_dns_geolocation_never_controls_isolation_or_replaces_configuration() {
        let (mut checks, settings, baseline) = fixture();
        let mut dns = CheckResult::local("dns-observation", "DNS", "deviation", "China CN", "");
        dns.integrity = "http_unverified".into();
        checks.push(dns);
        assert!(evaluate(&checks, &settings, Some(&baseline), true).all_passed);
        checks.retain(|c| c.id != "dns-policy");
        assert!(evaluate(&checks, &settings, Some(&baseline), true).is_tripped);
    }
    #[test]
    fn explicit_targets_and_baseline_are_not_silently_replaced() {
        let (checks, mut settings, baseline) = fixture();
        settings.pinned_egress_ip = Some("203.0.113.9".into());
        assert!(capture(&checks, &settings).is_err());
        settings.pinned_egress_ip = None;
        settings.target_timezone = Some("America/New_York".into());
        assert!(capture(&checks, &settings).is_err());
        settings.target_timezone = None;
        assert!(evaluate(&checks, &settings, None, true).is_tripped);
        settings.proxy_url = "http://127.0.0.1:7890".into();
        assert!(evaluate(&checks, &settings, Some(&baseline), true).is_tripped);
        assert_eq!(baseline.egress_ip, "203.0.113.8");
    }
    #[test]
    fn native_ipv6_filter_is_separate_from_physical_adapter_mode() {
        let (mut checks, settings, baseline) = fixture();
        let v6 = checks.iter_mut().find(|c| c.id == "ipv6-policy").unwrap();
        v6.integrity = "native_configuration".into();
        assert!(evaluate(&checks, &settings, Some(&baseline), true).all_passed);
        v6_unavailable(&mut checks);
        assert!(evaluate(&checks, &settings, Some(&baseline), true).is_tripped);
    }
    fn v6_unavailable(checks: &mut [CheckResult]) {
        checks
            .iter_mut()
            .find(|c| c.id == "ipv6-policy")
            .unwrap()
            .status = "unknown".into();
    }
}
