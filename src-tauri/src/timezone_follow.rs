//! City timezone bindings are tied to the measured IP, never inferred by country.
use crate::{models::CheckResult, platform, safety};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct FollowState {
    pub ip: Option<String>,
    pub target: Option<String>,
    pub error: Option<String>,
    pub application_blocked: bool,
    attempted_ip: Option<String>,
    attempted_at: Option<Instant>,
}
impl FollowState {
    pub fn due(&self, ip: &str, current_timezone: &str) -> bool {
        if self.application_blocked {
            return false;
        }
        if self.ip.as_deref() == Some(ip)
            && self
                .target
                .as_deref()
                .is_some_and(|tz| platform::timezone_matches(current_timezone, tz))
        {
            return false;
        }
        !(self.attempted_ip.as_deref() == Some(ip)
            && self
                .attempted_at
                .is_some_and(|at| at.elapsed() < Duration::from_secs(300)))
    }
    pub fn begin(&mut self, ip: &str) {
        self.attempted_ip = Some(ip.into());
        self.attempted_at = Some(Instant::now());
        self.error = None;
        self.application_blocked = false;
    }
    pub fn bind(&mut self, ip: String, target: String) {
        self.attempted_ip = Some(ip.clone());
        self.attempted_at = Some(Instant::now());
        self.ip = Some(ip);
        self.target = Some(target);
        self.error = None;
        self.application_blocked = false;
    }
    pub fn check(&self, checks: &[CheckResult]) -> CheckResult {
        let now = chrono::Utc::now();
        let ip = checks.iter().find(|c| {
            c.id == "egress-ipv4" && c.integrity == "tls_verified" && safety::fresh(c, now)
        });
        let timezone = checks.iter().find(|c| {
            c.id == "timezone" && c.integrity == "local_verified" && safety::fresh(c, now)
        });
        let bound = ip.is_some_and(|c| self.ip.as_deref() == Some(c.value.as_str()));
        let matched = bound
            && self.error.is_none()
            && timezone
                .zip(self.target.as_deref())
                .is_some_and(|(c, target)| platform::timezone_matches(&c.value, target));
        let mut check = CheckResult::local(
            "timezone-follow",
            "出口时区跟随",
            if matched { "match" } else { "unknown" },
            if matched {
                "已跟随出口时区"
            } else if self.error.is_some() {
                "时区跟随未完成"
            } else {
                "等待跟随出口时区"
            },
            self.error.clone().unwrap_or_else(|| {
                if bound {
                    format!(
                        "出口城市时区：{}",
                        self.target.as_deref().unwrap_or("未确认")
                    )
                } else {
                    "尚未取得当前出口 IP 对应的城市时区；保留当前系统时区。".into()
                }
            }),
        );
        check.source = "HTTPS 出口城市查询与本机时区对比".into();
        check.scope = "当前已观测出口 IP 的城市时区".into();
        check
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn checks(ip: &str, zone: &str) -> Vec<CheckResult> {
        let mut ip = CheckResult::local("egress-ipv4", "IP", "observed", ip, "");
        ip.integrity = "tls_verified".into();
        vec![
            ip,
            CheckResult::local("timezone", "TZ", "observed", zone, ""),
        ]
    }
    #[test]
    fn cached_timezone_only_passes_for_the_current_fresh_ip_and_matching_city() {
        let mut state = FollowState::default();
        state.bind("203.0.113.1".into(), "America/New_York".into());
        assert_eq!(
            state
                .check(&checks("203.0.113.1", "America/New_York"))
                .status,
            "match"
        );
        assert_ne!(
            state
                .check(&checks("203.0.113.2", "America/New_York"))
                .status,
            "match"
        );
        assert_ne!(
            state.check(&checks("203.0.113.1", "Asia/Shanghai")).status,
            "match"
        );
        let mut stale = checks("203.0.113.1", "America/New_York");
        stale[0].status = "stale".into();
        assert_ne!(state.check(&stale).status, "match");
    }
    #[test]
    fn stable_ip_is_cached_and_failures_do_not_repeat_authorization_prompts() {
        let mut state = FollowState::default();
        assert!(state.due("203.0.113.1", "Asia/Shanghai"));
        state.begin("203.0.113.1");
        assert!(!state.due("203.0.113.1", "Asia/Shanghai"));
        assert!(state.due("203.0.113.2", "Asia/Shanghai"));
        state.bind("203.0.113.1".into(), "America/New_York".into());
        assert!(!state.due("203.0.113.1", "America/New_York"));
        state.application_blocked = true;
        assert!(!state.due("203.0.113.2", "Asia/Shanghai"));
        state.begin("203.0.113.2");
        assert!(!state.application_blocked);
    }
}
