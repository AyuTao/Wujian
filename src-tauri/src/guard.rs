//! Strict policy gate, not an OS packet filter.
//! Only a verified native adapter may supply these inputs. UI settings and
//! diagnostic CheckResult values must never be converted into enforcement proof.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub tool_identity: String,
    pub path_id: String,
    pub service_session: String,
    pub network_epoch: u64,
    pub policy_revision: u64,
    pub rule_generation: u64,
}

pub(crate) struct Policy {
    pub binding: Binding,
    /// Explicit ISO country allowlist; an empty list must not allow anything.
    pub allowed_countries: Vec<String>,
    pub evidence_ttl_ms: u64,
    pub recovery_incident: Option<u64>,
}

#[derive(Default)]
pub(crate) struct Enforcement {
    pub supported: bool,
    pub all_entries_covered: bool,
    pub existing_flows_controlled: bool,
    pub dns_contained: bool,
    pub ipv4_ipv6_tcp_udp_controlled: bool,
    pub rules_verified: bool,
    pub helper_healthy: bool,
    pub binding: Option<Binding>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Constructed by the future native adapter; not exposed to IPC.
pub(crate) enum Integrity {
    /// Verified evidence tied to the enforced path and tool scope.
    EnforcedPath,
    /// HTTPS protects transport, but an arbitrary probe may use another egress.
    HttpsProbeOnly,
    HttpUnverified,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Constructed by the future native adapter; not exposed to IPC.
pub(crate) enum DnsVerdict {
    Contained,
    LeakObserved,
    Unknown,
}

pub(crate) struct Evidence {
    pub binding: Binding,
    /// Monotonic time since this service session started, never wall-clock time.
    pub observed_at_ms: u64,
    pub integrity: Integrity,
    pub country: Option<String>,
    pub dns: DnsVerdict,
}

pub(crate) struct RecoveryApproval {
    pub binding: Binding,
    pub incident: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Allow,
    Unsupported,
    CoverageIncomplete,
    RulesUnverified,
    BindingChanged,
    EvidenceMissing,
    EvidenceExpired,
    EvidenceUntrusted,
    CountryNotAllowed,
    DnsLeak,
    DnsUnknown,
    RecoveryRequired,
}

/// A denial means "do not open an allowed path". It does NOT attest that an OS
/// restriction exists. Only the adapter's independently verified receipt can do so.
pub(crate) fn evaluate(
    policy: &Policy,
    enforcement: &Enforcement,
    evidence: Option<&Evidence>,
    approval: Option<&RecoveryApproval>,
    now_ms: u64,
) -> Decision {
    if !enforcement.supported {
        return Decision::Unsupported;
    }
    if !enforcement.all_entries_covered
        || !enforcement.existing_flows_controlled
        || !enforcement.dns_contained
        || !enforcement.ipv4_ipv6_tcp_udp_controlled
    {
        return Decision::CoverageIncomplete;
    }
    if !enforcement.rules_verified || !enforcement.helper_healthy {
        return Decision::RulesUnverified;
    }
    if enforcement.binding.as_ref() != Some(&policy.binding) {
        return Decision::BindingChanged;
    }
    let Some(evidence) = evidence else {
        return Decision::EvidenceMissing;
    };
    if evidence.binding != policy.binding {
        return Decision::BindingChanged;
    }
    let Some(age) = now_ms.checked_sub(evidence.observed_at_ms) else {
        return Decision::EvidenceExpired;
    };
    if policy.evidence_ttl_ms == 0 || age >= policy.evidence_ttl_ms {
        return Decision::EvidenceExpired;
    }
    if evidence.integrity != Integrity::EnforcedPath {
        return Decision::EvidenceUntrusted;
    }
    match evidence.dns {
        DnsVerdict::LeakObserved => return Decision::DnsLeak,
        DnsVerdict::Unknown => return Decision::DnsUnknown,
        DnsVerdict::Contained => {}
    }
    // CN is prohibited by this product requirement, even if a malformed policy
    // includes it. Other countries require an explicit, uppercase ISO allowlist.
    let allowed_country = evidence.country.as_ref().is_some_and(|country| {
        country.len() == 2
            && country.bytes().all(|c| c.is_ascii_uppercase())
            && country != "CN"
            && policy.allowed_countries.contains(country)
    });
    if !allowed_country {
        return Decision::CountryNotAllowed;
    }
    if let Some(incident) = policy.recovery_incident {
        if !approval.is_some_and(|a| a.binding == policy.binding && a.incident == incident) {
            return Decision::RecoveryRequired;
        }
    }
    Decision::Allow
}

/// No native enforcement adapter is installed or implemented in this preview.
/// Kept in the actual command path, so invoking IPC directly cannot bypass UI.
pub(crate) fn require_current_protection(tool_id: &str) -> Result<(), String> {
    let policy = Policy {
        binding: Binding {
            tool_identity: tool_id.into(),
            path_id: String::new(),
            service_session: String::new(),
            network_epoch: 0,
            policy_revision: 0,
            rule_generation: 0,
        },
        allowed_countries: vec![],
        evidence_ttl_ms: 0,
        recovery_incident: None,
    };
    match evaluate(&policy, &Enforcement::default(), None, None, 0) {
        Decision::Allow => Ok(()),
        _ => Err("系统级保护尚未实现，无法确认出口与 DNS 已受限制；本版本不提供无保护启动。此门禁不影响从其他入口启动的程序，也不代表系统已阻断。".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Policy, Enforcement, Evidence) {
        let binding = Binding {
            tool_identity: "signed-tool-v1".into(),
            path_id: "verified-path".into(),
            service_session: "boot-session".into(),
            network_epoch: 3,
            policy_revision: 2,
            rule_generation: 7,
        };
        (
            Policy {
                binding: binding.clone(),
                allowed_countries: vec!["US".into()],
                evidence_ttl_ms: 1_000,
                recovery_incident: None,
            },
            Enforcement {
                supported: true,
                all_entries_covered: true,
                existing_flows_controlled: true,
                dns_contained: true,
                ipv4_ipv6_tcp_udp_controlled: true,
                rules_verified: true,
                helper_healthy: true,
                binding: Some(binding.clone()),
            },
            Evidence {
                binding,
                observed_at_ms: 5_000,
                integrity: Integrity::EnforcedPath,
                country: Some("US".into()),
                dns: DnsVerdict::Contained,
            },
        )
    }

    #[test]
    fn preview_cannot_launch_even_via_native_command_gate() {
        assert!(require_current_protection("claude-code").is_err());
    }

    #[test]
    fn only_complete_current_path_bound_proof_can_allow() {
        let (p, en, ev) = fixture();
        assert_eq!(evaluate(&p, &en, Some(&ev), None, 5_001), Decision::Allow);
        assert_eq!(
            evaluate(&p, &en, None, None, 5_001),
            Decision::EvidenceMissing
        );
        assert_eq!(
            evaluate(&p, &Enforcement::default(), Some(&ev), None, 5_001),
            Decision::Unsupported
        );
    }

    #[test]
    fn incomplete_native_coverage_never_allows() {
        for missing in 0..5 {
            let (p, mut en, ev) = fixture();
            match missing {
                0 => en.all_entries_covered = false,
                1 => en.existing_flows_controlled = false,
                2 => en.dns_contained = false,
                3 => en.ipv4_ipv6_tcp_udp_controlled = false,
                _ => en.supported = false,
            }
            assert_ne!(evaluate(&p, &en, Some(&ev), None, 5_001), Decision::Allow);
        }
    }

    #[test]
    fn helper_or_rule_failure_never_allows() {
        let (p, mut en, ev) = fixture();
        en.helper_healthy = false;
        assert_eq!(
            evaluate(&p, &en, Some(&ev), None, 5_001),
            Decision::RulesUnverified
        );
        en.helper_healthy = true;
        en.rules_verified = false;
        assert_eq!(
            evaluate(&p, &en, Some(&ev), None, 5_001),
            Decision::RulesUnverified
        );
    }

    #[test]
    fn country_unknown_prohibited_or_not_selected_denies() {
        let (mut p, en, mut ev) = fixture();
        p.allowed_countries.push("CN".into());
        for country in [
            None,
            Some("CN"),
            Some("DE"),
            Some("us"),
            Some("USA"),
            Some(""),
        ] {
            ev.country = country.map(String::from);
            assert_eq!(
                evaluate(&p, &en, Some(&ev), None, 5_001),
                Decision::CountryNotAllowed
            );
        }
        ev.country = Some("US".into());
        p.allowed_countries.clear();
        assert_eq!(
            evaluate(&p, &en, Some(&ev), None, 5_001),
            Decision::CountryNotAllowed
        );
    }

    #[test]
    fn dns_leak_or_unknown_denies_even_with_allowed_egress() {
        let (p, en, mut ev) = fixture();
        ev.dns = DnsVerdict::LeakObserved;
        assert_eq!(evaluate(&p, &en, Some(&ev), None, 5_001), Decision::DnsLeak);
        ev.dns = DnsVerdict::Unknown;
        assert_eq!(
            evaluate(&p, &en, Some(&ev), None, 5_001),
            Decision::DnsUnknown
        );
    }

    #[test]
    fn generic_https_and_http_observations_cannot_allow() {
        let (p, en, mut ev) = fixture();
        for integrity in [Integrity::HttpsProbeOnly, Integrity::HttpUnverified] {
            ev.integrity = integrity;
            assert_eq!(
                evaluate(&p, &en, Some(&ev), None, 5_001),
                Decision::EvidenceUntrusted
            );
        }
    }

    #[test]
    fn expired_future_or_zero_ttl_denies() {
        let (mut p, en, ev) = fixture();
        for now in [4_999, 6_000, u64::MAX] {
            assert_eq!(
                evaluate(&p, &en, Some(&ev), None, now),
                Decision::EvidenceExpired
            );
        }
        p.evidence_ttl_ms = 0;
        assert_eq!(
            evaluate(&p, &en, Some(&ev), None, 5_000),
            Decision::EvidenceExpired
        );
    }

    #[test]
    fn old_identity_path_session_epoch_policy_or_rules_deny() {
        for changed in 0..6 {
            let (p, mut en, mut ev) = fixture();
            match changed {
                0 => ev.binding.tool_identity.push('2'),
                1 => ev.binding.path_id.push('2'),
                2 => ev.binding.service_session.push('2'),
                3 => ev.binding.network_epoch += 1,
                4 => ev.binding.policy_revision += 1,
                _ => ev.binding.rule_generation += 1,
            }
            assert_eq!(
                evaluate(&p, &en, Some(&ev), None, 5_001),
                Decision::BindingChanged
            );
            ev.binding = p.binding.clone();
            en.binding.as_mut().unwrap().rule_generation += 1;
            assert_eq!(
                evaluate(&p, &en, Some(&ev), None, 5_001),
                Decision::BindingChanged
            );
        }
    }

    #[test]
    fn recovery_confirmation_must_match_current_incident_and_binding() {
        let (mut p, en, mut ev) = fixture();
        p.recovery_incident = Some(8);
        assert_eq!(
            evaluate(&p, &en, Some(&ev), None, 5_001),
            Decision::RecoveryRequired
        );
        let mut approval = RecoveryApproval {
            binding: p.binding.clone(),
            incident: 7,
        };
        assert_eq!(
            evaluate(&p, &en, Some(&ev), Some(&approval), 5_001),
            Decision::RecoveryRequired
        );
        approval.incident = 8;
        approval.binding.network_epoch += 1;
        assert_eq!(
            evaluate(&p, &en, Some(&ev), Some(&approval), 5_001),
            Decision::RecoveryRequired
        );
        approval.binding = p.binding.clone();
        assert_eq!(
            evaluate(&p, &en, Some(&ev), Some(&approval), 5_001),
            Decision::Allow
        );
        ev.country = Some("CN".into());
        assert_eq!(
            evaluate(&p, &en, Some(&ev), Some(&approval), 5_001),
            Decision::CountryNotAllowed
        );
    }
}
