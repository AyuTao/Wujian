//! A latched isolation incident. Diagnostics never release native restrictions.
use crate::firewall::Receipt;
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path};

/// Captured only by an explicit start action; never updated by diagnostics.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Baseline {
    pub egress_ip: String,
    pub dns_fingerprint: String,
    pub timezone: String,
    pub proxy_url: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProtectionStatus {
    pub tunnel_policy: Option<crate::firewall::policy::Policy>,
    pub tunnel_guard_confirmed: bool,
    pub armed: bool,
    pub dns_modified: bool,
    pub filter_may_exist: bool,
    pub ipv6_filtering: bool,
    /// Independent IPv6 intent survives restart; never implies whole-machine protection.
    pub ipv6_only: bool,
    pub isolation_pending: bool,
    pub receipt: Option<Receipt>,
    pub error: Option<String>,
    pub baseline: Option<Baseline>,
    pub incident_reason: Option<String>,
}
impl ProtectionStatus {
    pub fn complete_dns_write<T>(&mut self, result: &Result<T, String>) {
        match result {
            Ok(_) => {
                self.dns_modified = false;
                self.error = None;
            }
            Err(error) => {
                self.dns_modified = true;
                self.error = Some(error.clone());
            }
        }
    }
    pub fn can_release_ipv6(&self) -> bool {
        self.ipv6_only && !self.armed && !self.isolation_pending && self.tunnel_policy.is_none()
    }
    pub fn complete_ipv6_release(&mut self, receipt: Receipt) -> Result<(), String> {
        if !self.can_release_ipv6() || receipt.configuration_active {
            return Err("IPv6 恢复未确认，保留原配置记录".into());
        }
        self.ipv6_only = false;
        self.ipv6_filtering = false;
        self.filter_may_exist = false;
        self.receipt = Some(receipt);
        self.error = None;
        Ok(())
    }
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("protection.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let mut value = serde_json::from_slice::<Self>(&bytes).unwrap_or_else(|_| Self {
                    tunnel_policy: None,
                    tunnel_guard_confirmed: false,
                    armed: true,
                    dns_modified: false,
                    filter_may_exist: true,
                    ipv6_filtering: false,
                    ipv6_only: false,
                    isolation_pending: true,
                    error: Some("隔离记录损坏，请停止保护后重新开启".into()),
                    receipt: None,
                    baseline: None,
                    incident_reason: None,
                });
                value.ipv6_only |= !value.armed
                    && !value.isolation_pending
                    && (value.ipv6_filtering
                        || value
                            .receipt
                            .as_ref()
                            .is_some_and(|r| r.policy_mode == "ipv6"));
                value.ipv6_filtering = false;
                value.tunnel_guard_confirmed = false;
                // A saved receipt is history, never current enforcement evidence.
                if let Some(r) = &mut value.receipt {
                    r.enforcement_verified = false;
                }
                if value.isolation_pending {
                    value.error = None;
                    value
                        .incident_reason
                        .get_or_insert_with(|| "网络仍处于切断。同一节点恢复后会自动继续。".into());
                }
                value
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => Self {
                tunnel_policy: None,
                tunnel_guard_confirmed: false,
                armed: true,
                dns_modified: false,
                filter_may_exist: true,
                ipv6_filtering: false,
                ipv6_only: false,
                isolation_pending: true,
                receipt: None,
                baseline: None,
                incident_reason: None,
                error: Some(format!("隔离状态读取失败：{e}")),
            },
        }
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let temp = dir.join(format!(".protection-{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&temp).map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec(self).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            std::fs::rename(&temp, dir.join("protection.json")).map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result
    }
    pub fn should_isolate(&self, tripped: bool) -> bool {
        self.armed && tripped && !self.isolation_pending
    }
    pub fn begin_isolation(&mut self, tripped: bool, reason: Option<String>, retry: bool) -> bool {
        if !(self.should_isolate(tripped) || retry && self.armed && self.isolation_pending) {
            return false;
        }
        if self.incident_reason.is_none() {
            self.incident_reason = reason;
        }
        self.isolation_pending = true;
        self.filter_may_exist = true;
        self.ipv6_filtering = false;
        self.receipt = None;
        self.error = Some("等待管理员授权；授权完成前隔离未确认。".into());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_acknowledged_dns_commit_clears_pending_recovery_across_restart() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut status = ProtectionStatus {
            dns_modified: true,
            ..Default::default()
        };
        status.complete_dns_write::<()>(&Err("fixture reply lost".into()));
        status.save(&dir).unwrap();
        let mut status = ProtectionStatus::load(&dir);
        assert!(status.dns_modified);
        assert_eq!(status.error.as_deref(), Some("fixture reply lost"));
        status.complete_dns_write(&Ok::<_, String>(()));
        status.save(&dir).unwrap();
        let status = ProtectionStatus::load(&dir);
        assert!(!status.dns_modified);
        assert!(status.error.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn independent_ipv6_release_preserves_dns_and_survives_restart() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut status = ProtectionStatus {
            ipv6_filtering: true,
            filter_may_exist: true,
            dns_modified: true,
            ..Default::default()
        };
        // Also migrate the previous version's IPv6-only record.
        status.save(&dir).unwrap();
        status = ProtectionStatus::load(&dir);
        assert!(status.ipv6_only && !status.ipv6_filtering && !status.armed);
        let receipt = Receipt {
            configuration_active: false,
            ..Receipt::new(false, None, "test")
        };
        status.armed = true;
        assert!(status.complete_ipv6_release(receipt.clone()).is_err());
        status.armed = false;
        status.isolation_pending = true;
        assert!(status.complete_ipv6_release(receipt.clone()).is_err());
        status.isolation_pending = false;
        assert!(status
            .complete_ipv6_release(Receipt {
                configuration_active: true,
                ..receipt.clone()
            })
            .is_err());
        assert!(status.filter_may_exist);
        status.complete_ipv6_release(receipt).unwrap();
        assert!(status.dns_modified);
        assert!(!status.armed && !status.filter_may_exist && !status.ipv6_only);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn incident_stays_latched_until_explicit_release() {
        let mut status = ProtectionStatus {
            armed: true,
            ..Default::default()
        };
        assert!(status.should_isolate(true));
        status.isolation_pending = true;
        assert!(!status.should_isolate(false));
        assert!(!status.should_isolate(true));
        assert!(status.isolation_pending);
    }
    #[test]
    fn a_healthy_recheck_never_releases_or_replaces_the_incident() {
        let mut status = ProtectionStatus::default();
        assert!(!status.begin_isolation(true, Some("未启用".into()), false));
        status.armed = true;
        assert!(!status.begin_isolation(false, None, false));
        assert!(status.begin_isolation(true, Some("出口已变化".into()), false));
        assert!(status.receipt.is_none() && status.error.is_some());
        assert!(!status.begin_isolation(false, None, false));
        assert!(!status.begin_isolation(true, Some("DNS 已变化".into()), false));
        assert!(status.begin_isolation(false, None, true));
        assert_eq!(status.incident_reason.as_deref(), Some("出口已变化"));
        assert!(status.isolation_pending);
    }
    #[test]
    fn restart_does_not_trust_saved_enforcement_or_discard_fault() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let status = ProtectionStatus {
            tunnel_policy: None,
            tunnel_guard_confirmed: false,
            armed: true,
            dns_modified: false,
            filter_may_exist: true,
            ipv6_filtering: true,
            ipv6_only: false,
            isolation_pending: true,
            receipt: Some(Receipt {
                diagnostic_logs: None,
                policy_mode: "unknown".into(),
                guard_policy: None,
                backend: "fixture".into(),
                configuration_active: true,
                enforcement_verified: true,
                generation: None,
                checked_at: String::new(),
                detail: String::new(),
                switched_node: None,
            }),
            error: None,
            baseline: Some(Baseline {
                egress_ip: "203.0.113.8".into(),
                dns_fingerprint: "locked-config".into(),
                timezone: "Asia/Tokyo".into(),
                proxy_url: "http://127.0.0.1:7890".into(),
            }),
            incident_reason: Some("DNS 配置变化".into()),
        };
        status.save(&dir).unwrap();
        let restored = ProtectionStatus::load(&dir);
        assert!(restored.armed && restored.isolation_pending);
        assert!(!restored.receipt.unwrap().enforcement_verified);
        assert!(!restored.ipv6_filtering);
        assert_eq!(restored.baseline.unwrap().dns_fingerprint, "locked-config");
        assert_eq!(restored.incident_reason.as_deref(), Some("DNS 配置变化"));
        std::fs::write(dir.join("protection.json"), "bad json").unwrap();
        assert!(ProtectionStatus::load(&dir).isolation_pending);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
