//! A latched isolation incident. Diagnostics never release native restrictions.
use crate::firewall::Receipt;
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProtectionStatus {
    pub armed: bool,
    pub dns_modified: bool,
    pub filter_may_exist: bool,
    pub ipv6_filtering: bool,
    pub isolation_pending: bool,
    pub receipt: Option<Receipt>,
    pub error: Option<String>,
}
impl ProtectionStatus {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("protection.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let mut value = serde_json::from_slice::<Self>(&bytes).unwrap_or_else(|_| Self {
                    armed: true,
                    dns_modified: false,
                    filter_may_exist: true,
                    ipv6_filtering: false,
                    isolation_pending: true,
                    error: Some("隔离记录损坏，请授权核验或解除隔离".into()),
                    receipt: None,
                });
                value.ipv6_filtering = false;
                // A saved receipt is history, never current enforcement evidence.
                if let Some(r) = &mut value.receipt {
                    r.enforcement_verified = false;
                }
                if value.isolation_pending {
                    value.error = Some(
                        "发现上次隔离记录；请授权核验或明确解除，程序不会自动恢复联网。".into(),
                    );
                }
                value
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => Self {
                armed: true,
                dns_modified: false,
                filter_may_exist: true,
                ipv6_filtering: false,
                isolation_pending: true,
                receipt: None,
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
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn restart_does_not_trust_saved_enforcement_or_discard_fault() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let status = ProtectionStatus {
            armed: true,
            dns_modified: false,
            filter_may_exist: true,
            ipv6_filtering: true,
            isolation_pending: true,
            receipt: Some(Receipt {
                backend: "fixture".into(),
                configuration_active: true,
                enforcement_verified: true,
                generation: None,
                checked_at: String::new(),
                detail: String::new(),
            }),
            error: None,
        };
        status.save(&dir).unwrap();
        let restored = ProtectionStatus::load(&dir);
        assert!(restored.armed && restored.isolation_pending);
        assert!(!restored.receipt.unwrap().enforcement_verified);
        std::fs::write(dir.join("protection.json"), "bad json").unwrap();
        assert!(ProtectionStatus::load(&dir).isolation_pending);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
