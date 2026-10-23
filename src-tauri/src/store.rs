use crate::models::StoredData;
use std::{fs, io::Write, path::Path};

pub fn load(dir: &Path) -> Result<StoredData, String> {
    let path = dir.join("state.json");
    if !path.exists() {
        return Ok(StoredData::default());
    }
    let meta = fs::metadata(&path).map_err(|_| "无法读取本机设置".to_string())?;
    if meta.len() > 2 * 1024 * 1024 {
        return Err("本机设置文件超出大小限制，请备份后检查".into());
    }
    let text = fs::read_to_string(path).map_err(|_| "无法读取本机设置".to_string())?;
    let mut data: StoredData = serde_json::from_str(&text)
        .map_err(|_| "本机设置格式损坏；原文件已保留，请检查 state.json".to_string())?;
    if data.schema_version != 1 {
        return Err("本机设置版本不受支持，请使用匹配版本".into());
    }
    prune(&mut data);
    Ok(data)
}
/// Older files stored the observations as off because that was the default.
/// Turn them on once. A later save keeps whatever the user chooses.
pub fn apply_observation_defaults(data: &mut StoredData) -> bool {
    if data.observation_defaults_applied {
        return false;
    }
    data.settings.external_ip_consent = true;
    data.settings.dns_http_consent = true;
    data.observation_defaults_applied = true;
    true
}
pub fn prune(data: &mut StoredData) {
    let cutoff =
        chrono::Utc::now() - chrono::Duration::days(data.settings.history_days.clamp(1, 90) as i64);
    data.events.retain(|event| {
        chrono::DateTime::parse_from_rfc3339(&event.at)
            .is_ok_and(|time| time.with_timezone(&chrono::Utc) >= cutoff)
    });
    if data.events.len() > 500 {
        data.events.truncate(500);
    }
}
pub fn save(dir: &Path, data: &mut StoredData) -> Result<(), String> {
    prune(data);
    fs::create_dir_all(dir).map_err(|_| "无法创建本机数据目录".to_string())?;
    let temp = dir.join(format!(".state-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temp)
            .map_err(|_| "无法写入本机设置".to_string())?;
        let bytes = serde_json::to_vec_pretty(data).map_err(|_| "设置序列化失败".to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "本机设置写入失败".to_string())?;
        fs::rename(&temp, dir.join("state.json")).map_err(|_| "无法保存本机设置".to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_install_turns_observations_on_once() {
        let mut data: StoredData = serde_json::from_str(
            r#"{"schemaVersion":1,"settings":{"externalIpConsent":false,"dnsHttpConsent":false},"customTools":[],"events":[]}"#,
        )
        .unwrap();
        assert!(apply_observation_defaults(&mut data));
        assert!(data.settings.external_ip_consent && data.settings.dns_http_consent);
        data.settings.dns_http_consent = false;
        assert!(!apply_observation_defaults(&mut data));
        assert!(!data.settings.dns_http_consent);
    }
}
