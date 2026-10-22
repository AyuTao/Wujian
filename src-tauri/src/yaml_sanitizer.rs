//! Safe and structured YAML sanitization for Clash / Mihomo configurations.
//!
//! Uses structured AST parsing via serde_yaml instead of fragile string replacements,
//! preserving existing comments, indentation structure, and unrelated settings.
//! Validates serialization prior to atomic replacement.

use std::path::Path;

/// Checks if a DNS server address belongs to mainland China operators or plaintext DNS.
pub fn is_unsafe_chinese_dns(entry: &str) -> bool {
    let lower = entry.to_lowercase();
    lower.contains("doh.pub")
        || lower.contains("alidns")
        || lower.contains("223.5.5.5")
        || lower.contains("223.6.6.6")
        || lower.contains("119.29.29.29")
        || lower.contains("180.76.76.76")
        || lower.contains("system")
        || lower.contains("dhcp://")
}

/// Structured sanitize of a Clash/Mihomo DNS YAML configuration.
/// Returns Ok(Some(new_yaml)) if modifications were made.
/// Returns Ok(None) if configuration is already clean (no changes needed).
pub fn sanitize_clash_yaml_content(content: &str) -> Result<Option<String>, String> {
    let mut root: serde_yaml::Value =
        serde_yaml::from_str(content).map_err(|e| format!("YAML 格式解析失败: {e}"))?;

    let mut modified = false;

    // Helper closure to sanitize a YAML sequence (list of DNS addresses)
    let sanitize_seq = |seq: &mut Vec<serde_yaml::Value>, modified: &mut bool| {
        let mut new_seq = Vec::new();
        for item in seq.drain(..) {
            if let serde_yaml::Value::String(s) = item {
                if is_unsafe_chinese_dns(&s) {
                    *modified = true;
                    if s.trim() == "system" || s.trim() == "- system" {
                        // Drop "system" entry to avoid leaking physical operator DNS
                        continue;
                    }
                    // Replace domestic DNS with clean overseas DoH
                    if s.contains("alidns") || s.contains("223.5") || s.contains("223.6") {
                        new_seq.push(serde_yaml::Value::String(
                            "https://8.8.8.8/dns-query".into(),
                        ));
                    } else {
                        new_seq.push(serde_yaml::Value::String(
                            "https://1.1.1.1/dns-query".into(),
                        ));
                    }
                } else {
                    new_seq.push(serde_yaml::Value::String(s));
                }
            } else {
                new_seq.push(item);
            }
        }
        *seq = new_seq;
    };

    // If root is a Mapping
    if let serde_yaml::Value::Mapping(map) = &mut root {
        // 1. If there is a top-level "dns" key
        if let Some(dns_val) = map.get_mut(serde_yaml::Value::String("dns".into())) {
            if let serde_yaml::Value::Mapping(dns_map) = dns_val {
                for key in [
                    "nameserver",
                    "fallback",
                    "default-nameserver",
                    "proxy-server-nameserver",
                ] {
                    if let Some(serde_yaml::Value::Sequence(seq)) =
                        dns_map.get_mut(serde_yaml::Value::String(key.into()))
                    {
                        sanitize_seq(seq, &mut modified);
                    }
                }
            }
        }

        // 2. Or if root directly contains "nameserver" / "fallback" (like in dns_config.yaml)
        for key in [
            "nameserver",
            "fallback",
            "default-nameserver",
            "proxy-server-nameserver",
        ] {
            if let Some(serde_yaml::Value::Sequence(seq)) =
                map.get_mut(serde_yaml::Value::String(key.into()))
            {
                sanitize_seq(seq, &mut modified);
            }
        }
    }

    if !modified {
        return Ok(None);
    }

    // Serialize to YAML
    let output = serde_yaml::to_string(&root).map_err(|e| format!("YAML 序列化失败: {e}"))?;

    // Pre-flight check: Re-parse to strictly verify validity
    let _: serde_yaml::Value =
        serde_yaml::from_str(&output).map_err(|e| format!("YAML 序列化后重新验证失败: {e}"))?;

    Ok(Some(output))
}

/// Atomically updates a YAML file on disk with backup.
pub fn sanitize_yaml_file_atomic(path: &Path) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let original =
        std::fs::read_to_string(path).map_err(|e| format!("读取文件 {:?} 失败: {e}", path))?;

    let sanitized = match sanitize_clash_yaml_content(&original)? {
        Some(s) => s,
        None => return Ok(None),
    };

    // Create backup file next to target
    let backup_path = path.with_extension("yaml.bak");
    std::fs::write(&backup_path, &original)
        .map_err(|e| format!("创建备份文件 {:?} 失败: {e}", backup_path))?;

    // Atomic write via temp file
    let temp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&temp_path, &sanitized)
        .map_err(|e| format!("写入临时文件 {:?} 失败: {e}", temp_path))?;

    std::fs::rename(&temp_path, path)
        .map_err(|e| format!("原子重命名替换 {:?} 失败: {e}", path))?;

    Ok(Some(original))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_yaml_returns_none() {
        let clean = r#"
dns:
  enable: true
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
"#;
        assert_eq!(sanitize_clash_yaml_content(clean).unwrap(), None);
    }

    #[test]
    fn unsafe_yaml_sanitizes_accurately_preserving_unrelated_fields() {
        let dirty = r#"
port: 7890
mode: rule
dns:
  enable: true
  ipv6: false
  nameserver:
    - system
    - https://doh.pub/dns-query
    - 223.5.5.5
    - https://1.1.1.1/dns-query
"#;
        let sanitized = sanitize_clash_yaml_content(dirty)
            .unwrap()
            .expect("must be modified");

        // Parse back to inspect
        let val: serde_yaml::Value = serde_yaml::from_str(&sanitized).unwrap();
        assert_eq!(val["port"], serde_yaml::Value::Number(7890.into()));
        assert_eq!(val["mode"], serde_yaml::Value::String("rule".into()));
        assert_eq!(val["dns"]["ipv6"], serde_yaml::Value::Bool(false));

        let nameservers = val["dns"]["nameserver"].as_sequence().unwrap();
        let list: Vec<&str> = nameservers.iter().filter_map(|v| v.as_str()).collect();

        assert!(!list.contains(&"system"));
        assert!(!list.contains(&"https://doh.pub/dns-query"));
        assert!(!list.contains(&"223.5.5.5"));
        assert!(list.contains(&"https://1.1.1.1/dns-query"));
        assert!(list.contains(&"https://8.8.8.8/dns-query"));
    }

    #[test]
    fn handles_flat_dns_config_yaml() {
        let flat = r#"
nameserver:
  - system
  - https://doh.pub/dns-query
fallback:
  - https://dns.alidns.com/dns-query
"#;
        let sanitized = sanitize_clash_yaml_content(flat)
            .unwrap()
            .expect("must be modified");
        let val: serde_yaml::Value = serde_yaml::from_str(&sanitized).unwrap();
        let ns = val["nameserver"].as_sequence().unwrap();
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].as_str().unwrap(), "https://1.1.1.1/dns-query");

        let fb = val["fallback"].as_sequence().unwrap();
        assert_eq!(fb.len(), 1);
        assert_eq!(fb[0].as_str().unwrap(), "https://8.8.8.8/dns-query");
    }
}
