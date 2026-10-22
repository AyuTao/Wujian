//! Offline country lookup. GeoIP labels are classification data, not egress proof.
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Country {
    pub code: String,
    pub name: String,
    pub domestic: bool,
}

pub struct CountryDb {
    reader: Reader<Vec<u8>>,
}
impl CountryDb {
    pub fn open(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path).map_err(|_| "无法读取 GeoIP 数据库")?;
        if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
            return Err("GeoIP 数据库不是有效文件或超出 64 MiB".into());
        }
        let reader = Reader::open_readfile(path).map_err(|_| "GeoIP 数据库格式无效")?;
        Ok(Self { reader })
    }
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<Country>, String> {
        let result = self.reader.lookup(ip).map_err(|_| "无法查询 GeoIP 地址")?;
        let value: Option<Value> = result.decode().map_err(|_| "GeoIP 记录无法解码")?;
        Ok(value.as_ref().and_then(country_from_record))
    }
    pub fn china_networks(&self) -> Result<Vec<String>, String> {
        let mut result = Vec::new();
        let networks = self
            .reader
            .networks(Default::default())
            .map_err(|_| "无法遍历 GeoIP 数据库")?;
        for (index, entry) in networks.enumerate() {
            if index > 2_000_000 {
                return Err("GeoIP 数据库网络数量超出限制".into());
            }
            let record = entry.map_err(|_| "GeoIP 网络记录损坏")?;
            let value: Option<Value> = record.decode().map_err(|_| "GeoIP 网络数据无效")?;
            if value
                .as_ref()
                .and_then(country_from_record)
                .is_some_and(|v| v.domestic)
            {
                let cidr = record.network().map_err(|_| "GeoIP CIDR 无效")?;
                let text = cidr.to_string();
                let prefix: u8 = text
                    .rsplit_once('/')
                    .ok_or("GeoIP CIDR 缺少前缀")?
                    .1
                    .parse()
                    .map_err(|_| "GeoIP 前缀无效")?;
                if (!text.contains(':') && prefix < 8) || (text.contains(':') && prefix < 16) {
                    return Err("GeoIP 国内网段过宽，拒绝导出".into());
                }
                result.push(text);
            }
        }
        result.sort();
        result.dedup();
        if result.is_empty() {
            return Err("数据库没有 CN 网络，不生成放行表".into());
        }
        Ok(result)
    }
}

fn country_from_record(value: &Value) -> Option<Country> {
    // Never substitute registered_country: owner registration != IP location.
    let code = value["country"]["iso_code"]
        .as_str()
        .or_else(|| value["country_code"].as_str())
        .or_else(|| value.as_str())?;
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let translated = match code {
        "CN" => "中国大陆",
        "US" => "美国",
        "HK" => "香港",
        "MO" => "澳门",
        "TW" => "台湾",
        "JP" => "日本",
        "SG" => "新加坡",
        "KR" => "韩国",
        "GB" => "英国",
        "DE" => "德国",
        "CA" => "加拿大",
        "AU" => "澳大利亚",
        _ => code,
    };
    let name = value["country"]["names"]["zh-CN"]
        .as_str()
        .unwrap_or(translated)
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    Some(Country {
        code: code.into(),
        name,
        domestic: code == "CN",
    })
}

pub fn default_database() -> Option<PathBuf> {
    let home =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)?;
    [
        home.join(
            "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/Country.mmdb",
        ),
        home.join(".local/share/io.github.clash-verge-rev.clash-verge-rev/Country.mmdb"),
        home.join(".config/mihomo/Country.mmdb"),
        home.join(".config/clash/Country.mmdb"),
        home.join("AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev/Country.mmdb"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_invalid_or_registration_only_record_is_unknown() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"registered_country":{"iso_code":"US"}}),
            serde_json::json!({"country":{"iso_code":""}}),
            serde_json::json!({"country":{"iso_code":"cn"}}),
        ] {
            assert!(country_from_record(&value).is_none());
        }
    }
    #[test]
    fn geographical_country_is_distinct_from_registration_and_unknown() {
        let country = country_from_record(&serde_json::json!({"country":{"iso_code":"CN"},"registered_country":{"iso_code":"US"}})).unwrap();
        assert!(country.domestic);
        assert!(
            !country_from_record(&serde_json::json!({"country":{"iso_code":"US"}}))
                .unwrap()
                .domestic
        );
        assert_eq!(
            country_from_record(&serde_json::json!("JP")).unwrap().name,
            "日本"
        );
    }
}
