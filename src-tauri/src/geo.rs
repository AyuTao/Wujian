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
    pub fn place(&self, ip: IpAddr) -> Result<GeoPlace, String> {
        let result = self.reader.lookup(ip).map_err(|_| "无法查询 GeoIP 地址")?;
        let value: Option<Value> = result.decode().map_err(|_| "GeoIP 记录无法解码")?;
        Ok(value
            .as_ref()
            .map(place_from_record)
            .unwrap_or(GeoPlace::Unknown))
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

pub fn database_in_home(home: &Path) -> Option<PathBuf> {
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

pub fn default_database() -> Option<PathBuf> {
    let home =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)?;
    database_in_home(&home)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoPlace {
    Country(Country),
    /// Clash/Meta tags such as CLOUDFLARE are organizations, not countries.
    Label(String),
    Unknown,
}

pub fn place_from_record(value: &Value) -> GeoPlace {
    if let Some(country) = country_from_record(value) {
        return GeoPlace::Country(country);
    }
    let code = value["country"]["iso_code"]
        .as_str()
        .or_else(|| value["country_code"].as_str())
        .or_else(|| value.as_str())
        .unwrap_or("");
    if (3..=32).contains(&code.len()) && code.bytes().all(|byte| byte.is_ascii_uppercase()) {
        GeoPlace::Label(code.to_string())
    } else {
        GeoPlace::Unknown
    }
}

/// Mainland China, a missing record, and mixed countries refuse.
/// A provider tag such as CLOUDFLARE is shown, and does not by itself refuse.
pub fn require_places(found: &[GeoPlace]) -> Result<String, String> {
    if found.is_empty() {
        return Err("节点没有可确认国家的地址".into());
    }
    let mut country: Option<&Country> = None;
    let mut tags = Vec::new();
    for item in found {
        match item {
            GeoPlace::Country(item) if item.domestic => {
                return Err("节点地址位于中国大陆，不能当作国外出口".into());
            }
            GeoPlace::Country(item) => {
                if let Some(previous) = country {
                    if previous.code != item.code {
                        return Err("节点地址属于不同国家，不能确认唯一国外出口".into());
                    }
                }
                country = Some(item);
            }
            GeoPlace::Label(label) => {
                if !tags.iter().any(|tag| tag == label) {
                    tags.push(label.as_str());
                }
            }
            GeoPlace::Unknown => {
                return Err("节点地址的国家未知，不能确认出口在国外".into());
            }
        }
    }
    if let Some(country) = country {
        let mut label = format!("{} ({})", country.name, country.code);
        if !tags.is_empty() {
            label.push_str("，另有 ");
            label.push_str(&tags.join("、"));
        }
        return Ok(label);
    }
    if tags.len() == 1 {
        return Ok(format!("{}，未标明国家", tags[0]));
    }
    if tags.is_empty() {
        return Err("节点没有可确认国家的地址".into());
    }
    Err("节点地址被标成不同机构，不能确认出口".into())
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
    #[test]
    fn overseas_node_must_be_known_nondomestic_and_uniform() {
        let us = country_from_record(&serde_json::json!({"country":{"iso_code":"US"}})).unwrap();
        let jp = country_from_record(&serde_json::json!({"country":{"iso_code":"JP"}})).unwrap();
        let cn = country_from_record(&serde_json::json!({"country":{"iso_code":"CN"}})).unwrap();
        assert_eq!(
            require_places(&[GeoPlace::Country(us.clone())]).unwrap(),
            "美国 (US)"
        );
        assert!(require_places(&[GeoPlace::Country(cn)]).is_err());
        assert!(require_places(&[GeoPlace::Unknown]).is_err());
        assert!(require_places(&[GeoPlace::Country(us), GeoPlace::Country(jp)]).is_err());
        assert!(require_places(&[]).is_err());
        let tagged = place_from_record(&serde_json::json!({"country":{"iso_code":"CLOUDFLARE"}}));
        assert_eq!(tagged, GeoPlace::Label("CLOUDFLARE".into()));
        assert_eq!(require_places(&[tagged]).unwrap(), "CLOUDFLARE，未标明国家");
    }
}
