//! Current-user country/format settings. Never changes display-language preferences.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const JOURNAL: &str = "region-follow.json";
#[cfg(any(target_os = "linux", test))]
const FORMAT_KEYS: &[&str] = &[
    "LC_TIME",
    "LC_NUMERIC",
    "LC_MONETARY",
    "LC_MEASUREMENT",
    "LC_PAPER",
    "LC_ADDRESS",
    "LC_NAME",
    "LC_TELEPHONE",
];
const COUNTRIES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";
pub(crate) fn valid_country(country: &str) -> bool {
    COUNTRIES.split_whitespace().any(|c| c == country)
}
pub(crate) fn needs_adjustment(country: &str) -> bool {
    matches!(country, "CN" | "HK" | "MO")
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    backend: String,
    country: Option<String>,
    values: BTreeMap<String, Option<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct Journal {
    enabled: bool,
    original: Option<Snapshot>,
    intended: Option<Snapshot>,
}
impl Default for Journal {
    fn default() -> Self {
        Self {
            enabled: true,
            original: None,
            intended: None,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionInfo {
    pub current: Option<String>,
    pub original: Option<String>,
    pub can_restore: bool,
    pub following_enabled: bool,
    pub follows_egress: bool,
    pub restart_required: bool,
    pub backend: String,
    pub detail: String,
}
#[derive(Default)]
pub(crate) struct FollowState {
    pub info: Option<RegionInfo>,
    pub error: Option<String>,
    attempted: Option<(String, Option<String>, Instant)>,
}
impl FollowState {
    pub fn due(&self, ip: &str, country: Option<&str>) -> bool {
        !self
            .attempted
            .as_ref()
            .is_some_and(|(old_ip, old_country, at)| {
                old_ip == ip
                    && old_country.as_deref() == country
                    && at.elapsed()
                        < Duration::from_secs(if self.error.is_some() || country.is_none() {
                            300
                        } else {
                            30
                        })
            })
    }
    pub fn begin(&mut self, ip: &str, country: Option<&str>) {
        self.attempted = Some((ip.into(), country.map(str::to_string), Instant::now()));
    }
    pub fn check(&self) -> crate::models::CheckResult {
        let info = self.info.as_ref();
        crate::models::CheckResult::local(
            "system-region",
            "系统国家/地区",
            if self.error.is_some() || info.is_some_and(|i| i.detail.contains("建议")) {
                "review"
            } else if info.is_some_and(|i| i.follows_egress) {
                "match"
            } else if info.is_some_and(|i| i.current.is_some()) {
                "observed"
            } else {
                "unknown"
            },
            info.and_then(|i| i.current.as_deref())
                .unwrap_or("地区未知"),
            self.error.clone().unwrap_or_else(|| {
                info.map(|i| i.detail.clone())
                    .unwrap_or_else(|| "正在读取当前用户的系统地区；不修改界面语言。".into())
            }),
        )
    }
}
fn validate_locale(locale: &str) -> bool {
    !locale.is_empty()
        && locale.len() <= 160
        && locale
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-@.=;".contains(&b))
}
fn country_from_locale(locale: &str) -> Option<String> {
    if let Some((_, keywords)) = locale.split_once('@') {
        if let Some(region) = keywords
            .split(';')
            .find_map(|part| part.strip_prefix("rg="))
        {
            if region.len() == 6 && region.ends_with("zzzz") {
                let country = region[..2].to_ascii_uppercase();
                if valid_country(&country) {
                    return Some(country);
                }
            }
        }
    }
    locale
        .split(['.', '@'])
        .next()?
        .split(['_', '-'])
        .skip(1)
        .find(|part| valid_country(part))
        .map(str::to_string)
}
#[cfg(any(target_os = "macos", test))]
fn replace_country(locale: &str, country: &str) -> Result<String, String> {
    if !valid_country(country) || !validate_locale(locale) {
        return Err("系统地区或区域格式无效".into());
    }
    let (base, suffix) = locale
        .find(['.', '@'])
        .map(|i| (&locale[..i], &locale[i..]))
        .unwrap_or((locale, ""));
    let suffix = if let Some(keywords) = suffix.strip_prefix('@') {
        format!(
            "@{}",
            keywords
                .split(';')
                .map(|part| if part.starts_with("rg=") {
                    format!("rg={}zzzz", country.to_ascii_lowercase())
                } else {
                    part.to_string()
                })
                .collect::<Vec<_>>()
                .join(";")
        )
    } else {
        suffix.to_string()
    };
    let mut offset = 0;
    for (index, part) in base.split(['_', '-']).enumerate() {
        if index > 0 && valid_country(part) {
            return Ok(format!(
                "{}{}{}{suffix}",
                &base[..offset],
                country,
                &base[offset + part.len()..]
            ));
        }
        offset += part.len() + 1;
    }
    Ok(format!("{base}_{country}{suffix}"))
}

fn command(program: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let mut child = cmd.spawn().map_err(|_| "系统地区设置工具不可用")?;
    let pipe = child.stdout.take().ok_or("无法读取系统地区")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut bytes = vec![];
        let result = pipe
            .take(512 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let bytes = receiver
                    .recv_timeout(Duration::from_secs(15).saturating_sub(started.elapsed()))
                    .map_err(|_| "系统地区读取超时，操作结果未确认")?
                    .map_err(|_| "系统地区读取失败")?;
                if !status.success() || bytes.len() > 512 * 1024 {
                    return Err("系统地区设置工具未成功执行".into());
                }
                return String::from_utf8(bytes)
                    .map(|s| s.trim().to_string())
                    .map_err(|_| "系统地区返回格式无效".into());
            }
            Ok(None) if started.elapsed() < Duration::from_secs(15) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("系统地区操作结果未确认，请核对系统设置".into());
            }
        }
    }
}
fn read_journal(dir: &Path) -> Result<Journal, String> {
    let p = dir.join(JOURNAL);
    if !p.exists() {
        return Ok(Journal::default());
    }
    if fs::metadata(&p).map_err(|_| "无法读取地区恢复记录")?.len() > 64 * 1024 {
        return Err("地区恢复记录大小无效".into());
    }
    serde_json::from_slice(&fs::read(p).map_err(|_| "无法读取地区恢复记录")?)
        .map_err(|_| "地区恢复记录格式无效".into())
}
fn save_journal(dir: &Path, journal: &Journal) -> Result<(), String> {
    crate::firewall::write_private(
        &dir.join(JOURNAL),
        &serde_json::to_vec_pretty(journal).map_err(|_| "地区恢复记录格式无效")?,
    )
}
fn info(
    snapshot: &Snapshot,
    journal: &Journal,
    target: Option<&str>,
    detail: String,
) -> RegionInfo {
    RegionInfo {
        current: snapshot.country.clone(),
        original: journal.original.as_ref().and_then(|s| s.country.clone()),
        can_restore: journal.original.is_some(),
        following_enabled: journal.enabled,
        follows_egress: target.is_some() && snapshot.country.as_deref() == target,
        restart_required: journal.intended.is_some(),
        backend: snapshot.backend.clone(),
        detail,
    }
}
fn recommendation(current: Option<&str>, target: Option<&str>) -> String {
    if current.is_some_and(needs_adjustment) && target.is_none() {
        return "出口地区未知；系统地区仍是中国大陆、香港或澳门，建议在系统设置中手动修改。未自动选择其他国家。".into();
    }
    if target.is_none() {
        return "出口地区未知，保留当前系统地区和界面语言。".into();
    }
    if current != target {
        return "当前地区不在自动调整范围，保留原设置；可点击立即跟随地区。界面语言不变。".into();
    }
    "系统地区与已确认的出口一致；界面语言保持原样。部分应用需重启或重新登录才使用新格式。".into()
}
fn may_follow(current: &Snapshot, journal: &Journal, target: Option<&str>, explicit: bool) -> bool {
    journal.enabled
        && target.is_some_and(valid_country)
        && (explicit
            || journal
                .intended
                .as_ref()
                .map(|last| current == last)
                .unwrap_or_else(|| current.country.as_deref().is_some_and(needs_adjustment)))
}
/// Persist before mutation. Recovery accepts a partially applied transaction,
/// but never overwrites fields changed independently by the user.
fn recovery_snapshot(
    current: &Snapshot,
    original: &Snapshot,
    intended: &Snapshot,
) -> Result<Snapshot, String> {
    if current.backend != original.backend || current.backend != intended.backend {
        return Err("地区设置方式已变化，请在系统设置中核对原值".into());
    }
    for (key, before) in &original.values {
        if current.values.get(key) != Some(before)
            && current.values.get(key) != intended.values.get(key)
        {
            return Err("系统地区已被其他操作修改，已保留恢复记录，请手动核对".into());
        }
    }
    Ok(original.clone())
}
fn follow_sync(dir: &Path, target: Option<&str>, explicit: bool) -> Result<RegionInfo, String> {
    follow_sync_with(
        dir,
        target,
        explicit,
        backend::read_snapshot,
        backend::plan_snapshot,
        backend::write_snapshot,
    )
}
fn follow_sync_with(
    dir: &Path,
    target: Option<&str>,
    explicit: bool,
    mut read: impl FnMut() -> Result<Snapshot, String>,
    plan: impl FnOnce(&Snapshot, &str) -> Result<Snapshot, String>,
    mut write: impl FnMut(&Snapshot) -> Result<(), String>,
) -> Result<RegionInfo, String> {
    let mut journal = read_journal(dir)?;
    let current = crate::audit::record("region.read", || read())?;
    if explicit {
        journal.enabled = true;
        save_journal(dir, &journal)?;
    }
    if !may_follow(&current, &journal, target, explicit) {
        crate::audit::transition_kind(
            "region.decision",
            if current.country.as_deref().is_some_and(needs_adjustment) && target.is_none() {
                "manual_recommended"
            } else {
                "retained"
            },
            if target.is_none() {
                Some("egress_region_unknown")
            } else {
                None
            },
        );
        return Ok(info(
            &current,
            &journal,
            target,
            if !journal.enabled {
                "地区自动跟随已暂停。".into()
            } else {
                recommendation(current.country.as_deref(), target)
            },
        ));
    }
    let target = target.ok_or("出口地区未知，未修改系统地区")?;
    if current.country.as_deref() == Some(target)
        && (!explicit
            || journal
                .intended
                .as_ref()
                .is_none_or(|last| last == &current))
    {
        return Ok(info(
            &current,
            &journal,
            Some(target),
            recommendation(Some(target), Some(target)),
        ));
    }
    let planned = plan(&current, target)?;
    if journal.original.is_none() {
        journal.original = Some(current.clone());
    }
    journal.intended = Some(planned.clone());
    save_journal(dir, &journal)?;
    crate::audit::record("region.apply", || write(&planned))?;
    let verified = crate::audit::record("region.verify", || {
        let verified = read()?;
        if verified != planned {
            return Err("系统地区回读核验失败；原值已保留".into());
        }
        Ok(verified)
    })?;
    crate::audit::transition("region.decision", "followed", None);
    Ok(info(
        &verified,
        &journal,
        Some(target),
        recommendation(verified.country.as_deref(), Some(target)),
    ))
}
pub(crate) async fn follow(
    dir: PathBuf,
    target: Option<String>,
    explicit: bool,
) -> Result<RegionInfo, String> {
    tokio::task::spawn_blocking(move || follow_sync(&dir, target.as_deref(), explicit))
        .await
        .map_err(|_| "系统地区操作失败")?
}
pub(crate) async fn status(dir: PathBuf, target: Option<String>) -> Result<RegionInfo, String> {
    tokio::task::spawn_blocking(move || {
        let journal = read_journal(&dir)?;
        let current = backend::read_snapshot()?;
        Ok(info(
            &current,
            &journal,
            target.as_deref(),
            recommendation(current.country.as_deref(), target.as_deref()),
        ))
    })
    .await
    .map_err(|_| "系统地区读取失败")?
}
pub(crate) async fn restore(dir: PathBuf) -> Result<RegionInfo, String> {
    tokio::task::spawn_blocking(move || {
        let mut journal = read_journal(&dir)?;
        let current = backend::read_snapshot()?;
        if let (Some(original), Some(intended)) = (&journal.original, &journal.intended) {
            let restore = recovery_snapshot(&current, original, intended)?;
            crate::audit::record("region.restore.apply", || backend::write_snapshot(&restore))?;
            if backend::read_snapshot()? != restore {
                return Err("系统地区恢复回读核验失败；恢复记录仍保留".into());
            }
        }
        journal.original = None;
        journal.intended = None;
        journal.enabled = false;
        save_journal(&dir, &journal)?;
        let current = backend::read_snapshot()?;
        Ok(info(
            &current,
            &journal,
            None,
            "已恢复本工具修改的地区，并暂停自动跟随；界面语言未修改。".into(),
        ))
    })
    .await
    .map_err(|_| "系统地区恢复失败")?
}

#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)]
mod macos {
    use super::*;
    pub(super) fn read_snapshot() -> Result<Snapshot, String> {
        let locale = command("/usr/bin/defaults", &["read", "-g", "AppleLocale"])?;
        if !validate_locale(&locale) {
            return Err("无法确认 macOS 国家/地区格式".into());
        }
        Ok(Snapshot {
            backend: "macos".into(),
            country: country_from_locale(&locale),
            values: BTreeMap::from([("AppleLocale".into(), Some(locale))]),
        })
    }
    pub(super) fn plan_snapshot(current: &Snapshot, country: &str) -> Result<Snapshot, String> {
        let locale = current
            .values
            .get("AppleLocale")
            .and_then(|v| v.as_deref())
            .ok_or("系统地区格式未确认")?;
        Ok(Snapshot {
            backend: current.backend.clone(),
            country: Some(country.into()),
            values: BTreeMap::from([(
                "AppleLocale".into(),
                Some(replace_country(locale, country)?),
            )]),
        })
    }
    pub(super) fn write_snapshot(snapshot: &Snapshot) -> Result<(), String> {
        let locale = snapshot
            .values
            .get("AppleLocale")
            .and_then(|v| v.as_deref())
            .filter(|s| validate_locale(s))
            .ok_or("系统地区格式无效")?;
        command(
            "/usr/bin/defaults",
            &["write", "-g", "AppleLocale", "-string", locale],
        )?;
        Ok(())
    }
}

#[cfg(any(target_os = "windows", test))]
#[allow(dead_code)]
mod windows {
    use super::*;
    fn valid_geo_name(value: &str) -> bool {
        valid_country(value) || (value.len() == 3 && value.bytes().all(|b| b.is_ascii_digit()))
    }
    const WIN_NATIVE: &str = r#"Add-Type -TypeDefinition 'using System;using System.Text;using System.Runtime.InteropServices;public static class WujianGeo { [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern int GetUserDefaultGeoName(StringBuilder name,int size); [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool SetUserGeoName(string name); }';"#;
    fn powershell(script: &str) -> Result<String, String> {
        command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        )
    }
    pub(super) fn read_snapshot() -> Result<Snapshot, String> {
        let script=format!("$ErrorActionPreference='Stop';{WIN_NATIVE}$s=New-Object System.Text.StringBuilder 16;if([WujianGeo]::GetUserDefaultGeoName($s,16)-eq 0){{throw 'read region failed'}};@{{country=$s.ToString();culture=(Get-Culture).Name}}|ConvertTo-Json -Compress");
        let value: serde_json::Value =
            serde_json::from_str(&powershell(&script)?).map_err(|_| "Windows 地区返回格式无效")?;
        let raw_country = value["country"]
            .as_str()
            .filter(|s| valid_geo_name(s))
            .ok_or("Windows 国家/地区代码无效")?
            .to_string();
        let country = value["country"]
            .as_str()
            .filter(|s| valid_country(s))
            .map(str::to_string);
        let culture = value["culture"]
            .as_str()
            .filter(|s| validate_locale(s))
            .ok_or("Windows 区域格式无效")?;
        Ok(Snapshot {
            backend: "windows".into(),
            country: country.clone(),
            values: BTreeMap::from([
                ("country".into(), Some(raw_country)),
                ("culture".into(), Some(culture.into())),
            ]),
        })
    }
    pub(super) fn plan_snapshot(current: &Snapshot, country: &str) -> Result<Snapshot, String> {
        if !valid_country(country) {
            return Err("系统地区代码无效".into());
        }
        let language = current
            .values
            .get("culture")
            .and_then(|v| v.as_deref())
            .ok_or("Windows 区域格式无效")?
            .split('-')
            .next()
            .ok_or("Windows 区域格式无效")?;
        let script=format!("$ErrorActionPreference='Stop';$a=[Globalization.CultureInfo]::GetCultures([Globalization.CultureTypes]::SpecificCultures)|Where-Object {{try {{([Globalization.RegionInfo]::new($_.Name)).TwoLetterISORegionName -eq '{country}'}}catch{{$false}}}}|Sort-Object @{{Expression={{if($_.TwoLetterISOLanguageName -eq '{language}'){{0}}elseif($_.TwoLetterISOLanguageName -eq 'en'){{1}}else{{2}}}}}},Name; if(!$a){{throw 'region format missing'}}; @($a)[0].Name");
        let culture = powershell(&script)?;
        if !validate_locale(&culture) {
            return Err("目标国家的区域格式未安装".into());
        }
        Ok(Snapshot {
            backend: current.backend.clone(),
            country: Some(country.into()),
            values: BTreeMap::from([
                ("country".into(), Some(country.into())),
                ("culture".into(), Some(culture)),
            ]),
        })
    }
    pub(super) fn write_snapshot(snapshot: &Snapshot) -> Result<(), String> {
        let country = snapshot
            .values
            .get("country")
            .and_then(|value| value.as_deref())
            .filter(|s| valid_geo_name(s))
            .ok_or("Windows 地区代码无效")?;
        let culture = snapshot
            .values
            .get("culture")
            .and_then(|v| v.as_deref())
            .filter(|s| validate_locale(s))
            .ok_or("Windows 区域格式无效")?;
        let script=format!("$ErrorActionPreference='Stop';{WIN_NATIVE}Set-Culture -CultureInfo '{culture}';if(![WujianGeo]::SetUserGeoName('{country}')){{throw 'set region failed'}}");
        powershell(&script)?;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", test))]
#[allow(dead_code)]
mod linux {
    use super::*;
    fn config_home() -> Result<PathBuf, String> {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .filter(|path| path.is_absolute())
            .ok_or("找不到用户地区设置目录".into())
    }
    fn effective_locale() -> Option<String> {
        ["LC_ALL", "LC_TIME", "LANG"]
            .iter()
            .find_map(|key| std::env::var(key).ok().filter(|s| validate_locale(s)))
    }
    fn kde_tools() -> (&'static str, &'static str) {
        if command("kreadconfig6", &["--help"]).is_ok() {
            ("kreadconfig6", "kwriteconfig6")
        } else {
            ("kreadconfig5", "kwriteconfig5")
        }
    }
    pub(super) fn read_snapshot() -> Result<Snapshot, String> {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if desktop.contains("kde") {
            let (reader, _) = kde_tools();
            let base = command(
                reader,
                &[
                    "--file",
                    "plasma-localerc",
                    "--group",
                    "Formats",
                    "--key",
                    "LANG",
                ],
            )?;
            let mut values = BTreeMap::new();
            for key in FORMAT_KEYS {
                let value = command(
                    reader,
                    &[
                        "--file",
                        "plasma-localerc",
                        "--group",
                        "Formats",
                        "--key",
                        key,
                    ],
                )?;
                values.insert((*key).into(), (!value.is_empty()).then_some(value));
            }
            let locale = values
                .get("LC_TIME")
                .and_then(|v: &Option<String>| v.clone())
                .or_else(|| (!base.is_empty()).then_some(base))
                .or_else(effective_locale);
            return Ok(Snapshot {
                backend: "kde".into(),
                country: locale.as_deref().and_then(country_from_locale),
                values,
            });
        }
        if desktop.contains("gnome") || desktop.contains("unity") {
            let value = command("gsettings", &["get", "org.gnome.system.locale", "region"])?;
            let locale = value.trim_matches('\'').to_string();
            if !locale.is_empty() && !validate_locale(&locale) {
                return Err("GNOME 地区格式无效".into());
            }
            let country = if locale.is_empty() {
                effective_locale().as_deref().and_then(country_from_locale)
            } else {
                country_from_locale(&locale)
            };
            return Ok(Snapshot {
                backend: "gnome".into(),
                country,
                values: BTreeMap::from([("region".into(), Some(locale))]),
            });
        }
        command(
            "systemctl",
            &["--user", "show", "--property=Version", "--value"],
        )
        .map_err(|_| "当前桌面没有可用的用户地区格式接口，请在系统设置中手动修改")?;
        let path = config_home()?.join("environment.d/90-wujian-region.conf");
        let mut values = BTreeMap::new();
        for key in FORMAT_KEYS {
            values.insert((*key).into(), None);
        }
        if path.exists() {
            let text = fs::read_to_string(&path).map_err(|_| "无法读取地区格式设置")?;
            for line in text
                .lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                let (key, value) = line.split_once('=').ok_or("地区格式文件无效")?;
                if !FORMAT_KEYS.contains(&key) || !validate_locale(value) {
                    return Err("地区格式文件含其他设置，未修改".into());
                }
                values.insert(key.into(), Some(value.into()));
            }
        }
        let locale = values
            .get("LC_TIME")
            .and_then(|v| v.clone())
            .or_else(effective_locale);
        Ok(Snapshot {
            backend: "environment_d".into(),
            country: locale.as_deref().and_then(country_from_locale),
            values,
        })
    }
    pub(super) fn choose_locale(
        list: &str,
        language: &str,
        country: &str,
    ) -> Result<String, String> {
        let mut available: Vec<_> = list
            .lines()
            .filter(|s| {
                country_from_locale(s).as_deref() == Some(country)
                    && s.to_ascii_lowercase().contains("utf")
                    && validate_locale(s)
            })
            .collect();
        available.sort_by_key(|s| {
            (
                if s.starts_with(&format!("{language}_")) {
                    0
                } else if s.starts_with("en_") {
                    1
                } else {
                    2
                },
                *s,
            )
        });
        let selected = available
            .first()
            .ok_or("目标地区的 UTF-8 语言环境未安装，请先在系统地区设置中添加；未修改地区")?
            .to_string();
        Ok(selected)
    }
    pub(super) fn plan_snapshot(current: &Snapshot, country: &str) -> Result<Snapshot, String> {
        if !valid_country(country) {
            return Err("系统地区代码无效".into());
        }
        if std::env::var("LC_ALL").is_ok_and(|s| !s.is_empty()) {
            return Err("LC_ALL 覆盖了地区格式，请先在系统设置中调整；未修改界面语言".into());
        }
        let language = effective_locale()
            .unwrap_or_default()
            .split('_')
            .next()
            .unwrap_or("")
            .to_string();
        let list = command("locale", &["-a"])?;
        let selected = choose_locale(&list, &language, country)?;
        let values = if current.backend == "gnome" {
            BTreeMap::from([("region".into(), Some(selected))])
        } else {
            FORMAT_KEYS
                .iter()
                .map(|key| ((*key).into(), Some(selected.clone())))
                .collect()
        };
        Ok(Snapshot {
            backend: current.backend.clone(),
            country: Some(country.into()),
            values,
        })
    }
    pub(super) fn write_snapshot(snapshot: &Snapshot) -> Result<(), String> {
        match snapshot.backend.as_str() {
            "gnome" => {
                let value = snapshot
                    .values
                    .get("region")
                    .and_then(|v| v.as_deref())
                    .ok_or("GNOME 地区格式无效")?;
                if !value.is_empty() && !validate_locale(value) {
                    return Err("GNOME 地区格式无效".into());
                }
                command(
                    "gsettings",
                    &[
                        "set",
                        "org.gnome.system.locale",
                        "region",
                        &format!("'{value}'"),
                    ],
                )?;
            }
            "kde" => {
                let (_, writer) = kde_tools();
                for key in FORMAT_KEYS {
                    match snapshot.values.get(*key).and_then(|v| v.as_deref()) {
                        Some(value) if validate_locale(value) => {
                            command(
                                writer,
                                &[
                                    "--file",
                                    "plasma-localerc",
                                    "--group",
                                    "Formats",
                                    "--key",
                                    key,
                                    value,
                                ],
                            )?;
                        }
                        None => {
                            command(
                                writer,
                                &[
                                    "--file",
                                    "plasma-localerc",
                                    "--group",
                                    "Formats",
                                    "--key",
                                    key,
                                    "--delete",
                                ],
                            )?;
                        }
                        _ => return Err("KDE 地区格式无效".into()),
                    }
                }
            }
            "environment_d" => {
                let path = config_home()?.join("environment.d/90-wujian-region.conf");
                let mut text = String::from(
                    "# Wujian current-user regional formats; display language unchanged\n",
                );
                let mut populated = false;
                for key in FORMAT_KEYS {
                    if let Some(value) = snapshot.values.get(*key).and_then(|v| v.as_deref()) {
                        if !validate_locale(value) {
                            return Err("地区格式无效".into());
                        }
                        populated = true;
                        text.push_str(&format!("{key}={value}\n"));
                    }
                }
                if populated {
                    fs::create_dir_all(path.parent().ok_or("地区目录无效")?)
                        .map_err(|_| "无法创建地区格式目录")?;
                    crate::firewall::write_private(&path, text.as_bytes())?;
                } else if path.exists() {
                    fs::remove_file(path).map_err(|_| "无法恢复地区格式")?;
                }
                command("systemctl", &["--user", "daemon-reload"])?;
            }
            _ => return Err("当前桌面的地区设置方式不支持".into()),
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(target_os = "macos")]
use macos as backend;
#[cfg(target_os = "windows")]
use windows as backend;

pub(crate) async fn open_settings() -> Result<(), String> {
    tokio::task::spawn_blocking(|| {
        #[cfg(target_os = "macos")]
        {
            command(
                "/usr/bin/open",
                &["x-apple.systempreferences:com.apple.Localization-Settings.extension"],
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            let mut cmd = Command::new("explorer.exe");
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
            cmd.arg("ms-settings:regionlanguage")
                .spawn()
                .map_err(|_| "无法打开系统地区设置")?;
        }
        #[cfg(target_os = "linux")]
        {
            let desktop = std::env::var("XDG_CURRENT_DESKTOP")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let (program, args): (&str, &[&str]) = if desktop.contains("kde") {
                ("systemsettings", &["kcm_regionandlang"])
            } else {
                ("gnome-control-center", &["region"])
            };
            Command::new(program)
                .args(args)
                .spawn()
                .map_err(|_| "请从系统设置打开语言与地区，当前桌面未提供可用的地区设置入口")?;
        }
        Ok(())
    })
    .await
    .map_err(|_| "无法打开系统地区设置")?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(locale: &str) -> Snapshot {
        Snapshot {
            backend: "macos".into(),
            country: country_from_locale(locale),
            values: BTreeMap::from([("AppleLocale".into(), Some(locale.into()))]),
        }
    }
    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wujian-region-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
    #[test]
    fn locale_country_changes_preserve_language_script_and_other_preferences() {
        for (input, country, expected) in [
            ("zh_CN", "US", "zh_US"),
            (
                "zh_Hans_CN@calendar=gregorian",
                "JP",
                "zh_Hans_JP@calendar=gregorian",
            ),
            ("zh_Hant_HK", "SG", "zh_Hant_SG"),
            ("pt_MO.UTF-8", "CA", "pt_CA.UTF-8"),
            ("en-US", "GB", "en-GB"),
            ("de", "AT", "de_AT"),
            (
                "zh-Hans_CN@calendar=gregorian",
                "US",
                "zh-Hans_US@calendar=gregorian",
            ),
            (
                "en_CN@calendar=gregorian;rg=cnzzzz",
                "JP",
                "en_JP@calendar=gregorian;rg=jpzzzz",
            ),
        ] {
            assert_eq!(replace_country(input, country).unwrap(), expected);
            assert_eq!(country_from_locale(expected).as_deref(), Some(country));
        }
        let planned = macos::plan_snapshot(&snapshot("zh_Hans_CN"), "US").unwrap();
        assert_eq!(
            planned.values.keys().collect::<Vec<_>>(),
            vec!["AppleLocale"]
        );
        assert_eq!(planned.values["AppleLocale"].as_deref(), Some("zh_Hans_US"));
        for invalid in ["ZZ", "UK", "US';exit", "", "../../US"] {
            assert!(!valid_country(invalid));
            assert!(replace_country("zh_CN", invalid).is_err());
        }
        assert!(replace_country("zh_CN\nAppleLanguages=en", "US").is_err());
    }
    #[test]
    fn unknown_egress_recommends_manual_change_without_guessing_or_writing() {
        let dir = temp_dir();
        for country in ["CN", "HK", "MO"] {
            let current = snapshot(&format!("zh_{country}"));
            let result = follow_sync_with(
                &dir,
                None,
                false,
                || Ok(current.clone()),
                |_, _| panic!("unknown egress must not plan"),
                |_| panic!("unknown egress must not write"),
            )
            .unwrap();
            assert_eq!(result.current.as_deref(), Some(country));
            assert!(result.detail.contains("建议"));
            assert!(!result.can_restore);
        }
        assert!(!dir.join(JOURNAL).exists());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn transaction_saves_original_before_write_and_follows_only_owned_changes() {
        use std::cell::RefCell;
        let dir = temp_dir();
        let original = snapshot("zh_Hans_CN@calendar=gregorian");
        let active = RefCell::new(original.clone());
        let result = follow_sync_with(
            &dir,
            Some("US"),
            false,
            || Ok(active.borrow().clone()),
            macos::plan_snapshot,
            |next| {
                let saved = read_journal(&dir).unwrap();
                assert_eq!(saved.original.as_ref(), Some(&original));
                assert_eq!(saved.intended.as_ref(), Some(next));
                *active.borrow_mut() = next.clone();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(result.current.as_deref(), Some("US"));
        assert!(result.can_restore && result.restart_required);
        follow_sync_with(
            &dir,
            Some("JP"),
            false,
            || Ok(active.borrow().clone()),
            macos::plan_snapshot,
            |next| {
                *active.borrow_mut() = next.clone();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(read_journal(&dir).unwrap().original, Some(original.clone()));
        let journal = read_journal(&dir).unwrap();
        assert_eq!(
            recovery_snapshot(
                &active.borrow(),
                &original,
                journal.intended.as_ref().unwrap()
            )
            .unwrap(),
            original
        );
        *active.borrow_mut() = snapshot("zh_SG");
        let kept = follow_sync_with(
            &dir,
            Some("US"),
            false,
            || Ok(active.borrow().clone()),
            |_, _| panic!("manual edit must be retained"),
            |_| panic!("manual edit must not be overwritten"),
        )
        .unwrap();
        assert_eq!(kept.current.as_deref(), Some("SG"));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn failed_write_keeps_recovery_and_partial_restore_never_overwrites_manual_edits() {
        let dir = temp_dir();
        let current = snapshot("zh_CN");
        assert!(follow_sync_with(
            &dir,
            Some("US"),
            false,
            || Ok(current.clone()),
            macos::plan_snapshot,
            |_| Err("failed".into())
        )
        .is_err());
        let saved = read_journal(&dir).unwrap();
        assert_eq!(saved.original, Some(current));
        assert!(saved.intended.is_some());
        let original = Snapshot {
            backend: "windows".into(),
            country: Some("CN".into()),
            values: BTreeMap::from([
                ("country".into(), Some("CN".into())),
                ("culture".into(), Some("zh-CN".into())),
            ]),
        };
        let target = Snapshot {
            backend: "windows".into(),
            country: Some("US".into()),
            values: BTreeMap::from([
                ("country".into(), Some("US".into())),
                ("culture".into(), Some("en-US".into())),
            ]),
        };
        let mut partial = target.clone();
        partial
            .values
            .insert("culture".into(), Some("zh-CN".into()));
        assert_eq!(
            recovery_snapshot(&partial, &original, &target).unwrap(),
            original
        );
        partial
            .values
            .insert("culture".into(), Some("de-DE".into()));
        assert!(recovery_snapshot(&partial, &original, &target).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn only_specified_regions_or_prior_owned_changes_follow_automatically() {
        let journal = Journal::default();
        for country in ["CN", "HK", "MO"] {
            assert!(may_follow(
                &snapshot(&format!("zh_{country}")),
                &journal,
                Some("JP"),
                false
            ));
        }
        for country in ["US", "GB", "TW", "SG"] {
            assert!(!may_follow(
                &snapshot(&format!("en_{country}")),
                &journal,
                Some("JP"),
                false
            ));
        }
        for target in [None, Some("ZZ")] {
            assert!(!may_follow(&snapshot("zh_CN"), &journal, target, false));
        }
        let paused = Journal {
            enabled: false,
            ..Journal::default()
        };
        assert!(!may_follow(&snapshot("zh_CN"), &paused, Some("US"), false));
    }
    #[test]
    fn linux_selects_an_installed_target_locale_without_changing_message_language() {
        let list = "C\nzh_CN.utf8\nen_US.utf8\nzh_US.utf8\nfr_CA.utf8\nen_CA.utf8\n";
        assert_eq!(
            linux::choose_locale(list, "zh", "US").unwrap(),
            "zh_US.utf8"
        );
        assert_eq!(
            linux::choose_locale(list, "zh", "CA").unwrap(),
            "en_CA.utf8"
        );
        assert!(linux::choose_locale(list, "zh", "JP").is_err());
        assert!(
            !FORMAT_KEYS.contains(&"LANG")
                && !FORMAT_KEYS.contains(&"LC_MESSAGES")
                && !FORMAT_KEYS.contains(&"LC_ALL")
        );
    }
    #[test]
    fn unknown_region_advice_is_visible_and_retries_are_bounded() {
        let mut state = FollowState::default();
        assert!(state.due("1.1.1.1", None));
        state.begin("1.1.1.1", None);
        assert!(!state.due("1.1.1.1", None));
        assert!(state.due("2.2.2.2", None));
        state.info = Some(info(
            &snapshot("zh_CN"),
            &Journal::default(),
            None,
            recommendation(Some("CN"), None),
        ));
        assert_eq!(state.check().status, "review");
        assert!(state.check().detail.contains("建议"));
    }
}
