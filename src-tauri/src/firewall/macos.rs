use super::{
    command,
    render::{self, PF_ANCHOR},
    ManagedState, Receipt,
};
use std::{fs, path::Path};
const PF: &str = "/sbin/pfctl";
const STOCK_CONF: &str = "/etc/pf.conf";
const STOCK_APPLE: &str = "/etc/pf.anchors/com.apple";
async fn pf(args: &[&str]) -> Result<String, String> {
    command::run(Path::new(PF), args, None).await
}
fn rule_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
}
/// Refuse layouts in which an earlier quick pass/anchor could bypass our leaf.
/// We use a uniquely owned leaf of the system's wildcard. An empty main ruleset
/// may be given the stock anchor point; a ruleset that already has rules is not replaced.
pub fn reachable(root: &str, parent: &str, children: &str) -> Result<(), String> {
    let mut found = false;
    for line in rule_lines(root) {
        if line == "anchor \"com.apple/*\" all" || line == "anchor \"com.apple/*\"" {
            found = true;
            break;
        }
        if line.starts_with("anchor ") || (line.starts_with("pass ") && line.contains("quick")) {
            return Err(
                "PF 主规则在系统 wildcard 之前包含其他入口，不能确认隔断优先级；未覆盖主规则"
                    .into(),
            );
        }
        if line.starts_with("scrub-anchor ")
            || line.starts_with("nat-anchor ")
            || line.starts_with("rdr-anchor ")
            || line.starts_with("dummynet-anchor ")
            || line.starts_with("block ")
        {
            continue;
        }
        return Err(
            "PF 主规则在系统 wildcard 之前包含其他入口，不能确认隔断优先级；未覆盖主规则".into(),
        );
    }
    if !found {
        return Err("PF 当前主规则未调用 com.apple/*；不能只加载一个不会执行的 anchor".into());
    }
    let leaf = PF_ANCHOR.rsplit('/').next().unwrap();
    // The stock com.apple file contains AirDrop/ApplicationFirewall anchor
    // references. The root wildcard visits direct children alphabetically.
    for line in rule_lines(parent) {
        let target = line
            .strip_prefix("anchor \"")
            .and_then(|v| v.split_once('"'))
            .map(|(target, _)| target);
        if !target.is_some_and(|v| v.trim_end_matches("/*") >= leaf) {
            return Err("PF 父规则包含未支持的入口，未覆盖系统规则".into());
        }
    }
    for child in rule_lines(children) {
        let child = child.trim_matches('"').rsplit('/').next().unwrap_or(child);
        if child < leaf {
            return Err("PF 存在更早的子规则，无法确认隔断优先级".into());
        }
    }
    Ok(())
}
fn main_ruleset_is_empty(root: &str) -> bool {
    rule_lines(root).next().is_none()
}
fn read_system_file(path: &str) -> Result<String, String> {
    let path = Path::new(path);
    let meta = fs::symlink_metadata(path).map_err(|_| "无法读取系统 PF 配置")?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("系统 PF 配置类型异常，拒绝加载".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() == 0 || meta.len() > 65_536 {
            return Err("系统 PF 配置归属或大小异常，拒绝加载".into());
        }
    }
    fs::read_to_string(path).map_err(|_| "无法读取系统 PF 配置".into())
}
fn validate_stock_anchor_point() -> Result<(), String> {
    let stock = read_system_file(STOCK_CONF)?;
    let parent = read_system_file(STOCK_APPLE)?;
    reachable(&stock, &parent, "")
        .map_err(|_| "系统 PF 配置不能提供 com.apple/* 入口，拒绝加载".to_string())
}
async fn reject_skipped_interfaces() -> Result<(), String> {
    let interfaces = pf(&["-s", "Interfaces", "-v"]).await?;
    let mut current = "";
    for line in interfaces.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.split_whitespace().next().unwrap_or("");
        }
        if line.contains("skip") && !current.starts_with("lo") {
            return Err("PF 有非回环接口被跳过，无法确认整机覆盖".into());
        }
    }
    Ok(())
}
async fn preflight() -> Result<(), String> {
    reject_skipped_interfaces().await?;
    let root = pf(&["-sr"]).await?;
    if main_ruleset_is_empty(&root) {
        return validate_stock_anchor_point();
    }
    let parent = pf(&["-a", "com.apple", "-sr"]).await?;
    let anchors = pf(&["-a", "com.apple", "-s", "Anchors"]).await?;
    reachable(&root, &parent, &anchors)
}
/// Load the system anchor point only when nothing is currently evaluating rules.
/// A populated main ruleset is left untouched.
async fn ensure_anchor_point() -> Result<(), String> {
    let root = pf(&["-sr"]).await?;
    if !main_ruleset_is_empty(&root) {
        return Ok(());
    }
    validate_stock_anchor_point()?;
    pf(&["-f", STOCK_CONF])
        .await
        .map_err(|error| format!("无法加载系统 PF 入口：{error}"))?;
    Ok(())
}
pub async fn check_plan(policy: &super::policy::Policy) -> Result<(), String> {
    preflight().await?;
    let text = render::pf(policy)?;
    command::run(
        Path::new(PF),
        &["-n", "-a", PF_ANCHOR, "-f", "-"],
        Some(text.as_bytes()),
    )
    .await?;
    Ok(())
}
fn token(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("Token :")
                .or_else(|| line.trim().strip_prefix("Token:"))
        })
        .map(str::trim)
        .filter(|v| v.parse::<u64>().is_ok_and(|v| v > 0))
        .map(str::to_string)
}
pub async fn apply(state: &mut ManagedState, dir: &Path, reset: bool) -> Result<Receipt, String> {
    if !reset {
        return Err("首次启用 PF 需要确认重置现有 PF 连接状态；未执行网络修改".into());
    }
    ensure_anchor_point().await?;
    preflight().await?;
    let path = dir.join("anchor.conf");
    super::write_private(&path, render::pf(&state.policy)?.as_bytes())?;
    let path = path.to_str().ok_or("规则路径编码无效")?;
    pf(&["-n", "-a", PF_ANCHOR, "-f", path]).await?;
    // Track a single owned PF enable reference. Other services' references
    // and rules remain intact. Never call pfctl -d or replace a populated ruleset.
    let refs = pf(&["-s", "References"]).await?;
    let token_valid = state.pf_token.as_ref().is_some_and(|v| {
        refs.split(|c: char| !c.is_ascii_digit())
            .any(|part| part == v)
    });
    if !token_valid {
        let enabled = command::combined(Path::new(PF), &["-E"]).await?;
        state.pf_token =
            Some(token(&enabled).ok_or("PF 已请求开启，但未返回引用 token；请先核验 PF 状态")?);
        super::save_state(dir, state)?;
    }
    pf(&["-a", PF_ANCHOR, "-f", path]).await?;
    // PF states bypass later rule evaluation. Whole-machine restriction thus
    // requires a one-time state reset; it is explicitly disclosed/acknowledged.
    pf(&["-F", "states"]).await?;
    super::save_state(dir, state)?;
    status(Some(state)).await
}
pub async fn release(state: Option<&ManagedState>) -> Result<Receipt, String> {
    let rules = pf(&["-a", PF_ANCHOR, "-sr"]).await?;
    for line in rule_lines(&rules) {
        if !(line.starts_with("block drop ")
            || line.starts_with("pass ") && line.contains("no state"))
            || !line.contains("label \"wj-")
        {
            return Err("专属 anchor 含未知规则，拒绝清除".into());
        }
    }
    pf(&["-a", PF_ANCHOR, "-F", "rules"]).await?;
    pf(&["-a", PF_ANCHOR, "-F", "Tables"]).await?;
    if let Some(token) = state.and_then(|s| s.pf_token.as_deref()) {
        let refs = pf(&["-s", "References"]).await?;
        if refs
            .split(|c: char| !c.is_ascii_digit())
            .any(|part| part == token)
        {
            pf(&["-X", token]).await?;
        }
    }
    let after = pf(&["-a", PF_ANCHOR, "-sr"]).await?;
    if rule_lines(&after).next().is_some() {
        return Err("规则解除核验失败，请保持本地控制台可用".into());
    }
    Ok(Receipt::new(
        false,
        None,
        "已核验本软件 PF 规则为空，其他软件规则未删除；请复测联网。",
    ))
}
pub async fn status(state: Option<&ManagedState>) -> Result<Receipt, String> {
    let info = pf(&["-s", "info"]).await?;
    let rules = pf(&["-a", PF_ANCHOR, "-sr"]).await?;
    let Some(state) = state else {
        return Ok(Receipt::new(
            false,
            None,
            if rule_lines(&rules).next().is_some() {
                "存在规则但缺少本软件受管状态，不能确认。"
            } else {
                "没有本软件的受管隔断规则。"
            },
        ));
    };
    let enabled = info
        .lines()
        .any(|v| v.trim_start().starts_with("Status: Enabled"));
    if state.policy.tunnel_guard.is_some() {
        let rendered = render::pf(&state.policy)?;
        let parsed = command::run(
            Path::new(PF),
            &["-n", "-v", "-a", PF_ANCHOR, "-f", "-"],
            Some(rendered.as_bytes()),
        )
        .await?;
        // Every permit in this mode is stateless. Any surviving PF state could
        // bypass rule evaluation after an interface/route change.
        let states_empty = pf(&["-s", "states"]).await?.trim().is_empty();
        let active = enabled
            && same_guard_rules(&rules, &parsed)
            && states_empty
            && preflight().await.is_ok();
        let mut receipt = Receipt::new(
            active,
            Some(state.policy.generation.clone()),
            if active {
                "全局隧道限制已回读：仅允许指定 TUN、节点端点、私网、本机回环及 DHCP。"
            } else {
                "隧道防回落规则未完整回读，不能确认保护已生效；规则不会自动解除。"
            },
        );
        receipt.policy_mode = "tunnel".into();
        if active {
            receipt.guard_policy = Some(state.policy.clone());
        }
        return Ok(receipt);
    }
    let expected = render::pf(&state.policy)?;
    let parsed = command::run(
        Path::new(PF),
        &["-n", "-v", "-a", PF_ANCHOR, "-f", "-"],
        Some(expected.as_bytes()),
    )
    .await?;
    let exact = same_guard_rules(&rules, &parsed);
    let tables = if enabled && exact {
        let v4 = pf(&["-a", PF_ANCHOR, "-t", "wj_allow4", "-T", "show"])
            .await
            .unwrap_or_default();
        let v6 = pf(&["-a", PF_ANCHOR, "-t", "wj_allow6", "-T", "show"])
            .await
            .unwrap_or_default();
        table_matches(&v4, &state.policy.allowed4()) && table_matches(&v6, &state.policy.allowed6())
    } else {
        false
    };
    let reachable = preflight().await.is_ok();
    let active = enabled && exact && tables && reachable;
    let mut receipt = Receipt::new(
        active,
        Some(state.policy.generation.clone()),
        if active {
            "PF 已开启，主规则可达，四条隔断规则及地址表回读匹配；实际流量覆盖仍需实测。"
        } else {
            "PF 配置核验不完整，不能声称隔断已生效；请检查详情或解除。"
        },
    );
    receipt.policy_mode = if state.policy.lockdown {
        "isolation"
    } else if state.policy.ipv6_only {
        "ipv6"
    } else {
        "legacy"
    }
    .into();
    Ok(receipt)
}
fn same_guard_rules(actual: &str, expected: &str) -> bool {
    let filters = |text: &str| -> Vec<String> {
        rule_lines(text)
            .filter(|s| s.starts_with("pass ") || s.starts_with("block "))
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    };
    let expected = filters(expected);
    !expected.is_empty() && filters(actual) == expected
}
fn table_matches(text: &str, expected: &[super::cidr::Cidr]) -> bool {
    let mut actual = Vec::new();
    for line in text.lines().map(str::trim).filter(|v| !v.is_empty()) {
        let text = if line.contains('/') {
            line.to_string()
        } else {
            format!("{line}/{}", if line.contains(':') { 128 } else { 32 })
        };
        let Ok(cidr) = super::cidr::Cidr::parse(&text) else {
            return false;
        };
        actual.push(cidr);
    }
    actual.sort();
    actual.dedup();
    let mut expected = expected.to_vec();
    expected.sort();
    expected.dedup();
    actual == expected
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guard_readback_rejects_same_labels_with_changed_endpoint_or_extra_rule() {
        let expected = "pass out quick inet proto tcp from any to 9.9.9.9 port = 443 flags any no state label \"wj-test\"\nblock drop out quick all label \"wj-block\"";
        assert!(same_guard_rules(expected, expected));
        assert!(!same_guard_rules(
            &expected.replace("9.9.9.9", "8.8.8.8"),
            expected
        ));
        assert!(!same_guard_rules(
            &format!("{expected}\npass out quick all"),
            expected
        ));
        assert!(!same_guard_rules("", ""));
    }
    #[test]
    fn empty_main_rules_may_use_the_stock_anchor_point() {
        assert!(main_ruleset_is_empty(""));
        assert!(main_ruleset_is_empty("# comment only\n\n"));
        assert!(!main_ruleset_is_empty("block drop all\n"));
        assert!(!main_ruleset_is_empty("anchor \"com.apple/*\" all\n"));
        let stock = "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nrdr-anchor \"com.apple/*\"\ndummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";
        let parent = "anchor \"200.AirDrop/*\"\nanchor \"250.ApplicationFirewall/*\"\n";
        assert!(reachable(stock, parent, "").is_ok());
        assert!(reachable("pass quick all\nanchor \"com.apple/*\"\n", parent, "").is_err());
        assert!(validate_stock_anchor_point().is_ok());
        let dir = std::env::temp_dir().join(format!("wujian-pf-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pf.conf");
        fs::write(&path, stock).unwrap();
        assert!(read_system_file(path.to_str().unwrap()).is_err());
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn disconnected_anchor_or_earlier_bypass_is_rejected() {
        assert!(reachable("", "", "").is_err());
        assert!(reachable("anchor \"other/*\" all\nanchor \"com.apple/*\" all", "", "").is_err());
        assert!(reachable("pass quick all\nanchor \"com.apple/*\" all", "", "").is_err());
        assert!(reachable("anchor \"com.apple/*\" all", "pass quick all", "").is_err());
        assert!(reachable("anchor \"com.apple/*\" all", "", "000.aaa").is_err());
        assert!(reachable(
            "anchor \"com.apple/*\" all",
            "",
            "000.io.wujian\n250.ApplicationFirewall"
        )
        .is_ok());
    }
    #[test]
    fn stock_apple_anchors_are_supported_but_conditional_root_is_not() {
        assert!(reachable(
            "anchor \"com.apple/*\" all",
            "anchor \"200.AirDrop/*\" all\nanchor \"250.ApplicationFirewall/*\" all",
            "200.AirDrop\n250.ApplicationFirewall"
        )
        .is_ok());
        assert!(reachable("anchor \"com.apple/*\" inet proto tcp", "", "").is_err());
    }
    #[test]
    fn pf_token_must_be_numeric() {
        assert_eq!(token("pf enabled\nToken : 12345\n"), Some("12345".into()));
        assert_eq!(token("Token : ;rm"), None);
    }
    #[test]
    fn table_readback_must_match_not_just_count() {
        let expected = [super::super::cidr::Cidr::parse("223.5.5.0/24").unwrap()];
        assert!(table_matches(" 223.5.5.0/24\n", &expected));
        assert!(!table_matches(" 8.8.8.0/24\n", &expected));
    }
}
