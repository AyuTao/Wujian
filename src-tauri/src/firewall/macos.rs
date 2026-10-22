use super::{
    command,
    render::{self, PF_ANCHOR},
    ManagedState, Receipt,
};
use std::path::Path;
const PF: &str = "/sbin/pfctl";
async fn pf(args: &[&str]) -> Result<String, String> {
    command::run(Path::new(PF), args, None).await
}
fn rule_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
}
/// Refuse layouts in which an earlier quick pass/anchor could bypass our leaf.
/// We use a uniquely owned leaf of the system's existing wildcard; never reload
/// /etc/pf.conf or replace the root ruleset.
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
async fn preflight() -> Result<(), String> {
    let root = pf(&["-sr"]).await?;
    let parent = pf(&["-a", "com.apple", "-sr"]).await?;
    let anchors = pf(&["-a", "com.apple", "-s", "Anchors"]).await?;
    reachable(&root, &parent, &anchors)?;

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
    preflight().await?;
    let path = dir.join("anchor.conf");
    super::write_private(&path, render::pf(&state.policy)?.as_bytes())?;
    let path = path.to_str().ok_or("规则路径编码无效")?;
    pf(&["-n", "-a", PF_ANCHOR, "-f", path]).await?;
    // Track a single owned PF enable reference. Other services' references
    // and rules remain intact. Never call pfctl -d or load the global ruleset.
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
        if !line.starts_with("block drop ") || !line.contains("label \"wj-") {
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
    let labels = ["4-out", "4-in", "6-out", "6-in"];
    let signatures = [
        "block drop out quick inet ",
        "block drop in quick inet ",
        "block drop out quick inet6 ",
        "block drop in quick inet6 ",
    ];
    let lines: Vec<_> = rule_lines(&rules).collect();
    let exact = lines.len() == 4
        && labels.iter().zip(signatures).all(|(label, signature)| {
            lines.iter().any(|v| {
                v.starts_with(signature)
                    && v.contains(&format!("\"wj-{}-{label}\"", state.policy.generation))
            })
        });
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
    Ok(Receipt::new(
        active,
        Some(state.policy.generation.clone()),
        if active {
            "PF 已开启，主规则可达，四条隔断规则及地址表回读匹配；实际流量覆盖仍需实测。"
        } else {
            "PF 配置核验不完整，不能声称隔断已生效；请检查详情或解除。"
        },
    ))
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
