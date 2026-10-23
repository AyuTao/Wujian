use super::{
    command,
    render::{self, NFT_TABLE, OWNER},
    ManagedState, Receipt,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
fn executable() -> Result<PathBuf, String> {
    ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or("未安装 nftables，请先用发行版软件包管理器安装 nftables".into())
}
async fn nft(args: &[&str], input: Option<&str>) -> Result<String, String> {
    command::run(&executable()?, args, input.map(str::as_bytes)).await
}
async fn current() -> Result<Option<Value>, String> {
    let text = nft(&["-j", "list", "tables"], None).await?;
    let value: Value = serde_json::from_str(&text).map_err(|_| "无法解码 nftables 列表")?;
    let exists = value["nftables"]
        .as_array()
        .ok_or("nftables 表列表格式未知")?
        .iter()
        .any(|v| v["table"]["family"] == "inet" && v["table"]["name"] == NFT_TABLE);
    if !exists {
        return Ok(None);
    }
    let text = nft(&["-j", "list", "table", "inet", NFT_TABLE], None).await?;
    let value: Value = serde_json::from_str(&text).map_err(|_| "无法解码 nftables 规则")?;
    if !owned(&value) {
        return Err("同名 nftables 表不属于本软件，拒绝覆盖或清除".into());
    }
    Ok(Some(value))
}
fn owned(value: &Value) -> bool {
    value["nftables"].as_array().is_some_and(|items| {
        items.iter().any(|v| {
            v["table"]["name"] == NFT_TABLE
                && v["table"]["comment"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("{OWNER}:")))
        })
    })
}
fn generation_matches(value: &Value, generation: &str) -> bool {
    value["nftables"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|v| v["table"]["comment"] == format!("{OWNER}:{generation}"))
    })
}
pub async fn check_plan(policy: &super::policy::Policy) -> Result<(), String> {
    let ruleset: Value = serde_json::from_str(&nft(&["-j", "list", "ruleset"], None).await?)
        .map_err(|_| "无法解码当前 nftables ruleset")?;
    if ruleset["nftables"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.get("flowtable").is_some()))
    {
        return Err("检测到 flowtable 加速，已有转发流可能绕过常规过滤；暂不启用该布局".into());
    }
    let replace = current().await?.is_some();
    let script = render::nft(policy, replace)?;
    nft(&["-c", "-f", "-"], Some(&script)).await?;
    Ok(())
}
pub async fn apply(state: &mut ManagedState, dir: &Path) -> Result<Receipt, String> {
    let ruleset: Value = serde_json::from_str(&nft(&["-j", "list", "ruleset"], None).await?)
        .map_err(|_| "无法解码当前 nftables ruleset")?;
    if ruleset["nftables"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.get("flowtable").is_some()))
    {
        return Err("检测到 flowtable 加速，已有转发流可能绕过常规过滤；暂不启用该布局".into());
    }
    let replace = current().await?.is_some();
    let script = render::nft(&state.policy, replace)?;
    nft(&["-c", "-f", "-"], Some(&script)).await?;
    // Deletion and replacement are in ONE nft transaction. No flush ruleset.
    nft(&["-f", "-"], Some(&script)).await?;
    let value = current().await?.ok_or("nftables 未回读到本软件规则")?;
    if !generation_matches(&value, &state.policy.generation) {
        return Err("nftables 规则代次不匹配，未确认启用".into());
    }
    state.fingerprint = Some(super::fingerprint(&value));
    super::save_state(dir, state)?;
    status(Some(state)).await
}
pub async fn release() -> Result<Receipt, String> {
    if current().await?.is_some() {
        nft(&["delete", "table", "inet", NFT_TABLE], None).await?;
    }
    if current().await?.is_some() {
        return Err("nftables 表仍然存在，解除核验失败".into());
    }
    Ok(Receipt::new(
        false,
        None,
        "已核验本软件 nftables 表已移除，其他规则未清除；请复测联网。",
    ))
}
pub async fn status(state: Option<&ManagedState>) -> Result<Receipt, String> {
    let value = current().await?;
    let active = match (state, value.as_ref()) {
        (Some(state), Some(value)) => {
            generation_matches(value, &state.policy.generation)
                && state.fingerprint == Some(super::fingerprint(value))
        }
        _ => false,
    };
    Ok(Receipt::new(
        active,
        state.map(|s| s.policy.generation.clone()),
        if active {
            "nftables 表、代次及规则回读匹配；实际跨 TUN 和已有连接覆盖仍需实测。"
        } else if value.is_none() {
            "没有本软件的 nftables 隔断表。"
        } else {
            "存在本软件规则，但与受管配置不匹配，不能确认隔断状态。"
        },
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_named_table_is_not_owned() {
        assert!(!owned(
            &serde_json::json!({"nftables":[{"table":{"name":"wujian_guard","comment":"other-app"}}]})
        ));
        assert!(owned(
            &serde_json::json!({"nftables":[{"table":{"name":"wujian_guard","comment":"io.wujian.firewall.v1:abc"}}]})
        ));
    }
}
