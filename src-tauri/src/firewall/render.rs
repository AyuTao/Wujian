use super::policy::Policy;
pub const PF_ANCHOR: &str = "com.apple/000.io.wujian";
pub const NFT_TABLE: &str = "wujian_guard";
pub const WINDOWS_GROUP: &str = "Wujian.Firewall";
pub const OWNER: &str = "io.wujian.firewall.v1";
fn list(values: impl IntoIterator<Item = impl ToString>) -> String {
    values
        .into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
pub fn pf(policy: &Policy) -> Result<String, String> {
    policy.validate()?;
    let generation = &policy.generation;
    Ok(format!("# {OWNER}; owned anchor only; no global pass rules\ntable <wj_allow4> const {{ {} }}\ntable <wj_allow6> const {{ {} }}\nblock drop out quick inet to ! <wj_allow4> label \"wj-{generation}-4-out\"\nblock drop in quick inet from ! <wj_allow4> label \"wj-{generation}-4-in\"\nblock drop out quick inet6 to ! <wj_allow6> label \"wj-{generation}-6-out\"\nblock drop in quick inet6 from ! <wj_allow6> label \"wj-{generation}-6-in\"\n", list(policy.allowed4()), list(policy.allowed6())))
}
pub fn nft(policy: &Policy, replace: bool) -> Result<String, String> {
    policy.validate()?;
    let prefix = if replace {
        format!("delete table inet {NFT_TABLE}\n")
    } else {
        String::new()
    };
    let mut result = format!("{prefix}table inet {NFT_TABLE} {{\n comment \"{OWNER}:{}\"\n set allow4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {} }} }}\n set allow6 {{ type ipv6_addr; flags interval; auto-merge; elements = {{ {} }} }}\n", policy.generation, list(policy.allowed4()), list(policy.allowed6()));
    for (chain, address) in [("output", "daddr"), ("input", "saddr")] {
        result.push_str(&format!(" chain {chain} {{ type filter hook {chain} priority -190; policy accept;\n  ip {address} != @allow4 counter drop\n  ip6 {address} != @allow6 counter drop\n }}\n"));
    }
    result.push_str(" chain forward { type filter hook forward priority -190; policy accept;\n  ip daddr != @allow4 counter drop\n  ip saddr != @allow4 counter drop\n  ip6 daddr != @allow6 counter drop\n  ip6 saddr != @allow6 counter drop\n }\n}\n");
    Ok(result)
}
/// All variable strings in this script are validated numeric CIDRs or hex IDs.
/// Windows block rules take precedence: emit the exact complement, never a
/// blanket block with an allow-rule exception.
pub fn windows(policy: &Policy) -> Result<String, String> {
    policy.validate()?;
    let mut script = windows_header();
    script.push_str("$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)\nif ($profiles.Count -ne 3 -or @($profiles | Where-Object { $_.Enabled -ne 'True' -or $_.AllowLocalFirewallRules -eq 'False' }).Count -gt 0) { throw 'Firewall profiles or local rule merging do not permit protection' }\n");
    let denied = policy.denied();
    let mut names = Vec::new();
    for (index, chunk) in denied.chunks(128).enumerate() {
        let addresses = chunk
            .iter()
            .map(|v| format!("'{v}'"))
            .collect::<Vec<_>>()
            .join(",");
        for direction in ["Inbound", "Outbound"] {
            let name = format!("Wujian-{}-{direction}-{index}", policy.generation);
            names.push(format!("'{name}'"));
            script.push_str(&format!("if (-not (Get-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -DisplayName '{name}' -Group '{WINDOWS_GROUP}' -Description '{OWNER}' -Enabled True -Profile Any -Direction {direction} -Action Block -Protocol Any -RemoteAddress @({addresses}) | Out-Null }}\n"));
        }
    }
    script.push_str(&format!("$expected = @({})\n", names.join(",")));
    script.push_str(&format!("$active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $expected -contains $_.Name -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }})\nif ($active.Count -ne $expected.Count) {{ throw 'Active firewall rules failed readback; restrictions retained' }}\nGet-NetFirewallRule -PolicyStore PersistentStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $expected -notcontains $_.Name -and $_.Description -eq '{OWNER}' }} | Remove-NetFirewallRule\n"));
    script.push_str("Write-Output 'WUJIAN_APPLY_OK'\n");
    Ok(script)
}
pub fn windows_header() -> String {
    "$ErrorActionPreference = 'Stop'\n[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n".into()
}
pub fn windows_remove() -> String {
    format!("{}Get-NetFirewallRule -PolicyStore PersistentStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Where-Object {{ $_.Description -eq '{OWNER}' }} | Remove-NetFirewallRule\nWrite-Output 'WUJIAN_REMOVE_OK'\n", windows_header())
}
pub fn windows_status() -> String {
    format!("{}$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Sort-Object Name | ForEach-Object {{ @{{name=[string]$_.Name;enabled=[string]$_.Enabled;localRules=[string]$_.AllowLocalFirewallRules}} }})\n$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group '{WINDOWS_GROUP}' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {{ @{{name=$_.Name;description=$_.Description;enabled=[string]$_.Enabled;action=[string]$_.Action;direction=[string]$_.Direction;addresses=@($_ | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress | Sort-Object)}} }})\n@{{profiles=$profiles;rules=$rules}} | ConvertTo-Json -Depth 6 -Compress\n", windows_header())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            lockdown: false,
            ipv6_only: false,
            version: 1,
            generation: "b".repeat(32),
            cn_networks: vec!["223.5.5.0/24".into()],
            extra_allowed: vec![],
        }
    }
    #[test]
    fn pf_does_not_bypass_other_firewalls_or_scope_to_tcp() {
        let text = pf(&policy()).unwrap();
        assert_eq!(
            text.lines().filter(|v| v.starts_with("block drop")).count(),
            4
        );
        assert!(!text.lines().any(|v| v.starts_with("pass ")));
        assert!(!text.contains("proto tcp"));
        assert!(!text.contains("set skip"));
    }
    #[test]
    fn nft_replaces_only_owned_table_atomically_and_checks_existing_flows() {
        let text = nft(&policy(), true).unwrap();
        assert!(text.starts_with("delete table inet wujian_guard\n"));
        assert!(!text.contains("flush ruleset"));
        assert!(!text.contains("ct state established accept"));
        assert!(text.contains("hook output"));
        assert!(text.contains("hook input"));
        assert!(text.contains("hook forward"));
    }
    #[test]
    fn windows_uses_complement_and_creates_before_removing_old_rules() {
        let text = windows(&policy()).unwrap();
        assert!(!text.contains("-Action Allow"));
        assert!(!text.contains("'223.5.5.0/24'"));
        assert!(
            text.find("New-NetFirewallRule").unwrap()
                < text.find("Remove-NetFirewallRule").unwrap()
        );
        assert!(text.contains("-Direction Inbound"));
        assert!(text.contains("-Direction Outbound"));
        assert!(!windows_remove().contains("Reset"));
    }
}
