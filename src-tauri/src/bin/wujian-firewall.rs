use std::{path::Path, process::ExitCode};
use wujian_lib::firewall::{self, policy::Policy};
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = (|| -> Result<(), String> {
        match args.get(1).map(String::as_str) {
            Some("probe-executor") if args.len() == 2 => {
                let rt = tokio::runtime::Runtime::new().map_err(|_| "无法创建运行时")?;
                print!("{}", rt.block_on(firewall::probe_executor())?);
            }
            Some("plan") if args.len() == 4 => {
                let policy = Policy::from_database(Path::new(&args[2]))?;
                firewall::export_plan(&policy, Path::new(&args[3]))?;
                println!("Exported {} CN IPv4 networks, {} denied CIDRs for all three platforms; no firewall changes", policy.cn_networks.len(), policy.denied().len());
            }
            Some("fixture") if args.len() == 3 => {
                let policy = Policy {
                    lockdown: false,
                    ipv6_only: false,                    version: 1,
                    generation: "c".repeat(32),
                    cn_networks: vec!["223.5.5.0/24".into()],
                    extra_allowed: vec![],
                };
                firewall::export_plan(&policy, Path::new(&args[2]))?;
                firewall::export_plan(&Policy::isolation(), &Path::new(&args[2]).join("isolation"))?;
                firewall::export_plan(&Policy::ipv6_block(), &Path::new(&args[2]).join("ipv6"))?;
                println!("Synthetic test fixture exported; do not apply on a working computer");
            }
            Some("request") if args.len() == 3 => {
                let rt = tokio::runtime::Runtime::new().map_err(|_| "无法创建运行时")?;
                rt.block_on(firewall::helper(Path::new(&args[2]), false))?;
            }
            Some("--help" | "-h") | None => println!("wujian-firewall plan <Country.mmdb> <new-output-directory>\nwujian-firewall fixture <new-test-directory>\nwujian-firewall request <request.json> (administrator required)"),
            _ => return Err("无效参数，请使用 --help".into()),
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
