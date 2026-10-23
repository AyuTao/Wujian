use std::{path::Path, process::ExitCode};
use wujian_lib::firewall::{self, policy::Policy};
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = (|| -> Result<(), String> {
        match args.get(1).map(String::as_str) {
            Some("--tunnel-watchdog") if args.len() == 2 => {
                let rt = tokio::runtime::Runtime::new().map_err(|_| "无法创建运行时")?;
                rt.block_on(firewall::watchdog())?;
            }
            Some("--emergency-release") if args.len() == 2 => {
                let rt = tokio::runtime::Runtime::new().map_err(|_| "无法创建运行时")?;
                println!("{}", rt.block_on(firewall::emergency_release())?.detail);
            }
            Some("tunnel-fixture") if args.len() == 3 => {
                let mut policy = Policy::isolation();
                policy.lockdown = false;
                policy.tunnel_guard = Some(firewall::tunnel::TunnelGuard { uid: 501, interface: "utun6".into(), node: "synthetic".into(), server: "9.9.9.9".into(), port: 443,
                    protocols: vec!["tcp".into(), "udp".into()], addresses: vec!["9.9.9.9".parse().unwrap()], selected_chain: vec!["GLOBAL".into(), "synthetic".into()], prepared_at: chrono::Utc::now().to_rfc3339(), country: String::new(), dns_note: String::new(), dns_pins: vec![] });
                let dir = Path::new(&args[2]);
                std::fs::create_dir(dir).map_err(|_| "需要一个尚不存在的新目录")?;
                std::fs::write(dir.join("macos.conf"), firewall::render::pf(&policy)?).map_err(|_| "规则导出失败")?;
                println!("Synthetic global tunnel rules exported; no firewall changes");
            }
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
                    tunnel_guard: None,
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
