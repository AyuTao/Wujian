use std::{path::Path, process::ExitCode};
use wujian_lib::geo::CountryDb;
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let run = || -> Result<(), String> {
        if args.len() < 3 {
            return Err("Usage: wujian-geo lookup <mmdb> <ip> | export-cn <mmdb> <output>".into());
        }
        let db = CountryDb::open(Path::new(&args[2]))?;
        match args[1].as_str() {
            "lookup" if args.len() == 4 => {
                let ip = args[3].parse().map_err(|_| "IP 地址无效")?;
                println!(
                    "{}",
                    serde_json::to_string(&db.lookup(ip)?).map_err(|_| "无法序列化")?
                );
            }
            "export-cn" if args.len() == 4 => {
                let networks = db.china_networks()?;
                // Exclusive creation avoids silently replacing an existing dataset.
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&args[3])
                    .map_err(|_| "无法新建 CN 网段文件，目标可能已存在")?;
                writeln!(
                    file,
                    "# Generated from local MMDB; classification is approximate."
                )
                .map_err(|_| "写入失败")?;
                file.write_all(networks.join("\n").as_bytes())
                    .map_err(|_| "写入失败")?;
                file.sync_all().map_err(|_| "保存失败")?;
                println!("Exported {} CN networks", networks.len());
            }
            _ => return Err("无效的 Geo 命令或参数".into()),
        }
        Ok(())
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
