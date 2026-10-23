#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--emergency-release" {
        let result = tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(wujian_lib::firewall::emergency_release()));
        match result {
            Ok(receipt) => println!("{}", receipt.detail),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() == 2 && args[1] == "--tunnel-watchdog" {
        let result = tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(wujian_lib::firewall::watchdog()));
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() == 2 && matches!(args[1].as_str(), "--admin-install" | "--timezone-install") {
        if let Err(error) = wujian_lib::admin_install() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() == 2 && matches!(args[1].as_str(), "--admin-helper" | "--timezone-helper") {
        if let Err(error) = wujian_lib::admin_serve() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if args.get(1).is_some_and(|v| v == "--firewall-helper") {
        let result = (|| {
            let path = args.get(2).ok_or("缺少隔断请求文件")?;
            if args.len() > 4 || args.get(3).is_some_and(|v| v != "--result-file") {
                return Err("无效的 helper 参数".to_string());
            }
            let runtime = tokio::runtime::Runtime::new().map_err(|_| "无法启动系统操作运行时")?;
            runtime.block_on(wujian_lib::firewall::helper(
                std::path::Path::new(path),
                args.len() == 4,
            ))
        })();
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    wujian_lib::run();
}
