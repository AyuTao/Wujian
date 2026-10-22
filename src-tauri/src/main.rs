#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
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
