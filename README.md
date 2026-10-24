# 無間道 · Wujian

> **「Dario，我係中國人。」** 🕶️
>
> 无间道的梗，认真做的工具。

**为国人使用海外 AI 保驾护航。** 无间道是一款免费开源的桌面网络环境检查与防护工具，面向 Claude 等 AI 工具用户，帮助发现 IP、DNS、IPv6、时区等环境问题，尽量降低因网络配置异常带来的账号风控风险。

防封是初衷，不是保证：本工具无法决定 Claude 等服务的账号审核结果，也不承诺不封号。

## 能做什么

- **看清环境**：检查出口 IP 与地区、DNS、IPv6、时区和代理接管状态。
- **减少疏漏**：支持系统 DNS 设置、独立 IPv6 阻断，以及时区和系统地区跟随出口。
- **断线保护**：确认配置后启用防火墙保护，代理条件失效时尝试隔断连接。
- **方便排查**：诊断日志保存在本机，支持查看和导出。

不提供代理、节点或订阅，需要自备网络环境。

## 下载与使用

当前版本：**0.1.0-beta.2**，仍在测试中。支持 macOS 14+（Apple Silicon / Intel）、Windows x64 和 Linux x64；Windows / Linux 尚需更多实机验证。

安装包由 [GitHub Actions](https://github.com/AyuTao/Wujian/actions/workflows/release.yml) 编译，目前仅放在 [Releases](https://github.com/AyuTao/Wujian/releases) 的未发布草稿中，供仓库维护者下载测试，暂未提供公开下载。macOS 测试包未经 Apple 公证，Windows 测试包未做代码签名。

1. 打开 App，先检查网络环境。
2. 如需全局保护，先在 Clash Verge Rev / Mihomo 中开启 **Global + TUN**，并接管 DNS 53 端口。
3. 按提示确认保护计划，再开启保护；需要恢复联网时，在 App 中停止保护或解除隔断。

**保护作用于整机，可能影响其他应用；退出 App 不会自动解除规则。** 首次修改防火墙、DNS 或时区需要系统授权。完整操作、适配限制及紧急恢复方法见 [使用说明](docs/使用说明.md)；测试前请看 [测试指南](docs/测试指南.md)。

## 本地开发

技术栈：Tauri 2 + Rust + React + TypeScript。需要 Node.js 22、pnpm 11.25.0、Rust stable 及对应平台的 Tauri 构建依赖。

```sh
pnpm install --frozen-lockfile
pnpm tauri dev
```

```sh
pnpm test
pnpm build
pnpm tauri build
```

## 参与与许可

欢迎提交 [Issue](https://github.com/AyuTao/Wujian/issues) 和 PR。反馈时请附系统、版本、复现步骤及脱敏日志，勿上传订阅或凭据。

[MIT](LICENSE) · [第三方声明](NOTICE.md) · [开发进度](docs/开发进度.md)
