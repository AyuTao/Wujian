# 無間道 · Wujian

本地网络环境检查与 Kill Switch 工具，采用 Tauri、Rust 和 React，面向 macOS、Windows 与 Linux。当前版本为 **0.1.0-beta.1**。

读取系统 DNS、IPv6、采样路由及可识别的代理配置；经用户授权后，可查询公网出口、采样 DNS、修改 DNS，并请求管理员权限加载本工具的防火墙规则。本工具不包含代理内核、节点或流量服务，不会修改 Clash/Mihomo 的模式。

## 当前能力与边界

- 规则模式如实显示为规则模式；两个目标走 TUN 只代表采样路由，不推断全局接管。
- HTTPS 出口请求和 HTTP DNS 辅助采样分别授权，默认关闭。HTTP 数据保持不可信，不能作为“全链路无泄漏”证明；BrowserLeaks DNS/WebRTC 需要在浏览器中复测，curl 无法代替 WebRTC 检测。
- “阻断公网 IPv6”加载独立防火墙规则，不清除网卡 IPv6 地址或手动配置。
- 启用监测后，关键出口、地区、IPv6 或采样路由证据缺失、过期、变化时，请求管理员授权整机隔离。明确的 DNS 地区偏离或客户端直连模式也可触发。严格隔离仅保留回环通信，会中断互联网与局域网访问；诊断改善不会自动解除。
- DNS 修改先向指定解析器的 UDP 53 发送 example.com 可用性查询，再在原生特权 helper 中持久化原始配置。部分失败保留恢复记录，仅重试未完成的恢复任务。不会盲目写入 127.0.0.1。
- 结构化日志只在本机保存，可查看和导出；记录操作、结果、耗时和错误类别，不写入原始错误、IP、凭据、命令参数和用户路径。四份约 512 KiB 文件轮转。

**当前是轮询触发、需要管理员授权的测试实现。** 本地巡检约每 3 秒调度，监测开启后约每 10 秒尝试外部采样，实际间隔受查询耗时影响。授权完成前不能声称隔离成功；应用崩溃前尚未加载的规则不会自动出现。已加载的规则不会因普通退出/崩溃自动解除，重启系统后则须重新核验。规则回读 `configurationActive` 与实机断流验收 `enforcementVerified` 分开，后者不会由普通诊断自动设为 true。

本工具不能保证账号不被封禁，也不能证明所有应用、浏览器或 DNS 请求采用同一路径。国家未知时不会默认成美国；时区仅作参考，不自动改写。

## 开始测试

请先阅读 [测试指南](docs/测试指南.md)，从只读检查开始。需要断流的用例应在可本地恢复的测试机或虚拟机执行。

| 平台 | 原生规则 | DNS 修改要求 |
| --- | --- | --- |
| macOS 14+ | PF 独立 anchor；不覆盖系统主规则，不支持的优先级布局拒绝启用 | networksetup；保留 DHCP/静态 DNS 原值 |
| Windows | Windows Defender Firewall / PowerShell，需 UAC | 活动物理网卡 IPv4 DNS，保留静态值/自动模式 |
| Linux | nftables 独立 inet 表，需 nftables 与 polkit/pkexec | 仅支持 systemd-resolved/resolvectl；恢复本次修改前的运行时每接口 DNS 列表 |

已执行的本机验证和剩余实机测试见 [开发进度](docs/开发进度.md)。Windows/Linux 的 CI 编译通过也不等于已完成真实代理客户端断流验收。

出口地区使用本机 `Country.mmdb` 离线查询，不自动下载或分发数据库。当前从 Clash Verge Rev/Mihomo/Clash 的常见用户目录查找，找不到时显示未知；缺少地区证据时启用监测将请求隔离。请先在只读检查中确认检测结果。

## 开发与检查

需要 Node.js 22、package.json 指定的 pnpm、Rust stable，以及对应平台的 Tauri 编译依赖。Linux 构建依赖见 `.github/workflows/check.yml`。

```sh
pnpm install --frozen-lockfile
pnpm tauri dev
```

```sh
pnpm test
pnpm build
pnpm format:check
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo test --manifest-path src-tauri/Cargo.toml --locked
```

`pnpm tauri build` 只构建当前平台。GitHub Actions 提供三端检查；测试版打包通过手动 Release workflow 生成草稿预发布，附 SHA-256 校验文件。macOS 使用 ad-hoc 签名，未做 Apple 公证；Windows 未做代码签名。

`native/macos/` 中的 Network Extension 是独立研究组件，当前桌面包不安装或启用它。`docs/` 其他方案文档保留为设计资料，以本 README 和测试指南的当前行为为准。

## 许可证

[MIT](LICENSE)，版权归 AyuTao；第三方资料见 [NOTICE](NOTICE.md)。
