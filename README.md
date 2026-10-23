# 無間道 · Wujian

本地网络环境检查与实验性 Kill Switch 工具，采用 Tauri、Rust 和 React。跨平台诊断。全局 TUN 整机保护配合本机已安装的 Clash Verge Rev/Mihomo：macOS 使用 PF，Linux 使用 nftables，Windows 使用 Windows 防火墙。Windows 和 Linux 还没有在真实机器上验收。当前版本为 **0.1.0-beta.1**。

读取系统 DNS、IPv6、采样路由及可识别的代理配置；经用户授权后，可查询公网出口、采样 DNS、修改 DNS，并请求管理员权限加载本工具的防火墙规则。本工具不包含代理内核、节点或流量服务，不会修改 Clash/Mihomo 的模式。

## 当前能力与边界

- 规则模式如实显示为规则模式；两个目标走 TUN 只代表采样路由，不推断全局接管。
- HTTPS 出口请求和 HTTP DNS 辅助采样分别授权，默认关闭。HTTP 数据保持不可信，不能作为“全链路无泄漏”证明；BrowserLeaks DNS/WebRTC 需要在浏览器中复测，curl 无法代替 WebRTC 检测。
- “阻断公网 IPv6”加载独立防火墙规则，不清除网卡 IPv6 地址或手动配置。
- 全局整机保护要求客户端已开启 Global + TUN，且 TUN 劫持 53 端口。GLOBAL 必须最终选择单个节点；准备计划时用桌面用户目录中的 Country.mmdb 核对该节点地址。中国大陆、未知或国家不一致会拒绝。CLOUDFLARE 这类机构标签会写进确认框，本身不拒绝。国外 DNS 主上游、fallback 和其他域名策略必须是公网 IPv4 的 HTTPS，并且走代理；可以是另一个具体节点，那个节点的地址和端口会一并放行。直连和含 `&` 的组仍拒绝。`geosite:cn` 等国内策略可以直连，只在确认框提示；开启后防火墙仍会阻断物理网卡上的 DNS。不要求粘贴 DNS 片段。未知、直连、规则模式或不支持的节点会拒绝开启，不会先断网再让用户修复。
- 确认计划后预先加载 PF 防回落规则：只允许指定 TUN、精确节点端点、国外 DNS 若使用另一节点时的那个端点、本机回环、IPv4 DHCP，以及私网 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`。192.168.10 这类局域网地址继续可通。不放行国内公网、其他 VPN、公共 DNS、CGNAT、Fake-IP 或整个进程用户。所有许可均不创建 PF 状态，安装时清除旧 PF 状态，防止连接状态跨接口放行。Linux 使用独立表 `inet wujian_guard`，放行范围与上面相同，然后丢弃其余流量。Windows 只在物理网卡上拦截公网，指定 TUN 不在拦截名单里；节点地址上除已放行的端口外，其他 TCP、未使用的 UDP 和 ICMPv4 也会被拦住，其余 IP 协议仍可能从物理网卡到达该地址。公共 DNS、CGNAT 和 Fake-IP 都不能从物理网卡出去。
- macOS 安装 root 拥有的 launchd 常驻 helper；Linux 用 systemd，Windows 用 SYSTEM 计划任务。常驻进程起来之后，全局模式、指定 TUN、节点选择、DNS 路径或控制接口失效时，无需再次授权即可切断到只剩回环。macOS 装好常驻组件后，之后的开启和修改不再弹密码；Linux 每次操作走 pkexec，Windows 每次走 UAC。同一节点和 DNS 路径恢复后，即使 utun 名称变了，也会自动重新加载原来的计划，不再要求授权或重新确认。节点、端口或 DNS 路径变了则保持切断，需要停止后重新确认。出口 IP、地区、系统时区和 DNS 观测仅供诊断；IP 变化记录提醒，不参与防回落触发。
- 主界面的出口行显示网站请求观测 IP 与地区，DNS 行显示本次解析器出口 IP 与地区；两者不要求地址相同。DNS 行跟随整体检测更新，无独立“复查”按钮；未授权、采样失败及过期结果明确标注，不用系统 DNS 列表或网站出口冒充解析器结果。独立的“DNS 配置”行显示系统解析入口，设置按钮直达 DNS 设置。
- DNS 默认只读，不改写 Clash/VPN 的解析策略。监测涵盖系统解析入口与可读取的作用域（macOS 含 `/etc/resolver`；systemd-resolved 含每链路 DNS 与域），不覆盖未暴露的客户端上游、应用自有 DoH 或全部域名。国内 DNS 属于正常分流配置；HTTP 辅助采样与 DNS 地区不控制断网，单次采样不能证明无泄漏。
- 国内网站转圈时，应区分 Fake-IP 应答和真实上游解析；国外 DoH 需要可用的连接路径，不能仅把上游改成海外地址。
- 普通诊断支持其他代理或 VPN；全局整机保护只适配上述客户端。采样路由不是全系统覆盖证明，防回落由预先加载的防火墙限制实现。发现系统代理时需在设置明确填写检测代理地址，不会静默绕过。
- DNS 修改先向指定解析器的 UDP 53 发送 example.com 可用性查询，再在原生特权 helper 中持久化原始配置。部分失败保留恢复记录，仅重试未完成的恢复任务。不会盲目写入 127.0.0.1。
- DNS 设置仍可生成两种 Mihomo 片段：全部域名经 GLOBAL，或国内外分流。片段不会写入客户端，也不替换节点，粘贴不是开启条件。国外 DNS 若仍直连会拒绝开启；走另一个具体代理节点则放行该节点端点。节点域名的直连引导只在保护开启前可用，保护中会被阻断，优先使用 IP 节点。
- 结构化日志只在本机保存，可查看和导出；记录操作 ID、结果、耗时、错误类别、版本及平台，不写入原始错误、IP、凭据、命令参数和用户路径。App 与管理员 helper 分别保留四份约 512 KiB 轮转文件，导出合并两者并显示收集完整性；Windows/Linux 收集系统日志可能需要授权。前端异常、自动隔断与恢复也会记录。

**仍属实验实现，尚未完成真实断线与断流验收。** 防回落规则在开启确认后持续驻留内核，不等待出口轮询；常驻 helper 约每 2 秒检查代理状态，检查耗时会延长实际间隔。异常转为完全隔断仍有检测与执行间隔。界面本地巡检约每 3 秒，获授权的外部观测默认每 15 秒、保护期间约每 10 秒更新，外部查询不控制新模式的隔断。`configurationActive` 仅表示规则、优先级和内容回读匹配，`enforcementVerified` 不由诊断自动设为 true。

已加载的规则不会因 UI 崩溃自动解除；对应系统的常驻服务会尝试重启 helper。不能承诺 macOS 开机早期、其他 root 软件改写 PF 或系统故障时零泄漏。仅支持可读取的单个内联 IPv4 节点；provider、插件、链式代理、负载均衡和端口跳跃暂不适配。切换节点、端口或 DNS 路径需要先停止保护，再重新确认。只是关掉再打开 TUN、utun 名称变化，会用原来的计划自动继续，不扩大白名单。

正常恢复：在界面选择停止保护／解除隔断。macOS 卸下本工具的 launchd job 和 PF anchor，不关闭全局 PF，也不执行 `pfctl -d`。Linux 只删除本工具的 nftables 表。Windows 只删除本工具的防火墙组。如果界面无法打开，可执行已安装 helper 的 `--emergency-release`。macOS 上是 `sudo /var/db/io.wujian.firewall/tunnel-helper --emergency-release`；不要使用 `pfctl -d` 或清空系统防火墙。Linux 和 Windows 的这条恢复路径还没有在真实机器上运行过。旧版本已开启的基线监测保留原有故障处理，停止后再次开启使用新的全局保护。

本工具不能保证账号不被封禁，也不能证明所有应用、浏览器或 DNS 请求采用同一路径。国家未知时不会默认成美国。时区行“设置”提供“跟随出口 IP 时区”和“手动自定义时区”。选择跟随会保存模式并允许 HTTPS 出口查询，经同一检测路径先向 `https://ipinfo.io/{出口IP}/json` 取城市 IANA 时区，失败时再查 `https://ipwho.is/{出口IP}`，前后核对出口与本机网络配置后记录目标时区；不按国家猜城市。macOS 第一次需要改时区、开启保护、修改 DNS 或阻断 IPv6 时申请一次管理员权限，并安装常驻 root 组件。之后这些操作都由该组件完成，不再弹授权。取消后再次打开不会询问；明确点击这些操作才会再问。组件已安装但没有响应时，不会重复弹授权。同一出口复用已查询时区，检测到出口变化后重新匹配；手动模式保留自定义目标。首次实际修改前备份原时区，时区相同不重复申请权限。查询失败保留当前时区。跟随在新全局保护期间继续运行，隔断期间暂停；全局保护不以时区作为断网条件。恢复原时区会停止跟随。

## 开始测试

请先阅读 [测试指南](docs/测试指南.md)，从只读检查开始。需要断流的用例应在可本地恢复的测试机或虚拟机执行。

| 平台 | 原生规则 | DNS 修改要求 |
| --- | --- | --- |
| macOS 14+ | PF 独立 anchor；主规则为空时加载系统入口，已有主规则不覆盖 | networksetup；保留 DHCP/静态 DNS 原值 |
| Windows | Windows Defender Firewall / PowerShell，需 UAC | 活动物理网卡 IPv4 DNS，保留静态值/自动模式 |
| Linux | nftables 独立 inet 表，需 nftables 与 polkit/pkexec | 仅支持 systemd-resolved/resolvectl；恢复本次修改前的运行时每接口 DNS 列表 |

已执行的本机验证和剩余实机测试见 [开发进度](docs/开发进度.md)。Windows/Linux 的 CI 编译通过也不等于已完成真实代理客户端断流验收。

出口地区使用本机 `Country.mmdb` 离线查询，不自动下载或分发数据库。可在设置指定已有本机数据库的绝对路径（无需安装 Clash）；留空时从 Clash Verge Rev/Mihomo/Clash 常见用户目录查找。找不到时显示未知。开启全局保护时另用桌面用户目录里的这份数据库核对节点地址是否在国外，只在准备计划时查一次，不轮询出口 IP。设置里另选的数据库只影响出口地区显示。

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

`pnpm tauri build` 只构建当前平台。GitHub Actions 提供三端检查；测试版打包通过手动 Release workflow 生成未发布草稿，安装包仅上传该草稿，附 SHA-256 校验文件与构建提交；不上传 Actions 安装包 artifact，不自动公开发布。macOS 使用 ad-hoc 签名，未做 Apple 公证；Windows 未做代码签名。

`native/macos/` 中的 Network Extension 是独立研究组件，当前桌面包不安装或启用它。`docs/` 其他方案文档保留为设计资料，以本 README 和测试指南的当前行为为准。

## 许可证

[MIT](LICENSE)，版权归 AyuTao；第三方资料见 [NOTICE](NOTICE.md)。
