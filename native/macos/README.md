# macOS 隔断技术验证（Network Extension 实验备份）

用户要求不依赖个人 Apple 开发者证书，主方向已改为 macOS 自带 PF 与本机管理员授权，具体约束见 [PF 验证说明](PF验证说明.md)。此目录原有 Network Extension 源码仅保留为实验备份，不是产品必装依赖。

当前 NE 源码未安装、未接入主应用、未通过实机断流验收。产品界面仍保持一页，验证宿主仅供开发使用。

`GuardCore` 通过不可变前缀树判定原始 IPv4/IPv6 包；`PacketFilterProvider.swift` 将判定接入 Apple NEFilterPacketProvider。限制模式保留 CN 和本地网络，拒绝非 CN/未知公网地址及公网 IPv6，入站按来源判断，规则不依赖 TCP 新建连接标志。数据无效时 Provider 拒绝所有 IP 包。

数据库只做地址分类，可能缺失或过期。Country 库不提供城市／时区；国家分类不能证明 AI 服务看到的出口，也不能证明 DNS 或 WebRTC 无泄露。该模式不自动触发、检测或恢复。允许 CN、局域网、CGNAT/Tailscale 地址可能允许这些地址上的代理或中继，必须实测与现有 TUN 的交互，不能称为完整服务隔绝。

## 编译验证

```sh
swift test --package-path native/macos/GuardCore
python3 native/macos/build.py --typecheck-only
python3 native/macos/build.py --mmdb /path/to/Country.mmdb
```

默认只生成不可安装的本地 ad-hoc 编译验证包，激活按钮会拒绝安装。脚本不会安装、开启过滤或更改网络。CN 表和构建目录均已忽略，不分发用户现有数据库。数据库许可与更新源在发布前另行确定。

可安装构建还需 `--sign-identity`、`--host-profile`、`--extension-profile`。宿主 Bundle ID 为 `io.wujian.guard.host`，扩展为 `io.wujian.guard.packet`；描述文件必须授权相应 Network Extension 能力，同属一团队且未过期。非 App Store 发布需合适的 Developer ID 签名；构建后仍须完成分发签名／公证和系统授权。现有证书不等于已拥有对应描述文件。

开启会影响整机国外节点连接，只应在隔离测试机执行；宿主提供本机解除入口，不依赖网络。`--status` 只报告配置，明确返回 `enforcementVerified: false`，不把 NEFilterManager.isEnabled 当作实际断流验收。

待实机验收：已有 TCP/QUIC 连接、UDP/STUN、IPv6、Clash/Tailscale TUN、代理节点、休眠／重连、Provider 异常和卸载恢复。自动监测到隔断及确认恢复仍待接入。

参考：[Apple 部署说明](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)、[MMDB 文件规范](https://maxmind.github.io/MaxMind-DB/)。
