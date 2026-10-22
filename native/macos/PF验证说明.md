# 无个人开发者证书的 macOS 隔断方向

用户要求：开源项目不依赖其个人 Apple 开发者证书。主应用配置采用 Tauri 的 ad-hoc 签名 `signingIdentity: "-"`；原 Network Extension 代码仅作为实验备份。普通应用的下载隔离与系统网络过滤权限分开处理。

`xattr -dr com.apple.quarantine "/Applications/无间道.app"` 是移除指定应用下载隔离属性的命令示例，不会取得管理员权限或 Network Extension entitlement。当前未执行该命令；也不应把移除所有扩展属性当作系统过滤安装。

优先验证系统自带 PF：本机管理员授权后加载本软件专属规则，以离线 CN 网段表限制公网目标。PF 不要求调用者携带 Apple Network Extension 的开发者证书；仍需要管理员权限，不能描述为零授权隔断。

当前状态：已核对本机 `pfctl(8)`、`pf.conf(5)` 和 `xattr(1)` 手册及 `/etc/pf.conf`，仅只读。PF 执行器已接入共用 Rust 模块与应用入口，但尚未通过实机断流验收；没有修改系统规则、清除连接、安装后台服务或更改隔离属性。主应用保持保护未实现状态。

实现必须验证：

- 本软件专属 anchor 确实被当前运行的主规则引用；不能只加载一个未被调用的 anchor 就宣称生效。
- 已有 state 可能先于新规则匹配；必须验证已有 TCP/UDP 的断流方法，不默认清空其他软件的全部状态。
- Clash/Tailscale TUN、代理外层与内层、IPv4/IPv6、WebRTC UDP 均须实测。允许 CN 或局域网目标不等于这些目标上的中继不能访问海外。
- 单独管理本软件的规则与 PF enable 引用，解除时不整体禁用 PF、不覆盖其他规则。用户解除路径在本机可用，不能依赖在线查询。
- 请求管理员授权前，先生成可审查规则、目标范围及恢复步骤。检测请求的受限路径和异常到确认恢复的联动另行实现。

先完成这条路径的隔离测试验收，再向主应用报告真实保护能力。当前不能宣称 PF 已完成实机隔断验收。

参考：[Tauri ad-hoc 签名](https://v2.tauri.app/distribute/sign/macos/#ad-hoc-signing)、本机 `man pfctl` / `man pf.conf` / `man xattr`。
