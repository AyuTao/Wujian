import type { ProtectionStatus } from "./types";

export function protectionLabel(status?: ProtectionStatus): string {
  if (!status) return "防护状态未确认";
  if (status.error) return "隔离未确认 · 请查看错误并授权核验";
  if (status.isolationPending) {
    return status.receipt?.configurationActive
      ? "隔离规则已加载 · 实际流量覆盖待验收"
      : "隔离未确认 · 等待管理员授权或重试";
  }
  if (status.armed) return "监测中 · 未确认系统隔离";
  if (status.ipv6Filtering && status.receipt?.configurationActive)
    return "IPv6 阻断规则已回读 · 未开启监测";
  if (status.filterMayExist || status.dnsModified)
    return "本工具有待恢复的配置";
  return "未启用防护";
}
