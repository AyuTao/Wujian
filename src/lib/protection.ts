import type { ProtectionStatus } from "./types";

export function protectionLabel(status?: ProtectionStatus): string {
  if (!status) return "状态未确认";
  if (status.error) return "保护未确认";
  if (status.isolationPending) {
    return status.receipt?.configurationActive &&
      status.receipt.policyMode === "isolation"
      ? "隔断已加载"
      : "隔断未确认";
  }
  if (status.armed)
    return status.tunnelGuardConfirmed &&
      status.receipt?.configurationActive &&
      status.receipt.policyMode === "tunnel"
      ? "保护已开启"
      : "保护未确认";
  if (status.ipv6Filtering && status.receipt?.configurationActive)
    return "仅 IPv6 阻断";
  if (status.filterMayExist || status.dnsModified) return "有配置待恢复";
  return "未开启";
}
