import type { CheckResult } from "./types";

export function isIpAddress(value: string): boolean {
  const parts = value.split(".");
  if (
    parts.length === 4 &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
  )
    return true;
  return (
    value.includes(":") &&
    /^[0-9a-f:]+(?:[0-9.]+)?$/i.test(value) &&
    value.split(":").length >= 3
  );
}
export function hasObservedValue(check?: CheckResult): check is CheckResult {
  return Boolean(
    check && ["observed", "review", "match", "stale"].includes(check.status),
  );
}
export function isCurrent(check: CheckResult, now: number): boolean {
  const age = now - Date.parse(check.observedAt);
  return check.status !== "stale" && age >= 0 && age < 30_000;
}
export function probeIssue(
  check: CheckResult | undefined,
  label: string,
): string {
  if (!check) return `${label}待检测`;
  const reason = `${check.value} ${check.detail}`;
  if (reason.includes("隔离期间")) return "隔离中，暂停检测";
  if (reason.includes("授权")) return `${label}检测未授权`;
  if (reason.includes("明确检测代理") || reason.includes("填写要使用的代理"))
    return "请在设置指定检测代理";
  if (reason.includes("超时") || reason.includes("超过"))
    return `${label}检测超时`;
  const http = reason.match(/HTTP (\d{3})/);
  if (http) return `${label}检测服务 HTTP ${http[1]}`;
  if (
    reason.includes("接口缺少") ||
    reason.includes("JSON") ||
    reason.includes("无效的 DNS")
  )
    return `${label}检测服务响应异常`;
  if (reason.includes("连接") || reason.includes("TLS"))
    return `${label}检测连接失败`;
  return `${label}检测失败`;
}
