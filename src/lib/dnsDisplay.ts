import type { CheckResult } from "./types";
import {
  hasObservedValue,
  isCurrent,
  isIpAddress,
  probeIssue,
} from "./probeDisplay";

export function dnsEndpoint(check?: CheckResult): CheckResult["endpoint"] {
  if (!hasObservedValue(check)) return undefined;
  if (check.endpoint && isIpAddress(check.endpoint.address))
    return check.endpoint;
  // Older native binaries return a validated address and location in value.
  const [address, ...location] = check.value.split(" · ");
  return isIpAddress(address)
    ? {
        address,
        countryCode: null,
        location: location.join(" · ") || "地区未知",
      }
    : undefined;
}

export function dnsDisplay(
  check: CheckResult | undefined,
  consented: boolean,
  now = Date.now(),
  previous?: CheckResult,
) {
  const note =
    "本次 DNS 出口采样；IP 不必与网站出口相同，也不等同于浏览器的全部解析路径。";
  const title = [note, check?.detail, check?.scope].filter(Boolean).join("\n");
  if (!consented)
    return {
      text: "未开启 DNS 出口观测",
      badge: "未检测",
      countryCode: "",
      current: false,
      title,
    };
  const record = dnsEndpoint(check) ? check : previous;
  const endpoint = dnsEndpoint(record);
  if (!record || !endpoint)
    return {
      text: probeIssue(check, "DNS"),
      badge: check?.status === "not_run" ? "未检测" : "失败",
      countryCode: "",
      current: false,
      title,
    };
  const current = record === check && isCurrent(record, now);
  const text = `${endpoint.address} · ${endpoint.location || "地区未知"}`;
  return {
    text: current ? text : `上次：${text}`,
    badge: current ? "PASS" : record !== check ? "上次" : "待更新",
    countryCode: endpoint.countryCode ?? "",
    current,
    title: [
      title,
      !current && `上次成功：${record.observedAt}`,
      record !== check && probeIssue(check, "DNS"),
    ]
      .filter(Boolean)
      .join("\n"),
  };
}
