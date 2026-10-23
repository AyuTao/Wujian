import type { CheckResult } from "./types";
import {
  hasObservedValue,
  isCurrent,
  isIpAddress,
  probeIssue,
} from "./probeDisplay";

export function hasEgressAddress(check?: CheckResult): check is CheckResult {
  return hasObservedValue(check) && isIpAddress(check.value);
}
export function egressDisplay(
  check: CheckResult | undefined,
  region: CheckResult | undefined,
  now = Date.now(),
  previous?: { ip?: CheckResult; region?: CheckResult },
) {
  // The raw observation remains useful when the policy gate has expired or failed.
  const record = hasEgressAddress(check) ? check : previous?.ip;
  const country = record === check ? region : previous?.region;
  const code = hasObservedValue(country)
    ? (country.value.match(/\(([A-Z]{2})\)/)?.[1] ?? "")
    : "";
  if (!record || !hasEgressAddress(record))
    return {
      text: probeIssue(check, "出口"),
      countryCode: "",
      current: false,
      title: check?.detail ?? "",
    };
  const current = record === check && isCurrent(record, now);
  const text = `${record.value} (${code || "地区未知"})`;
  return {
    text: current ? text : `上次：${text}`,
    countryCode: code,
    current,
    title: [
      check?.detail,
      !current && `上次成功：${record.observedAt}`,
      record !== check && probeIssue(check, "出口"),
    ]
      .filter(Boolean)
      .join("\n"),
  };
}
