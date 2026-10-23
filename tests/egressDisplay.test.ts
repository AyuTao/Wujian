import { describe, expect, it } from "vitest";
import { egressDisplay } from "../src/lib/egressDisplay";
import type { CheckResult } from "../src/lib/types";
const now = Date.parse("2026-10-23T01:00:00Z");
const ip: CheckResult = {
  id: "egress-ipv4",
  label: "IP",
  status: "review",
  value: "203.0.113.8",
  observedAt: new Date(now).toISOString(),
  integrity: "tls_verified",
  detail: "HTTPS 出口请求",
  scope: "所选代理",
  source: "ipify",
  suggestion: null,
};
const region = {
  ...ip,
  id: "egress-region",
  value: "美国 (US)",
  integrity: "local_verified" as const,
};
describe("egress observation display", () => {
  it("keeps the measured IP visible after policy freshness expires", () => {
    expect(egressDisplay(ip, region, now).text).toBe("203.0.113.8 (US)");
    const expired = egressDisplay(ip, region, now + 30_001);
    expect(expired.text).toBe("上次：203.0.113.8 (US)");
    expect(expired.current).toBe(false);
  });
  it("keeps prior success separate from a failed current request", () => {
    const failed = {
      ...ip,
      status: "unknown" as const,
      value: "本次出口未确认",
      detail: "检测服务返回 HTTP 503",
    };
    const view = egressDisplay(failed, undefined, now, { ip, region });
    expect(view.text).toBe("上次：203.0.113.8 (US)");
    expect(view.title).toContain("HTTP 503");
    expect(view.current).toBe(false);
    expect(egressDisplay(failed, undefined, now).text).toBe(
      "出口检测服务 HTTP 503",
    );
  });
  it("shows a known IP even when geolocation is unavailable", () => {
    expect(egressDisplay(ip, undefined, now).text).toBe(
      "203.0.113.8 (地区未知)",
    );
  });
});
