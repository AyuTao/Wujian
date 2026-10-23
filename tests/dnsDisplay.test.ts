import { describe, expect, it } from "vitest";
import { dnsDisplay } from "../src/lib/dnsDisplay";
import type { CheckResult } from "../src/lib/types";

const now = Date.parse("2026-10-23T01:00:00Z");
const observation: CheckResult = {
  id: "dns-observation",
  label: "DNS 解析出口",
  status: "observed",
  value: "74.125.181.153 · United States, Los Angeles",
  detail: "HTTP 辅助采样，仅供参考",
  suggestion: null,
  scope: "所选代理路径",
  source: "ip-api DNS",
  observedAt: new Date(now).toISOString(),
  integrity: "http_unverified",
  endpoint: {
    address: "74.125.181.153",
    countryCode: "US",
    location: "United States, Los Angeles",
  },
};

describe("DNS row", () => {
  it("reads successful observations from an older native backend", () => {
    const legacy = { ...observation, endpoint: undefined };
    const result = dnsDisplay(legacy, true, now);
    expect(result.text).toBe("74.125.181.153 · United States, Los Angeles");
    expect(result.current).toBe(true);
  });
  it("retains the last observation after a failed refresh and states the real error", () => {
    const failure = {
      ...observation,
      status: "unknown" as const,
      endpoint: undefined,
      value: "本次解析出口未确认",
      detail: "指定检测服务请求超时",
    };
    const result = dnsDisplay(failure, true, now + 1000, observation);
    expect(result.text).toMatch(/^上次：74\.125\.181\.153/);
    expect(result.current).toBe(false);
    expect(result.title).toContain("DNS检测超时");
    expect(dnsDisplay(failure, true, now).text).toBe("DNS检测超时");
    expect(dnsDisplay(failure, false, now, observation).text).toBe(
      "未开启 DNS 出口观测",
    );
  });

  it("shows the observed resolver and region without substituting a configured or website IP", () => {
    const result = dnsDisplay(observation, true, now);
    expect(result.text).toBe("74.125.181.153 · United States, Los Angeles");
    expect(result.countryCode).toBe("US");
    expect(result.current).toBe(true);
    expect(result.badge).toBe("PASS");
  });
  it("does not pretend a measurement exists without consent or a response", () => {
    expect(dnsDisplay(observation, false, now).current).toBe(false);
    expect(dnsDisplay(undefined, true, now).text).toBe("DNS待检测");
    expect(
      dnsDisplay({ ...observation, status: "unknown" }, true, now).current,
    ).toBe(false);
  });
  it("does not reuse an expired or invalidated result as the current resolver", () => {
    for (const time of [now + 30_000, now - 1]) {
      const result = dnsDisplay(observation, true, time);
      expect(result.current).toBe(false);
      expect(result.badge).toBe("待更新");
      expect(result.text).toMatch(/^上次：/);
    }
    expect(
      dnsDisplay({ ...observation, status: "stale" }, true, now).current,
    ).toBe(false);
  });
  it("keeps unknown location unknown and supports an IPv6 upstream resolver", () => {
    const result = dnsDisplay(
      {
        ...observation,
        endpoint: {
          address: "2001:4860:4860::8888",
          countryCode: null,
          location: "",
        },
      },
      true,
      now,
    );
    expect(result.text).toBe("2001:4860:4860::8888 · 地区未知");
    expect(result.countryCode).toBe("");
  });
});
