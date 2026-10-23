import { describe, expect, it } from "vitest";
import { redactReport, redactText, summarizeChecks } from "../src/lib/report";
import type { AppSnapshot, CheckResult } from "../src/lib/types";
const check = (status: CheckResult["status"]): CheckResult => ({
  id: "test",
  label: "check",
  status,
  value: "",
  detail: "",
  suggestion: null,
  scope: "test",
  source: "fixture",
  observedAt: "2026-10-21T12:00:00Z",
  integrity: "local_verified",
});
describe("evidence aggregation", () => {
  it("never labels incomplete evidence as a match", () => {
    for (const state of [
      "unknown",
      "review",
      "stale",
      "not_run",
      "running",
    ] as const)
      expect(summarizeChecks([check("match"), check(state)])).not.toBe("match");
  });
  it("configuration observations are informational, never an overall pass", () => {
    expect(summarizeChecks([check("observed"), check("match")])).toBe(
      "observed",
    );
    expect(summarizeChecks([check("observed"), check("unknown")])).toBe(
      "unknown",
    );
  });
  it("distinguishes not run and not applicable", () => {
    expect(summarizeChecks([])).toBe("not_run");
    expect(summarizeChecks([check("not_applicable")])).toBe("not_applicable");
  });
});
describe("default report redaction", () => {
  it("removes addresses and sensitive local paths but keeps evidence timestamps", () => {
    expect(redactText("当前 IP 203.0.113.21")).not.toContain("203.0.113.21");
    expect(redactText("DNS 2001:db8::12")).not.toContain("2001:db8::12");
    expect(redactText("/Users/private-user/.local/bin/claude")).not.toContain(
      "private-user",
      "private-nic-name",
      "192.0.2.53",
    );
    expect(redactText("2026-10-21T12:00:00Z")).toBe("2026-10-21T12:00:00Z");
  });
  it("does not export tool paths or proxy endpoints", () => {
    const snapshot: AppSnapshot = {
      tools: [
        {
          id: "x",
          name: "Claude Code",
          kind: "cli",
          installed: true,
          path: "/Users/private-user/claude",
          canLaunch: false,
          protection: "unsupported",
          note: "",
        },
      ],
      checks: [
        {
          ...check("observed"),
          endpoint: {
            address: "198.51.100.88",
            countryCode: "US",
            location: "US · resolver 198.51.100.89",
          },
        },
      ],
      platform: "test",
      version: "test",
      networkEpoch: 0,
      observedAt: "",
      proxySummary: "",
      dnsServers: ["203.0.113.12"],
      physicalDns: {
        adapters: [
          {
            service: "private-nic-name",
            automatic: false,
            servers: ["192.0.2.53"],
          },
        ],
        observedAt: "",
        error: null,
        runtimeOnly: false,
      },
      settings: {
        theme: "system",
        externalIpConsent: false,
        dnsHttpConsent: false,
        proxyUrl: "http://secret-host:7890",
        monitorIntervalSec: 0,
        historyDays: 7,
        pinnedEgressIp: "198.51.100.99",
        geoipDatabasePath: "/Users/private/geo/Country.mmdb",
      },
      events: [],
    };
    const json = JSON.stringify(redactReport(snapshot));
    for (const secret of [
      "private-user",
      "private-nic-name",
      "192.0.2.53",
      "/Users/private/geo/Country.mmdb",
      "secret-host",
      "203.0.113.12",
      "198.51.100.99",
      "198.51.100.88",
      "198.51.100.89",
    ])
      expect(json).not.toContain(secret);
    expect(json).toContain("unsupported");
  });
});
