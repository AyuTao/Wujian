import { describe, expect, it } from "vitest";
import { protectionLabel } from "../src/lib/protection";
import type { ProtectionStatus } from "../src/lib/types";

describe("native isolation status", () => {
  it("does not report a cut-off from an armed flag or a failed operation", () => {
    const status: ProtectionStatus = {
      armed: true,
      isolationPending: true,
      receipt: null,
      error: "授权取消",
    };
    expect(protectionLabel(status)).toContain("未确认");
    expect(protectionLabel(undefined)).toContain("未确认");
    expect(
      protectionLabel({ ...status, isolationPending: false, error: null }),
    ).toContain("未确认系统隔离");
  });
  it("distinguishes configured rules from real packet enforcement", () => {
    expect(
      protectionLabel({
        armed: true,
        isolationPending: true,
        error: null,
        receipt: {
          backend: "fixture",
          configurationActive: true,
          enforcementVerified: false,
          generation: null,
          checkedAt: "",
          detail: "",
        },
      }),
    ).toContain("实际流量覆盖待验收");
  });
  it("keeps DNS recovery and IPv6-only configuration separate from full isolation", () => {
    const base: ProtectionStatus = {
      armed: false,
      isolationPending: false,
      error: null,
      receipt: null,
    };
    expect(protectionLabel({ ...base, dnsModified: true })).toContain("待恢复");
    expect(
      protectionLabel({
        ...base,
        ipv6Filtering: true,
        receipt: {
          backend: "fixture",
          configurationActive: true,
          enforcementVerified: false,
          generation: null,
          checkedAt: "",
          detail: "",
        },
      }),
    ).toContain("未开启监测");
  });
});
