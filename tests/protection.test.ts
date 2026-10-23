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
    expect(protectionLabel(status)).toBe("保护未确认");
    expect(protectionLabel(undefined)).toBe("状态未确认");
    expect(
      protectionLabel({ ...status, isolationPending: false, error: null }),
    ).toBe("保护未确认");
  });
  it("distinguishes configured rules from real packet enforcement", () => {
    expect(
      protectionLabel({
        armed: true,
        isolationPending: true,
        error: null,
        receipt: {
          policyMode: "isolation",
          backend: "fixture",
          configurationActive: true,
          enforcementVerified: false,
          generation: null,
          checkedAt: "",
          detail: "",
        },
      }),
    ).toBe("隔断已加载");
  });
  it("keeps DNS recovery and IPv6-only configuration separate from full isolation", () => {
    const base: ProtectionStatus = {
      armed: false,
      isolationPending: false,
      error: null,
      receipt: null,
    };
    expect(protectionLabel({ ...base, dnsModified: true })).toBe(
      "有配置待恢复",
    );
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
    ).toBe("仅 IPv6 阻断");
  });
  it("never confuses a tunnel permit or an armed flag with whole-machine isolation", () => {
    const status: ProtectionStatus = {
      armed: true,
      isolationPending: false,
      tunnelGuardConfirmed: true,
      error: null,
      receipt: {
        policyMode: "tunnel",
        backend: "fixture",
        configurationActive: true,
        enforcementVerified: false,
        generation: "test",
        checkedAt: "",
        detail: "",
      },
    };
    expect(protectionLabel(status)).toBe("保护已开启");
    expect(protectionLabel({ ...status, receipt: null })).toBe("保护未确认");
    expect(protectionLabel({ ...status, isolationPending: true })).toBe(
      "隔断未确认",
    );
  });
});
