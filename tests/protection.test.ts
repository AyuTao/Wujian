import { describe, expect, it } from "vitest";
import {
  protectionLabel,
  needsProtectionRecovery,
} from "../src/lib/protection";
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

describe("independent IPv6 UI", () => {
  const base: ProtectionStatus = {
    armed: false,
    isolationPending: false,
    filterMayExist: true,
    receipt: null,
    error: null,
  };
  it("does not offer whole-machine isolation recovery for independent IPv6, including after restart or failure", () => {
    expect(needsProtectionRecovery(base)).toBe(true);
    expect(needsProtectionRecovery({ ...base, ipv6Filtering: true })).toBe(
      false,
    );
    const ipv6 = { ...base, ipv6Only: true };
    expect(needsProtectionRecovery(ipv6)).toBe(false);
    expect(needsProtectionRecovery({ ...ipv6, error: "授权取消" })).toBe(false);
    expect(protectionLabel(ipv6)).toBe("IPv6 规则待核验");
    expect(needsProtectionRecovery({ ...ipv6, isolationPending: true })).toBe(
      true,
    );
  });
});
