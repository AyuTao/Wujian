import { describe, expect, it } from "vitest";
import {
  mainlandPublicDns,
  OVERSEAS_SYSTEM_DNS,
  physicalDnsDisplay,
} from "../src/lib/systemDns";

describe("system DNS", () => {
  it("flags known mainland public resolvers and ignores loopback and overseas DNS", () => {
    expect(
      mainlandPublicDns([
        "114.114.114.114",
        "127.0.0.1",
        "1.1.1.1",
        "8.8.8.8",
        "8.8.4.4",
      ]),
    ).toEqual(["114.114.114.114"]);
    expect(mainlandPublicDns(["223.5.5.5", "223.5.5.5"])).toEqual([
      "223.5.5.5",
    ]);
    expect(mainlandPublicDns(["119.29.29.29%en0"])).toEqual(["119.29.29.29"]);
    expect(mainlandPublicDns(["127.0.0.1", "192.168.10.1", "1.1.1.1"])).toEqual(
      [],
    );
    expect(mainlandPublicDns([])).toEqual([]);
    expect(mainlandPublicDns([...OVERSEAS_SYSTEM_DNS])).toEqual([]);
  });
});

describe("physical and effective DNS are distinct", () => {
  const physical = (servers: string[], automatic = false) => ({
    adapters: [{ service: "Wi-Fi", automatic, servers }],
    observedAt: "2026-10-23T14:34:10Z",
    error: null,
    runtimeOnly: false,
  });
  it("keeps committed physical DNS when TUN exposes a domestic effective resolver", () => {
    const view = physicalDnsDisplay(physical(["1.1.1.1", "1.0.0.1"]), [
      "114.114.114.114",
    ]);
    expect(view.servers).toEqual(["1.1.1.1", "1.0.0.1"]);
    expect(view.offerOverseas).toBe(false);
    expect(view.mainland).toEqual([]);
  });
  it("offers changing automatic DNS if the effective entry is domestic", () => {
    const view = physicalDnsDisplay(physical([], true), ["114.114.114.114"]);
    expect(view.text).toBe("自动 DNS");
    expect(view.offerOverseas).toBe(true);
  });
  it("exposes a physical overwrite instead of continuing to show the last desired values", () => {
    const view = physicalDnsDisplay(physical(["114.114.114.114"]), [
      "127.0.0.1",
    ]);
    expect(view.mainland).toEqual(["114.114.114.114"]);
    expect(view.detail).toContain("Wi-Fi：114.114.114.114");
    expect(view.offerOverseas).toBe(true);
  });
  it("never substitutes effective DNS for an unavailable physical read", () => {
    for (const state of [
      undefined,
      { ...physical(["1.1.1.1"]), error: "读取失败" },
    ]) {
      const view = physicalDnsDisplay(state, ["114.114.114.114"]);
      expect(view.readable).toBe(false);
      expect(view.servers).toEqual([]);
      expect(view.offerOverseas).toBe(false);
    }
  });
  it("includes multiple adapters and automatic mode without duplicates", () => {
    const state = physical(["1.1.1.1"]);
    state.adapters.push({
      service: "Offline Ethernet",
      automatic: true,
      servers: [],
    });
    state.adapters.push({
      service: "USB",
      automatic: false,
      servers: ["1.1.1.1"],
    });
    expect(physicalDnsDisplay(state).text).toBe("1.1.1.1 / 自动 DNS");
    expect(physicalDnsDisplay(state).detail).toContain(
      "Offline Ethernet：自动 DNS",
    );
  });
});
