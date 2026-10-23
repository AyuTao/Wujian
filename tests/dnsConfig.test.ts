import { describe, expect, it } from "vitest";
import {
  mihomoDnsFragment,
  mihomoGlobalDnsFragment,
  systemDnsAddresses,
} from "../src/lib/dnsConfig";

describe("DNS configuration", () => {
  it("global guard clears split policies and pins resolver traffic to GLOBAL", () => {
    const yaml = mihomoGlobalDnsFragment("https://1.1.1.1/dns-query");
    expect(yaml).toContain("nameserver-policy: {}");
    expect(yaml).toContain(
      'nameserver:\n    - "https://1.1.1.1/dns-query#GLOBAL"',
    );
    expect(yaml).toContain("fallback: []");
    expect(yaml).not.toContain("geosite:cn");
    expect(() =>
      mihomoGlobalDnsFragment("https://dns.example/dns-query"),
    ).toThrow();
    expect(() =>
      mihomoGlobalDnsFragment("https://1.1.1.1/dns-query#DIRECT"),
    ).toThrow();
  });
  it("accepts domestic system resolvers without imposing a country policy", () => {
    expect(systemDnsAddresses("223.5.5.5，114.114.114.114 223.5.5.5")).toEqual([
      "223.5.5.5",
      "114.114.114.114",
    ]);
    for (const value of [
      "",
      "1.1.1.999",
      "https://dns.example/dns-query",
      "1.1.1.1;reboot",
    ]) {
      expect(() => systemDnsAddresses(value)).toThrow();
    }
  });
  it("keeps domestic queries direct and overseas queries on the selected group", () => {
    const yaml = mihomoDnsFragment(
      "114.114.114.114",
      "https://1.1.1.1/dns-query",
      "🌍选择代理节点",
    );
    expect(yaml).toContain('"geosite:cn":\n      - "114.114.114.114#DIRECT"');
    expect(yaml).toContain(
      'direct-nameserver:\n    - "114.114.114.114#DIRECT"',
    );
    expect(yaml).toContain('"https://1.1.1.1/dns-query#🌍选择代理节点"');
    expect(yaml).not.toMatch(/^rules:|^proxies:|^tun:/m);
  });
  it("rejects a missing proxy group and resolver options that could change the intended route", () => {
    for (const group of [
      "",
      "DIRECT",
      "RULES",
      "name#DIRECT",
      "name&h3=true",
      "x\ny",
    ]) {
      expect(() =>
        mihomoDnsFragment("223.5.5.5", "https://8.8.8.8/dns-query", group),
      ).toThrow();
    }
    for (const resolver of [
      "http://1.1.1.1/dns-query",
      "https://1.1.1.1/dns-query#DIRECT",
      "https://user:pass@example.com/dns-query",
    ]) {
      expect(() => mihomoDnsFragment("223.5.5.5", resolver, "Proxy")).toThrow();
    }
  });
  it("quotes group names without allowing YAML injection", () => {
    const yaml = mihomoDnsFragment(
      "223.5.5.5",
      "https://1.1.1.1/dns-query",
      'node: "west"',
    );
    expect(yaml).toContain(
      JSON.stringify('https://1.1.1.1/dns-query#node: "west"'),
    );
  });
});
