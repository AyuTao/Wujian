import type { PhysicalDns } from "./types";

/** Mainland public resolvers. Loopback, LAN, and overseas DNS stay allowed. */
const MAINLAND_PUBLIC_DNS = new Set([
  "114.114.114.114",
  "114.114.115.115",
  "223.5.5.5",
  "223.6.6.6",
  "119.29.29.29",
  "119.28.28.28",
  "182.254.116.116",
  "182.254.118.118",
  "180.76.76.76",
  "1.2.4.8",
  "210.2.4.8",
  "101.226.4.6",
  "123.125.81.6",
]);

export const OVERSEAS_SYSTEM_DNS = ["1.1.1.1", "1.0.0.1"] as const;

export function mainlandPublicDns(servers: readonly string[]): string[] {
  const found: string[] = [];
  for (const server of servers) {
    const ip = server.split("%")[0]?.trim();
    if (ip && MAINLAND_PUBLIC_DNS.has(ip) && !found.includes(ip))
      found.push(ip);
  }
  return found;
}

/** Saved adapter values never fall back to VPN/TUN effective resolvers. */
export function physicalDnsDisplay(
  physical: PhysicalDns | undefined,
  effective: readonly string[] = [],
) {
  const readable = Boolean(
    physical && !physical.error && physical.adapters.length,
  );
  const servers = readable
    ? [...new Set(physical!.adapters.flatMap((adapter) => adapter.servers))]
    : [];
  const automatic =
    readable && physical!.adapters.some((adapter) => adapter.automatic);
  const text = !readable
    ? physical?.error || "网卡配置未知"
    : [servers.join("、"), automatic ? "自动 DNS" : ""]
        .filter(Boolean)
        .join(" / ");
  const detail = !readable
    ? text
    : physical!.adapters
        .map(
          (adapter) =>
            `${adapter.service}：${adapter.automatic ? "自动 DNS" : adapter.servers.join("、")}`,
        )
        .join("；");
  const mainland = mainlandPublicDns(servers);
  const offerOverseas = Boolean(
    readable &&
    (mainland.length || (automatic && mainlandPublicDns(effective).length)),
  );
  return {
    readable,
    offerOverseas,
    servers,
    text,
    detail,
    mainland,
  };
}
