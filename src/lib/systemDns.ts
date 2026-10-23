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
