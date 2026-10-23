function ipv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255)
  );
}

export function systemDnsAddresses(value: string): string[] {
  const addresses = [
    ...new Set(
      value
        .trim()
        .split(/[\s,，、]+/)
        .filter(Boolean),
    ),
  ];
  if (
    !addresses.length ||
    addresses.length > 4 ||
    addresses.some((ip) => !ipv4(ip))
  ) {
    throw new Error("请输入 1 至 4 个 IPv4 DNS 地址，用逗号或空格分隔。");
  }
  return addresses;
}

/** DNS-only merge fragment: never replaces the user's proxies or routing rules. */
export function mihomoDnsFragment(
  domestic: string,
  overseas: string,
  proxyGroup: string,
): string {
  domestic = domestic.trim();
  overseas = overseas.trim();
  proxyGroup = proxyGroup.trim();
  if (!ipv4(domestic))
    throw new Error(
      "国内 DNS 请填写 IPv4 地址，例如 223.5.5.5 或 114.114.114.114。",
    );
  let url: URL;
  try {
    url = new URL(overseas);
  } catch {
    throw new Error("国外 DNS 请填写 HTTPS DoH 地址。");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    url.pathname !== "/dns-query"
  ) {
    throw new Error(
      "国外 DNS 需为不含凭据、查询参数或 # 后缀的 HTTPS /dns-query 地址。",
    );
  }
  if (
    !proxyGroup ||
    proxyGroup.length > 100 ||
    /[\u0000-\u001f\u007f#&]/.test(proxyGroup) ||
    ["DIRECT", "REJECT", "RULES"].includes(proxyGroup.toUpperCase())
  ) {
    throw new Error("请填写已有代理组名称（不能是 DIRECT、REJECT 或 RULES）。");
  }
  const quote = JSON.stringify;
  const direct = quote(`${domestic}#DIRECT`);
  return [
    "# 合并到客户端的 DNS 覆写，不要用本片段替换整份配置。",
    "# 代理组必须存在且选择代理节点；使用 Rule 模式。",
    "# 现有 rules 须在默认代理规则前保留 GEOSITE,cn,DIRECT 和 GEOIP,CN,DIRECT。",
    "# geosite:cn 依赖客户端已有的 CN 域名库；应用后重新加载并分别验证国内外访问。",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  respect-rules: false",
    "  default-nameserver:",
    `    - ${quote(domestic)}`,
    "  proxy-server-nameserver:",
    `    - ${direct}`,
    "  direct-nameserver:",
    `    - ${direct}`,
    "  direct-nameserver-follow-policy: false",
    "  nameserver-policy:",
    '    "geosite:cn":',
    `      - ${direct}`,
    "  nameserver:",
    `    - ${quote(`${overseas}#${proxyGroup}`)}`,
    "  fallback: []",
    "",
  ].join("\n");
}

/** Global guard DNS: no domestic-policy/DIRECT resolver exceptions. */
export function mihomoGlobalDnsFragment(overseas: string): string {
  // Reuse the strict DoH URL validation used by the split fragment.
  mihomoDnsFragment("223.5.5.5", overseas, "GLOBAL");
  const url = new URL(overseas.trim());
  if (!ipv4(url.hostname))
    throw new Error(
      "全局保护请使用 IPv4 字面地址的 DoH，避免上游域名引导解析。",
    );
  return [
    "# 在客户端开启 Global + TUN；GLOBAL 必须选中实际节点。",
    "# 替换 DNS 覆写中的同名字段，清除旧 nameserver-policy 和 fallback。",
    "# 节点域名引导仅在保护开启前可直连；保护中禁止此路径，建议使用 IP 节点。",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  respect-rules: false",
    "  default-nameserver: [223.5.5.5, 223.6.6.6]",
    '  proxy-server-nameserver: ["https://223.5.5.5/dns-query#DIRECT"]',
    "  direct-nameserver: []",
    "  nameserver-policy: {}",
    "  nameserver:",
    `    - ${JSON.stringify(`${overseas.trim()}#GLOBAL`)}`,
    "  fallback: []",
    "",
  ].join("\n");
}
