export function regionName(value?: string | null): string {
  if (!value) return "地区未知";
  if (!/^[A-Z]{2}$/.test(value)) return value;
  const known: Record<string, string> = {
    CN: "中国大陆",
    HK: "香港",
    MO: "澳门",
  };
  try {
    return `${known[value] ?? new Intl.DisplayNames(["zh-CN"], { type: "region" }).of(value) ?? value} (${value})`;
  } catch {
    return value;
  }
}
