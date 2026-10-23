import type { AppSnapshot, CheckResult, CheckState } from "./types";
export function summarizeChecks(checks: CheckResult[]): CheckState {
  if (!checks.length || checks.every((check) => check.status === "not_run"))
    return "not_run";
  for (const status of [
    "deviation",
    "stale",
    "running",
    "review",
    "unknown",
    "not_run",
  ] as const) {
    if (checks.some((check) => check.status === status))
      return status === "not_run" ? "unknown" : status;
  }
  if (checks.some((check) => check.status === "observed")) return "observed";
  return checks.some((check) => check.status === "match")
    ? "match"
    : "not_applicable";
}
export function redactText(text: string): string {
  if (/^\d{4}-\d{2}-\d{2}T/.test(text)) return text;
  return text
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[IP 已隐藏]")
    .replace(/(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.%]*/gi, "[IPv6 已隐藏]")
    .replace(
      /\/(?:Users|home|Volumes|Applications|opt|usr|tmp)\/[^\n，。；]+/g,
      "[本地路径已隐藏]",
    )
    .replace(/[A-Za-z]:\\[^\n，。；]+/g, "[本地路径已隐藏]");
}
export function redactReport(snapshot: AppSnapshot) {
  return {
    app: "无间道",
    version: snapshot.version,
    exportedAt: new Date().toISOString(),
    platform: snapshot.platform,
    networkEpoch: snapshot.networkEpoch,
    note: "默认隐藏 IP、代理地址与完整本地路径；此报告不证明已启用访问保护。",
    tools: snapshot.tools.map(({ path: _path, ...tool }) => ({
      ...tool,
      name: redactText(tool.name),
      note: redactText(tool.note),
    })),
    checks: snapshot.checks.map((check) => ({
      ...check,
      value: redactText(check.value),
      detail: redactText(check.detail),
      suggestion: check.suggestion ? redactText(check.suggestion) : null,
      source: redactText(check.source),
      ...(check.endpoint
        ? {
            endpoint: {
              address: "[IP 已隐藏]",
              countryCode: check.endpoint.countryCode,
              location: redactText(check.endpoint.location),
            },
          }
        : {}),
    })),
    settings: {
      ...snapshot.settings,
      proxyUrl: snapshot.settings.proxyUrl ? "[代理地址已隐藏]" : "",
      pinnedEgressIp: snapshot.settings.pinnedEgressIp ? "[IP 已隐藏]" : null,
      geoipDatabasePath: snapshot.settings.geoipDatabasePath
        ? "[本地路径已隐藏]"
        : null,
    },
    events: snapshot.events.map((event) => ({
      ...event,
      title: redactText(event.title),
      detail: redactText(event.detail),
    })),
  };
}
