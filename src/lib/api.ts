import { invoke as nativeInvoke, isTauri } from "@tauri-apps/api/core";
import type {
  AppSnapshot,
  CheckReport,
  CheckResult,
  Settings,
  ToolInfo,
  FirewallPlan,
  FirewallReceipt,
  TimezoneInfo,
  DiagnosticEntry,
} from "./types";
import { redactReport } from "./report";
import { captureFrontendEvent } from "./diagnostics";
async function invoke<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await nativeInvoke<T>(command, args);
  } catch (error) {
    captureFrontendEvent("frontend.ipc_failure");
    throw error;
  }
}
export const isNative = () => typeof window !== "undefined" && isTauri();
const wait = () => new Promise((resolve) => setTimeout(resolve, 480));
const now = () => new Date().toISOString();
const demoTools: ToolInfo[] = [
  {
    id: "claude-code",
    name: "Claude Code",
    kind: "cli",
    installed: true,
    path: "/示例/claude",
    canLaunch: false,
    protection: "unsupported",
    note: "示例条目，不代表本机安装状态；系统级保护尚未实现。",
  },
  {
    id: "codex-cli",
    name: "Codex CLI",
    kind: "cli",
    installed: true,
    path: "/示例/codex",
    canLaunch: false,
    protection: "unsupported",
    note: "示例条目，不代表本机安装状态；系统级保护尚未实现。",
  },
  {
    id: "claude-desktop",
    name: "Claude",
    kind: "desktop",
    installed: false,
    path: null,
    canLaunch: false,
    protection: "unsupported",
    note: "界面演示不扫描本机应用。",
  },
];
let demo: AppSnapshot = {
  tools: demoTools,
  checks: [],
  platform: "桌面预览",
  version: "0.1.0-beta.1",
  networkEpoch: 0,
  observedAt: now(),
  proxySummary: "演示路径，未读取本机配置",
  dnsServers: [],
  settings: {
    theme: "system",
    externalIpConsent: false,
    dnsHttpConsent: false,
    proxyUrl: "",
    monitorIntervalSec: 0,
    historyDays: 7,
  },
  events: [],
  isDisguised: false,
};
export async function getSnapshot(): Promise<AppSnapshot> {
  if (isNative()) return invoke<AppSnapshot>("get_snapshot");
  return structuredClone(demo);
}
export async function discoverTools(): Promise<ToolInfo[]> {
  if (isNative()) return invoke<ToolInfo[]>("discover_tools");
  await wait();
  demo.events.unshift({
    id: String(Date.now()),
    at: now(),
    kind: "scan",
    title: "演示工具已刷新",
    detail: "未扫描本机，也未启动任何程序。",
    level: "info",
  });
  return structuredClone(demo.tools);
}
export async function saveSettings(settings: Settings): Promise<Settings> {
  if (isNative()) return invoke<Settings>("save_settings", { settings });
  demo.settings = structuredClone(settings);
  return structuredClone(settings);
}
export async function runChecks(
  expectedEpoch: number,
  trigger: "manual" | "startup" | "settings" = "manual",
): Promise<CheckReport> {
  if (isNative())
    return invoke<CheckReport>("run_checks", { expectedEpoch, trigger });
  await wait();
  const make = (
    id: string,
    label: string,
    value: string,
    detail: string,
    status: CheckResult["status"] = "review",
  ): CheckResult => ({
    id,
    label,
    value,
    detail,
    status,
    suggestion: null,
    source: "模拟数据",
    scope: "仅用于界面演示",
    observedAt: now(),
    integrity: "local_verified",
  });
  demo.checks = [
    make(
      "dns-config",
      "系统 DNS 配置",
      "示例：127.0.0.1",
      "示例本机存根；不是当前系统配置。",
    ),
    make(
      "proxy-config",
      "代理与检测路径",
      "演示路径",
      "桌面程序才能读取实际本机配置。",
    ),
    make(
      "ipv6-policy",
      "IPv6 保护范围",
      "尚未验证",
      "当前尚未建立网络访问限制。",
      "unknown",
    ),
    make(
      "egress-ipv4",
      "公网 IPv4 出口",
      demo.settings.externalIpConsent ? "198.51.100.28" : "尚未授权外部查询",
      "文档专用示例地址；浏览器演示不会调用 API。",
      demo.settings.externalIpConsent ? "review" : "not_run",
    ),
    make(
      "dns-observation",
      "DNS 解析出口观测",
      demo.settings.dnsHttpConsent ? "203.0.113.8" : "尚未授权 HTTP DNS 观测",
      "仅为模拟值，不代表实际解析路径。",
      demo.settings.dnsHttpConsent ? "review" : "not_run",
    ),
  ];
  const dnsObservation = demo.checks.find(
    (check) => check.id === "dns-observation",
  );
  if (dnsObservation && demo.settings.dnsHttpConsent) {
    dnsObservation.endpoint = {
      address: "203.0.113.8",
      countryCode: null,
      location: "示例地区（模拟）",
    };
  }
  demo.observedAt = now();
  demo.events.unshift({
    id: String(Date.now()),
    at: now(),
    kind: "check",
    title: "演示检查完成",
    detail: "未发起任何真实网络请求或系统操作。",
    level: "info",
  });
  return {
    checks: structuredClone(demo.checks),
    observedAt: demo.observedAt,
    networkEpoch: demo.networkEpoch,
    proxySummary: demo.proxySummary,
    dnsServers: demo.dnsServers,
  };
}
export async function addTool(path: string): Promise<ToolInfo> {
  if (isNative()) return invoke<ToolInfo>("add_tool", { path });
  throw new Error("界面演示不验证本机路径。请在桌面版中添加工具。");
}
export async function launchTool(toolId: string): Promise<void> {
  if (isNative()) return invoke<void>("launch_tool", { toolId });
  throw new Error("界面演示不会启动本机程序。");
}
export async function exportReport(snapshot: AppSnapshot): Promise<string> {
  const text = JSON.stringify(redactReport(snapshot), null, 2);
  if (isNative()) return invoke<string>("export_report", { reportJson: text });
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `无间道-脱敏报告-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  return "已下载脱敏报告";
}

export async function prepareFirewall(
  databasePath: string,
): Promise<FirewallPlan> {
  if (!isNative()) throw new Error("系统隔断只能在桌面应用中操作。");
  return invoke<FirewallPlan>("prepare_firewall", {
    databasePath: databasePath.trim() || null,
  });
}
export async function firewallAction(
  action: "apply" | "release" | "status" | "verify" | "isolate",
  planId: string | null,
  acknowledge: boolean,
): Promise<FirewallReceipt> {
  if (!isNative()) throw new Error("界面演示不会修改防火墙。");
  return invoke<FirewallReceipt>("firewall_action", {
    action,
    planId,
    acknowledge,
  });
}

export async function getTimezoneInfo(): Promise<TimezoneInfo> {
  if (isNative()) return invoke<TimezoneInfo>("get_system_timezone");
  return {
    current: "Asia/Shanghai",
    original: demo.settings.originalTimezone ?? null,
  };
}

export async function setTimezone(
  targetTimezone: string,
): Promise<TimezoneInfo> {
  if (isNative()) {
    return invoke<TimezoneInfo>("set_system_timezone", {
      targetTz: targetTimezone,
    });
  }
  demo.settings.originalTimezone =
    demo.settings.originalTimezone ?? "Asia/Shanghai";
  return {
    current: targetTimezone,
    original: demo.settings.originalTimezone,
  };
}

export async function restoreTimezone(): Promise<TimezoneInfo> {
  if (isNative()) return invoke<TimezoneInfo>("restore_system_timezone");
  const orig = demo.settings.originalTimezone ?? "Asia/Shanghai";
  demo.settings.originalTimezone = null;
  return {
    current: orig,
    original: null,
  };
}

export async function pinEgressIp(ip: string | null): Promise<string | null> {
  if (isNative()) return invoke<string | null>("pin_egress_ip", { ip });
  demo.settings.pinnedEgressIp = ip;
  return ip;
}

export async function openExternalUrl(url: string): Promise<void> {
  if (isNative()) {
    return invoke("open_url", { url });
  } else {
    window.open(url, "_blank");
  }
}

export async function optimizeAllGates(): Promise<CheckReport> {
  if (isNative()) {
    return invoke<CheckReport>("optimize_all_gates");
  }
  return runChecks(0);
}

export async function restoreAllNetwork(): Promise<CheckReport> {
  if (isNative()) {
    return invoke<CheckReport>("restore_all_network");
  }
  return runChecks(0);
}

export async function toggleGate(
  gateId: string,
  enable: boolean,
): Promise<CheckReport> {
  if (isNative()) {
    return invoke<CheckReport>("toggle_gate", { gateId, enable });
  }
  return runChecks(0);
}

export async function exitApp(): Promise<void> {
  if (isNative()) {
    return invoke("exit_app");
  }
}

export async function configureDns(servers: string[]): Promise<void> {
  if (!isNative()) throw new Error("DNS 设置只能在桌面应用中修改。");
  return invoke<void>("configure_dns", { servers });
}
export async function followEgressTimezone(): Promise<TimezoneInfo> {
  if (!isNative()) throw new Error("跟随出口时区只能在桌面应用中执行。");
  return invoke<TimezoneInfo>("follow_egress_timezone");
}
export async function getDiagnosticLogs(): Promise<DiagnosticEntry[]> {
  return isNative() ? invoke<DiagnosticEntry[]>("get_diagnostic_logs") : [];
}
export async function exportDiagnosticLogs(): Promise<
  import("./types").DiagnosticExport
> {
  if (!isNative()) throw new Error("桌面版才能导出诊断日志。");
  return invoke<import("./types").DiagnosticExport>("export_diagnostic_logs");
}
