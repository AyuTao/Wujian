export type CheckState =
  | "observed"
  | "not_run"
  | "running"
  | "match"
  | "deviation"
  | "review"
  | "unknown"
  | "stale"
  | "not_applicable";
export type GuardState =
  | "disabled"
  | "establishing"
  | "restricted"
  | "allowed_by_policy"
  | "fault"
  | "unsupported";
export interface ToolInfo {
  id: string;
  name: string;
  kind: "cli" | "desktop";
  installed: boolean;
  path: string | null;
  canLaunch: boolean;
  protection: GuardState;
  note: string;
}
export interface CheckResult {
  id: string;
  label: string;
  status: CheckState;
  value: string;
  detail: string;
  suggestion: string | null;
  scope: string;
  source: string;
  observedAt: string;
  integrity:
    | "local_verified"
    | "native_configuration"
    | "tls_verified"
    | "http_unverified"
    | "unverified";
}
export interface Settings {
  theme: "system" | "light" | "dark";
  externalIpConsent: boolean;
  dnsHttpConsent: boolean;
  proxyUrl: string;
  monitorIntervalSec: number;
  historyDays: number;
  pinnedEgressIp?: string | null;
  originalTimezone?: string | null;
}

export interface TimezoneInfo {
  current: string;
  original: string | null;
}
export interface HistoryEvent {
  id: string;
  at: string;
  kind: "scan" | "check" | "network" | "settings";
  title: string;
  detail: string;
  level: "info" | "warning";
}
export interface GateCheck {
  id: string;
  name: string;
  passed: boolean;
  value: string;
  detail: string;
}

export interface CircuitBreakerReport {
  allPassed: boolean;
  isTripped: boolean;
  trippedReason: string | null;
  gates: GateCheck[];
}

export interface AppSnapshot {
  tools: ToolInfo[];
  checks: CheckResult[];
  platform: string;
  version: string;
  networkEpoch: number;
  observedAt: string;
  proxySummary: string;
  dnsServers: string[];
  settings: Settings;
  events: HistoryEvent[];
  isDisguised?: boolean;
  protection?: ProtectionStatus;
  circuitBreaker?: CircuitBreakerReport;
}
export interface CheckReport {
  checks: CheckResult[];
  observedAt: string;
  networkEpoch: number;
  proxySummary: string;
  dnsServers: string[];
  circuitBreaker?: CircuitBreakerReport;
}

export interface FirewallPlan {
  id: string;
  backend: string;
  cnNetworkCount: number;
  deniedNetworkCount: number;
  resetsConnections: boolean;
  summary: string;
  rules: string;
}
export interface FirewallReceipt {
  backend: string;
  configurationActive: boolean;
  enforcementVerified: boolean;
  generation: string | null;
  checkedAt: string;
  detail: string;
}

export interface ProtectionStatus {
  armed: boolean;
  isolationPending: boolean;
  dnsModified?: boolean;
  filterMayExist?: boolean;
  ipv6Filtering?: boolean;
  receipt: FirewallReceipt | null;
  error: string | null;
}

export interface DiagnosticEntry {
  at: string;
  session: string;
  operation: string;
  outcome: string;
  errorKind: string | null;
  durationMs: number | null;
}
