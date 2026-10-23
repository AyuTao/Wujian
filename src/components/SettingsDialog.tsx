import { useEffect, useRef, useState } from "react";
import {
  saveSettings,
  runChecks,
  getDiagnosticLogs,
  exportDiagnosticLogs,
  firewallAction,
  isNative,
  configureDns,
  toggleGate,
  followEgressTimezone,
  restoreTimezone,
} from "../lib/api";
import type { AppSnapshot, DiagnosticEntry } from "../lib/types";
import { protectionLabel } from "../lib/protection";
import styles from "./SettingsDialog.module.css";
import { systemDnsAddresses } from "../lib/dnsConfig";

export default function SettingsDialog({
  snapshot,
  onClose,
  onRefresh,
  initialSection,
}: {
  snapshot: AppSnapshot;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  initialSection?: "dns" | "timezone";
}) {
  const [settings, setSettings] = useState(snapshot.settings);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [logs, setLogs] = useState<DiagnosticEntry[]>([]);
  const [dnsInput, setDnsInput] = useState(snapshot.dnsServers.join(", "));
  const dnsSection = useRef<HTMLElement>(null);
  const timezoneSection = useRef<HTMLLabelElement>(null);
  useEffect(() => {
    if (initialSection === "dns")
      dnsSection.current?.scrollIntoView({ block: "start" });
    if (initialSection === "timezone")
      timezoneSection.current?.scrollIntoView({ block: "start" });
  }, [initialSection]);
  const native = isNative();
  const policyLocked = Boolean(
    snapshot.protection?.armed || snapshot.protection?.isolationPending,
  );
  async function perform(action: () => Promise<void>) {
    setPending(true);
    setError("");
    setMessage("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      try {
        await onRefresh();
      } catch (e) {
        setError(String(e));
      }
      setPending(false);
    }
  }
  return (
    <div
      className={styles.backdrop}
      role="dialog"
      aria-modal="true"
      aria-labelledby="settings-title"
    >
      <div className={styles.panel}>
        <header>
          <h3 id="settings-title">设置</h3>
          <button disabled={pending} onClick={onClose} aria-label="关闭设置">
            ✕
          </button>
        </header>
        <section>
          <strong>{protectionLabel(snapshot.protection)}</strong>
          {snapshot.protection?.error && (
            <p className={styles.error} role="alert">
              {snapshot.protection.error}
            </p>
          )}
          {snapshot.protection?.incidentReason && (
            <p role="status">{snapshot.protection.incidentReason}</p>
          )}
          {snapshot.protection?.baseline && (
            <p className={styles.hint}>
              {snapshot.protection.baseline.egressIp} ·{" "}
              {snapshot.protection.baseline.timezone}
            </p>
          )}
          {snapshot.protection?.filterMayExist &&
            !snapshot.protection.tunnelPolicy && (
              <div className={styles.actions}>
                <button
                  disabled={pending}
                  onClick={() =>
                    void perform(async () => {
                      await firewallAction("verify", null, false);
                    })
                  }
                >
                  重新核对规则
                </button>
                {snapshot.protection.isolationPending && (
                  <button
                    disabled={pending}
                    onClick={() =>
                      void perform(async () => {
                        await firewallAction("isolate", null, true);
                      })
                    }
                  >
                    重试整机隔断
                  </button>
                )}
              </div>
            )}
        </section>
        <section>
          <h4>检测</h4>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                setSettings(await saveSettings(settings));
                if (settings.timezoneMode === "egress")
                  await followEgressTimezone();
                await runChecks(snapshot.networkEpoch, "settings");
                setMessage("已保存");
              });
            }}
          >
            <label>
              <input
                type="checkbox"
                disabled={pending || policyLocked}
                checked={settings.externalIpConsent}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    externalIpConsent: e.target.checked,
                  })
                }
              />
              查询出口 IP
            </label>
            <label>
              <input
                type="checkbox"
                disabled={pending || policyLocked}
                checked={settings.dnsHttpConsent}
                onChange={(e) =>
                  setSettings({ ...settings, dnsHttpConsent: e.target.checked })
                }
              />
              观测 DNS
            </label>
            <label ref={timezoneSection}>
              时区
              <select
                disabled={pending || policyLocked}
                value={settings.timezoneMode ?? "manual"}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    timezoneMode: e.target.value as "manual" | "egress",
                    externalIpConsent:
                      e.target.value === "egress"
                        ? true
                        : settings.externalIpConsent,
                  })
                }
              >
                <option value="egress">跟随出口</option>
                <option value="manual">手动</option>
              </select>
            </label>
            {snapshot.settings.timezoneMode === "egress" && (
              <p className={styles.hint} role="status">
                {snapshot.checks.find((check) => check.id === "timezone-follow")
                  ?.value ?? "等待出口"}
              </p>
            )}
            <label>
              手动时区
              <input
                disabled={
                  pending || policyLocked || settings.timezoneMode === "egress"
                }
                value={settings.targetTimezone ?? ""}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    targetTimezone: e.target.value.trim() || null,
                  })
                }
                placeholder="Asia/Shanghai"
                spellCheck={false}
              />
            </label>
            {policyLocked && (
              <p className={styles.hint}>保护中不能改这些设置。</p>
            )}
            <div className={styles.actions}>
              <button disabled={pending || policyLocked}>保存</button>
              {settings.timezoneMode === "egress" && (
                <button
                  type="button"
                  disabled={
                    pending ||
                    !native ||
                    snapshot.protection?.isolationPending ||
                    Boolean(
                      snapshot.protection?.armed &&
                      !snapshot.protection?.tunnelGuardConfirmed,
                    )
                  }
                  onClick={() =>
                    void perform(async () => {
                      if (!policyLocked)
                        setSettings(await saveSettings(settings));
                      const tz = await followEgressTimezone();
                      await runChecks(snapshot.networkEpoch, "settings");
                      setMessage(`时区已设为 ${tz.current}`);
                    })
                  }
                >
                  跟随出口
                </button>
              )}
              <button
                type="button"
                disabled={
                  pending ||
                  policyLocked ||
                  !settings.targetTimezone ||
                  !native ||
                  settings.timezoneMode === "egress"
                }
                onClick={() =>
                  void perform(async () => {
                    setSettings(
                      await saveSettings({
                        ...settings,
                        timezoneMode: "manual",
                      }),
                    );
                    await toggleGate("gate-timezone", true);
                    await runChecks(snapshot.networkEpoch, "settings");
                    setMessage("已应用指定时区。");
                  })
                }
              >
                应用手动时区
              </button>
              {snapshot.settings.originalTimezone && (
                <button
                  type="button"
                  disabled={pending || policyLocked || !native}
                  onClick={() =>
                    void perform(async () => {
                      const tz = await restoreTimezone();
                      setSettings({
                        ...settings,
                        timezoneMode: "manual",
                        originalTimezone: null,
                        targetTimezone: tz.current,
                      });
                      await runChecks(snapshot.networkEpoch, "settings");
                      setMessage("已恢复原时区");
                    })
                  }
                >
                  恢复原时区
                </button>
              )}
            </div>
          </form>
        </section>
        <section ref={dnsSection}>
          <h4>DNS</h4>
          <p className={styles.hint}>
            {snapshot.dnsServers.join("、") || "系统 DNS 未知"}
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                await configureDns(systemDnsAddresses(dnsInput));
                await runChecks(snapshot.networkEpoch, "settings");
                setMessage("系统 DNS 已写入");
              });
            }}
          >
            <label>
              系统 DNS
              <input
                disabled={pending || policyLocked || !native}
                value={dnsInput}
                onChange={(e) => setDnsInput(e.target.value)}
                placeholder="223.5.5.5, 114.114.114.114"
                spellCheck={false}
              />
            </label>
            <button disabled={pending || policyLocked || !native}>写入</button>
          </form>
        </section>
        <section>
          <h4>日志</h4>
          <p className={styles.hint}>
            导出会收集 App 和系统保护日志。Windows/Linux
            可能请求管理员权限；取消后仍导出 App 日志。
          </p>
          <div className={styles.actions}>
            <button
              disabled={pending}
              onClick={() =>
                void perform(async () => {
                  setLogs(await getDiagnosticLogs());
                })
              }
            >
              查看
            </button>
            <button
              disabled={pending || !native}
              onClick={() =>
                void perform(async () => {
                  const result = await exportDiagnosticLogs();
                  setMessage(
                    `日志已导出：${result.path}（${result.systemLogs === "included" ? "含系统保护日志" : result.systemLogs === "partial" ? "部分系统保护日志缺失" : "仅 App 日志，系统保护日志未收集"}）${result.appHealthy ? "" : "；日志健康检查发现缺失，详见导出文件。"}`,
                  );
                })
              }
            >
              导出
            </button>
          </div>
          {logs.length > 0 && (
            <pre>
              {logs
                .map(
                  (l) =>
                    `${l.at} [${l.source || "legacy"}] ${l.operation} ${l.outcome}${l.errorKind ? ` (${l.errorKind})` : ""}${l.durationMs != null ? ` ${l.durationMs}ms` : ""}${l.operationId ? ` #${l.operationId.slice(0, 8)}` : ""}`,
                )
                .join("\n")}
            </pre>
          )}
        </section>
        {error && (
          <p className={styles.error} role="alert">
            {error}
          </p>
        )}
        {message && (
          <p className={styles.message} role="status">
            {message}
          </p>
        )}
      </div>
    </div>
  );
}
