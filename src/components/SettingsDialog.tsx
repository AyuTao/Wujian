import { regionName } from "../lib/regionDisplay";
import { useEffect, useState } from "react";
import {
  saveSettings,
  getAutostart,
  setAutostart,
  setAutoArm,
  armAutomatically,
  runChecks,
  getDiagnosticLogs,
  diagnosticLogDirectory,
  pickSaveDirectory,
  openDirectory,
  exportDiagnosticLogs,
  firewallAction,
  isNative,
  configureDns,
  followEgressTimezone,
  getSystemRegion,
  followEgressRegion,
  restoreSystemRegion,
  openSystemRegionSettings,
} from "../lib/api";
import type { AppSnapshot, DiagnosticEntry, RegionInfo } from "../lib/types";
import { notifyError, notifyOk } from "../lib/notify";
import { protectionLabel } from "../lib/protection";
import styles from "./SettingsDialog.module.css";
import { physicalDnsDisplay } from "../lib/systemDns";
import { systemDnsAddresses } from "../lib/dnsConfig";

function logLine(entry: DiagnosticEntry): string {
  return `${entry.at} [${entry.source || "legacy"}] ${entry.operation} ${entry.outcome}${entry.errorKind ? ` (${entry.errorKind})` : ""}${entry.durationMs != null ? ` ${entry.durationMs}ms` : ""}${entry.operationId ? ` #${entry.operationId.slice(0, 8)}` : ""}`;
}
function parentDirectory(file: string): string {
  const slash = Math.max(file.lastIndexOf("/"), file.lastIndexOf("\\"));
  return slash > 0 ? file.slice(0, slash) : file;
}

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
  const [region, setRegion] = useState<RegionInfo | null>(null);
  const [regionError, setRegionError] = useState("");
  const [pending, setPending] = useState(false);
  const [logs, setLogs] = useState<DiagnosticEntry[]>([]);
  const [logDir, setLogDir] = useState("");
  const [exportPath, setExportPath] = useState("");
  const physicalDns = physicalDnsDisplay(snapshot.physicalDns);
  const [dnsInput, setDnsInput] = useState(physicalDns.servers.join(", "));
  const [tab, setTab] = useState<"general" | "dns" | "logs">(
    initialSection === "dns" ? "dns" : "general",
  );
  const [autostart, setAutostartValue] = useState<boolean | null>(null);
  useEffect(() => {
    let active = true;
    getAutostart()
      .then((value) => {
        if (active) setAutostartValue(value);
      })
      .catch((e) => {
        if (active) notifyError(String(e));
      });
    return () => {
      active = false;
    };
  }, []);
  useEffect(() => {
    if (!isNative()) return;
    diagnosticLogDirectory()
      .then(setLogDir)
      .catch(() => setLogDir(""));
  }, []);
  useEffect(() => {
    if (!isNative()) return;
    let active = true;
    getSystemRegion()
      .then((value) => {
        if (active) {
          setRegion(value);
          setRegionError("");
        }
      })
      .catch((error) => {
        if (active) setRegionError(String(error));
      });
    return () => {
      active = false;
    };
  }, [snapshot.checks.find((check) => check.id === "system-region")?.value]);
  const native = isNative();
  const policyLocked = Boolean(
    snapshot.protection?.armed || snapshot.protection?.isolationPending,
  );
  async function perform(action: () => Promise<void>) {
    setPending(true);
    try {
      await action();
    } catch (e) {
      notifyError(e instanceof Error ? e.message : String(e));
    } finally {
      try {
        await onRefresh();
      } catch (e) {
        notifyError(String(e));
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
        <nav className={styles.tabs} aria-label="设置分类">
          {(
            [
              ["general", "启动与检测"],
              ["dns", "DNS"],
              ["logs", "日志"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              aria-pressed={tab === id}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        <section hidden={tab !== "general"}>
          <label className={styles.startup}>
            <input
              type="checkbox"
              checked={autostart === true}
              disabled={pending || !native || autostart === null}
              onChange={(e) => {
                const enabled = e.target.checked;
                void perform(async () => {
                  setAutostartValue(await setAutostart(enabled));
                  notifyOk(
                    enabled ? "已开启登录后自动启动" : "已关闭开机自动启动",
                  );
                });
              }}
            />
            开机自动启动
          </label>
          <p className={styles.hint}>登录后打开 App。</p>
          <label className={styles.startup}>
            <input
              type="checkbox"
              checked={settings.autoArm === true}
              disabled={pending || !native}
              onChange={(e) => {
                const enabled = e.target.checked;
                void perform(async () => {
                  await setAutoArm(enabled);
                  setSettings((current) => ({ ...current, autoArm: enabled }));
                  if (!enabled) {
                    notifyOk("已关闭登录后自动开启保护");
                    return;
                  }
                  const message = await armAutomatically();
                  notifyOk(message || "已开启登录后自动开启保护");
                });
              }}
            />
            登录后自动开启保护
          </label>
          <p className={styles.hint}>当前线路不合格时，改选下一条可用线路。</p>
          <h4>检测与时区</h4>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                const next = { ...settings, timezoneMode: "egress" as const };
                setSettings(await saveSettings(next));
                await followEgressTimezone();
                await runChecks(snapshot.networkEpoch, "settings");
                notifyOk("已保存");
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
            <p className={styles.hint}>时区跟随出口 IP。</p>
            {policyLocked && (
              <p className={styles.hint}>保护中不能改这些设置。</p>
            )}
            <div className={styles.actions}>
              <button disabled={pending || policyLocked}>保存</button>
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
                    const tz = await followEgressTimezone();
                    await runChecks(snapshot.networkEpoch, "settings");
                    notifyOk(`时区已设为 ${tz.current}`);
                  })
                }
              >
                立即跟随
              </button>
            </div>
          </form>
          <h4>系统国家/地区</h4>
          <p className={styles.hint}>
            当前：
            {regionName(
              region?.current ??
                snapshot.checks.find((check) => check.id === "system-region")
                  ?.value,
            )}
            ；界面语言保持原样。
          </p>
          <p className={styles.hint}>
            {regionError ||
              snapshot.checks.find((check) => check.id === "system-region")
                ?.detail ||
              region?.detail ||
              "中国大陆、香港、澳门地区将自动跟随已确认的 IP 出口；出口未知时建议手动修改。"}
          </p>
          {region && !region.followingEnabled && (
            <p className={styles.hint}>
              地区自动跟随已暂停；点击“立即跟随地区”可重新启用。
            </p>
          )}
          {region?.restartRequired && (
            <p className={styles.hint}>
              部分应用需重启，Linux 桌面可能需重新登录。
            </p>
          )}
          <div className={styles.actions}>
            <button
              type="button"
              disabled={
                pending ||
                !native ||
                Boolean(snapshot.protection?.isolationPending)
              }
              onClick={() =>
                void perform(async () => {
                  const next = await followEgressRegion();
                  setRegion(next);
                  setRegionError("");
                  notifyOk(next.detail);
                })
              }
            >
              立即跟随地区
            </button>
            <button
              type="button"
              disabled={pending || !native}
              onClick={() => void perform(openSystemRegionSettings)}
            >
              系统地区设置
            </button>
            <button
              type="button"
              disabled={pending || !native || !region?.canRestore}
              onClick={() =>
                void perform(async () => {
                  const next = await restoreSystemRegion();
                  setRegion(next);
                  setRegionError("");
                  notifyOk("已恢复地区并暂停自动跟随");
                })
              }
            >
              恢复原地区
            </button>
          </div>
        </section>
        <section hidden={tab !== "dns"}>
          <h4>DNS</h4>
          <p className={styles.hint}>
            当前生效入口：{snapshot.dnsServers.join("、") || "未知"}
          </p>
          <p className={styles.hint}>
            {snapshot.physicalDns?.runtimeOnly
              ? "网卡运行时 DNS"
              : "物理网卡保存的 DNS"}
            ：{physicalDns.detail}
            <br />
            最近读取：
            {snapshot.physicalDns?.observedAt
              ? new Date(snapshot.physicalDns.observedAt).toLocaleTimeString()
              : "未知"}
            <br />
            生效入口可能包含 TUN / VPN。配置里出现 114
            等国内地址不会单独阻止开启保护，也不能单凭地址判定泄露。
          </p>
          <p className={styles.hint}>海外公共 DNS 预设</p>
          <div className={styles.actions}>
            {[
              { name: "Cloudflare", servers: ["1.1.1.1", "1.0.0.1"] },
              { name: "Google", servers: ["8.8.8.8", "8.8.4.4"] },
            ].map((preset) => (
              <button
                key={preset.name}
                disabled={pending || policyLocked || !native}
                onClick={() =>
                  void perform(async () => {
                    await configureDns(preset.servers);
                    setDnsInput(preset.servers.join(", "));
                    await runChecks(snapshot.networkEpoch, "settings");
                    notifyOk(`已应用 ${preset.name} DNS，停止保护后保留`);
                  })
                }
              >
                使用 {preset.name}
              </button>
            ))}
          </div>
          <p className={styles.hint}>
            macOS / Windows 修改现有物理网卡的 IPv4
            DNS，包含暂时断网的网卡；Linux 仅修改活动接口的运行时
            DNS。成功后停止保护会保留新值，改回请手动填写。
            代理客户端可能在退出时覆盖系统 DNS，建议先退出客户端再修改；内部 DNS
            需在客户端设置，实际解析位置仍需检测。
          </p>
          {policyLocked && (
            <p className={styles.hint}>请先停止整机保护，再修改 DNS。</p>
          )}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                await configureDns(systemDnsAddresses(dnsInput));
                await runChecks(snapshot.networkEpoch, "settings");
                notifyOk("系统 DNS 已写入，停止保护后保留");
              });
            }}
          >
            <label>
              系统 DNS
              <input
                disabled={pending || policyLocked || !native}
                value={dnsInput}
                onChange={(e) => setDnsInput(e.target.value)}
                placeholder="1.1.1.1, 1.0.0.1"
                spellCheck={false}
              />
            </label>
            <button disabled={pending || policyLocked || !native}>写入</button>
          </form>
        </section>
        <section hidden={tab !== "logs"}>
          <h4>日志</h4>
          {logDir && (
            <button
              type="button"
              className={styles.pathButton}
              disabled={pending || !native}
              onClick={() =>
                void perform(async () => {
                  await openDirectory(logDir);
                })
              }
            >
              {logDir}
            </button>
          )}
          <div className={styles.actions}>
            <button
              disabled={pending}
              onClick={() =>
                void perform(async () => {
                  setLogs(await getDiagnosticLogs());
                  notifyOk("已显示最近日志");
                })
              }
            >
              查看
            </button>
            <button
              disabled={pending || !native}
              onClick={() =>
                void perform(async () => {
                  const directory = await pickSaveDirectory();
                  if (!directory) {
                    notifyOk("已取消保存");
                    return;
                  }
                  const result = await exportDiagnosticLogs(directory);
                  setExportPath(result.path);
                  notifyOk(
                    result.systemLogs === "included"
                      ? "已保存，含系统保护日志"
                      : result.systemLogs === "partial"
                        ? "已保存，部分系统保护日志缺失"
                        : "已保存，仅 App 日志",
                  );
                })
              }
            >
              导出
            </button>
          </div>
          {exportPath && (
            <button
              type="button"
              className={styles.pathButton}
              disabled={pending || !native}
              onClick={() =>
                void perform(async () => {
                  await openDirectory(parentDirectory(exportPath));
                })
              }
            >
              {exportPath}
            </button>
          )}
          {logs.length > 0 && (
            <pre className={styles.logs}>{logs.map(logLine).join("\n")}</pre>
          )}
        </section>
      </div>
    </div>
  );
}
