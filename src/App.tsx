import { useEffect, useRef, useState } from "react";
import {
  getSnapshot,
  isNative,
  runChecks,
  firewallAction,
  saveSettings,
  exitApp,
  openExternalUrl,
  optimizeAllGates,
  restoreAllNetwork,
  configureDns,
  getDiagnosticLogs,
  exportDiagnosticLogs,
} from "./lib/api";
import type { AppSnapshot, DiagnosticEntry, Settings } from "./lib/types";
import { protectionLabel } from "./lib/protection";
import styles from "./App.module.css";

const native = isNative();
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const stateLabels: Record<string, string> = {
  match: "已核验",
  observed: "采样",
  review: "待核验",
  unknown: "未知",
  not_run: "未检测",
  stale: "已过期",
  deviation: "风险",
  not_applicable: "不适用",
};

export default function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [pending, setPending] = useState("check");
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const [dnsInput, setDnsInput] = useState("");
  const [logs, setLogs] = useState<DiagnosticEntry[]>([]);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    action: () => Promise<void>;
  } | null>(null);
  const busy = Boolean(pending);
  const current = useRef(snapshot);
  current.current = snapshot;
  const protection = snapshot?.protection;
  const active = Boolean(protection?.armed || protection?.isolationPending);
  const needsRestore = Boolean(
    active || protection?.filterMayExist || protection?.dnsModified,
  );

  async function refresh() {
    const next = await getSnapshot();
    setSnapshot(next);
    return next;
  }
  async function perform(name: string, action: () => Promise<void>) {
    setPending(name);
    setError("");
    setFeedback("");
    try {
      await action();
    } catch (e) {
      setError(errorText(e));
    } finally {
      try {
        await refresh();
      } catch (e) {
        setError(errorText(e));
      }
      setPending("");
    }
  }
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const next = await getSnapshot();
        if (disposed) return;
        setSnapshot(next);
        setSettings(next.settings);
        await runChecks(next.networkEpoch);
        if (!disposed) await refresh();
      } catch (e) {
        if (!disposed) setError(errorText(e));
      } finally {
        if (!disposed) setPending("");
      }
    })();
    if (native) {
      void import("@tauri-apps/api/event").then(async ({ listen }) => {
        const stop = await listen<AppSnapshot>("snapshot-updated", (event) => {
          if (!disposed) setSnapshot(event.payload);
        });
        if (disposed) stop();
        else unlisten = stop;
      });
    }
    const key = (e: KeyboardEvent) => {
      if (
        (e.metaKey || e.ctrlKey) &&
        ["q", "w"].includes(e.key.toLowerCase())
      ) {
        e.preventDefault();
        const p = current.current?.protection;
        if (
          p?.armed ||
          p?.isolationPending ||
          p?.filterMayExist ||
          p?.dnsModified
        )
          setError("请先停止防护并恢复本工具的配置，再退出。");
        else void exitApp().catch((e) => setError(errorText(e)));
      }
    };
    window.addEventListener("keydown", key, true);
    return () => {
      disposed = true;
      unlisten?.();
      window.removeEventListener("keydown", key, true);
    };
  }, []);

  async function recheck() {
    await perform("check", async () => {
      const next = await getSnapshot();
      await runChecks(next.networkEpoch);
      setFeedback("当前路径检查完成。");
    });
  }
  function requestArm() {
    setConfirm({
      title: "启用整机监测与 Kill Switch",
      message:
        "将请求管理员授权加载公网 IPv6 阻断规则。关键证据缺失、过期或网络变化时，会再次请求管理员授权整机隔离，仅保留本机回环。隔离会中断互联网和局域网连接，且不会自动解除。\n\n当前版本依赖应用轮询与管理员授权，不能保证瞬时断流或应用崩溃后的自动拦截。请先保存工作并完成外部检测授权。",
      action: () =>
        perform("arm", async () => {
          await firewallAction("apply", null, true);
        }),
    });
  }
  function requestRestore() {
    setConfirm({
      title: "停止防护并恢复配置",
      message:
        "将解除本工具的防火墙规则、停止监测，并按备份恢复本工具修改的 DNS。解除隔离后恢复联网。恢复失败时保留备份并显示错误，可重试。",
      action: () =>
        perform("restore", async () => {
          await restoreAllNetwork();
          setFeedback("本工具的配置已恢复。");
        }),
    });
  }
  const checks = snapshot?.checks ?? [];
  const checkIds = [
    "egress-ipv4",
    "egress-region",
    "dns-config",
    "dns-observation",
    "ipv6-policy",
    "network-route",
    "proxy-mode",
  ];
  const ordered = checkIds
    .map((id) => checks.find((c) => c.id === id))
    .filter((c) => c !== undefined);
  return (
    <div className={styles.screen}>
      <header className={styles.topNav}>
        <div className={styles.brandRow}>
          <span className={styles.brandTitle}>無間道</span>
          <span className={styles.brandSub}>网络环境检查</span>
        </div>
        <div className={styles.headerRight}>
          <span
            className={`${styles.statusBadge} ${protection?.error ? styles.badgeWarn : styles.badgeArmed}`}
          >
            {snapshot?.version ?? "Beta"}
          </span>
          <button
            className={styles.btnIconReload}
            onClick={() => void recheck()}
            disabled={busy}
            title="重新核验"
          >
            {busy ? "…" : "↻"}
          </button>
        </div>
      </header>
      <main className={styles.container}>
        {!native && (
          <p className={styles.notice}>界面预览：不会检测或修改本机网络。</p>
        )}
        <section className={styles.statusPanel} aria-live="polite">
          <strong>{protectionLabel(protection)}</strong>
          {protection?.error && <p role="alert">{protection.error}</p>}
          {protection?.receipt && <p>{protection.receipt.detail}</p>}
          {snapshot?.circuitBreaker?.isTripped && (
            <p>监测判定需隔离。{snapshot.circuitBreaker.trippedReason}</p>
          )}
          <p>配置回读与实际断流验收分别记录；诊断通过不会自动解除隔离。</p>
        </section>
        {error && (
          <p className={styles.errorPanel} role="alert">
            {error}
          </p>
        )}
        {feedback && (
          <p className={styles.notice} role="status">
            {feedback}
          </p>
        )}
        <div className={styles.cardsContainer}>
          {ordered.map((check) => (
            <details key={check.id} className={styles.checkDetail}>
              <summary
                className={`${styles.itemCardRow} ${check.status === "match" ? styles.rowPass : ""}`}
              >
                <span className={styles.rowColTitle}>{check.label}</span>
                <span className={styles.rowColData} title={check.value}>
                  {check.value}
                </span>
                <span className={styles.stampPending}>
                  {stateLabels[check.status] ?? check.status}
                </span>
              </summary>
              <p>{check.detail}</p>
              <p>
                {check.scope} · {check.source}
              </p>
              {check.suggestion && <p>{check.suggestion}</p>}
            </details>
          ))}
        </div>
        <div className={styles.controlArea}>
          <button
            className={`${styles.primaryActionBtn} ${active ? styles.primaryWarn : styles.primaryReady}`}
            disabled={busy || !native}
            onClick={active ? requestRestore : requestArm}
          >
            {active ? "停止防护并解除隔离" : "启用监测与 Kill Switch"}
          </button>
          <div className={styles.dualTools}>
            <button
              className={styles.btnOptimize}
              disabled={busy || !native || protection?.isolationPending}
              onClick={() =>
                setConfirm({
                  title: "阻断公网 IPv6",
                  message:
                    "将请求管理员授权加载本工具的 IPv6 阻断规则，并清理现有连接状态。不会清除网卡地址。操作可能中断现有连接。",
                  action: () =>
                    perform("ipv6", async () => {
                      await optimizeAllGates();
                    }),
                })
              }
            >
              阻断公网 IPv6
            </button>
            <button
              className={styles.btnRestore}
              disabled={busy || !native}
              onClick={requestRestore}
            >
              恢复本工具配置
            </button>
          </div>
          {protection?.filterMayExist && (
            <div className={styles.dualTools}>
              <button
                className={styles.btnRestore}
                disabled={busy}
                onClick={() =>
                  void perform("verify", async () => {
                    await firewallAction("verify", null, false);
                  })
                }
              >
                授权核验规则
              </button>
              {protection.isolationPending && (
                <button
                  className={styles.btnRestore}
                  disabled={busy}
                  onClick={() =>
                    void perform("retry", async () => {
                      await firewallAction("apply", null, true);
                    })
                  }
                >
                  重试隔离授权
                </button>
              )}
            </div>
          )}
        </div>
        <details className={styles.settingsPanel}>
          <summary>检测授权与设置</summary>
          {settings && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void perform("settings", async () => {
                  setSettings(await saveSettings(settings));
                  setFeedback("授权与路径已保存，请重新检查。");
                });
              }}
            >
              <label>
                <input
                  type="checkbox"
                  disabled={busy}
                  checked={settings.externalIpConsent}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      externalIpConsent: e.target.checked,
                    })
                  }
                />
                允许向 api.ipify.org 发起 HTTPS 出口查询
              </label>
              <label>
                <input
                  type="checkbox"
                  disabled={busy}
                  checked={settings.dnsHttpConsent}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      dnsHttpConsent: e.target.checked,
                    })
                  }
                />
                允许向 edns.ip-api.com 发起 HTTP DNS 辅助采样（明文、可被篡改）
              </label>
              <label>
                检测使用的本机代理 URL（可选）
                <input
                  disabled={busy}
                  value={settings.proxyUrl}
                  onChange={(e) =>
                    setSettings({ ...settings, proxyUrl: e.target.value })
                  }
                  placeholder="http://127.0.0.1:7890"
                  spellCheck={false}
                />
              </label>
              <p>
                留空时使用直接检测路径；检测到系统代理时会跳过，避免绕过代理误测。规则或全局模式均由代理客户端管理，本工具只读取可识别的配置。
              </p>
              <button className={styles.btnGateToggle} disabled={busy}>
                保存授权与路径
              </button>
            </form>
          )}
        </details>
        <details className={styles.settingsPanel}>
          <summary>修改系统 DNS</summary>
          <p>
            请输入已有解析器的 IPv4 地址，以逗号分隔。先向每个地址的 UDP 53 发送
            example.com
            查询验证可用性，再请求管理员授权、保存原值并修改活动物理接口。可用性不代表无泄漏。
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setConfirm({
                title: "修改系统 DNS",
                message:
                  "将测试所填 DNS 并修改活动物理接口的解析器。请先确认代理客户端提供的地址和端口。恢复时使用修改前的原值。",
                action: () =>
                  perform("dns", async () => {
                    await configureDns(
                      dnsInput.split(/[,，\s]+/).filter(Boolean),
                    );
                    setFeedback("DNS 已修改并回读；请重新采样与浏览器复测。");
                  }),
              });
            }}
          >
            <label>
              解析器 IPv4
              <input
                disabled={busy}
                value={dnsInput}
                onChange={(e) => setDnsInput(e.target.value)}
                placeholder="例如代理客户端提供的 127.0.0.1"
              />
            </label>
            <button
              className={styles.btnGateToggle}
              disabled={
                busy ||
                !native ||
                !dnsInput.trim() ||
                protection?.isolationPending
              }
            >
              验证并应用 DNS
            </button>
          </form>
        </details>
        <details className={styles.settingsPanel}>
          <summary>诊断日志</summary>
          <p>
            仅记录操作、结果、耗时与错误类别；不记录
            IP、代理凭据、命令参数、原始错误或用户路径。日志只保存在本机，约 2
            MiB 轮转。
          </p>
          <div className={styles.dualTools}>
            <button
              className={styles.btnRestore}
              disabled={busy}
              onClick={() =>
                void perform("logs", async () => {
                  setLogs(await getDiagnosticLogs());
                })
              }
            >
              查看最近日志
            </button>
            <button
              className={styles.btnRestore}
              disabled={busy || !native}
              onClick={() =>
                void perform("export", async () => {
                  setFeedback(`日志已导出：${await exportDiagnosticLogs()}`);
                })
              }
            >
              导出诊断日志
            </button>
          </div>
          <pre className={styles.logPreview}>
            {logs.length
              ? logs
                  .map(
                    (l) =>
                      `${l.at} ${l.operation} ${l.outcome}${l.errorKind ? ` (${l.errorKind})` : ""}`,
                  )
                  .join("\n")
              : "暂无已读取日志"}
          </pre>
        </details>
        <div className={styles.bottomAux}>
          <button
            className={styles.btnGateToggle}
            onClick={() =>
              void openExternalUrl("https://browserleaks.com/dns").catch((e) =>
                setError(errorText(e)),
              )
            }
          >
            DNS 浏览器复测 ↗
          </button>
          <button
            className={styles.btnGateToggle}
            onClick={() =>
              void openExternalUrl("https://browserleaks.com/webrtc").catch(
                (e) => setError(errorText(e)),
              )
            }
          >
            WebRTC 复测 ↗
          </button>
          <button
            className={styles.btnAuxExit}
            disabled={busy}
            onClick={() =>
              needsRestore
                ? setError("请先恢复本工具配置，再退出。")
                : void exitApp().catch((e) => setError(errorText(e)))
            }
          >
            退出
          </button>
        </div>
      </main>
      {confirm && (
        <div
          className={styles.modalBackdrop}
          role="dialog"
          aria-modal="true"
          aria-labelledby="confirmation-title"
        >
          <div className={styles.modal}>
            <h3 id="confirmation-title">{confirm.title}</h3>
            <p>{confirm.message}</p>
            <div className={styles.dualTools}>
              <button
                autoFocus
                className={styles.btnRestore}
                onClick={() => setConfirm(null)}
              >
                取消
              </button>
              <button
                className={styles.btnOptimize}
                onClick={() => {
                  const action = confirm.action;
                  setConfirm(null);
                  void action();
                }}
              >
                确认操作
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
