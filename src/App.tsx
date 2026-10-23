import { useEffect, useRef, useState } from "react";
import * as Flags from "country-flag-icons/react/3x2";
import {
  getSnapshot,
  isNative,
  runChecks,
  firewallAction,
  prepareFirewall,
  exitApp,
  openExternalUrl,
  toggleGate,
  getTimezoneInfo,
  restoreAllNetwork,
} from "./lib/api";
import type { AppSnapshot, CheckResult, TimezoneInfo } from "./lib/types";
import styles from "./App.module.css";
import { captureFrontendEvent } from "./lib/diagnostics";
import SettingsDialog from "./components/SettingsDialog";
import { dnsDisplay, dnsEndpoint } from "./lib/dnsDisplay";
import { egressDisplay, hasEgressAddress } from "./lib/egressDisplay";

const native = isNative();
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

function CountryFlag({
  code,
  style,
}: {
  code: string;
  style?: React.CSSProperties;
}) {
  const FlagComponent = (
    Flags as Record<
      string,
      React.ComponentType<{ style?: React.CSSProperties }>
    >
  )[code.toUpperCase()];
  return FlagComponent ? (
    <FlagComponent style={style} />
  ) : (
    <span style={style}>?</span>
  );
}

export default function App() {
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [pending, setPending] = useState("check");
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [settingsSection, setSettingsSection] = useState<
    "dns" | "timezone" | undefined
  >();
  const [timezoneInfo, setTimezoneInfo] = useState<TimezoneInfo>({
    current: Intl.DateTimeFormat().resolvedOptions().timeZone,
    original: null,
  });
  const [confirmModal, setConfirmModal] = useState<{
    open: boolean;
    title: string;
    message: string;
    confirmText: string;
    isDanger?: boolean;
    onConfirm: () => void;
  } | null>(null);

  const busy = Boolean(pending);
  const protection = snapshot?.protection;
  const isArmed = Boolean(protection?.armed);
  const isTripped = Boolean(protection?.isolationPending);
  const needsRecovery = Boolean(protection?.filterMayExist && !isArmed);
  const isolationLoaded =
    isTripped &&
    Boolean(protection?.receipt?.configurationActive) &&
    protection?.receipt?.policyMode === "isolation" &&
    !protection?.error;
  const allGatesPassed = Boolean(snapshot?.circuitBreaker?.allPassed);
  const gates = snapshot?.circuitBreaker?.gates ?? [];

  async function refresh() {
    const next = await getSnapshot();
    setSnapshot(next);
    if (native) {
      try {
        const tz = await getTimezoneInfo();
        setTimezoneInfo(tz);
      } catch {
        // ignore
      }
    }
    return next;
  }

  async function perform(name: string, action: () => Promise<void>) {
    setPending(name);
    setFeedback("");
    try {
      await action();
      setError("");
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
        if (native) {
          try {
            const tz = await getTimezoneInfo();
            if (!disposed) setTimezoneInfo(tz);
          } catch {
            // ignore
          }
        }
        await runChecks(next.networkEpoch, "startup");
        if (!disposed) await refresh();
      } catch (e) {
        if (!disposed) setError(errorText(e));
      } finally {
        if (!disposed) setPending("");
      }
    })();

    if (native) {
      void import("@tauri-apps/api/event")
        .then(async ({ listen }) => {
          const stop = await listen<AppSnapshot>(
            "snapshot-updated",
            (event) => {
              if (!disposed) setSnapshot(event.payload);
            },
          );
          if (disposed) stop();
          else unlisten = stop;
        })
        .catch(() => captureFrontendEvent("frontend.event_subscription"));
    }

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  async function recheck() {
    await perform("check", async () => {
      const next = await getSnapshot();
      await runChecks(next.networkEpoch);
      setFeedback("实时核验完成");
    });
  }

  async function handleToggleGate(gateId: string, enable: boolean) {
    await perform("toggle-gate", async () => {
      await toggleGate(gateId, enable);
      const tz = await getTimezoneInfo();
      setTimezoneInfo(tz);
      setFeedback(
        gateId === "gate-dns"
          ? "已复查 DNS 配置，未修改客户端设置"
          : enable
            ? "配置操作完成，请核对检测结果"
            : "本工具配置已恢复",
      );
    });
  }

  async function handleOptimizeAll() {
    await perform("optimize-all", async () => {
      if (!g4?.passed) await toggleGate("gate-ipv6", true);
      setFeedback("已请求阻断公网 IPv6；DNS 和时区保持原配置");
    });
  }

  async function handleRestoreAll() {
    setConfirmModal({
      open: true,
      title: "恢复本工具配置",
      message:
        "将停止守护、解除本工具的隔离和 IPv6 阻断，并恢复本工具备份的 DNS 与时区。不会把所有网卡重置为默认值。",
      confirmText: "立即还原",
      isDanger: false,
      onConfirm: async () => {
        await perform("restore-all", async () => {
          await restoreAllNetwork();
          const tz = await getTimezoneInfo();
          setTimezoneInfo(tz);
          setFeedback("本工具配置已恢复，请复测联网");
        });
      },
    });
  }

  async function toggleDisguise() {
    if (isTripped || needsRecovery) {
      setConfirmModal({
        open: true,
        title: "停止保护并解除规则",
        message:
          "网络保持切断。原来的节点和 TUN 恢复后会自己继续。这里会停止保护并恢复联网。",
        confirmText: "立即解除隔离",
        isDanger: true,
        onConfirm: async () => {
          await perform("disarm", async () => {
            await firewallAction("release", null, true);
            setFeedback("已解除断路隔离");
          });
        },
      });
      return;
    }

    if (isArmed) {
      setConfirmModal({
        open: true,
        title: "停止卧底防护",
        message:
          "停止后将卸载常驻保护 helper，解除本工具的防火墙限制，恢复常规联网。",
        confirmText: "停止防护",
        isDanger: true,
        onConfirm: async () => {
          await perform("disarm", async () => {
            await firewallAction("release", null, true);
            setFeedback("已停止防护");
          });
        },
      });
      return;
    }

    await perform("prepare-guard", async () => {
      const plan = await prepareFirewall("");
      setConfirmModal({
        open: true,
        title: "确认全局 TUN 整机保护",
        message: plan.summary,
        confirmText: "加载防火墙并开启",
        isDanger: false,
        onConfirm: async () => {
          await perform("arm", async () => {
            await firewallAction("apply", plan.id, true);
            setFeedback("保护已开启");
          });
        },
      });
    });
  }

  const checks = snapshot?.checks ?? [];
  const region = checks.find((c) => c.id === "egress-region");
  const ipCheck = checks.find(
    (c) => c.id === "egress-ipv4" || c.id === "egress-ip",
  );

  const g1 = gates.find((g) => g.id === "gate-ip");
  const g2 = gates.find((g) => g.id === "gate-timezone");
  const g3 = gates.find((g) => g.id === "gate-dns");
  const g4 = gates.find((g) => g.id === "gate-ipv6");
  const g5 = gates.find((g) => g.id === "gate-tunnel");
  const g6 = gates.find((g) => g.id === "gate-mode");
  const modePassed = Boolean(
    g6?.passed &&
    checks.find((check) => check.id === "proxy-mode")?.status === "match",
  );
  const dnsConfigPassed = Boolean(g3?.passed && snapshot?.dnsServers.length);
  const vergeInstalled =
    checks.find((check) => check.id === "clash-verge-app")?.status === "match";
  const vergeLabel =
    checks.find((check) => check.id === "clash-verge-app")?.value ??
    "未发现 Clash Verge";

  const history = useRef<{
    path: string;
    ip?: CheckResult;
    region?: CheckResult;
    dns?: CheckResult;
  }>({ path: "" });
  const path = `${snapshot?.settings.proxyUrl}|${snapshot?.settings.externalIpConsent}|${snapshot?.settings.dnsHttpConsent}`;
  const previous = history.current.path === path ? history.current : undefined;
  const dnsCheck = checks.find((c) => c.id === "dns-observation");
  useEffect(() => {
    const last: typeof history.current =
      history.current.path === path ? history.current : { path };
    history.current = {
      path,
      ip:
        hasEgressAddress(ipCheck) && ipCheck.status !== "stale"
          ? ipCheck
          : last.ip,
      region:
        hasEgressAddress(ipCheck) && ipCheck.status !== "stale"
          ? region
          : last.region,
      dns:
        dnsEndpoint(dnsCheck) && dnsCheck?.status !== "stale"
          ? dnsCheck
          : last.dns,
    };
  }, [path, ipCheck, region, dnsCheck]);
  const egressView = egressDisplay(ipCheck, region, Date.now(), previous);
  const isIpPass = Boolean(g1?.passed && egressView.current);
  const dnsView = dnsDisplay(
    dnsCheck,
    Boolean(snapshot?.settings.dnsHttpConsent),
    Date.now(),
    previous?.dns,
  );
  const currentTimezone =
    checks.find((c) => c.id === "timezone")?.value || timezoneInfo.current;

  const isChecking = busy && pending === "check";

  return (
    <div className={styles.screen}>
      {/* 顶部单行标题条 */}
      <header className={styles.topNav}>
        <div className={styles.brandRow}>
          <span className={styles.brandTitle}>無間道</span>
          <span className={styles.brandDivider}>-</span>
          <span className={styles.brandSub}>Dario，我係中國人</span>
        </div>
        <div className={styles.headerRight}>
          <button
            className={styles.btnIconReload}
            onClick={() => setShowSettings(true)}
            disabled={busy || !snapshot}
            title="检测与守护设置"
            aria-label="设置"
          >
            ⚙
          </button>
          <div
            className={`${styles.statusBadge} ${
              isArmed
                ? styles.badgeArmed
                : allGatesPassed
                  ? styles.badgePass
                  : styles.badgeWarn
            }`}
            title={
              !isTripped && !isArmed && allGatesPassed
                ? "全局模式和 TUN 已通过，整机保护尚未开启"
                : !isTripped && !isArmed
                  ? "需要全局模式，并指定一个 TUN"
                  : undefined
            }
          >
            {isTripped
              ? isolationLoaded
                ? "已隔断"
                : "隔断未确认"
              : isArmed
                ? protection?.tunnelGuardConfirmed
                  ? "保护中"
                  : "保护未核验"
                : allGatesPassed
                  ? "可开启保护"
                  : "条件不足"}
          </div>
          <button
            className={styles.btnIconReload}
            onClick={() => void recheck()}
            disabled={busy}
            title="重新核验"
          >
            {busy ? "..." : "↻"}
          </button>
        </div>
      </header>

      {/* 提示浮层 */}
      {error && (
        <div className={styles.topToast} onClick={() => setError("")}>
          <span>{error}</span>
        </div>
      )}
      {feedback && (
        <div className={styles.bottomFeedback} onClick={() => setFeedback("")}>
          <span>{feedback}</span>
        </div>
      )}

      {/* 400x600 紧凑单屏容器 */}
      <div className={styles.container}>
        <div className={styles.cardsContainer}>
          {/* 1. 属地 */}
          <div
            className={`${styles.itemCardRow} ${isIpPass ? styles.rowPass : styles.rowFail}`}
            title={egressView.title}
          >
            <span className={styles.rowColTitle}>出口</span>
            <div className={styles.rowColData}>
              <CountryFlag
                code={egressView.countryCode}
                style={{ width: "18px", height: "13px", flexShrink: 0 }}
              />
              <span
                className={
                  isIpPass ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking && !hasEgressAddress(ipCheck) && !previous?.ip
                  ? "核验中..."
                  : egressView.text}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              {isIpPass ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
            </div>
          </div>

          {/* 2. 时区：持续跟随出口或手动自定义 */}
          <div
            className={`${styles.itemCardRow} ${g2?.passed ? styles.rowPass : styles.rowFail}`}
            title={g2?.detail}
          >
            <span className={styles.rowColTitle}>时区</span>
            <div className={styles.rowColData}>
              <span
                className={
                  g2?.passed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {currentTimezone || "未知时区"}
                {snapshot?.settings.timezoneMode === "egress"
                  ? " · 跟随出口"
                  : ""}
              </span>
            </div>
            <div className={styles.rowColAction}>
              <button
                className={styles.btnGateToggle}
                disabled={busy || !snapshot}
                onClick={() => {
                  setSettingsSection("timezone");
                  setShowSettings(true);
                }}
                title="设置跟随出口 IP 或手动自定义时区"
              >
                设置
              </button>
            </div>
            <div className={styles.rowColStamp}>
              {g2?.passed ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
            </div>
          </div>

          {/* 3. DNS：实际解析出口 */}
          <div
            className={`${styles.itemCardRow} ${dnsView.current ? styles.rowPass : styles.rowFail}`}
            title={dnsView.title}
          >
            <span className={styles.rowColTitle}>DNS</span>
            <div className={styles.rowColData}>
              {dnsView.countryCode && (
                <CountryFlag
                  code={dnsView.countryCode}
                  style={{ width: "18px", height: "13px", flexShrink: 0 }}
                />
              )}
              <span
                className={
                  dnsView.current ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking &&
                !dnsEndpoint(dnsCheck) &&
                !dnsEndpoint(previous?.dns)
                  ? "检测中..."
                  : dnsView.text}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              <span
                className={
                  dnsView.current ? styles.redStampPass : styles.stampPending
                }
              >
                {dnsView.badge}
              </span>
            </div>
          </div>

          <div
            className={`${styles.itemCardRow} ${dnsConfigPassed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={`${styles.rowColTitle} ${styles.dnsConfigTitle}`}>
              DNS配置
            </span>
            <div
              className={styles.rowColData}
              title={snapshot?.dnsServers.join("、")}
            >
              <span
                className={
                  dnsConfigPassed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {snapshot?.dnsServers.join("、") || "解析入口未知"}
              </span>
            </div>
            <div className={styles.rowColAction}>
              <button
                className={styles.btnGateToggle}
                disabled={busy || !snapshot}
                onClick={() => {
                  setSettingsSection("dns");
                  setShowSettings(true);
                }}
                title="系统 DNS 设置与解析策略"
              >
                设置
              </button>
            </div>
            <div className={styles.rowColStamp}>
              <span
                className={
                  dnsConfigPassed ? styles.redStampPass : styles.stampPending
                }
              >
                {dnsConfigPassed ? "PASS" : "FAIL"}
              </span>
            </div>
          </div>

          {/* 5. IPv6 */}
          <div
            className={`${styles.itemCardRow} ${g4?.passed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={styles.rowColTitle}>IPv6</span>
            <div className={styles.rowColData}>
              <span
                className={
                  g4?.passed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking && !g4?.passed
                  ? "核验中..."
                  : g4?.passed
                    ? "公网已停用/阻断"
                    : "公网未停用或未知"}
              </span>
            </div>
            <div className={styles.rowColAction}>
              <button
                className={`${styles.btnGateToggle} ${g4?.passed ? "" : styles.btnGateActive}`}
                disabled={busy || isArmed || isTripped}
                onClick={() =>
                  void handleToggleGate("gate-ipv6", !protection?.ipv6Filtering)
                }
                title="加载或解除本工具的公网 IPv6 阻断规则，不改写网卡配置"
              >
                {protection?.ipv6Filtering ? "恢复" : "阻断"}
              </button>
            </div>
            <div className={styles.rowColStamp}>
              {g4?.passed ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
            </div>
          </div>

          {/* 5. 网卡 */}
          <div
            className={`${styles.itemCardRow} ${g5?.passed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={styles.rowColTitle}>网卡</span>
            <div className={styles.rowColData}>
              <span
                className={
                  g5?.passed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking && !g5?.passed
                  ? "核验中..."
                  : (g5?.value ?? "TUN 状态未确认")}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              <span
                className={
                  g5?.passed ? styles.redStampPass : styles.stampPending
                }
              >
                {g5?.passed ? "PASS" : "FAIL"}
              </span>
            </div>
          </div>

          {/* Clash Verge 是否装在本机。不提供下载。 */}
          <div
            className={`${styles.itemCardRow} ${vergeInstalled ? styles.rowPass : styles.rowFail}`}
          >
            <span className={`${styles.rowColTitle} ${styles.dnsConfigTitle}`}>
              客户端
            </span>
            <div className={styles.rowColData}>
              <span
                className={
                  vergeInstalled ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {vergeLabel}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              <span
                className={
                  vergeInstalled ? styles.redStampPass : styles.stampPending
                }
              >
                {vergeInstalled ? "PASS" : "FAIL"}
              </span>
            </div>
          </div>

          {/* 6. 全局模式与 TUN */}
          <div
            className={`${styles.itemCardRow} ${modePassed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={styles.rowColTitle}>模式</span>
            <div className={styles.rowColData}>
              <span
                className={
                  modePassed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking && !modePassed
                  ? "核验中..."
                  : modePassed
                    ? "全局模式"
                    : (g6?.value ?? "代理模式未确认")}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              <span
                className={
                  modePassed ? styles.redStampPass : styles.stampPending
                }
              >
                {modePassed ? "PASS" : "FAIL"}
              </span>
            </div>
          </div>
        </div>

        {/* 底部控制台 */}
        <div className={styles.controlArea}>
          <button
            className={`${styles.primaryActionBtn} ${
              isTripped
                ? styles.primaryWarn
                : isArmed
                  ? styles.primaryProtecting
                  : allGatesPassed
                    ? styles.primaryReady
                    : styles.primaryWarn
            }`}
            disabled={busy}
            onClick={() => void toggleDisguise()}
          >
            <span>
              {pending === "prepare-guard"
                ? "正在核对节点和 DNS…"
                : pending === "arm"
                  ? "正在加载防火墙…"
                  : pending === "disarm" || pending === "restore-all"
                    ? "正在解除保护…"
                    : isTripped || needsRecovery
                      ? "解除断路隔离"
                      : isArmed
                        ? "停止卧底防护"
                        : allGatesPassed
                          ? "检查并开启整机保护"
                          : "检查全局 TUN 开启条件"}
            </span>
          </button>
          {pending === "prepare-guard" && (
            <p className={styles.pendingNote}>正在读取本机代理，还没改网络</p>
          )}
          {pending === "arm" && (
            <p className={styles.pendingNote}>正在写入防火墙规则</p>
          )}
          {isTripped && isArmed && Boolean(protection?.tunnelPolicy) && (
            <p className={styles.pendingNote}>
              TUN 和原来的节点恢复后，会自动继续保护
            </p>
          )}

          <div className={styles.dualTools}>
            <button
              className={styles.btnOptimize}
              disabled={busy || isArmed || isTripped}
              onClick={() => void handleOptimizeAll()}
              title="仅加载公网 IPv6 阻断，不改写 DNS 和时区"
            >
              阻断公网 IPv6
            </button>

            <button
              className={styles.btnRestore}
              disabled={busy}
              onClick={() => void handleRestoreAll()}
              title="停止守护，仅恢复本工具的修改和备份"
            >
              恢复本工具配置
            </button>
          </div>

          <div className={styles.bottomAux}>
            <a
              className={styles.auxLink}
              onClick={(e) => {
                e.preventDefault();
                void openExternalUrl("https://browserleaks.com/dns");
              }}
            >
              浏览器复测 ↗
            </a>

            <button
              className={styles.btnAuxExit}
              disabled={busy}
              onClick={() => {
                if (isArmed) {
                  setError(
                    "防护运行中！必须先点击【停止卧底防护】后再安全退出。",
                  );
                } else {
                  void perform("exit", exitApp);
                }
              }}
            >
              退出程序
            </button>
          </div>
        </div>
      </div>

      {protection?.error && (
        <div
          className={styles.topToast}
          role="alert"
          onClick={() => setShowSettings(true)}
        >
          {protection.error}
        </div>
      )}
      {showSettings && snapshot && (
        <SettingsDialog
          snapshot={snapshot}
          initialSection={settingsSection}
          onClose={() => {
            setShowSettings(false);
            setSettingsSection(undefined);
          }}
          onRefresh={async () => {
            await refresh();
          }}
        />
      )}
      {/* 确认对话框 */}
      {confirmModal?.open && (
        <div className={styles.modalBackdrop} role="dialog" aria-modal="true">
          <div className={styles.modal}>
            <h3 className={styles.modalTitle}>{confirmModal.title}</h3>
            <p className={styles.modalMessage}>{confirmModal.message}</p>
            <div className={styles.dualTools}>
              <button
                className={styles.btnRestore}
                onClick={() => setConfirmModal(null)}
              >
                取消
              </button>
              <button
                className={
                  confirmModal.isDanger ? styles.btnDanger : styles.btnOptimize
                }
                onClick={() => {
                  const action = confirmModal.onConfirm;
                  setConfirmModal(null);
                  void action();
                }}
              >
                {confirmModal.confirmText}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
