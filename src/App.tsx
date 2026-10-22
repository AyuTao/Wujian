import { useEffect, useRef, useState } from "react";
import {
  getSnapshot,
  isNative,
  runChecks,
  prepareFirewall,
  firewallAction,
  getTimezoneInfo,
  exitApp,
  openExternalUrl,
  optimizeAllGates,
  restoreAllNetwork,
  toggleGate,
} from "./lib/api";
import type {
  AppSnapshot,
  FirewallPlan,
  FirewallReceipt,
  TimezoneInfo,
} from "./lib/types";
import styles from "./App.module.css";
import * as Flags from "country-flag-icons/react/3x2";
import SettingsDialog from "./components/SettingsDialog";
import { protectionLabel } from "./lib/protection";

function CountryFlag({
  code,
  style,
}: {
  code: string;
  style?: React.CSSProperties;
}) {
  const FlagComp = (
    Flags as Record<
      string,
      React.ComponentType<{ style?: React.CSSProperties }>
    >
  )[code.toUpperCase()];
  if (!FlagComp) return null;
  return (
    <FlagComp
      style={{
        width: "32px",
        height: "22px",
        borderRadius: "3px",
        boxShadow: "0 2px 8px rgba(0,0,0,0.5)",
        flexShrink: 0,
        ...style,
      }}
    />
  );
}

const native = isNative();
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

// 自动跟随出口国家的时区与解析档案
interface CountryProfile {
  code: string;
  name: string;
  timezone: string;
  timezoneLabel: string;
  dnsTarget: string;
}

const COUNTRY_PROFILES: Record<string, CountryProfile> = {
  US: {
    code: "US",
    name: "美国 (United States)",
    timezone: "America/Los_Angeles",
    timezoneLabel: "美国太平洋时区 (America/Los_Angeles)",
    dnsTarget: "美国本土合规加密解析通道",
  },
  JP: {
    code: "JP",
    name: "日本 (Japan)",
    timezone: "Asia/Tokyo",
    timezoneLabel: "日本标准时区 (Asia/Tokyo)",
    dnsTarget: "日本本土合规加密解析通道",
  },
  SG: {
    code: "SG",
    name: "新加坡 (Singapore)",
    timezone: "Asia/Singapore",
    timezoneLabel: "新加坡标准时区 (Asia/Singapore)",
    dnsTarget: "亚太合规加密解析通道",
  },
  GB: {
    code: "GB",
    name: "英国 (United Kingdom)",
    timezone: "Europe/London",
    timezoneLabel: "伦敦标准时区 (Europe/London)",
    dnsTarget: "欧洲合规加密解析通道",
  },
  DE: {
    code: "DE",
    name: "德国 (Germany)",
    timezone: "Europe/Berlin",
    timezoneLabel: "中欧标准时区 (Europe/Berlin)",
    dnsTarget: "欧洲合规加密解析通道",
  },
  HK: {
    code: "HK",
    name: "中国香港 (Hong Kong)",
    timezone: "Asia/Hong_Kong",
    timezoneLabel: "香港标准时区 (Asia/Hong_Kong)",
    dnsTarget: "亚太国际合规加密解析通道",
  },
  TW: {
    code: "TW",
    name: "中国台湾 (Taiwan)",
    timezone: "Asia/Taipei",
    timezoneLabel: "台北标准时区 (Asia/Taipei)",
    dnsTarget: "亚太国际合规加密解析通道",
  },
  KR: {
    code: "KR",
    name: "韩国 (Korea)",
    timezone: "Asia/Seoul",
    timezoneLabel: "韩国标准时区 (Asia/Seoul)",
    dnsTarget: "亚太合规加密解析通道",
  },
  CA: {
    code: "CA",
    name: "加拿大 (Canada)",
    timezone: "America/Toronto",
    timezoneLabel: "加拿大东部时区 (America/Toronto)",
    dnsTarget: "北美合规加密解析通道",
  },
  AU: {
    code: "AU",
    name: "澳大利亚 (Australia)",
    timezone: "Australia/Sydney",
    timezoneLabel: "澳洲东部时区 (Australia/Sydney)",
    dnsTarget: "澳洲合规加密解析通道",
  },
};

export default function App() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [snapshot, setSnapshot] = useState<AppSnapshot | null>(null);
  const [pending, setPending] = useState("check");
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const [firewallPlan, setFirewallPlan] = useState<FirewallPlan | null>(null);
  const [firewallReceipt, setFirewallReceipt] =
    useState<FirewallReceipt | null>(null);
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

  const generation = useRef(0);
  const snapshotRef = useRef<AppSnapshot | null>(null);
  const firewallReceiptRef = useRef<FirewallReceipt | null>(null);
  snapshotRef.current = snapshot;
  firewallReceiptRef.current = firewallReceipt;
  const busy = Boolean(pending);

  // 初始化实时网络排查
  async function initializeAndCheck() {
    const request = ++generation.current;
    setPending("check");
    setError("");
    try {
      const data = await getSnapshot();
      if (request !== generation.current) return;
      setSnapshot(data);

      try {
        const tz = await getTimezoneInfo();
        setTimezoneInfo(tz);
      } catch {
        // ignore
      }

      try {
        const status = await firewallAction("status", null, false);
        setFirewallReceipt(status);
      } catch {
        // ignore
      }

      try {
        const report = await runChecks(data.networkEpoch);
        const refreshed = await getSnapshot();
        setSnapshot({ ...refreshed, ...report });
      } catch {
        // ignore
      }
    } catch (e) {
      if (request === generation.current) setError(errorText(e));
    } finally {
      if (request === generation.current) setPending("");
    }
  }

  useEffect(() => {
    void initializeAndCheck();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        (e.metaKey || e.ctrlKey) &&
        (e.key === "q" || e.key === "Q" || e.key === "w" || e.key === "W")
      ) {
        e.preventDefault();
        e.stopPropagation();
        const armed = Boolean(
          firewallReceiptRef.current?.configurationActive ||
          snapshotRef.current?.protection?.armed ||
          snapshotRef.current?.protection?.filterMayExist ||
          snapshotRef.current?.protection?.dnsModified ||
          snapshotRef.current?.protection?.isolationPending,
        );
        if (armed) {
          setError(
            "安全防护运行中。请先点击【停止严格防护】解除网络隔离后，方可退出应用。",
          );
        } else {
          void exitApp();
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown, true);

    let unlistenSnapshot: (() => void) | undefined;
    if (native) {
      import("@tauri-apps/api/event").then(({ listen }) => {
        listen<AppSnapshot>("snapshot-updated", (event) => {
          setSnapshot(event.payload);
          if (event.payload.protection?.error)
            setError(event.payload.protection.error);
        }).then((u) => {
          unlistenSnapshot = u;
        });
      });
    }

    return () => {
      generation.current++;
      window.removeEventListener("keydown", handleKeyDown, true);
      if (unlistenSnapshot) unlistenSnapshot();
    };
  }, []);

  useEffect(() => {
    if (!feedback) return;
    const timer = window.setTimeout(() => setFeedback(""), 4000);
    return () => window.clearTimeout(timer);
  }, [feedback]);

  // 严格防护开关执行
  async function executeDisguiseAction(active: boolean) {
    setPending(active ? "disarm" : "arm");
    setError("");
    try {
      let plan = firewallPlan;
      if (!active && !plan) {
        plan = await prepareFirewall("");
        setFirewallPlan(plan);
      }
      const receipt = await firewallAction(
        active ? "release" : "apply",
        plan?.id ?? null,
        true,
      );
      setFirewallReceipt(receipt);
      const fresh = await getSnapshot();
      setSnapshot(fresh);
      setFeedback(
        active
          ? "已停止防护并恢复本工具配置"
          : protectionLabel(fresh.protection),
      );
      if (fresh.protection?.error) setError(fresh.protection.error);
    } catch (e) {
      setError(errorText(e));
      try {
        setSnapshot(await getSnapshot());
      } catch {
        /* keep the last known incident */
      }
    } finally {
      setPending("");
    }
  }

  async function toggleDisguise() {
    if (busy || !native) return;
    const active =
      snapshot?.protection?.armed ||
      snapshot?.protection?.isolationPending ||
      false;
    if (active) {
      setConfirmModal({
        open: true,
        title: "解除网络严格防护",
        message:
          "确认停止防护并解除本工具的隔离规则？DNS 按备份恢复，解除后将恢复联网。",
        confirmText: "确认解除",
        isDanger: true,
        onConfirm: () => void executeDisguiseAction(true),
      });
      return;
    }

    if (!allGatesPassed) {
      setConfirmModal({
        open: true,
        title: "合规检测未全部通过警告",
        message:
          "当前档案仍有待核验项。启用后会请求管理员授权阻断公网 IPv6；关键证据缺失、过期或网络变化时，再请求整机隔离，仅保留本机回环。\n\n请先在设置里授权检测并核对代理路径。断流依赖轮询和管理员授权，隔离不会自动解除。是否继续？",
        confirmText: "强制请求整机隔离",
        isDanger: true,
        onConfirm: () => void executeDisguiseAction(false),
      });
      return;
    }

    void executeDisguiseAction(false);
  }

  // 一键全链路合规优化 (自动灭活 IPv6、锁定安全 DNS、自动对齐当前出口国家时区)
  async function handleOptimizeAll() {
    if (busy || !native) return;
    setPending("optimize-all");
    setError("");
    try {
      const report = await optimizeAllGates();
      const fresh = await getSnapshot();
      setSnapshot({ ...fresh, ...report });
      const tz = await getTimezoneInfo();
      setTimezoneInfo(tz);

      setFeedback(
        "IPv6 阻断规则已回读；DNS 请在设置中单独配置，时区仅供参考。",
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPending("");
    }
  }

  // 一键还原初始网络 (恢复网卡 IPv6 自动、恢复系统默认 DNS、恢复原始时区)
  async function handleRestoreAll() {
    if (busy || !native) return;
    setConfirmModal({
      open: true,
      title: "恢复本工具的网络配置",
      message:
        "将停止防护、解除本工具的防火墙规则，并按备份恢复本工具修改的 DNS。静态原值不会被统一改成 DHCP，失败记录保留供重试。确认恢复？",
      confirmText: "确认恢复",
      isDanger: false,
      onConfirm: async () => {
        setPending("restore-all");
        setError("");
        try {
          const report = await restoreAllNetwork();
          const fresh = await getSnapshot();
          setSnapshot({ ...fresh, ...report });
          const tz = await getTimezoneInfo();
          setTimezoneInfo(tz);
          setFeedback("本工具的规则和 DNS 修改已恢复");
        } catch (e) {
          setError(errorText(e));
        } finally {
          setPending("");
        }
      },
    });
  }

  // 单关点击开启 / 校准 / 恢复
  async function handleToggleGate(gateId: string, enable: boolean) {
    if (busy || !native) return;
    if (gateId !== "gate-ipv6") {
      setSettingsOpen(true);
      return;
    }
    setPending(`gate-${gateId}`);
    setError("");
    try {
      const report = await toggleGate(gateId, enable);
      const fresh = await getSnapshot();
      setSnapshot({ ...fresh, ...report });

      setFeedback(enable ? "本工具的 IPv6 阻断规则已回读" : "本工具配置已恢复");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPending("");
    }
  }

  // 重新排查
  async function recheck() {
    if (!snapshot || busy) return;
    setPending("check");
    setError("");
    try {
      const report = await runChecks(snapshot.networkEpoch);
      const data = await getSnapshot();
      setSnapshot({ ...data, ...report });
      setFeedback("网络环境实时重新核验完成");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPending("");
    }
  }

  // 关键数据分析
  const checks = snapshot?.checks ?? [];
  const byId = (id: string) => checks.find((item) => item.id === id);
  const ip = byId("egress-ipv4");
  const validIp =
    ip &&
    ["match", "review", "observed"].includes(ip.status) &&
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip.value);
  const region = byId("egress-region");
  const dnsObs = byId("dns-observation");

  const isArmed = Boolean(
    snapshot?.protection?.armed || snapshot?.protection?.isolationPending,
  );
  const isChecking = pending === "check";

  // 断路器状态判定
  const cb = snapshot?.circuitBreaker;
  const isTripped = Boolean(
    snapshot?.protection?.isolationPending &&
    snapshot.protection.receipt?.configurationActive &&
    !snapshot.protection.error,
  );
  const isolationUnconfirmed = Boolean(
    snapshot?.protection?.error ||
    (snapshot?.protection?.isolationPending && !isTripped),
  );
  const gates = cb?.gates ?? [];
  const allGatesPassed = gates.length >= 6 && gates.every((g) => g.passed);
  const passedCount = gates.filter((g) => g.passed).length;

  const g1 = gates.find((g) => g.id === "gate-ip");
  const g2 = gates.find((g) => g.id === "gate-timezone");
  const g3 = gates.find((g) => g.id === "gate-dns");
  const g4 = gates.find((g) => g.id === "gate-ipv6");
  const g5 = gates.find((g) => g.id === "gate-tunnel");
  const g6 = gates.find((g) => g.id === "gate-mode");

  // 提取当时的真实 DNS IP
  const currentDnsIp = (() => {
    if (dnsObs?.value) {
      const match = dnsObs.value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (match) return match[0];
    }
    const servers = snapshot?.dnsServers ?? [];
    if (servers.length > 0 && servers[0]) return servers[0];
    return "未检测";
  })();

  // 出口国家自动推断与联动
  const parsedCountryCode = (() => {
    const searchStr = `${region?.value ?? ""} ${g1?.value ?? ""}`;
    const parenMatch = searchStr.match(/\(([A-Z]{2})\)/);
    if (parenMatch) return parenMatch[1];
    const wordMatch = searchStr.match(/\b([A-Z]{2})\b/);
    if (wordMatch && wordMatch[1] !== "IP") return wordMatch[1];
    return "";
  })();
  const currentProfile: CountryProfile = COUNTRY_PROFILES[
    parsedCountryCode
  ] ?? {
    code: parsedCountryCode,
    name: `${parsedCountryCode} 出海节点`,
    timezone: "America/Los_Angeles",
    timezoneLabel: "目标节点时区",
    dnsTarget: `${parsedCountryCode} 本土安全加密通道`,
  };

  return (
    <div className={styles.screen}>
      {/* 顶部标题区 (单行紧凑) */}
      <header className={styles.topNav}>
        <div className={styles.brandRow}>
          <span className={styles.brandTitle}>無間道</span>
          <span className={styles.brandDivider}>-</span>
          <span className={styles.brandSub}>Dario，我係中國人</span>
        </div>
        <div className={styles.headerRight}>
          <div
            className={`${styles.statusBadge} ${
              isolationUnconfirmed
                ? styles.badgeWarn
                : isArmed
                  ? styles.badgeArmed
                  : allGatesPassed
                    ? styles.badgePass
                    : styles.badgeWarn
            }`}
          >
            {isolationUnconfirmed
              ? "待授权"
              : isTripped
                ? "规则已载入"
                : isArmed
                  ? "防护中"
                  : allGatesPassed
                    ? `${passedCount}/6 就绪`
                    : `${passedCount}/6 破绽`}
          </div>
          <button
            className={styles.btnIconReload}
            disabled={busy || !snapshot}
            onClick={() => setSettingsOpen(true)}
            title="设置与诊断日志"
            aria-label="设置与诊断日志"
          >
            ⚙
          </button>
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

      {settingsOpen && snapshot && (
        <SettingsDialog
          snapshot={snapshot}
          onClose={() => setSettingsOpen(false)}
          onRefresh={async () => {
            setSnapshot(await getSnapshot());
          }}
        />
      )}
      {/* 错误提示浮层 */}
      {error && (
        <div className={styles.topToast} onClick={() => setError("")}>
          <span>{error}</span>
        </div>
      )}

      {/* 400x600 极简单屏主体 */}
      <div className={styles.container}>
        <div className={styles.cardsContainer}>
          {/* 1. 属地 */}
          <div
            className={`${styles.itemCardRow} ${g1?.passed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={styles.rowColTitle}>属地</span>
            <div className={styles.rowColData}>
              <CountryFlag
                code={currentProfile.code}
                style={{ width: "18px", height: "13px", flexShrink: 0 }}
              />
              <span
                className={
                  g1?.passed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking && !g1?.passed
                  ? "核验中..."
                  : validIp
                    ? `${ip.value}${currentProfile.code ? ` (${currentProfile.code})` : ""}`
                    : "未连接出海节点"}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              {g1?.passed ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
            </div>
          </div>

          {/* 2. 时区 */}
          <div
            className={`${styles.itemCardRow} ${g2?.passed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={styles.rowColTitle}>时区</span>
            <div className={styles.rowColData}>
              <span
                className={
                  g2?.passed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {timezoneInfo.current || "未知时区"}
              </span>
            </div>
            <div className={styles.rowColAction}>
              {timezoneInfo.current === currentProfile.timezone ? (
                <button
                  className={styles.btnGateToggle}
                  disabled={busy}
                  onClick={() => void handleToggleGate("gate-timezone", false)}
                  title="恢复系统原始时区"
                >
                  恢复
                </button>
              ) : (
                <button
                  className={`${styles.btnGateToggle} ${styles.btnGateActive}`}
                  disabled={busy}
                  onClick={() => void handleToggleGate("gate-timezone", true)}
                  title="打开时区说明与设置"
                >
                  对齐
                </button>
              )}
            </div>
            <div className={styles.rowColStamp}>
              {g2?.passed ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
            </div>
          </div>

          {/* 3. DNS */}
          <div
            className={`${styles.itemCardRow} ${g3?.passed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={styles.rowColTitle}>DNS</span>
            <div className={styles.rowColData}>
              <CountryFlag
                code={currentProfile.code}
                style={{ width: "18px", height: "13px", flexShrink: 0 }}
              />
              <span
                className={
                  g3?.passed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking && !g3?.passed ? "核验中..." : currentDnsIp}
              </span>
            </div>
            <div className={styles.rowColAction}>
              <button
                className={`${styles.btnGateToggle} ${g3?.passed ? "" : styles.btnGateActive}`}
                disabled={busy}
                onClick={() => void handleToggleGate("gate-dns", !g3?.passed)}
              >
                {g3?.passed ? "恢复" : "锁定"}
              </button>
            </div>
            <div className={styles.rowColStamp}>
              {g3?.passed ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
            </div>
          </div>

          {/* 4. IPv6 */}
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
                    ? "已阻断 / 已停用"
                    : "尚未核验"}
              </span>
            </div>
            <div className={styles.rowColAction}>
              <button
                className={`${styles.btnGateToggle} ${g4?.passed ? "" : styles.btnGateActive}`}
                disabled={busy}
                onClick={() => void handleToggleGate("gate-ipv6", !g4?.passed)}
              >
                {g4?.passed ? "恢复" : "抹除"}
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
                  : (byId("network-route")?.value ?? "未核验")}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              {g5?.passed ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
            </div>
          </div>

          {/* 6. 路由 */}
          <div
            className={`${styles.itemCardRow} ${g6?.passed ? styles.rowPass : styles.rowFail}`}
          >
            <span className={styles.rowColTitle}>路由</span>
            <div className={styles.rowColData}>
              <span
                className={
                  g6?.passed ? styles.dataPassColor : styles.dataFailColor
                }
              >
                {isChecking && !g6?.passed
                  ? "核验中..."
                  : (byId("proxy-mode")?.value ?? "模式未知")}
              </span>
            </div>
            <div className={styles.rowColStamp}>
              {g6?.passed ? (
                <span className={styles.redStampPass}>PASS</span>
              ) : (
                <span className={styles.stampPending}>FAIL</span>
              )}
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
              {isTripped
                ? "解除断路隔离"
                : isArmed
                  ? "停止卧底防护"
                  : allGatesPassed
                    ? "批准生效 · 潜入美方 AI"
                    : "强制批准 (破绽将断路)"}
            </span>
          </button>

          <div className={styles.dualTools}>
            <button
              className={styles.btnOptimize}
              disabled={busy}
              onClick={() => void handleOptimizeAll()}
              title="应用公网 IPv6 阻断规则；DNS 在设置中单独配置，时区仅供参考"
            >
              一键抹除优化
            </button>

            <button
              className={styles.btnRestore}
              disabled={busy}
              onClick={() => void handleRestoreAll()}
              title="解除本工具规则并按原值恢复 DNS"
            >
              还原系统配置
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
              权威验证 ↗
            </a>

            <button
              className={styles.btnAuxExit}
              disabled={busy}
              onClick={() => {
                if (
                  isArmed ||
                  snapshot?.protection?.filterMayExist ||
                  snapshot?.protection?.dnsModified
                ) {
                  setError(
                    "防护运行中！必须先点击【停止卧底防护】后再安全退出。",
                  );
                } else {
                  void exitApp();
                }
              }}
            >
              退出程序
            </button>
          </div>
        </div>
      </div>

      {/* 沉浸式拟态确认对话框 */}
      {confirmModal?.open && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.8)",
            backdropFilter: "blur(8px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
          }}
        >
          <div
            style={{
              background: "#0a0f1d",
              border: "1px solid rgba(56, 189, 248, 0.35)",
              borderRadius: "8px",
              padding: "26px 30px",
              maxWidth: "480px",
              width: "90%",
              boxShadow: "0 25px 60px rgba(0, 0, 0, 0.9)",
              color: "#f8fafc",
              display: "flex",
              flexDirection: "column",
              gap: "16px",
            }}
          >
            <h3
              style={{
                margin: 0,
                fontSize: "17px",
                color: confirmModal.isDanger ? "#f87171" : "#38bdf8",
                fontWeight: 700,
                letterSpacing: "0.5px",
              }}
            >
              {confirmModal.title}
            </h3>
            <p
              style={{
                margin: 0,
                fontSize: "14px",
                lineHeight: "1.65",
                color: "rgba(255, 255, 255, 0.88)",
                whiteSpace: "pre-line",
              }}
            >
              {confirmModal.message}
            </p>
            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: "12px",
                marginTop: "12px",
              }}
            >
              <button
                onClick={() => setConfirmModal(null)}
                style={{
                  padding: "9px 18px",
                  background: "rgba(255, 255, 255, 0.08)",
                  border: "1px solid rgba(255, 255, 255, 0.18)",
                  borderRadius: "4px",
                  color: "#cbd5e1",
                  cursor: "pointer",
                  fontSize: "13.5px",
                }}
              >
                取消
              </button>
              <button
                onClick={() => {
                  const cb = confirmModal.onConfirm;
                  setConfirmModal(null);
                  cb();
                }}
                style={{
                  padding: "9px 20px",
                  background: confirmModal.isDanger ? "#dc2626" : "#0284c7",
                  border: "none",
                  borderRadius: "4px",
                  color: "#ffffff",
                  fontWeight: "bold",
                  cursor: "pointer",
                  fontSize: "13.5px",
                }}
              >
                {confirmModal.confirmText}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 底部反馈消息 */}
      {feedback && <div className={styles.bottomFeedback}>{feedback}</div>}
    </div>
  );
}
