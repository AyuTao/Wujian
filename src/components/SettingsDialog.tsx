import { useState } from "react";
import {
  saveSettings,
  configureDns,
  getDiagnosticLogs,
  exportDiagnosticLogs,
  firewallAction,
  isNative,
} from "../lib/api";
import type { AppSnapshot, DiagnosticEntry } from "../lib/types";
import { protectionLabel } from "../lib/protection";
import styles from "./SettingsDialog.module.css";

export default function SettingsDialog({
  snapshot,
  onClose,
  onRefresh,
}: {
  snapshot: AppSnapshot;
  onClose: () => void;
  onRefresh: () => Promise<void>;
}) {
  const [settings, setSettings] = useState(snapshot.settings);
  const [dns, setDns] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [logs, setLogs] = useState<DiagnosticEntry[]>([]);
  const native = isNative();
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
          <h3 id="settings-title">卧底档案 · 设置</h3>
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
          {snapshot.protection?.receipt && (
            <p>{snapshot.protection.receipt.detail}</p>
          )}
          <p>
            Kill Switch
            依赖轮询与管理员授权，授权完成前隔离未确认；规则回读不能代替实际断流测试。隔离不会自动解除。
          </p>
          {snapshot.protection?.filterMayExist && (
            <div className={styles.actions}>
              <button
                disabled={pending}
                onClick={() =>
                  void perform(async () => {
                    await firewallAction("verify", null, false);
                  })
                }
              >
                授权核验规则
              </button>
              {snapshot.protection.isolationPending && (
                <button
                  disabled={pending}
                  onClick={() =>
                    void perform(async () => {
                      await firewallAction("apply", null, true);
                    })
                  }
                >
                  重试隔离授权
                </button>
              )}
            </div>
          )}
        </section>
        <section>
          <h4>检测授权与路径</h4>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                setSettings(await saveSettings(settings));
                setMessage("已保存，请关闭设置后重新核验。");
              });
            }}
          >
            <label>
              <input
                type="checkbox"
                disabled={pending}
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
                disabled={pending}
                checked={settings.dnsHttpConsent}
                onChange={(e) =>
                  setSettings({ ...settings, dnsHttpConsent: e.target.checked })
                }
              />
              允许 HTTP DNS 辅助采样（*.edns.ip-api.com，明文、可被篡改）
            </label>
            <label>
              本机代理 URL
              <input
                disabled={pending}
                value={settings.proxyUrl}
                onChange={(e) =>
                  setSettings({ ...settings, proxyUrl: e.target.value })
                }
                placeholder="http://127.0.0.1:7890"
                spellCheck={false}
              />
            </label>
            <p>
              留空使用直接检测路径；发现系统代理时跳过，避免绕过代理误测。本工具不修改客户端的规则/全局模式。DNS
              单次采样不能证明全系统无泄漏。
            </p>
            <button disabled={pending}>保存检测设置</button>
          </form>
        </section>
        <section>
          <h4>DNS 设置</h4>
          <p>当前解析器：{snapshot.dnsServers.join("、") || "未知"}</p>
          <p>
            输入现有解析器的 IPv4，以逗号分隔。应用前向 UDP 53 查询 example.com
            验证可用，再请求管理员授权并备份原值。恢复时保留原先的静态值/自动模式。
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                await configureDns(dns.split(/[,，\s]+/).filter(Boolean));
                setMessage("DNS 已修改并回读，请重新核验和浏览器复测。");
              });
            }}
          >
            <label>
              解析器 IPv4
              <input
                disabled={pending}
                value={dns}
                onChange={(e) => setDns(e.target.value)}
                placeholder="填写代理客户端提供的实际地址"
              />
            </label>
            <button
              disabled={
                pending ||
                !native ||
                !dns.trim() ||
                snapshot.protection?.isolationPending
              }
            >
              验证并应用 DNS
            </button>
          </form>
          <p>
            时区仅供参考，国家级地区信息无法推断节点城市时区，本工具不再自动改写时区。
          </p>
        </section>
        <section>
          <h4>诊断日志</h4>
          <p>
            日志只保存在本机，约 2 MiB
            轮转。仅记录操作、结果、耗时和错误类别，不写入
            IP、代理凭据、原始错误、命令参数或用户路径。
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
              查看最近日志
            </button>
            <button
              disabled={pending || !native}
              onClick={() =>
                void perform(async () => {
                  setMessage(`日志已导出：${await exportDiagnosticLogs()}`);
                })
              }
            >
              导出诊断日志
            </button>
          </div>
          {logs.length > 0 && (
            <pre>
              {logs
                .map(
                  (l) =>
                    `${l.at} ${l.operation} ${l.outcome}${l.errorKind ? ` (${l.errorKind})` : ""}`,
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
