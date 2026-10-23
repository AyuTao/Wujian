import { Component, type ReactNode } from "react";
import { captureFrontendEvent } from "../lib/diagnostics";
import { exportDiagnosticLogs } from "../lib/api";

export default class ErrorBoundary extends Component<
  { children: ReactNode },
  { failed: boolean; message: string; exporting: boolean }
> {
  state = { failed: false, message: "", exporting: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch() {
    captureFrontendEvent("frontend.render");
  }
  async exportLogs() {
    this.setState({ exporting: true });
    try {
      const result = await exportDiagnosticLogs();
      this.setState({
        message: `日志已导出：${result.path}（${result.systemLogs === "included" ? "含系统保护日志" : result.systemLogs === "partial" ? "部分系统保护日志缺失" : "仅 App 日志"}）`,
      });
    } catch {
      this.setState({ message: "日志导出失败；可重新打开应用后再导出。" });
    } finally {
      this.setState({ exporting: false });
    }
  }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main style={{ padding: 24 }} role="alert">
        <h2>界面遇到错误</h2>
        <p>已尝试记录诊断事件。重新载入界面不会解除系统保护规则。</p>
        <button
          disabled={this.state.exporting}
          onClick={() => void this.exportLogs()}
        >
          导出诊断日志
        </button>{" "}
        <button onClick={() => window.location.reload()}>重新载入界面</button>
        {this.state.message && <p>{this.state.message}</p>}
      </main>
    );
  }
}
