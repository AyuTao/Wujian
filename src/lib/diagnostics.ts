import { invoke, isTauri } from "@tauri-apps/api/core";

export type FrontendEvent =
  | "frontend.render"
  | "frontend.error"
  | "frontend.unhandled_rejection"
  | "frontend.event_subscription"
  | "frontend.ipc_failure";
const lastReported = new Map<FrontendEvent, number>();

// Only a closed event identifier crosses IPC: messages/stacks can contain secrets.
export function captureFrontendEvent(operation: FrontendEvent): void {
  if (!isTauri()) return;
  const now = Date.now();
  if (now - (lastReported.get(operation) ?? 0) < 10_000) return;
  lastReported.set(operation, now);
  void invoke("record_frontend_event", { operation }).catch(() => {
    // Reporting failure must never trigger another unhandled rejection.
  });
}

export function installFrontendDiagnostics(): () => void {
  const onError = () => captureFrontendEvent("frontend.error");
  const onRejection = () =>
    captureFrontendEvent("frontend.unhandled_rejection");
  window.addEventListener("error", onError);
  window.addEventListener("unhandledrejection", onRejection);
  return () => {
    window.removeEventListener("error", onError);
    window.removeEventListener("unhandledrejection", onRejection);
  };
}
