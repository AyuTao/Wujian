import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const { invoke, isTauri } = vi.hoisted(() => ({
  invoke: vi.fn().mockResolvedValue(undefined),
  isTauri: vi.fn().mockReturnValue(true),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke, isTauri }));
import {
  captureFrontendEvent,
  installFrontendDiagnostics,
} from "../src/lib/diagnostics";

describe("local frontend diagnostics", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-23T00:00:00Z"));
    invoke.mockClear();
    isTauri.mockReturnValue(true);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });
  it("reports identifiers without exception messages, URLs or stack traces and throttles repeats", () => {
    captureFrontendEvent("frontend.error");
    captureFrontendEvent("frontend.error");
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("record_frontend_event", {
      operation: "frontend.error",
    });
    vi.advanceTimersByTime(10_001);
    captureFrontendEvent("frontend.error");
    expect(invoke).toHaveBeenCalledTimes(2);
  });
  it("handles reporter failure without another unhandled rejection", async () => {
    invoke.mockRejectedValueOnce(
      new Error("token=secret /Users/private 203.0.113.8"),
    );
    captureFrontendEvent("frontend.ipc_failure");
    await Promise.resolve();
    expect(invoke.mock.calls[0][1]).toEqual({
      operation: "frontend.ipc_failure",
    });
  });
  it("installs and removes global capture listeners and ignores browser preview", () => {
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    vi.stubGlobal("window", { addEventListener, removeEventListener });
    const cleanup = installFrontendDiagnostics();
    expect(addEventListener.mock.calls.map(([type]) => type)).toEqual([
      "error",
      "unhandledrejection",
    ]);
    cleanup();
    expect(removeEventListener.mock.calls.map(([type]) => type)).toEqual([
      "error",
      "unhandledrejection",
    ]);
    isTauri.mockReturnValue(false);
    captureFrontendEvent("frontend.render");
    expect(invoke).not.toHaveBeenCalled();
  });
});
