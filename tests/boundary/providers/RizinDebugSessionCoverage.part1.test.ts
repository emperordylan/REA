import { afterEach, expect, it, vi } from "vitest";
import { RizinDebugSessionManager } from "../../../src/rizin/RizinDebugSessionManager.js";
import { rizinCommand } from "../../../src/rizin/RizinCommand.js";
import {
  createRizinCoverageHarness,
  createInjectedProcess,
  incompleteStop,
} from "./RizinDebugSessionCoverage.fixtures.js";

const { cleanup, makeProvider, missingProviderPath, start, track } =
  createRizinCoverageHarness();
afterEach(cleanup);

it.skipIf(process.platform === "win32")(
  "builds the one-shot command with the caller's path and command",
  () => {
    expect(rizinCommand({ path: "./sample file", command: "izz" })).toEqual([
      "-N",
      "-q",
      "-c",
      "izz",
      expect.stringMatching(/sample file/u),
    ]);
  },
);

it.skipIf(process.platform === "win32")(
  "rejects unsupported, pre-cancelled, and failed startup requests",
  async () => {
    const windows = new RizinDebugSessionManager({}, { platform: "win32" });
    expect((await windows.start({ path: "/tmp/a" })).ok).toBe(false);
    const aborted = new AbortController();
    aborted.abort();
    expect((await windows.start({ path: "/tmp/a" }, aborted.signal)).ok).toBe(
      false,
    );

    const failed = await makeProvider("process.exit(9);");
    const manager = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: failed,
    });
    track(manager);
    const result = await manager.start({ path: "/tmp/a" });
    expect(result.ok).toBe(false);

    const missing = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: missingProviderPath(),
    });
    track(missing);
    const spawnFailure = await missing.start({ path: "/tmp/a" });
    expect(spawnFailure.ok).toBe(false);
  },
);

it.skipIf(process.platform === "win32")(
  "returns a startup timeout when Rizin exits before its initial frame",
  async () => {
    const provider = await makeProvider("process.exit(0);");
    const manager = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: provider,
    });
    track(manager);
    const result = await manager.start({ path: "/tmp/early-exit" });
    expect(result.ok).toBe(false);
  },
);

it.skipIf(process.platform === "win32")(
  "times out startup through the frame wait when Rizin never emits a frame",
  async () => {
    const injected = createInjectedProcess({ startup: () => undefined });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      {
        spawnProcess: injected.spawnProcess,
        stopProcess: async () => ({ status: "stopped" }),
      },
    );
    track(manager);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const starting = manager.start({ path: "/tmp/no-startup-frame" });
      await new Promise<void>((resolve) => setImmediate(resolve));
      await new Promise<void>((resolve) => setImmediate(resolve));
      await vi.advanceTimersByTimeAsync(30_001);
      const result = await starting;
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.message).toContain("timed out");
    } finally {
      vi.useRealTimers();
    }
  },
);

it.skipIf(process.platform === "win32")(
  "rejects an oversized initial frame instead of marking the session ready",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("x".repeat(16 * 1024 * 1024 + 1) + "\\0"); process.stdin.resume();',
    );
    const manager = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: provider,
    });
    track(manager);

    const result = await manager.start({ path: "/tmp/oversized-startup" });

    expect(result.ok).toBe(false);
  },
);

it.skipIf(process.platform === "win32")(
  "cancels startup while waiting for the initial NUL frame",
  async () => {
    const provider = await makeProvider(
      'setTimeout(() => process.stdout.write("\\0"), 500); process.stdin.resume();',
    );
    const manager = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: provider,
    });
    track(manager);
    const abort = new AbortController();
    const starting = manager.start({ path: "/tmp/cancel-start" }, abort.signal);
    setTimeout(() => abort.abort(), 20);
    expect((await starting).ok).toBe(false);
  },
);

it.skipIf(process.platform === "win32")(
  "preserves startup cleanup uncertainty after cancellation",
  async () => {
    const provider = await makeProvider(
      "process.stdin.resume(); setInterval(() => {}, 1000);",
    );
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: provider },
      { stopProcess: incompleteStop },
    );
    track(manager);
    const abort = new AbortController();
    const starting = manager.start({ path: "/tmp/cancel-start" }, abort.signal);
    setTimeout(() => abort.abort(), 100);
    const result = await starting;
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error.message).toContain("injected stop uncertainty");
  },
);

it.skipIf(process.platform === "win32")(
  "rejects commands for missing and pre-cancelled sessions",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); process.stdin.resume();',
    );
    const { manager, sessionId } = await start(provider);
    expect((await manager.execute("missing", "dr")).ok).toBe(false);
    const aborted = new AbortController();
    aborted.abort();
    expect((await manager.execute(sessionId, "dr", aborted.signal)).ok).toBe(
      false,
    );
    expect(manager.status(sessionId)?.state).toBe("ready");
    expect((await manager.close("missing")).ok).toBe(false);
  },
);

it.skipIf(process.platform === "win32")(
  "retains sessions in status when close cannot confirm process cleanup",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); process.stdin.resume();',
    );
    const { manager, sessionId } = await start(provider, {
      stopProcess: incompleteStop,
    });
    expect((await manager.close(sessionId)).ok).toBe(false);
    expect(manager.status(sessionId)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "closes a session after unsolicited frames make command correlation unsafe",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); setTimeout(() => process.stdout.write("unexpected\\0"), 20); process.stdin.resume();',
    );
    const { manager, sessionId } = await start(provider);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const result = await manager.execute(sessionId, "dr");
    expect(result.ok).toBe(false);
    expect(manager.status(sessionId)?.state).toBe("closed");
    expect((await manager.close(sessionId)).ok).toBe(true);
  },
);
