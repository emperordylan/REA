import { afterEach, expect, it } from "vitest";
import { RizinDebugSessionManager } from "../../../src/rizin/RizinDebugSessionManager.js";
import {
  createRizinCoverageHarness,
  createInjectedProcess,
  incompleteStop,
} from "./RizinDebugSessionCoverage.fixtures.js";

const { cleanup, makeProvider, start, track } = createRizinCoverageHarness();
afterEach(cleanup);

it.skipIf(process.platform === "win32")(
  "discards an oversized frame split across deterministic stream chunks",
  async () => {
    const injected = createInjectedProcess({
      onWrite: (text, control) => {
        const marker = /!echo (.+)\n/u.exec(text)?.[1];
        if (marker !== undefined)
          setImmediate(() => {
            control.output(Buffer.alloc(16 * 1024 * 1024 + 1, 0x61));
            control.output(Buffer.from("discard tail"));
            control.output(Buffer.from([0]));
            control.output(Buffer.from(`${marker}\0`));
          });
      },
    });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      {
        spawnProcess: injected.spawnProcess,
        frameTimeoutMs: 1000,
        stopProcess: async () => ({ status: "stopped" }),
      },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const result = await manager.execute(started.value.session_id, "large");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.result.output_truncated).toBe(true);
  },
);

it.skipIf(process.platform === "win32")(
  "closes an injected session on an oversized unsolicited frame",
  async () => {
    const injected = createInjectedProcess();
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      { spawnProcess: injected.spawnProcess },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    injected.control.output(Buffer.alloc(16 * 1024 * 1024 + 1, 0x61));
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "preserves unsolicited history and marks oversized recent frames",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); process.stdin.resume(); setTimeout(() => process.stdout.write("x".repeat(17000) + "\\0"), 20);',
    );
    const { manager, sessionId } = await start(provider);
    await new Promise((resolve) => setTimeout(resolve, 100));
    const status = manager.status(sessionId);
    expect(status?.recent_output_truncated).toBe(true);
    expect(status?.recent_output.at(-1)).toContain("[recent frame truncated]");
  },
);

it.skipIf(process.platform === "win32")(
  "bounds recent history after many unsolicited frames",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0" + Array.from({ length: 70 }, (_, i) => "frame" + i + "\\0").join("")); process.stdin.resume();',
    );
    const { manager, sessionId } = await start(provider);
    const status = manager.status(sessionId);
    expect(status?.recent_output).toHaveLength(64);
    expect(status?.recent_output_truncated).toBe(true);
  },
);

it.skipIf(process.platform === "win32")(
  "returns partial unknown evidence when the process exits mid-command",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); process.stdin.setEncoding("utf8"); process.stdin.on("data", () => { process.stdout.write("partial\\0"); process.exit(0); });',
    );
    const { manager, sessionId } = await start(provider);
    const result = await manager.execute(sessionId, "dr");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.result).toMatchObject({
        output: "partial",
        completion_status: "unknown",
      });
      expect(result.value.evidence.limitations.join(" ")).toContain(
        "Rizin exited before",
      );
    }
  },
);

it.skipIf(process.platform === "win32")(
  "cancels a command after sending it and stops its owned session",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); process.stdin.resume();',
    );
    const { manager, sessionId } = await start(provider);
    const abort = new AbortController();
    const execution = manager.execute(sessionId, "slow", abort.signal);
    setTimeout(() => abort.abort(), 30);
    expect((await execution).ok).toBe(false);
    expect(manager.status(sessionId)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "keeps timeout evidence unavailable when cleanup cannot confirm process stop",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); process.stdin.setEncoding("utf8"); process.stdin.on("data", (chunk) => { if (chunk.includes("slow")) process.stdout.write("partial\\0"); });',
    );
    const { manager, sessionId } = await start(provider, {
      frameTimeoutMs: 25,
      stopProcess: incompleteStop,
    });
    const result = await manager.execute(sessionId, "slow");
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error.message).toContain("injected stop uncertainty");
  },
);

it.skipIf(process.platform === "win32")(
  "keeps truncated output unavailable when cleanup cannot confirm process stop",
  async () => {
    const provider = await makeProvider(
      `process.stdout.write("\\0");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const end = input.indexOf("\\n");
    if (end < 0) break;
    const line = input.slice(0, end); input = input.slice(end + 1);
    if (line === "many") process.stdout.write(Array.from({ length: 4100 }, (_, i) => "frame" + i + "\\0").join(""));
    else if (line.startsWith("!echo ")) process.stdout.write(line.slice(6) + "\\0");
  }
});`,
    );
    const { manager, sessionId } = await start(provider, {
      frameTimeoutMs: 1000,
      stopProcess: incompleteStop,
    });
    const result = await manager.execute(sessionId, "many");
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error.message).toContain("injected stop uncertainty");
  },
);

it.skipIf(process.platform === "win32")(
  "preserves the cleanup uncertainty when cancellation cannot confirm process stop",
  async () => {
    const provider = await makeProvider(
      'process.stdout.write("\\0"); process.stdin.resume();',
    );
    const { manager, sessionId } = await start(provider, {
      stopProcess: incompleteStop,
    });
    const abort = new AbortController();
    const execution = manager.execute(sessionId, "slow", abort.signal);
    setTimeout(() => abort.abort(), 30);
    const result = await execution;
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error.message).toContain("injected stop uncertainty");
  },
);

it.skipIf(process.platform === "win32")(
  "cancels a queued command without sending it after the prior command completes",
  async () => {
    const provider = await makeProvider(
      `process.stdout.write("\\0");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const end = input.indexOf("\\n");
    if (end < 0) break;
    const line = input.slice(0, end); input = input.slice(end + 1);
    if (line === "first") setTimeout(() => {}, 100);
    else if (line.startsWith("!echo ")) setTimeout(() => process.stdout.write(line.slice(6) + "\\0"), 100);
  }
});`,
    );
    const { manager, sessionId } = await start(provider, {
      frameTimeoutMs: 300,
    });
    const first = manager.execute(sessionId, "first");
    const abort = new AbortController();
    const queued = manager.execute(sessionId, "second", abort.signal);
    setTimeout(() => abort.abort(), 20);
    expect((await queued).ok).toBe(false);
    expect((await first).ok).toBe(true);
  },
);
