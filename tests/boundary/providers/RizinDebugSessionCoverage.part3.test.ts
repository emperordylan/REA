import { afterEach, expect, it, vi } from "vitest";
import { RizinDebugSessionManager } from "../../../src/rizin/RizinDebugSessionManager.js";
import {
  createRizinCoverageHarness,
  abortOnCheck,
  createInjectedProcess,
} from "./RizinDebugSessionCoverage.fixtures.js";

const { cleanup, track } = createRizinCoverageHarness();
afterEach(cleanup);

it.skipIf(process.platform === "win32")(
  "times out when an active command produces no frame",
  async () => {
    const injected = createInjectedProcess();
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      {
        spawnProcess: injected.spawnProcess,
        frameTimeoutMs: 10,
        stopProcess: async () => ({ status: "stopped" }),
      },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const result = await manager.execute(started.value.session_id, "wait");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.result.completion_status).toBe("unknown");
      expect(result.value.evidence.raw_result).toEqual(result.value.result);
      expect(result.value.evidence.limitations).toEqual([
        "The current debugger target identity is not established by the Rizin session identifier.",
        "The command timed out before its completion marker; retained output is partial and completion is unknown.",
        "The owned debugger process was stopped because output correlation could no longer be guaranteed.",
        "The command is unrestricted and may access local files, the shell, network, or mutate the target.",
      ]);
    }
  },
);

it.skipIf(process.platform === "win32")(
  "preserves frame separators in partial output when a command times out",
  async () => {
    const injected = createInjectedProcess({
      onWrite: (_text, control) => {
        control.output("first frame\0second frame\0");
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

    const result = await manager.execute(started.value.session_id, "wait");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.result.output).toBe("first frame\nsecond frame");
      expect(result.value.result.completion_status).toBe("unknown");
    }
  },
);

it.skipIf(process.platform === "win32")(
  "preserves queued partial frames when the command deadline reaches zero",
  async () => {
    const injected = createInjectedProcess({
      onWrite: (_text, control) => {
        control.output("first frame\0second frame\0third frame\0");
      },
    });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      { spawnProcess: injected.spawnProcess, frameTimeoutMs: 1000 },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    const clock = vi.spyOn(Date, "now");
    clock
      .mockReturnValueOnce(100)
      .mockReturnValueOnce(100)
      .mockReturnValueOnce(100)
      .mockReturnValue(1100);
    let result;
    try {
      result = await manager.execute(started.value.session_id, "wait");
    } finally {
      clock.mockRestore();
    }

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.result.output).toBe("first frame\nsecond frame");
      expect(result.value.result.completion_status).toBe("unknown");
    }
  },
);

it.skipIf(process.platform === "win32")(
  "does not convert an unexpected frame waiter error into a timeout",
  async () => {
    const injected = createInjectedProcess({
      onWrite: (_text, control) => {
        setImmediate(() => control.stdinError());
      },
    });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      {
        spawnProcess: injected.spawnProcess,
        frameTimeoutMs: 100,
        stopProcess: async () => ({ status: "stopped" }),
      },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    const result = await manager.execute(started.value.session_id, "wait");

    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error.message).toContain("Rizin stdin stream failed");
  },
);

it.skipIf(process.platform === "win32")(
  "cancels a command after capturing its completion frame",
  async () => {
    let signal: AbortSignal;
    const injected = createInjectedProcess({
      onWrite: (text, control) => {
        const marker = /!echo (.+)\n/u.exec(text)?.[1];
        if (marker !== undefined) control.output(Buffer.from(`${marker}\0`));
      },
    });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      { spawnProcess: injected.spawnProcess },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    signal = abortOnCheck(5);
    const result = await manager.execute(
      started.value.session_id,
      "dr",
      signal,
    );
    expect(result.ok).toBe(false);
  },
);

it.skipIf(process.platform === "win32")(
  "handles cancellation observed immediately after installing the frame waiter",
  async () => {
    const injected = createInjectedProcess();
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      {
        spawnProcess: injected.spawnProcess,
        stopProcess: async () => ({ status: "stopped" }),
      },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const result = await manager.execute(
      started.value.session_id,
      "wait",
      abortOnCheck(5),
    );
    expect(result.ok).toBe(false);
  },
);

it.skipIf(process.platform === "win32").each([false, true])(
  "maps a frame-wait listener installation failure without losing cleanup (incomplete=%s)",
  async (incomplete) => {
    const injected = createInjectedProcess();
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      {
        spawnProcess: injected.spawnProcess,
        stopProcess: async () =>
          incomplete
            ? { status: "incomplete", reason: "injected stop uncertainty" }
            : { status: "stopped" },
        frameTimeoutMs: 1000,
      },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const controller = new AbortController();
    let registrations = 0;
    const signal = {
      get aborted() {
        return false;
      },
      addEventListener(
        type: Parameters<AbortSignal["addEventListener"]>[0],
        listener: Parameters<AbortSignal["addEventListener"]>[1],
        options?: Parameters<AbortSignal["addEventListener"]>[2],
      ) {
        registrations += 1;
        if (registrations === 2)
          throw new Error("injected frame waiter registration failure");
        controller.signal.addEventListener(type, listener, options);
      },
      removeEventListener: controller.signal.removeEventListener.bind(
        controller.signal,
      ),
      dispatchEvent: controller.signal.dispatchEvent.bind(controller.signal),
      onabort: null,
      reason: undefined,
      throwIfAborted: () => undefined,
    } as AbortSignal;
    const result = await manager.execute(
      started.value.session_id,
      "wait",
      signal,
    );
    expect(result.ok).toBe(false);
    if (!result.ok && incomplete)
      expect(result.error.message).toContain("injected stop uncertainty");
  },
);

it.skipIf(process.platform === "win32")(
  "correlates an injected command frame with its generated marker",
  async () => {
    const injected = createInjectedProcess({
      onWrite: (text, control) => {
        const marker = /!echo (.+)\n/u.exec(text)?.[1];
        if (marker !== undefined)
          setImmediate(() => control.output(Buffer.from(`output${marker}\0`)));
      },
    });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      { spawnProcess: injected.spawnProcess },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const result = await manager.execute(started.value.session_id, "dr");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.result.output).toBe("output");
  },
);

it.skipIf(process.platform === "win32")(
  "preserves process-exit evidence when exit occurs before frame waiting",
  async () => {
    const injected = createInjectedProcess({
      onWrite: (_text, control) => control.exit(),
    });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      { spawnProcess: injected.spawnProcess },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const result = await manager.execute(started.value.session_id, "dr");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.result.completion_status).toBe("unknown");
      expect(result.value.result).toMatchObject({
        command: "dr",
        output: "",
        output_truncated: false,
        completion_status: "unknown",
        backend: null,
      });
      expect(result.value.evidence.raw_result).toEqual(result.value.result);
      expect(result.value.evidence.limitations).toEqual([
        "The current debugger target identity is not established by the Rizin session identifier.",
        "Rizin exited before the command-completion marker; retained frame output is partial and command completion is unknown.",
        "The command is unrestricted and may access local files, the shell, network, or mutate the target.",
      ]);
    }
  },
);

it.skipIf(process.platform === "win32")(
  "rejects a queued command when the process exits before its frame wait begins",
  async () => {
    const injected = createInjectedProcess({
      onWrite: (text, control) => {
        const marker = /!echo (.+)\n/u.exec(text)?.[1];
        if (marker !== undefined) setImmediate(() => control.exit());
      },
    });
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: "injected-rizin" },
      { spawnProcess: injected.spawnProcess },
    );
    track(manager);
    const started = await manager.start({ path: "/tmp/injected" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const first = manager.execute(started.value.session_id, "first");
    const queued = manager.execute(started.value.session_id, "second");
    expect((await first).ok).toBe(true);
    const second = await queued;
    expect(second.ok).toBe(true);
    if (second.ok)
      expect(second.value.result.completion_status).toBe("unknown");
  },
);
