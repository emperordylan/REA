import { spawn } from "node:child_process";
import { once } from "node:events";

import { expect, it, vi } from "vitest";

import {
  closeOwnedDebuggerSessions,
  stopOwnedDebuggerProcess,
} from "../../../src/process/ownedDebuggerSession.js";
import { ProviderProcessSupervisor } from "../../../src/process/ProviderProcess.js";

it("retains process supervision after an incomplete stop and disposes after a retry observes exit", async () => {
  let waits = 0;
  let disposals = 0;
  let outputUnrefs = 0;
  const signals: NodeJS.Signals[] = [];
  const session = {
    id: "debugger-session",
    exited: false,
    launched: {
      process: {
        kill: (signal: NodeJS.Signals): boolean => {
          signals.push(signal);
          return true;
        },
      },
    },
    detachInferior: async () =>
      ({
        status: "detached",
        outputSink: "durable",
      }) as const,
    supervisor: {
      waitForExit: async (): Promise<boolean> => {
        waits += 1;
        return waits === 3;
      },
      waitForOutputClose: async (): Promise<boolean> => true,
      dispose: (): void => {
        disposals += 1;
      },
      unrefOutputStreams: (): void => {
        outputUnrefs += 1;
      },
    },
  };

  const first = await stopOwnedDebuggerProcess(session, "GDB", {
    platform: "linux",
  });
  expect(first).toEqual({
    status: "incomplete",
    reason: "Owned GDB process did not exit after direct termination.",
  });
  expect(disposals).toBe(0);
  expect(outputUnrefs).toBe(0);
  expect(signals).toEqual(["SIGTERM", "SIGKILL"]);

  const retry = await stopOwnedDebuggerProcess(session, "GDB", {
    platform: "linux",
  });
  expect(retry).toEqual({ status: "stopped" });
  expect(disposals).toBe(1);
  expect(waits).toBe(3);
});

it("refuses Windows job-backed debugger termination before signaling", async () => {
  const signals: NodeJS.Signals[] = [];
  let outputUnrefs = 0;
  const session = {
    id: "windows-debugger",
    exited: false,
    launched: {
      process: {
        kill: (signal: NodeJS.Signals): boolean => {
          signals.push(signal);
          return true;
        },
      },
    },
    supervisor: {
      waitForExit: async (): Promise<boolean> => false,
      waitForOutputClose: async (): Promise<boolean> => false,
      dispose: (): void => {},
      unrefOutputStreams: (): void => {
        outputUnrefs += 1;
      },
    },
  };

  await expect(
    stopOwnedDebuggerProcess(session, "GDB", { platform: "win32" }),
  ).resolves.toEqual({
    status: "incomplete",
    reason:
      "Owned GDB process cannot be stopped safely on Windows because job termination can also terminate its inferior processes.",
  });
  expect(signals).toEqual([]);
  expect(outputUnrefs).toBe(0);
});

it("retains an already-exited Windows session while its job has descendants", async () => {
  let outputUnrefs = 0;
  let disposals = 0;
  const result = await stopOwnedDebuggerProcess(
    {
      id: "windows-already-exited",
      exited: true,
      launched: { process: { kill: () => true } },
      supervisor: {
        waitForExit: async () => false,
        waitForOutputClose: async () => false,
        dispose: () => {
          disposals += 1;
        },
        unrefOutputStreams: () => {
          outputUnrefs += 1;
        },
      },
    },
    "GDB",
    { platform: "win32" },
  );

  expect(result).toEqual({
    status: "incomplete",
    reason:
      "Owned GDB process leader exited, but its Windows Job Object still has active descendants or has not reported settlement.",
  });
  expect(disposals).toBe(0);
  expect(outputUnrefs).toBe(0);
});

it("retains an exited POSIX session while descendants still hold its output streams", async () => {
  let outputUnrefs = 0;
  let disposals = 0;
  const result = await stopOwnedDebuggerProcess(
    {
      id: "posix-already-exited-with-descendant",
      exited: true,
      launched: { process: { kill: () => true } },
      supervisor: {
        waitForExit: async () => true,
        waitForOutputClose: async () => false,
        dispose: () => {
          disposals += 1;
        },
        unrefOutputStreams: () => {
          outputUnrefs += 1;
        },
      },
    },
    "GDB",
    { platform: "linux" },
  );

  expect(result).toEqual({
    status: "incomplete",
    reason:
      "Owned GDB process leader exited, but inherited output streams are still open or have not reported settlement.",
  });
  expect(disposals).toBe(0);
  expect(outputUnrefs).toBe(0);
});

it("does not signal a POSIX debugger when provider detach cannot be verified", async () => {
  const signals: NodeJS.Signals[] = [];
  const result = await stopOwnedDebuggerProcess(
    {
      id: "unverified-detach",
      exited: false,
      launched: { process: { kill: (signal) => (signals.push(signal), true) } },
      detachInferior: async () => {
        throw new Error("MI detach failed");
      },
      supervisor: {
        waitForExit: async () => false,
        waitForOutputClose: async () => false,
        dispose: () => {},
        unrefOutputStreams: () => {},
      },
    },
    "GDB",
    { platform: "linux" },
  );

  expect(result).toEqual({
    status: "incomplete",
    reason: "Owned GDB inferior detach could not be verified: MI detach failed",
  });
  expect(signals).toEqual([]);
});

it("allows closing when the provider confirms no inferior is attached", async () => {
  const signals: NodeJS.Signals[] = [];
  const result = await stopOwnedDebuggerProcess(
    {
      id: "no-inferior",
      exited: false,
      launched: { process: { kill: (signal) => (signals.push(signal), true) } },
      detachInferior: async () => ({ status: "no-inferior" }),
      supervisor: {
        waitForExit: async () => true,
        waitForOutputClose: async () => false,
        dispose: () => {},
        unrefOutputStreams: () => {},
      },
    },
    "GDB",
    { platform: "linux" },
  );

  expect(result).toEqual({ status: "stopped" });
  expect(signals).toEqual(["SIGTERM"]);
});

it("fails closed when detach lacks durable output sink confirmation", async () => {
  const signals: NodeJS.Signals[] = [];
  const result = await stopOwnedDebuggerProcess(
    {
      id: "non-durable-sink",
      exited: false,
      launched: { process: { kill: (signal) => (signals.push(signal), true) } },
      detachInferior: async () => ({ status: "detached" }) as never,
      supervisor: {
        waitForExit: async () => true,
        waitForOutputClose: async () => false,
        dispose: () => {},
        unrefOutputStreams: () => {},
      },
    },
    "GDB",
    { platform: "linux" },
  );

  expect(result).toEqual({
    status: "incomplete",
    reason:
      "Owned GDB provider did not confirm no inferior or detachment with a durable output sink.",
  });
  expect(signals).toEqual([]);
});

it("retains an owned debugger when inferior detach does not settle", async () => {
  vi.useFakeTimers();
  const signals: NodeJS.Signals[] = [];
  let detachCalls = 0;
  let resolveDetach!: (value: {
    readonly status: "detached";
    readonly outputSink: "durable";
  }) => void;
  let disposals = 0;
  try {
    const session = {
      id: "detach-timeout",
      exited: false,
      launched: {
        process: {
          kill: (signal: NodeJS.Signals) => (signals.push(signal), true),
        },
      },
      detachInferior: () => {
        detachCalls += 1;
        if (detachCalls > 1)
          return Promise.resolve({
            status: "detached",
            outputSink: "durable",
          } as const);
        return new Promise<{
          readonly status: "detached";
          readonly outputSink: "durable";
        }>((resolve) => {
          resolveDetach = resolve;
        });
      },
      supervisor: {
        waitForExit: async () => true,
        waitForOutputClose: async () => false,
        dispose: () => {
          disposals += 1;
        },
        unrefOutputStreams: () => {},
      },
    };

    const attempt = stopOwnedDebuggerProcess(session, "GDB", {
      platform: "linux",
    });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await attempt).toEqual({
      status: "incomplete",
      reason: "Owned GDB inferior detach was not verified within 1000 ms.",
    });
    const retry = stopOwnedDebuggerProcess(session, "GDB", {
      platform: "linux",
    });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await retry).toEqual({
      status: "incomplete",
      reason: "Owned GDB inferior detach was not verified within 1000 ms.",
    });
    expect(detachCalls).toBe(1);
    expect(signals).toEqual([]);
    expect(disposals).toBe(0);

    resolveDetach({ status: "detached", outputSink: "durable" });
    await vi.advanceTimersByTimeAsync(0);
    expect(
      await stopOwnedDebuggerProcess(session, "GDB", { platform: "linux" }),
    ).toEqual({ status: "stopped" });
    expect(detachCalls).toBe(2);
    expect(signals).toEqual(["SIGTERM"]);
    expect(disposals).toBe(1);
  } finally {
    vi.useRealTimers();
  }
});

it("requires the Windows Job Object to close before releasing an exited session", async () => {
  let closeWaits = 0;
  let disposals = 0;
  const session = {
    id: "windows-job-settlement",
    exited: true,
    launched: { process: { kill: () => true } },
    supervisor: {
      waitForExit: async () => true,
      waitForOutputClose: async () => ++closeWaits > 1,
      dispose: () => {
        disposals += 1;
      },
      unrefOutputStreams: () => {},
    },
  };

  expect(
    await stopOwnedDebuggerProcess(session, "GDB", { platform: "win32" }),
  ).toMatchObject({ status: "incomplete" });
  expect(disposals).toBe(0);
  expect(
    await stopOwnedDebuggerProcess(session, "GDB", { platform: "win32" }),
  ).toEqual({ status: "already_exited" });
  expect(closeWaits).toBe(2);
  expect(disposals).toBe(1);
});

it("disposes supervision when a process had already exited", async () => {
  let disposals = 0;
  const lifecycle: string[] = [];
  let outputUnrefs = 0;
  const result = await stopOwnedDebuggerProcess(
    {
      id: "already-exited",
      exited: true,
      launched: { process: { kill: () => true } },
      supervisor: {
        waitForExit: async () => false,
        waitForOutputClose: async () => true,
        dispose: () => {
          lifecycle.push("dispose");
          disposals += 1;
        },
        unrefOutputStreams: () => {
          lifecycle.push("unref");
          outputUnrefs += 1;
        },
      },
    },
    "GDB",
    { platform: "linux" },
  );

  expect(result).toEqual({ status: "already_exited" });
  expect(disposals).toBe(1);
  expect(outputUnrefs).toBe(1);
  expect(lifecycle).toEqual(["unref", "dispose"]);
});

it.skipIf(process.platform === "win32")(
  "keeps supervision until a late-writing descendant closes inherited output after leader exit",
  async () => {
    const inferiorSource = [
      'setTimeout(() => { process.stdout.write("late-stdout-sentinel\\n"); process.stderr.write("late-stderr-sentinel\\n"); }, 250);',
      "setTimeout(() => process.exit(0), 400);",
    ].join("\n");
    const debuggerSource = [
      'const { spawn } = require("node:child_process");',
      `spawn(process.execPath, ["-e", ${JSON.stringify(inferiorSource)}], { stdio: "inherit" });`,
      "process.exit(0);",
    ].join("\n");
    const child = spawn(process.execPath, ["-e", debuggerSource], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const supervisor = new ProviderProcessSupervisor({
      process: child,
      ownsProcessLifetime: true,
    });

    try {
      await once(child, "exit");
      const result = await stopOwnedDebuggerProcess(
        {
          id: "leader-exited-with-inferior",
          exited: true,
          launched: { process: child },
          supervisor,
        },
        "GDB",
        { platform: "linux" },
      );

      expect(result).toEqual({ status: "already_exited" });
      expect(supervisor.snapshot().stdout.text).toContain(
        "late-stdout-sentinel",
      );
      expect(supervisor.snapshot().stderr.text).toContain(
        "late-stderr-sentinel",
      );
    } finally {
      supervisor.dispose();
    }
  },
);

it("does not escalate when the debugger exits after SIGTERM", async () => {
  const signals: NodeJS.Signals[] = [];
  const lifecycle: string[] = [];
  let disposals = 0;
  const result = await stopOwnedDebuggerProcess(
    {
      id: "graceful-exit",
      exited: false,
      launched: {
        process: {
          kill: (signal: NodeJS.Signals): boolean => {
            signals.push(signal);
            return true;
          },
        },
      },
      detachInferior: async () =>
        ({
          status: "detached",
          outputSink: "durable",
        }) as const,
      supervisor: {
        waitForExit: async () => true,
        waitForOutputClose: async () => true,
        dispose: () => {
          lifecycle.push("dispose");
          disposals += 1;
        },
        unrefOutputStreams: () => lifecycle.push("unref"),
      },
    },
    "Rizin",
    { platform: "linux" },
  );

  expect(result).toEqual({ status: "stopped" });
  expect(signals).toEqual(["SIGTERM"]);
  expect(disposals).toBe(1);
  expect(lifecycle).toEqual(["unref", "dispose"]);
});

it("disposes supervision when the debugger exits after SIGKILL", async () => {
  let waits = 0;
  let disposals = 0;
  const lifecycle: string[] = [];
  const signals: NodeJS.Signals[] = [];
  const result = await stopOwnedDebuggerProcess(
    {
      id: "forced-exit",
      exited: false,
      launched: {
        process: {
          kill: (signal: NodeJS.Signals): boolean => {
            signals.push(signal);
            return true;
          },
        },
      },
      detachInferior: async () =>
        ({
          status: "detached",
          outputSink: "durable",
        }) as const,
      supervisor: {
        waitForExit: async () => {
          waits += 1;
          return waits === 2;
        },
        waitForOutputClose: async () => true,
        dispose: () => {
          lifecycle.push("dispose");
          disposals += 1;
        },
        unrefOutputStreams: () => lifecycle.push("unref"),
      },
    },
    "Rizin",
    { platform: "linux" },
  );

  expect(result).toEqual({ status: "stopped" });
  expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
  expect(disposals).toBe(1);
  expect(lifecycle).toEqual(["unref", "dispose"]);
});

it.skipIf(process.platform === "win32")(
  "lets the probe exit while an inferior still holds debugger output pipes open",
  async () => {
    const providerProcessUrl = new URL(
      "../../../dist/process/ProviderProcess.js",
      import.meta.url,
    ).href;
    const debuggerSessionUrl = new URL(
      "../../../dist/process/ownedDebuggerSession.js",
      import.meta.url,
    ).href;
    const debuggerSource = [
      'const { spawn } = require("node:child_process");',
      'const inferior = spawn(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], { stdio: "inherit" });',
      "process.stdout.write(`debugger=${process.pid} inferior=${inferior.pid}\\n`);",
      "setInterval(() => {}, 1000);",
    ].join("\n");
    const probeSource = [
      'import { spawn } from "node:child_process";',
      `import { ProviderProcessSupervisor } from ${JSON.stringify(providerProcessUrl)};`,
      `import { stopOwnedDebuggerProcess } from ${JSON.stringify(debuggerSessionUrl)};`,
      `const child = spawn(process.execPath, ["-e", ${JSON.stringify(debuggerSource)}], { stdio: ["ignore", "pipe", "pipe"] });`,
      "const supervisor = new ProviderProcessSupervisor({ process: child, ownsProcessLifetime: true });",
      "let output = '';",
      "let debuggerPid;",
      "const pid = await new Promise((resolve, reject) => {",
      "  const timer = setTimeout(() => reject(new Error('debugger did not report inferior pid')), 2000);",
      "  child.stdout.on('data', (chunk) => {",
      "    output += chunk.toString();",
      "    const debuggerMatch = /^debugger=(\\d+)/mu.exec(output);",
      "    if (debuggerMatch) process.stderr.write(`debugger-pid=${debuggerMatch[1]}\\n`);",
      "    const match = /inferior=(\\d+)\\r?\\n/mu.exec(output);",
      "    if (match) { clearTimeout(timer); resolve(Number(match[1])); }",
      "  });",
      "  child.once('error', reject);",
      "});",
      "const session = { id: 'debugger', get exited() { return child.exitCode !== null || child.signalCode !== null; }, launched: { process: child }, supervisor };",
      "session.detachInferior = async () => ({ status: 'detached', outputSink: 'durable' });",
      "const result = await stopOwnedDebuggerProcess(session, 'GDB', { platform: 'linux' });",
      "process.stdout.write(JSON.stringify({ pid, result }));",
    ].join("\n");
    const probe = spawn(
      process.execPath,
      ["--input-type=module", "-e", probeSource],
      {
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let probeOutput = "";
    let debuggerPid: number | undefined;
    probe.stdout.on("data", (chunk) => {
      probeOutput += chunk.toString();
    });
    probe.stderr.on("data", (chunk: Buffer) => {
      const match = /^debugger-pid=(\d+)$/mu.exec(chunk.toString());
      if (match?.[1] !== undefined) debuggerPid = Number(match[1]);
    });
    let inferiorPid: number | undefined;

    try {
      const resultLine = await new Promise<string>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error("probe did not report debugger stop")),
          3_000,
        );
        const onData = (chunk: Buffer | string): void => {
          const text = chunk.toString();
          const line = text.match(
            /\{"pid":\d+,"result":\{"status":"stopped"\}\}/u,
          );
          if (line !== null) {
            clearTimeout(timeout);
            resolve(line[0]);
          }
        };
        probe.stdout.on("data", onData);
        probe.once("error", (cause) => {
          clearTimeout(timeout);
          reject(cause);
        });
      });
      const result = JSON.parse(resultLine) as { pid: number };
      inferiorPid = result.pid;

      const exited = await Promise.race([
        once(probe, "exit").then(() => true),
        new Promise<false>((resolve) =>
          setTimeout(() => resolve(false), 1_000),
        ),
      ]);
      expect(exited).toBe(true);
      expect(probeOutput).toContain('"status":"stopped"');
      expect(() => process.kill(inferiorPid!, 0)).not.toThrow();
    } finally {
      if (inferiorPid !== undefined) {
        try {
          process.kill(inferiorPid, "SIGKILL");
        } catch {
          // The fixture may have exited on its own.
        }
      }
      if (debuggerPid !== undefined) {
        try {
          process.kill(debuggerPid, "SIGKILL");
        } catch {
          // The debugger may have exited on its own.
        }
      }
      if (probe.exitCode === null && probe.signalCode === null)
        probe.kill("SIGKILL");
      if (probe.exitCode === null && probe.signalCode === null)
        await once(probe, "exit").catch(() => undefined);
    }
  },
);

it.skipIf(process.platform === "win32")(
  "preserves inferior stdout and stderr after the debugger stops",
  async () => {
    const inferiorSource = [
      'setTimeout(() => { process.stdout.write("stdout-after-stop-sentinel\\n"); process.stderr.write("stderr-after-stop-sentinel\\n"); }, 700);',
      "setTimeout(() => process.exit(0), 4000);",
    ].join("\n");
    const debuggerSource = [
      'const { spawn } = require("node:child_process");',
      `const inferior = spawn(process.execPath, ["-e", ${JSON.stringify(inferiorSource)}], { stdio: "inherit" });`,
      "process.stdout.write(`inferior=${inferior.pid}\\n`);",
      "setInterval(() => {}, 1000);",
    ].join("\n");
    const child = spawn(process.execPath, ["-e", debuggerSource], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const supervisor = new ProviderProcessSupervisor({
      process: child,
      ownsProcessLifetime: true,
    });
    let stdout = "";
    let stderr = "";
    let inferiorPid: number | undefined;
    let checkOutput: (() => void) | undefined;
    let finishOutput: (() => void) | undefined;
    const outputReceived = new Promise<void>((resolve) => {
      finishOutput = resolve;
    });
    const trackOutput = (stream: "stdout" | "stderr", chunk: Buffer): void => {
      if (stream === "stdout") stdout += chunk.toString();
      else stderr += chunk.toString();
      checkOutput?.();
    };
    child.stdout.on("data", (chunk: Buffer) => trackOutput("stdout", chunk));
    child.stderr.on("data", (chunk: Buffer) => trackOutput("stderr", chunk));
    checkOutput = () => {
      if (
        stdout.includes("stdout-after-stop-sentinel") &&
        stderr.includes("stderr-after-stop-sentinel")
      )
        finishOutput?.();
    };
    const ready = new Promise<number>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("debugger did not report inferior pid")),
        2_000,
      );
      const checkReady = (): void => {
        const match = /^inferior=(\d+)$/mu.exec(stdout);
        if (match?.[1] !== undefined) {
          clearTimeout(timeout);
          resolve(Number(match[1]));
        }
      };
      const onStdout = (): void => checkReady();
      child.stdout.on("data", onStdout);
      child.once("error", (cause) => {
        clearTimeout(timeout);
        reject(cause);
      });
    });

    try {
      const pid = await ready;
      inferiorPid = pid;
      const result = await stopOwnedDebuggerProcess(
        {
          id: "debugger-with-inferior",
          get exited() {
            return child.exitCode !== null || child.signalCode !== null;
          },
          launched: { process: child },
          detachInferior: async () =>
            ({
              status: "detached",
              outputSink: "durable",
            }) as const,
          supervisor,
        },
        "GDB",
        { platform: "linux" },
      );

      expect(result).toEqual({ status: "stopped" });
      await Promise.race([
        outputReceived,
        new Promise<never>((_resolve, reject) =>
          setTimeout(
            () =>
              reject(new Error("inferior output sentinels were not observed")),
            2_000,
          ),
        ),
      ]);
      expect(stdout).toContain("stdout-after-stop-sentinel");
      expect(stderr).toContain("stderr-after-stop-sentinel");
      expect(child.stdout.destroyed).toBe(false);
      expect(child.stderr.destroyed).toBe(false);
      expect(() => process.kill(pid, 0)).not.toThrow();
    } finally {
      if (inferiorPid !== undefined) {
        try {
          process.kill(inferiorPid, "SIGKILL");
        } catch {
          // The fixture may have exited on its own.
        }
        await Promise.race([
          once(child, "close"),
          new Promise<void>((resolve) => setTimeout(resolve, 1_000)),
        ]);
        if (child.exitCode === null && child.signalCode === null) {
          child.kill("SIGKILL");
          await Promise.race([
            once(child, "exit"),
            new Promise<void>((resolve) => setTimeout(resolve, 1_000)),
          ]);
        }
      } else if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        await once(child, "exit").catch(() => undefined);
      }
      supervisor.dispose();
    }
  },
);

it("removes stopped sessions and retains incomplete sessions when closing all", async () => {
  const sessions = new Map([
    ["stopped", { id: "stopped" }],
    ["incomplete", { id: "incomplete" }],
  ]);

  await expect(
    closeOwnedDebuggerSessions(
      sessions,
      async (session) =>
        session.id === "incomplete"
          ? { status: "incomplete", reason: "process remains alive" }
          : { status: "stopped" },
      "GDB",
    ),
  ).rejects.toMatchObject({
    errors: [expect.objectContaining({ message: "process remains alive" })],
  });
  expect([...sessions.keys()]).toEqual(["incomplete"]);
});

it("does not remove a replacement session installed under the same key while stopping", async () => {
  const original = { id: "shared-key", generation: "old" };
  const replacement = { id: "shared-key", generation: "new" };
  const sessions = new Map([["shared-key", original]]);
  let finishStop!: (result: { readonly status: "stopped" }) => void;
  const stopping = new Promise<{ readonly status: "stopped" }>((resolve) => {
    finishStop = resolve;
  });

  const closing = closeOwnedDebuggerSessions(
    sessions,
    async () => stopping,
    "GDB",
  );
  await Promise.resolve();
  sessions.set("shared-key", replacement);
  finishStop({ status: "stopped" });
  await closing;

  expect(sessions.get("shared-key")).toBe(replacement);
});

it("closes an empty owned-session collection", async () => {
  const sessions = new Map<string, { id: string }>();
  await expect(
    closeOwnedDebuggerSessions(
      sessions,
      async () => ({ status: "stopped" }),
      "GDB",
    ),
  ).resolves.toBeUndefined();
});

it("settles every stop and retains rejected sessions while removing successful ones", async () => {
  const sessions = new Map([
    ["stopped", { id: "stopped" }],
    ["rejected", { id: "rejected" }],
    ["string-rejected", { id: "string-rejected" }],
    ["incomplete", { id: "incomplete" }],
  ]);
  const calls: string[] = [];

  await expect(
    closeOwnedDebuggerSessions(
      sessions,
      async (session) => {
        calls.push(session.id);
        if (session.id === "rejected") throw new Error("signal failed");
        if (session.id === "string-rejected") throw "string rejection";
        if (session.id === "incomplete")
          return { status: "incomplete", reason: "still alive" };
        return { status: "stopped" };
      },
      "GDB",
    ),
  ).rejects.toMatchObject({
    message: "One or more owned GDB processes did not stop cleanly",
    errors: [
      expect.objectContaining({ message: "signal failed" }),
      expect.objectContaining({ message: "string rejection" }),
      expect.objectContaining({ message: "still alive" }),
    ],
  });

  expect(calls).toHaveLength(4);
  expect([...sessions.keys()]).toEqual([
    "rejected",
    "string-rejected",
    "incomplete",
  ]);
});
