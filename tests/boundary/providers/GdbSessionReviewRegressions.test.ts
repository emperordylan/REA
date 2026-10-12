import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, expect, it } from "vitest";

import { GdbSessionManager } from "../../../src/gdb/GdbSessionManager.js";

let directory: string | undefined;
const managers: Array<{ closeAll(): Promise<void> }> = [];

const expectOwnedProcessExited = async (pidText: string): Promise<void> => {
  const pid = Number(pidText);
  expect(Number.isInteger(pid)).toBe(true);
  expect(() => process.kill(pid, 0)).toThrow();
};

it("keeps persistent GDB sessions unavailable on Windows", async () => {
  const gdb = await new GdbSessionManager({
    environment: { REA_GDB_COMMAND: "/missing/gdb" },
    platform: "win32",
  }).start();

  expect(gdb.ok).toBe(false);
  if (!gdb.ok) {
    expect(gdb.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(gdb.error.message).toContain("Job Object");
  }
});

afterEach(async () => {
  await Promise.all(
    managers
      .splice(0)
      .map((manager) => manager.closeAll().catch(() => undefined)),
  );
  if (directory !== undefined)
    await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

it.skipIf(process.platform === "win32")(
  "marks GDB status history truncated when old MI records are discarded",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-history-truncated-"));
    const provider = join(directory, "fake-gdb-history-truncated.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n" + Array.from({ length: 300 }, (_, index) =>
  "=thread-group-added,id=\\"i" + index + "\\"\\n").join(""));
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  for (const line of chunk.split("\\n")) {
    const match = /^(\\d+)/.exec(line);
    if (match) process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    expect(
      manager.status(started.value.session_id)?.recent_mi_records_truncated,
    ).toBe(true);
  },
);

it.skipIf(process.platform === "win32")(
  "returns partial GDB observations with unknown completion on command timeout",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-command-timeout-"));
    const provider = join(directory, "fake-gdb-command-timeout.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
await import("node:fs/promises").then((fs) => fs.writeFile(${JSON.stringify(join(directory ?? "", "pid"))}, String(process.pid)));
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match && line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
    else if (match) process.stdout.write("~\\"partial output\\n\\"\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
      commandTimeoutMs: 40,
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    const result = await manager.execute(
      started.value.session_id,
      "shell sleep 5",
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.result).toMatchObject({
        completion_status: "unknown",
        records: ['~"partial output', '"'],
      });
      expect(result.value.evidence.limitations.join(" ")).toContain("partial");
    }
    await expectOwnedProcessExited(
      await readFile(join(directory, "pid"), "utf8"),
    );
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "keeps queued GDB commands serialized when a waiting request is cancelled",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-queue-cancel-"));
    const provider = join(directory, "fake-gdb-queue-cancel.mjs");
    const overlapPath = join(directory, "overlap");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
let firstActive = false;
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n"); if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line); if (!match) continue;
    if (line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
    else if (line.includes("first")) {
      firstActive = true;
      setTimeout(() => { firstActive = false; process.stdout.write(match[1] + "^done\\n"); }, 100);
    } else {
      if (line.includes("third") && firstActive) import("node:fs/promises").then((fs) => fs.writeFile(${JSON.stringify(overlapPath)}, "overlap"));
      process.stdout.write(match[1] + "^done\\n");
    }
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const first = manager.execute(started.value.session_id, "first");
    const controller = new AbortController();
    const second = manager.execute(
      started.value.session_id,
      "second",
      controller.signal,
    );
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
    controller.abort();
    const third = manager.execute(started.value.session_id, "third");
    expect((await second).ok).toBe(false);
    expect((await first).ok).toBe(true);
    expect((await third).ok).toBe(true);
    await expect(readFile(overlapPath, "utf8")).rejects.toThrow();
  },
);

it.skipIf(process.platform === "win32")(
  "marks GDB exit-fallback output truncated when MI history was bounded",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-exit-truncated-"));
    const provider = join(directory, "fake-gdb-exit-truncated.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n"); if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line); if (!match) continue;
    if (line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
    else {
      process.stdout.write(Array.from({ length: 300 }, (_, index) => "=thread-created,id=\\"" + index + "\\"\\n").join(""));
      process.exit(0);
    }
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    const result = await manager.execute(
      started.value.session_id,
      "info threads",
    );

    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.result).toMatchObject({
        process_exit_observed: true,
        output_truncated: false,
        completion_status: "unknown",
      });
    if (result.ok) expect(result.value.result.records).toHaveLength(300);
  },
);

it.skipIf(process.platform === "win32")(
  "cancels a running GDB command and retains its closed status",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-command-cancel-"));
    const provider = join(directory, "fake-gdb-command-cancel.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match && line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    const result = await manager.execute(
      started.value.session_id,
      "shell sleep 600",
      controller.signal,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "reports bounded GDB stderr retention in session status",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-diagnostic-limit-"));
    const provider = join(directory, "fake-gdb-diagnostic-limit.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stderr.write("x".repeat(100000));
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match) process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    expect(
      manager.status(started.value.session_id)?.diagnostics_truncated,
    ).toBe(true);
  },
);

it.skipIf(process.platform === "win32")(
  "converts a GDB stdin pipe failure into a provider session error",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-stdin-error-"));
    const provider = join(directory, "fake-gdb-stdin-error.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n"); if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match && line.includes("auto-load off")) {
      process.stdout.write(match[1] + "^done\\n");
      setTimeout(() => import("node:fs").then((fs) => fs.closeSync(0)), 50);
    }
  }
});
setInterval(() => {}, 1000);
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));

    const result = await manager.execute(
      started.value.session_id,
      "info files",
    );

    expect(result.ok).toBe(false);
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "keeps GDB exit-fallback Evidence scoped to the active command",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-command-exit-scope-"));
    const provider = join(directory, "fake-gdb-command-exit-scope.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line); if (!match) continue;
    if (line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
    else if (line.includes("first command")) process.stdout.write("~first-command-only\\n" + match[1] + "^done\\n");
    else process.stdout.write("~second-command-partial\\n@target-partial\\n@target-tail\\n&log-partial\\n&log-tail\\n~second-command-tail\\n", () => process.exit(7));
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    expect(
      (await manager.execute(started.value.session_id, "first command")).ok,
    ).toBe(true);
    const exited = await manager.execute(
      started.value.session_id,
      "second command",
    );

    expect(exited.ok).toBe(true);
    if (exited.ok) {
      expect(exited.value.result).toMatchObject({
        command: "second command",
        mi: "",
        process_exit_observed: true,
        records: [
          "~second-command-partial",
          "@target-partial",
          "@target-tail",
          "&log-partial",
          "&log-tail",
          "~second-command-tail",
        ],
        console: ["~second-command-partial", "~second-command-tail"].join("\n"),
        target: ["@target-partial", "@target-tail"].join("\n"),
        log: ["&log-partial", "&log-tail"].join("\n"),
        output_truncated: false,
        completion_status: "unknown",
      });
      expect(exited.value.result.records.join(" ")).not.toContain(
        "first-command-only",
      );
      expect(exited.value.evidence.normalized_result).toMatchObject({
        command: "second command",
        records: [
          "~second-command-partial",
          "@target-partial",
          "@target-tail",
          "&log-partial",
          "&log-tail",
          "~second-command-tail",
        ],
        console: ["~second-command-partial", "~second-command-tail"].join("\n"),
        target: ["@target-partial", "@target-tail"].join("\n"),
        log: ["&log-partial", "&log-tail"].join("\n"),
        completion_status: "unknown",
      });
      expect(exited.value.evidence.parameters).toMatchObject({
        command: "second command",
        session_id: started.value.session_id,
      });
      expect(exited.value.evidence.raw_result).toMatchObject({
        command: "second command",
        records: [
          "~second-command-partial",
          "@target-partial",
          "@target-tail",
          "&log-partial",
          "&log-tail",
          "~second-command-tail",
        ],
        completion_status: "unknown",
      });
      expect(exited.value.evidence.limitations.join(" ")).toContain(
        "only records retained for the active command",
      );
      expect(exited.value.evidence.limitations.join(" ")).toContain(
        "The active GDB inferior identity is not established by the debugger session identifier.",
      );
    }
  },
);

it.skipIf(process.platform === "win32")(
  "preserves the GDB cleanup failure when a running command is cancelled",
  async () => {
    directory = await mkdtemp(
      join(tmpdir(), "rea-gdb-cancel-cleanup-failure-"),
    );
    const provider = join(directory, "fake-gdb-cancel-cleanup-failure.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line); if (!match) continue;
    if (line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
      stopProcess: async (session) => {
        session.launched.process.kill("SIGTERM");
        return {
          status: "incomplete",
          reason: "simulated debugger cleanup failure",
        };
      },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const controller = new AbortController();
    const execution = manager.execute(
      started.value.session_id,
      "shell sleep 600",
      controller.signal,
    );
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 30));
    controller.abort();

    const cancelled = await execution;

    expect(cancelled.ok).toBe(false);
    if (!cancelled.ok) {
      expect(cancelled.error._tag).toBe("AnalysisCapabilityUnavailableError");
      expect(cancelled.error.message).toContain(
        "simulated debugger cleanup failure",
      );
    }
  },
);
