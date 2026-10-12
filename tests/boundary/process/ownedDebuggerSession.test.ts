import { expect, it } from "vitest";

import {
  closeOwnedDebuggerSessions,
  stopOwnedDebuggerProcess,
} from "../../../src/process/ownedDebuggerSession.js";

it("retains process supervision after an incomplete stop and disposes after a retry observes exit", async () => {
  let waits = 0;
  let disposals = 0;
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
    supervisor: {
      waitForExit: async (): Promise<boolean> => {
        waits += 1;
        return waits === 3;
      },
      dispose: (): void => {
        disposals += 1;
      },
    },
  };

  const first = await stopOwnedDebuggerProcess(session, "GDB");
  expect(first).toEqual({
    status: "incomplete",
    reason: "Owned GDB process did not exit after direct termination.",
  });
  expect(disposals).toBe(0);
  expect(signals).toEqual(["SIGTERM", "SIGKILL"]);

  const retry = await stopOwnedDebuggerProcess(session, "GDB");
  expect(retry).toEqual({ status: "stopped" });
  expect(disposals).toBe(1);
  expect(waits).toBe(3);
});

it("refuses Windows job-backed debugger termination before signaling", async () => {
  const signals: NodeJS.Signals[] = [];
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
      dispose: (): void => {},
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
});

it("disposes supervision when a process had already exited", async () => {
  let disposals = 0;
  const result = await stopOwnedDebuggerProcess(
    {
      id: "already-exited",
      exited: true,
      launched: { process: { kill: () => true } },
      supervisor: {
        waitForExit: async () => false,
        dispose: () => {
          disposals += 1;
        },
      },
    },
    "GDB",
  );

  expect(result).toEqual({ status: "already_exited" });
  expect(disposals).toBe(1);
});

it("does not escalate when the debugger exits after SIGTERM", async () => {
  const signals: NodeJS.Signals[] = [];
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
      supervisor: {
        waitForExit: async () => true,
        dispose: () => {
          disposals += 1;
        },
      },
    },
    "Rizin",
  );

  expect(result).toEqual({ status: "stopped" });
  expect(signals).toEqual(["SIGTERM"]);
  expect(disposals).toBe(1);
});

it("disposes supervision when the debugger exits after SIGKILL", async () => {
  let waits = 0;
  let disposals = 0;
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
      supervisor: {
        waitForExit: async () => {
          waits += 1;
          return waits === 2;
        },
        dispose: () => {
          disposals += 1;
        },
      },
    },
    "Rizin",
  );

  expect(result).toEqual({ status: "stopped" });
  expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
  expect(disposals).toBe(1);
});

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
