/** Result of terminating one debugger process owned by this application. */
export type OwnedDebuggerStopResult =
  | { readonly status: "stopped" | "already_exited" }
  | { readonly status: "incomplete"; readonly reason: string };

interface OwnedDebuggerProcess {
  readonly id: string;
  readonly exited: boolean;
  readonly launched: {
    readonly process: { kill(signal: NodeJS.Signals): boolean };
  };
  readonly supervisor: {
    waitForExit(timeoutMs: number): Promise<boolean>;
    dispose(): void;
  };
}

/** Stop only the directly owned debugger process, never its process group or target. */
export const stopOwnedDebuggerProcess = async (
  session: OwnedDebuggerProcess,
  debuggerName: string,
  options: { readonly platform?: NodeJS.Platform } = {},
): Promise<OwnedDebuggerStopResult> => {
  if (session.exited) {
    session.supervisor.dispose();
    return { status: "already_exited" };
  }
  if ((options.platform ?? process.platform) === "win32")
    return {
      status: "incomplete",
      reason: `Owned ${debuggerName} process cannot be stopped safely on Windows because job termination can also terminate its inferior processes.`,
    };
  session.launched.process.kill("SIGTERM");
  if (!(await session.supervisor.waitForExit(300))) {
    session.launched.process.kill("SIGKILL");
    const exitedAfterKill = await session.supervisor.waitForExit(1_000);
    if (exitedAfterKill) {
      session.supervisor.dispose();
      return { status: "stopped" };
    }
    return {
      status: "incomplete",
      reason: `Owned ${debuggerName} process did not exit after direct termination.`,
    };
  }
  session.supervisor.dispose();
  return { status: "stopped" };
};

/** Stop every owned session and retain failed sessions for possible recovery. */
export const closeOwnedDebuggerSessions = async <
  Session extends { id: string },
>(
  sessions: Map<string, Session>,
  stop: (session: Session) => Promise<OwnedDebuggerStopResult>,
  debuggerName: string,
): Promise<void> => {
  const results = await Promise.allSettled(
    [...sessions.values()].map(async (session) => ({
      session,
      result: await stop(session),
    })),
  );
  const failures: Error[] = [];
  for (const settled of results) {
    if (settled.status === "rejected") {
      failures.push(
        settled.reason instanceof Error
          ? settled.reason
          : new Error(String(settled.reason)),
      );
      continue;
    }
    const { session, result } = settled.value;
    if (result.status === "incomplete") failures.push(new Error(result.reason));
    else sessions.delete(session.id);
  }
  if (failures.length > 0)
    throw new AggregateError(
      failures,
      `One or more owned ${debuggerName} processes did not stop cleanly`,
    );
};
