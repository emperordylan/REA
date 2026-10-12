/** Result of terminating one debugger process owned by this application. */
export type OwnedDebuggerStopResult =
  | { readonly status: "stopped" | "already_exited" }
  | { readonly status: "incomplete"; readonly reason: string };

const DETACH_TIMEOUT_MS = 1_000;
export type OwnedDebuggerDetachResult =
  | { readonly status: "no-inferior" }
  | { readonly status: "detached"; readonly outputSink: "durable" };
const detachAttempts = new WeakMap<
  object,
  Promise<OwnedDebuggerDetachResult>
>();

const waitForInferiorDetach = async (
  session: object,
  detach: () => Promise<OwnedDebuggerDetachResult>,
): Promise<OwnedDebuggerDetachResult | undefined> => {
  let attempt = detachAttempts.get(session);
  if (attempt === undefined) {
    const pending = Promise.resolve().then(detach);
    let tracked!: Promise<OwnedDebuggerDetachResult>;
    tracked = pending.then(
      (result) => {
        if (detachAttempts.get(session) === tracked)
          detachAttempts.delete(session);
        return result;
      },
      (cause: unknown) => {
        if (detachAttempts.get(session) === tracked)
          detachAttempts.delete(session);
        throw cause;
      },
    );
    attempt = tracked;
    detachAttempts.set(session, tracked);
  }
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      attempt,
      new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), DETACH_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};

interface OwnedDebuggerProcess {
  readonly id: string;
  readonly exited: boolean;
  readonly launched: {
    readonly process: { kill(signal: NodeJS.Signals): boolean };
  };
  /** Must return only after the provider verifies detachment or no inferior. */
  /** Confirms no inferior, or detaches only after verifying a durable output sink. */
  readonly detachInferior?: () => Promise<OwnedDebuggerDetachResult>;
  readonly supervisor: {
    waitForExit(timeoutMs: number): Promise<boolean>;
    /** WindowsOwnedProcess closes output only after the whole Job Object settles. */
    waitForOutputClose(timeoutMs: number): Promise<boolean>;
    unrefOutputStreams(): void;
    dispose(): void;
  };
}

/** Stop only the directly owned debugger process, never its process group or target. */
export const stopOwnedDebuggerProcess = async (
  session: OwnedDebuggerProcess,
  debuggerName: string,
  options: { readonly platform?: NodeJS.Platform } = {},
): Promise<OwnedDebuggerStopResult> => {
  const platform = options.platform ?? process.platform;
  if (session.exited) {
    try {
      if (!(await session.supervisor.waitForOutputClose(1_000)))
        return {
          status: "incomplete",
          reason:
            platform === "win32"
              ? `Owned ${debuggerName} process leader exited, but its Windows Job Object still has active descendants or has not reported settlement.`
              : `Owned ${debuggerName} process leader exited, but inherited output streams are still open or have not reported settlement.`,
        };
    } catch (cause: unknown) {
      return {
        status: "incomplete",
        reason:
          platform === "win32"
            ? `Owned ${debuggerName} Windows Job Object settlement could not be verified: ${cause instanceof Error ? cause.message : String(cause)}`
            : `Owned ${debuggerName} inherited output stream settlement could not be verified: ${cause instanceof Error ? cause.message : String(cause)}`,
      };
    }
    if (platform !== "win32") session.supervisor.unrefOutputStreams();
    session.supervisor.dispose();
    return { status: "already_exited" };
  }
  if (platform === "win32")
    return {
      status: "incomplete",
      reason: `Owned ${debuggerName} process cannot be stopped safely on Windows because job termination can also terminate its inferior processes.`,
    };
  try {
    if (session.detachInferior === undefined)
      return {
        status: "incomplete",
        reason: `Owned ${debuggerName} inferior detach cannot be verified because the provider has no detach capability.`,
      };
    const detached = await waitForInferiorDetach(
      session,
      session.detachInferior,
    );
    if (detached === undefined)
      return {
        status: "incomplete",
        reason: `Owned ${debuggerName} inferior detach was not verified within ${DETACH_TIMEOUT_MS} ms.`,
      };
    const verifiedNoInferior =
      typeof detached === "object" &&
      detached !== null &&
      detached.status === "no-inferior";
    const detachedWithSink =
      typeof detached === "object" &&
      detached !== null &&
      detached.status === "detached" &&
      detached.outputSink === "durable";
    if (!verifiedNoInferior && !detachedWithSink)
      return {
        status: "incomplete",
        reason: `Owned ${debuggerName} provider did not confirm no inferior or detachment with a durable output sink.`,
      };
  } catch (cause: unknown) {
    return {
      status: "incomplete",
      reason: `Owned ${debuggerName} inferior detach could not be verified: ${cause instanceof Error ? cause.message : String(cause)}`,
    };
  }
  session.launched.process.kill("SIGTERM");
  if (!(await session.supervisor.waitForExit(300))) {
    session.launched.process.kill("SIGKILL");
    const exitedAfterKill = await session.supervisor.waitForExit(1_000);
    if (exitedAfterKill) {
      session.supervisor.unrefOutputStreams();
      session.supervisor.dispose();
      return { status: "stopped" };
    }
    return {
      status: "incomplete",
      reason: `Owned ${debuggerName} process did not exit after direct termination.`,
    };
  }
  session.supervisor.unrefOutputStreams();
  session.supervisor.dispose();
  return { status: "stopped" };
};

/**
 * Stop every owned session and retain failed sessions for possible recovery.
 * Callers must block replacement admission and drain in-flight starts until
 * this settles; incomplete cleanup leaves the old owner in the map for retry.
 */
export const closeOwnedDebuggerSessions = async <
  Session extends { id: string },
>(
  sessions: Map<string, Session>,
  stop: (session: Session) => Promise<OwnedDebuggerStopResult>,
  debuggerName: string,
): Promise<void> => {
  const results = await Promise.allSettled(
    [...sessions.entries()].map(async ([key, session]) => ({
      key,
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
    const { key, session, result } = settled.value;
    if (result.status === "incomplete") failures.push(new Error(result.reason));
    else if (sessions.get(key) === session) sessions.delete(key);
  }
  if (failures.length > 0)
    throw new AggregateError(
      failures,
      `One or more owned ${debuggerName} processes did not stop cleanly`,
    );
};
