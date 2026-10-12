import { randomUUID } from "node:crypto";

import {
  AnalysisCapabilityUnavailableError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import {
  closeOwnedDebuggerSessions,
  stopOwnedDebuggerProcess,
  type OwnedDebuggerDetachResult,
} from "../process/ownedDebuggerSession.js";

const STARTUP_TIMEOUT_MS = 10_000;
const COMMAND_TIMEOUT_MS = 120_000;
const MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_MI_LINE_BYTES = 16 * 1024 * 1024;
const MAX_RECENT_MI_LINE_BYTES = 64 * 1024;
const MAX_DIAGNOSTIC_BYTES = 64 * 1024;
const DEFAULT_MAX_SESSIONS = 8;
const MAX_PENDING_GDB_COMMANDS = 16;
const RECENT_RECORD_TRUNCATION_MARKER = "[recent record truncated]";

export const GDB_PROVIDER_IDENTITY = {
  id: "gnu.gdb",
  name: "GNU GDB",
  version: null,
} as const;

interface PendingCommand {
  readonly token: number;
  readonly command: string;
  readonly evidenceCommand: string;
  readonly lines: string[];
  outputBytes: number;
  outputTruncated: boolean;
  readonly resolve: (result: GdbCommandResult) => void;
  readonly reject: (error: Error) => void;
  readonly cleanup: () => void;
  timer: ReturnType<typeof setTimeout>;
}

export interface GdbCommandResult {
  readonly command: string;
  readonly mi: string;
  readonly records: readonly string[];
  readonly console: string;
  readonly target: string;
  readonly log: string;
  readonly process_exit_observed?: boolean;
  readonly process_exit_code?: number | null;
  readonly process_exit_signal?: NodeJS.Signals | null;
  readonly output_truncated: boolean;
  readonly completion_status: "complete" | "unknown";
}

class GdbCommandTimeoutError extends AnalysisTimeoutError {
  constructor(
    readonly partial: GdbCommandResult,
    readonly evidence: Evidence,
    timeoutMs: number,
  ) {
    super("gdb_console", timeoutMs);
  }
}

const truncateUtf8RecordPrefix = (line: string): string => {
  const budget =
    MAX_RECENT_MI_LINE_BYTES -
    Buffer.byteLength(RECENT_RECORD_TRUNCATION_MARKER, "utf8");
  let prefix = "";
  let retainedBytes = 0;
  for (const codePoint of line) {
    const codePointBytes = Buffer.byteLength(codePoint, "utf8");
    if (retainedBytes + codePointBytes > budget) break;
    prefix += codePoint;
    retainedBytes += codePointBytes;
  }
  return `${prefix}${RECENT_RECORD_TRUNCATION_MARKER}`;
};

const gdbThreadGroupCount = (mi: string): number | undefined => {
  const marker = mi.indexOf("groups=[");
  if (marker < 0) return undefined;
  const start = marker + "groups=[".length;
  let squareDepth = 1;
  let objectDepth = 0;
  let quoted = false;
  let escaped = false;
  let count = 0;
  for (let index = start; index < mi.length; index += 1) {
    const character = mi[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quoted = false;
      continue;
    }
    if (character === '"') {
      quoted = true;
      continue;
    }
    if (character === "[") squareDepth += 1;
    else if (character === "]") {
      squareDepth -= 1;
      if (squareDepth === 0) {
        const body = mi.slice(start, index);
        if (body.includes("groups=[")) return undefined;
        return count;
      }
    } else if (character === "{") {
      if (squareDepth === 1 && objectDepth === 0) count += 1;
      objectDepth += 1;
    } else if (character === "}") {
      objectDepth -= 1;
      if (objectDepth < 0) return undefined;
    }
  }
  return undefined;
};

class GdbCommandProcessExitError extends Error {
  constructor(readonly partial: GdbCommandResult) {
    super("GDB exited before returning the active MI command result");
  }
}

interface GdbSession {
  readonly id: string;
  readonly miVersion: "mi3" | "mi2";
  readonly launched: SpawnedOwnedProviderProcess;
  readonly supervisor: ProviderProcessSupervisor;
  /** Confirms target disposition and any durable sink before process cleanup. */
  readonly detachInferior: () => Promise<OwnedDebuggerDetachResult>;
  readonly inferiorTty: string | undefined;
  inferiorTtyVerified: boolean;
  noInferiorVerified: boolean;
  stopAttempt: ReturnType<typeof stopOwnedDebuggerProcess> | undefined;
  readonly pending: Map<number, PendingCommand>;
  readonly lines: string[];
  buffer: string;
  ready: boolean;
  exited: boolean;
  exitCode: number | null;
  exitSignal: NodeJS.Signals | null;
  nextToken: number;
  startupResolve: (() => void) | undefined;
  startupReject: ((error: Error) => void) | undefined;
  commandTail: Promise<void>;
  pendingCommandCount: number;
  protocolError: string | undefined;
  recentRecordsTruncated: boolean;
}

/** Owns persistent GDB/MI sessions independently from the active binary target. */
export class GdbSessionManager {
  readonly #sessions = new Map<string, GdbSession>();
  readonly #activeStarts = new Map<
    AbortController,
    Promise<
      Result<
        { readonly session_id: string; readonly mi_version: "mi3" | "mi2" },
        AnalysisError
      >
    >
  >();
  readonly #command: string;
  readonly #environment: NodeJS.ProcessEnv;
  readonly #commandTimeoutMs: number;
  readonly #startupTimeoutMs: number;
  readonly #platform: NodeJS.Platform;
  readonly #stopProcess: typeof stopOwnedDebuggerProcess;
  readonly #spawnProcess: typeof spawnOwnedProviderProcess;
  readonly #maxSessions: number;
  #sessionReservations = 0;
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(
    options: {
      readonly environment?: Readonly<NodeJS.ProcessEnv>;
      readonly commandTimeoutMs?: number;
      readonly startupTimeoutMs?: number;
      readonly platform?: NodeJS.Platform;
      readonly stopProcess?: typeof stopOwnedDebuggerProcess;
      readonly spawnProcess?: typeof spawnOwnedProviderProcess;
      readonly maxSessions?: number;
    } = {},
  ) {
    this.#environment = { ...(options.environment ?? process.env) };
    this.#command = this.#environment.REA_GDB_COMMAND ?? "gdb";
    this.#commandTimeoutMs = options.commandTimeoutMs ?? COMMAND_TIMEOUT_MS;
    this.#startupTimeoutMs = options.startupTimeoutMs ?? STARTUP_TIMEOUT_MS;
    this.#platform = options.platform ?? process.platform;
    this.#stopProcess = options.stopProcess ?? stopOwnedDebuggerProcess;
    this.#spawnProcess = options.spawnProcess ?? spawnOwnedProviderProcess;
    this.#maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
  }

  async start(
    signal?: AbortSignal,
    options: { readonly inferiorTty?: string } = {},
  ): Promise<
    Result<
      { readonly session_id: string; readonly mi_version: "mi3" | "mi2" },
      AnalysisError
    >
  > {
    if (
      options.inferiorTty !== undefined &&
      (options.inferiorTty.length === 0 || options.inferiorTty.includes("\0"))
    )
      return err(
        new AnalysisInputError("start_gdb_session", undefined, [
          {
            path: ["inferior_tty"],
            reason: "invalid_value",
            message:
              "The inferior TTY path must be non-empty and must not contain NUL.",
          },
        ]),
      );
    if (this.#closing || signal?.aborted)
      return err(new AnalysisCancelledError("start_gdb_session"));
    const controller = new AbortController();
    const relayAbort = (): void => controller.abort(signal?.reason);
    signal?.addEventListener("abort", relayAbort, { once: true });
    if (signal?.aborted) relayAbort();
    const tracked = Promise.resolve()
      .then(() => this.#startWithReservation(controller.signal, options))
      .finally(() => {
        signal?.removeEventListener("abort", relayAbort);
        this.#activeStarts.delete(controller);
      });
    this.#activeStarts.set(controller, tracked);
    return tracked;
  }

  async #startWithReservation(
    signal?: AbortSignal,
    options: { readonly inferiorTty?: string } = {},
  ): Promise<
    Result<
      { readonly session_id: string; readonly mi_version: "mi3" | "mi2" },
      AnalysisError
    >
  > {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("start_gdb_session"));
    const occupied = this.#sessions.size + this.#sessionReservations;
    if (occupied >= this.#maxSessions)
      return err(
        new AnalysisResourceConstraintError(
          "start_gdb_session",
          "memory",
          "GDB session capacity reached.",
          {
            max_sessions: this.#maxSessions,
            active_or_reserved_sessions: occupied,
          },
        ),
      );
    this.#sessionReservations += 1;
    let reservationHeld = true;
    const releaseReservation = (): void => {
      if (!reservationHeld) return;
      reservationHeld = false;
      this.#sessionReservations -= 1;
    };
    try {
      return await this.#startReserved(releaseReservation, signal, options);
    } finally {
      releaseReservation();
    }
  }

  async #startReserved(
    releaseReservation: () => void,
    signal?: AbortSignal,
    options: { readonly inferiorTty?: string } = {},
  ): Promise<
    Result<
      { readonly session_id: string; readonly mi_version: "mi3" | "mi2" },
      AnalysisError
    >
  > {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("start_gdb_session"));
    if (this.#platform === "win32")
      return err(
        new AnalysisCapabilityUnavailableError(
          "gdb",
          "start_gdb_session",
          "Persistent Windows GDB sessions are unavailable because the owned Job Object cleanup can terminate debugger inferiors.",
        ),
      );
    const id = randomUUID();
    const mi3 = await this.#startProtocol(
      id,
      "mi3",
      releaseReservation,
      signal,
      options.inferiorTty,
    );
    return mi3.ok || signal?.aborted || this.#sessions.has(id)
      ? mi3
      : this.#startProtocol(
          id,
          "mi2",
          releaseReservation,
          signal,
          options.inferiorTty,
        );
  }

  async #startProtocol(
    id: string,
    miVersion: "mi3" | "mi2",
    releaseReservation: () => void,
    signal?: AbortSignal,
    inferiorTty?: string,
  ): Promise<
    Result<
      { readonly session_id: string; readonly mi_version: "mi3" | "mi2" },
      AnalysisError
    >
  > {
    let launched: SpawnedOwnedProviderProcess;
    try {
      const spawnOptions: OwnedProviderProcessSpawnOptions = {
        command: this.#command,
        arguments: ["--nx", "--quiet", `--interpreter=${miVersion}`],
        runId: randomUUID(),
        stdin: "pipe",
        hostEnvironment: this.#environment,
        ...(signal === undefined ? {} : { signal }),
      };
      launched = await this.#spawnProcess(spawnOptions);
    } catch (cause) {
      return err(
        new AnalysisCapabilityUnavailableError(
          "gdb",
          "start_gdb_session",
          cause instanceof Error ? cause.message : "Unable to start GDB",
        ),
      );
    }
    const supervisor = new ProviderProcessSupervisor(
      { process: launched.process, ownsProcessLifetime: false },
      { captureStdout: false, maxDiagnosticBytes: MAX_DIAGNOSTIC_BYTES },
    );
    const session: GdbSession = {
      id,
      miVersion,
      launched,
      supervisor,
      detachInferior: () => this.#detachInferior(session),
      inferiorTty,
      inferiorTtyVerified: false,
      noInferiorVerified: false,
      stopAttempt: undefined,
      pending: new Map(),
      lines: [],
      buffer: "",
      ready: false,
      exited: false,
      exitCode: null,
      exitSignal: null,
      nextToken: 1,
      startupResolve: undefined,
      startupReject: undefined,
      commandTail: Promise.resolve(),
      pendingCommandCount: 0,
      protocolError: undefined,
      recentRecordsTruncated: false,
    };
    launched.process.stdout?.setEncoding("utf8");
    launched.process.stdout?.on("data", (chunk: string | Buffer) =>
      this.#receive(session, String(chunk)),
    );
    launched.process.stdin?.on("error", (cause: Error) =>
      this.#failProtocol(session, `GDB stdin stream failed: ${cause.message}`),
    );
    launched.process.stdin?.once("close", () => {
      if (!session.exited && session.protocolError === undefined)
        this.#failProtocol(session, "GDB stdin stream closed unexpectedly.");
    });
    launched.process.once("exit", (code, signalCode) => {
      session.exited = true;
      session.exitCode = code;
      session.exitSignal = signalCode;
      for (const pending of session.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(
          new GdbCommandProcessExitError({
            command: pending.command,
            mi: "",
            records: [...pending.lines],
            console: pending.lines
              .filter((line) => line.startsWith("~"))
              .join("\n"),
            target: pending.lines
              .filter((line) => line.startsWith("@"))
              .join("\n"),
            log: pending.lines
              .filter((line) => line.startsWith("&"))
              .join("\n"),
            process_exit_observed: true,
            process_exit_code: code,
            process_exit_signal: signalCode,
            output_truncated: pending.outputTruncated,
            completion_status: "unknown",
          }),
        );
      }
      session.pending.clear();
      session.startupReject?.(new Error("GDB exited during startup"));
    });
    let startupTimer!: ReturnType<typeof setTimeout>;
    let startupAbortListener!: () => void;
    try {
      await new Promise<void>((resolve, reject) => {
        session.startupResolve = resolve;
        session.startupReject = reject;
        startupAbortListener = () =>
          reject(new AnalysisCancelledError("start_gdb_session"));
        signal?.addEventListener("abort", startupAbortListener, {
          once: true,
        });
        if (signal?.aborted) startupAbortListener();
        startupTimer = setTimeout(
          () =>
            reject(
              new AnalysisTimeoutError(
                "start_gdb_session",
                this.#startupTimeoutMs,
                {
                  cause: new Error(
                    "GDB did not emit the MI prompt before the startup deadline",
                  ),
                },
              ),
            ),
          this.#startupTimeoutMs,
        );
        startupTimer.unref();
      });
      session.ready = true;
      if (signal?.aborted)
        throw new AnalysisCancelledError("start_gdb_session");
      const autoLoad = await this.#request(
        session,
        "-gdb-set auto-load off",
        signal,
        "start_gdb_session",
      );
      if (!/^\d+\^done(?:,|$)/u.test(autoLoad.mi)) {
        throw new AnalysisCapabilityUnavailableError(
          "gdb",
          "start_gdb_session",
          `GDB rejected the required automatic-loading disable command (${autoLoad.mi}); the session was not started.`,
        );
      }
      if (inferiorTty !== undefined) {
        const configured = await this.#request(
          session,
          `-inferior-tty-set ${miQuote(inferiorTty)}`,
          signal,
          "start_gdb_session",
        );
        if (
          configured.completion_status !== "complete" ||
          configured.output_truncated ||
          !/^\d+\^done(?:,|$)/u.test(configured.mi)
        )
          throw new AnalysisCapabilityUnavailableError(
            "gdb",
            "start_gdb_session",
            "GDB did not confirm the inferior TTY configuration.",
          );
        const observed = await this.#request(
          session,
          "-inferior-tty-show",
          signal,
          "start_gdb_session",
        );
        const reportedTty =
          observed.completion_status === "complete" &&
          !observed.output_truncated
            ? miStringField(observed.mi, "inferior_tty_terminal")
            : undefined;
        if (
          !/^\d+\^done(?:,|$)/u.test(observed.mi) ||
          reportedTty !== inferiorTty
        )
          throw new AnalysisCapabilityUnavailableError(
            "gdb",
            "start_gdb_session",
            "GDB did not report the exact caller-selected inferior TTY after configuration.",
          );
        session.inferiorTtyVerified = true;
      }
      if (signal?.aborted)
        throw new AnalysisCancelledError("start_gdb_session");
      this.#sessions.set(id, session);
      releaseReservation();
      return ok({ session_id: id, mi_version: miVersion });
    } catch (cause) {
      const startupExited =
        cause instanceof GdbCommandProcessExitError || session.exited;
      const processExit =
        cause instanceof GdbCommandProcessExitError
          ? cause.partial
          : startupExited
            ? {
                command: "GDB startup",
                mi: "",
                records: [...session.lines],
                console: session.lines
                  .filter((line) => line.startsWith("~"))
                  .join("\n"),
                target: session.lines
                  .filter((line) => line.startsWith("@"))
                  .join("\n"),
                log: session.lines
                  .filter((line) => line.startsWith("&"))
                  .join("\n"),
                process_exit_observed: true,
                process_exit_code: session.exitCode,
                process_exit_signal: session.exitSignal,
                output_truncated: session.recentRecordsTruncated,
                completion_status: "unknown" as const,
              }
            : undefined;
      const startupEvidenceResult =
        processExit ??
        (session.lines.length > 0
          ? {
              command: "GDB startup",
              mi: "",
              records: [...session.lines],
              console: session.lines
                .filter((line) => line.startsWith("~"))
                .join("\n"),
              target: session.lines
                .filter((line) => line.startsWith("@"))
                .join("\n"),
              log: session.lines
                .filter((line) => line.startsWith("&"))
                .join("\n"),
              output_truncated: session.recentRecordsTruncated,
              completion_status: "unknown" as const,
            }
          : undefined);
      const startupEvidence =
        startupEvidenceResult === undefined
          ? undefined
          : createEvidence(undefined, GDB_PROVIDER_IDENTITY, {
              predicateType: "rea.debugger.startup-observation",
              operation: "start_gdb_session",
              parameters: {
                mi_version: miVersion,
                command: startupEvidenceResult.command,
              },
              result: {
                ...startupEvidenceResult,
                records: [...startupEvidenceResult.records],
              },
              rawResult: {
                ...startupEvidenceResult,
                records: [...startupEvidenceResult.records],
              },
              subjectUnavailableReason:
                "No usable debugger session became ready during GDB startup.",
              limitations: [
                "GDB startup failed before a usable session could be established; captured startup records are incomplete.",
              ],
            });
      const processOutput = session.supervisor.snapshot();
      const capturedOutput = {
        stdout: processOutput.stdout.text,
        stderr: processOutput.stderr.text,
        truncated:
          processOutput.diagnosticTruncated === true ||
          processOutput.stdout.observedBytes > processOutput.stdout.bytes ||
          processOutput.stderr.observedBytes > processOutput.stderr.bytes,
        stdout_bytes: processOutput.stdout.observedBytes,
        stderr_bytes: processOutput.stderr.observedBytes,
        exit_code: processOutput.exitCode ?? null,
        signal: processOutput.signal ?? null,
      };
      const stopped = await this.#stopDebuggerOnly(session);
      if (stopped.status === "incomplete") {
        this.#sessions.set(id, session);
        releaseReservation();
        const cleanup = { reason: stopped.reason, resources: [session.id] };
        const details = {
          cause,
          capturedOutput,
          cleanup,
          ...(startupEvidence === undefined
            ? {}
            : { partialObservation: startupEvidence }),
        };
        if (cause instanceof AnalysisTimeoutError)
          return err(
            new AnalysisTimeoutError(cause.operation, cause.timeoutMs, details),
          );
        if (cause instanceof AnalysisCancelledError)
          return err(new AnalysisCancelledError(cause.operation, details));
        const startupFailureMessage =
          cause instanceof Error ? cause.message : String(cause);
        return err(
          new AnalysisCapabilityUnavailableError(
            "gdb",
            "start_gdb_session",
            `GDB startup failed (${startupFailureMessage}) and its owned process could not be confirmed stopped: ${stopped.reason}`,
            details,
          ),
        );
      }
      const errorDetails = {
        cause,
        capturedOutput,
        ...(startupEvidence === undefined
          ? {}
          : { partialObservation: startupEvidence }),
      };
      const error =
        signal?.aborted || cause instanceof AnalysisCancelledError
          ? new AnalysisCancelledError("start_gdb_session", errorDetails)
          : cause instanceof AnalysisTimeoutError
            ? new AnalysisTimeoutError(
                cause.operation,
                cause.timeoutMs,
                errorDetails,
              )
            : cause instanceof AnalysisCapabilityUnavailableError
              ? new AnalysisCapabilityUnavailableError(
                  "gdb",
                  "start_gdb_session",
                  cause.message,
                  errorDetails,
                )
              : session.protocolError !== undefined
                ? new AnalysisCapabilityUnavailableError(
                    "gdb",
                    "start_gdb_session",
                    session.protocolError,
                    errorDetails,
                  )
                : startupExited
                  ? new AnalysisCapabilityUnavailableError(
                      "gdb",
                      "start_gdb_session",
                      `GDB exited during startup (exit code ${String(session.exitCode)}, signal ${String(session.exitSignal)}).`,
                      errorDetails,
                    )
                  : new AnalysisTimeoutError(
                      "start_gdb_session",
                      this.#startupTimeoutMs,
                      errorDetails,
                    );
      return err(error);
    } finally {
      clearTimeout(startupTimer);
      signal?.removeEventListener("abort", startupAbortListener);
    }
  }

  async execute(
    sessionId: string,
    command: string,
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly result: GdbCommandResult; readonly evidence: Evidence },
      AnalysisError
    >
  > {
    const session = this.#sessions.get(sessionId);
    if (
      session === undefined ||
      !session.ready ||
      session.exited ||
      session.protocolError !== undefined
    )
      return err(
        new AnalysisInputError("gdb_console", undefined, [
          {
            path: ["session_id"],
            reason: "invalid_value",
            message: "GDB session is unavailable or closed.",
          },
        ]),
      );
    if (signal?.aborted) return err(new AnalysisCancelledError("gdb_console"));
    try {
      return await this.#serialize(
        session,
        async () => {
          if (session.exited || session.protocolError !== undefined)
            return err(new AnalysisInputError("gdb_console"));
          session.noInferiorVerified = false;
          if (commandMayChangeInferiorOutput(command))
            session.inferiorTtyVerified = false;
          try {
            const result = await this.#request(
              session,
              `-interpreter-exec console ${miQuote(command)}`,
              signal,
              "gdb_console",
              command,
            );
            const evidence = createEvidence(
              undefined,
              { id: "gnu.gdb", name: "GNU GDB", version: null },
              {
                predicateType: "rea.debugger.console-observation",
                operation: "gdb_console",
                parameters: { session_id: sessionId, command },
                result: {
                  command,
                  mi: result.mi,
                  records: [...result.records],
                  console: result.console,
                  target: result.target,
                  log: result.log,
                  output_truncated: result.output_truncated,
                  completion_status: result.completion_status,
                },
                rawResult: {
                  command,
                  mi: result.mi,
                  records: [...result.records],
                  console: result.console,
                  target: result.target,
                  log: result.log,
                  output_truncated: result.output_truncated,
                  completion_status: result.completion_status,
                },
                subjectUnavailableReason:
                  "The active GDB inferior identity is not established by the debugger session identifier.",
                limitations: [
                  "MI records are preserved raw; their semantics depend on GDB version and target.",
                  "The unrestricted GDB console can access local shell, filesystem, network, and target controls.",
                ],
              },
            );
            return ok({ result, evidence });
          } catch (cause) {
            if (cause instanceof AnalysisCancelledError)
              return err(
                new AnalysisCancelledError("gdb_console", {
                  cause,
                  ...(cause.cleanup === undefined
                    ? {}
                    : { cleanup: cause.cleanup }),
                  ...(cause.partialObservation === undefined
                    ? {}
                    : { partialObservation: cause.partialObservation }),
                }),
              );
            if (cause instanceof AnalysisCapabilityUnavailableError)
              return err(cause as AnalysisError);
            if (cause instanceof GdbCommandTimeoutError) {
              const result = cause.partial;
              return ok({ result, evidence: cause.evidence });
            }
            if (session.protocolError !== undefined)
              return err(await this.#stopAfterProtocolFailure(session, cause));
            if (cause instanceof GdbCommandProcessExitError) {
              const processExit = cause as GdbCommandProcessExitError;
              const result: GdbCommandResult = {
                ...processExit.partial,
                command,
              };
              const evidence = createEvidence(
                undefined,
                { id: "gnu.gdb", name: "GNU GDB", version: null },
                {
                  predicateType: "rea.debugger.console-observation",
                  operation: "gdb_console",
                  parameters: { session_id: sessionId, command },
                  result: { ...result, records: [...result.records] },
                  rawResult: { ...result, records: [...result.records] },
                  subjectUnavailableReason:
                    "The active GDB inferior identity is not established by the debugger session identifier.",
                  limitations: [
                    "GDB exited before returning a correlated MI result record; only records retained for the active command are returned raw.",
                    ...(result.output_truncated
                      ? [
                          "Retained MI records are a truncated prefix; output completeness is unknown.",
                        ]
                      : []),
                  ],
                },
              );
              return ok({ result, evidence });
            }
            return err(
              new AnalysisTimeoutError("gdb_console", this.#commandTimeoutMs, {
                cause,
              }),
            );
          }
        },
        signal,
        "gdb_console",
      );
    } catch (cause) {
      return err(
        cause instanceof AnalysisError
          ? cause
          : new AnalysisCancelledError("gdb_console", { cause }),
      );
    }
  }

  status(sessionId: string):
    | {
        readonly session_id: string;
        readonly mi_version: "mi3" | "mi2";
        readonly state: "ready" | "closed";
        readonly recent_mi_records: readonly string[];
        readonly recent_mi_records_truncated: boolean;
        readonly stderr: string;
        readonly stderr_observed_bytes: number;
        readonly stderr_truncated: boolean;
        readonly diagnostics_truncated: boolean;
        readonly inferior_tty: string | null;
        readonly inferior_tty_verified: boolean;
      }
    | undefined {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) return undefined;
    const diagnostics = session.supervisor.snapshot();
    return {
      session_id: session.id,
      mi_version: session.miVersion,
      state:
        session.exited || session.protocolError !== undefined || !session.ready
          ? "closed"
          : "ready",
      recent_mi_records: [...session.lines],
      recent_mi_records_truncated: session.recentRecordsTruncated,
      stderr: diagnostics.stderr.text,
      stderr_observed_bytes: diagnostics.stderr.observedBytes,
      stderr_truncated:
        diagnostics.stderr.observedBytes > diagnostics.stderr.bytes,
      diagnostics_truncated: diagnostics.diagnosticTruncated === true,
      inferior_tty: session.inferiorTty ?? null,
      inferior_tty_verified: session.inferiorTtyVerified,
    };
  }

  async close(
    sessionId: string,
  ): Promise<
    Result<
      { readonly target_state: "none_observed" | "unknown" },
      AnalysisError
    >
  > {
    const session = this.#sessions.get(sessionId);
    if (session === undefined)
      return err(new AnalysisInputError("close_gdb_session"));
    if (session.exited) {
      const stopped = await this.#stopDebuggerOnly(session);
      if (stopped.status === "incomplete")
        return err(
          new AnalysisCapabilityUnavailableError(
            "gdb",
            "close_gdb_session",
            stopped.reason,
          ),
        );
      this.#sessions.delete(sessionId);
      return ok({ target_state: "unknown" });
    }
    try {
      return await this.#serialize(
        session,
        async () => {
          if (session.exited) {
            const stopped = await this.#stopDebuggerOnly(session);
            if (stopped.status === "incomplete")
              return err(
                new AnalysisCapabilityUnavailableError(
                  "gdb",
                  "close_gdb_session",
                  stopped.reason,
                ),
              );
            this.#sessions.delete(sessionId);
            return ok({ target_state: "unknown" });
          }
          let targetState: "none_observed" | "unknown" = "unknown";
          try {
            const groups = await this.#request(
              session,
              "-list-thread-groups --recurse 1",
            );
            if (
              groups.completion_status !== "complete" ||
              groups.output_truncated ||
              !/^\d+\^done(?:,|$)/u.test(groups.mi)
            )
              throw new Error(
                "GDB could not confirm its complete, untruncated inferior list before shutdown.",
              );
            const groupCount = gdbThreadGroupCount(groups.mi);
            if (groupCount === undefined)
              throw new Error(
                "GDB returned an unknown inferior list before shutdown.",
              );
            if (groupCount > 0 && !session.inferiorTtyVerified)
              return err(
                new AnalysisInputError("close_gdb_session", undefined, [
                  {
                    path: ["session_id"],
                    reason: "invalid_value",
                    message:
                      "Live GDB thread groups remain and no verified durable inferior TTY is configured. Select a safe disposition through the GDB console or restart with inferior_tty before closing.",
                  },
                ]),
              );
            if (groupCount === 0) {
              session.noInferiorVerified = true;
              targetState = "none_observed";
              await this.#request(session, "-gdb-exit");
            } else {
              session.noInferiorVerified = false;
              const disposition = await this.#detachInferior(session);
              targetState =
                disposition.status === "no-inferior"
                  ? "none_observed"
                  : "unknown";
            }
          } catch {
            // If MI synchronization is lost, stop only the owned debugger process.
          }
          const stopped = await this.#stopDebuggerOnly(session);
          if (stopped.status === "incomplete")
            return err(
              new AnalysisCapabilityUnavailableError(
                "gdb",
                "close_gdb_session",
                stopped.reason,
              ),
            );
          this.#sessions.delete(sessionId);
          return ok({ target_state: targetState });
        },
        undefined,
        "close_gdb_session",
      );
    } catch (cause) {
      if (cause instanceof AnalysisError) return err(cause);
      throw cause;
    }
  }

  async closeAll(): Promise<void> {
    this.#closing = true;
    this.#closePromise ??= this.#drainStartsAndCloseSessions().catch(
      (cause: unknown) => {
        this.#closePromise = undefined;
        throw cause;
      },
    );
    return this.#closePromise;
  }

  async #drainStartsAndCloseSessions(): Promise<void> {
    const active = [...this.#activeStarts.entries()];
    for (const [controller] of active) controller.abort();
    await Promise.allSettled(active.map(([, start]) => start));
    await closeOwnedDebuggerSessions(
      this.#sessions,
      (session) => this.#stopDebuggerOnly(session),
      "GDB",
    );
  }

  async #serialize<Value>(
    session: GdbSession,
    operation: () => Promise<Value>,
    signal?: AbortSignal,
    operationName: "gdb_console" | "close_gdb_session" = "gdb_console",
  ): Promise<Value> {
    if (session.pendingCommandCount >= MAX_PENDING_GDB_COMMANDS)
      throw new AnalysisResourceConstraintError(
        operationName,
        "transport",
        "GDB command queue capacity reached.",
        {
          max_pending_commands: MAX_PENDING_GDB_COMMANDS,
          active_or_queued_commands: session.pendingCommandCount,
        },
      );
    session.pendingCommandCount += 1;
    const previous = session.commandTail;
    let release: (() => void) | undefined;
    let acquired = false;
    session.commandTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      await waitForGdbCommandTurn(previous, signal);
      acquired = true;
      return await operation();
    } finally {
      if (acquired) {
        session.pendingCommandCount -= 1;
        release?.();
      } else {
        // The cancelled placeholder still occupies commandTail until its turn.
        // Keep its reservation until then so repeated cancellations cannot
        // bypass the per-session queue bound while an earlier command stalls.
        void previous.then(() => {
          session.pendingCommandCount -= 1;
          release?.();
        });
      }
    }
  }

  #receive(session: GdbSession, data: string): void {
    const combined = session.buffer + data;
    session.buffer = "";
    const parts = combined.split(/\r?\n/u);
    if (!combined.endsWith("\n")) session.buffer = parts.pop()!;
    if (Buffer.byteLength(session.buffer, "utf8") > MAX_MI_LINE_BYTES) {
      this.#failProtocol(
        session,
        "GDB emitted a partial MI line exceeding the 16 MiB protocol limit.",
      );
      return;
    }
    const lines = parts.filter((line) => line.length > 0);
    if (
      lines.some((line) => Buffer.byteLength(line, "utf8") > MAX_MI_LINE_BYTES)
    ) {
      this.#failProtocol(
        session,
        "GDB emitted an MI line exceeding the 16 MiB protocol limit.",
      );
      return;
    }
    for (const line of lines) {
      if (Buffer.byteLength(line, "utf8") > MAX_RECENT_MI_LINE_BYTES) {
        session.lines.push(truncateUtf8RecordPrefix(line));
        session.recentRecordsTruncated = true;
      } else session.lines.push(line);
    }
    if (session.lines.length > 256) {
      session.lines.splice(0, session.lines.length - 256);
      session.recentRecordsTruncated = true;
    }
    if (combined.includes("(gdb)")) session.startupResolve?.();
    for (const line of lines) {
      for (const pending of session.pending.values()) {
        const lineBytes = Buffer.byteLength(line, "utf8") + 1;
        if (pending.outputBytes + lineBytes <= MAX_COMMAND_OUTPUT_BYTES) {
          pending.lines.push(line);
          pending.outputBytes += lineBytes;
        } else pending.outputTruncated = true;
      }
      const match = /^(\d+)\^(done|running|connected|error|exit)(?:,|$)/u.exec(
        line,
      );
      if (match === null) continue;
      const token = Number(match[1]);
      const pending = session.pending.get(token);
      if (pending === undefined) continue;
      clearTimeout(pending.timer);
      session.pending.delete(token);
      pending.cleanup();
      const records = [...pending.lines];
      pending.resolve({
        command: "",
        mi: line,
        records,
        console: records.filter((record) => record.startsWith("~")).join("\n"),
        target: records.filter((record) => record.startsWith("@")).join("\n"),
        log: records.filter((record) => record.startsWith("&")).join("\n"),
        output_truncated: pending.outputTruncated,
        completion_status: "complete",
      });
    }
  }

  #failProtocol(session: GdbSession, message: string): void {
    if (session.protocolError !== undefined) return;
    session.protocolError = message;
    for (const pending of session.pending.values()) {
      clearTimeout(pending.timer);
      pending.cleanup();
      pending.reject(new Error(message));
    }
    session.pending.clear();
    session.startupReject?.(new Error(message));
  }

  async #stopAfterProtocolFailure(
    session: GdbSession,
    cause: unknown,
  ): Promise<AnalysisCapabilityUnavailableError> {
    const stopped = await this.#stopDebuggerOnly(session);
    return new AnalysisCapabilityUnavailableError(
      "gdb",
      "gdb_console",
      stopped.status === "incomplete"
        ? `${session.protocolError} The owned process could not be confirmed stopped: ${stopped.reason}`
        : session.protocolError!,
      { cause },
    );
  }

  #stopDebuggerOnly(
    session: GdbSession,
  ): ReturnType<typeof stopOwnedDebuggerProcess> {
    if (session.stopAttempt !== undefined) return session.stopAttempt;
    const attempt = this.#stopProcess(session, "GDB").finally(() => {
      if (session.stopAttempt === attempt) session.stopAttempt = undefined;
    });
    session.stopAttempt = attempt;
    return attempt;
  }

  async #detachInferior(
    session: GdbSession,
  ): Promise<OwnedDebuggerDetachResult> {
    if (session.exited)
      throw new Error("GDB exited before inferior state could be verified.");
    if (
      session.protocolError !== undefined ||
      session.pending.size > 0 ||
      session.pendingCommandCount > 1
    )
      throw new Error(
        "GDB MI state is not synchronized; inferior state is unknown.",
      );
    const groups = await this.#request(
      session,
      "-list-thread-groups --recurse 1",
    );
    if (
      groups.completion_status !== "complete" ||
      groups.output_truncated ||
      !/^\d+\^done(?:,|$)/u.test(groups.mi)
    )
      throw new Error("GDB could not confirm its inferior state.");
    const groupCount = gdbThreadGroupCount(groups.mi);
    if (groupCount === 0) {
      session.noInferiorVerified = true;
      return { status: "no-inferior" };
    }
    session.noInferiorVerified = false;
    if (groupCount !== 1)
      throw new Error(
        groupCount === undefined
          ? "GDB returned an unknown recursive inferior list."
          : "GDB reports multiple inferiors; automatic detach cannot be confirmed safely.",
      );
    if (!session.inferiorTtyVerified)
      throw new Error(
        "GDB cannot detach the live inferior because no durable output sink was verified at session startup.",
      );
    const observedTty = await this.#request(session, "-inferior-tty-show");
    if (
      observedTty.completion_status !== "complete" ||
      observedTty.output_truncated ||
      !/^\d+\^done(?:,|$)/u.test(observedTty.mi) ||
      miStringField(observedTty.mi, "inferior_tty_terminal") !==
        session.inferiorTty
    )
      throw new Error(
        "GDB no longer reports the caller-selected inferior TTY; detachment cannot be confirmed safely.",
      );
    const detached = await this.#request(session, "-target-detach");
    if (
      detached.completion_status !== "complete" ||
      detached.output_truncated ||
      !/^\d+\^done(?:,|$)/u.test(detached.mi)
    )
      throw new Error("GDB did not confirm inferior detachment.");
    return { status: "detached", outputSink: "durable" };
  }

  #request(
    session: GdbSession,
    command: string,
    signal?: AbortSignal,
    operation: "gdb_console" | "start_gdb_session" = "gdb_console",
    evidenceCommand: string = command,
  ): Promise<GdbCommandResult> {
    const stdin = session.launched.process.stdin;
    if (session.exited)
      return Promise.reject(new Error("GDB MI process has exited"));
    if (
      stdin === null ||
      stdin === undefined ||
      stdin.destroyed ||
      !stdin.writable
    ) {
      const message = "GDB MI input stream is closed";
      this.#failProtocol(session, message);
      return Promise.reject(new Error(message));
    }
    const token = session.nextToken++;
    return new Promise<GdbCommandResult>((resolve, reject) => {
      let abortListener!: () => void;
      const cleanup = (): void => {
        signal?.removeEventListener("abort", abortListener);
      };
      let pending!: PendingCommand;
      const timer = setTimeout(() => {
        session.pending.delete(token);
        session.protocolError =
          "A GDB MI command timed out; untagged stream output can no longer be safely correlated with later commands.";
        pending.cleanup();
        const partial: GdbCommandResult = {
          command: pending.evidenceCommand,
          mi: "",
          records: [...pending.lines],
          console: pending.lines
            .filter((line) => line.startsWith("~"))
            .join("\n"),
          target: pending.lines
            .filter((line) => line.startsWith("@"))
            .join("\n"),
          log: pending.lines.filter((line) => line.startsWith("&")).join("\n"),
          output_truncated: pending.outputTruncated,
          completion_status: "unknown",
        };
        const timeout = new AnalysisTimeoutError(
          operation,
          this.#commandTimeoutMs,
          { cause: new Error(`GDB MI command timed out: ${command}`) },
        );
        const evidence = createEvidence(undefined, GDB_PROVIDER_IDENTITY, {
          predicateType:
            operation === "start_gdb_session"
              ? "rea.debugger.startup-observation"
              : "rea.debugger.console-observation",
          operation,
          parameters: { session_id: session.id, command: pending.evidenceCommand },
          result: { ...partial, records: [...partial.records] },
          rawResult: { ...partial, records: [...partial.records] },
          subjectUnavailableReason:
            "The active GDB inferior identity is not established by the debugger session identifier.",
          limitations: [
            "The GDB command exceeded its deadline; retained MI and stream records are partial and command completion is unknown.",
            "Cleanup of the owned GDB process was requested because output correlation could no longer be guaranteed.",
            "The unrestricted GDB console can access local shell, filesystem, network, and target controls.",
          ],
        });
        void this.#stopDebuggerOnly(session).then(
          (stopped) => {
            if (
              stopped.status === "incomplete" &&
              operation === "start_gdb_session"
            ) {
              pending.reject(
                new AnalysisTimeoutError(operation, this.#commandTimeoutMs, {
                  cause: timeout,
                  cleanup: { reason: stopped.reason, resources: [session.id] },
                  partialObservation: evidence,
                }),
              );
              return;
            }
            pending.reject(
              stopped.status === "incomplete"
                ? new AnalysisCapabilityUnavailableError(
                    "gdb",
                    "gdb_console",
                    `GDB command output could not be correlated and its owned process could not be confirmed stopped: ${stopped.reason}`,
                    {
                      cause: timeout,
                      cleanup: {
                        reason: stopped.reason,
                        resources: [session.id],
                      },
                      partialObservation: evidence,
                    },
                  )
                : new GdbCommandTimeoutError(
                    partial,
                    evidence,
                    this.#commandTimeoutMs,
                  ),
            );
          },
          (cause: unknown) =>
            pending.reject(
              new AnalysisCapabilityUnavailableError(
                "gdb",
                "gdb_console",
                "GDB command output could not be correlated and owned process shutdown failed.",
                {
                  cause: new AggregateError(
                    [timeout, cause],
                    "GDB timeout and cleanup both failed.",
                  ),
                  cleanup: {
                    reason:
                      cause instanceof Error ? cause.message : String(cause),
                    resources: [session.id],
                  },
                  partialObservation: evidence,
                },
              ),
            ),
        );
      }, this.#commandTimeoutMs);
      pending = {
        token,
        command,
        evidenceCommand,
        lines: [],
        resolve: (result) => {
          cleanup();
          resolve(result);
        },
        reject: (error) => {
          cleanup();
          reject(error);
        },
        cleanup,
        timer,
        outputBytes: 0,
        outputTruncated: false,
      };
      session.pending.set(token, pending);
      abortListener = (): void => {
        clearTimeout(pending.timer);
        const partial: GdbCommandResult = {
          command: pending.evidenceCommand,
          mi: "",
          records: [...pending.lines],
          console: pending.lines
            .filter((line) => line.startsWith("~"))
            .join("\n"),
          target: pending.lines
            .filter((line) => line.startsWith("@"))
            .join("\n"),
          log: pending.lines.filter((line) => line.startsWith("&")).join("\n"),
          output_truncated: pending.outputTruncated,
          completion_status: "unknown",
        };
        const evidence = createEvidence(undefined, GDB_PROVIDER_IDENTITY, {
          predicateType: "rea.debugger.console-observation",
          operation: "gdb_console",
          parameters: { session_id: session.id, command: pending.evidenceCommand },
          result: { ...partial, records: [...partial.records] },
          rawResult: { ...partial, records: [...partial.records] },
          subjectUnavailableReason:
            "The active GDB inferior identity is not established by the debugger session identifier.",
          limitations: [
            "The GDB command was cancelled; retained MI records are partial and command completion is unknown.",
            "The owned GDB process was stopped because output correlation could no longer be guaranteed.",
            "The unrestricted GDB console can access local shell, filesystem, network, and target controls.",
          ],
        });
        session.pending.delete(token);
        session.protocolError =
          "A GDB MI command was cancelled; the owned session was stopped because output correlation can no longer be guaranteed.";
        void this.#stopDebuggerOnly(session).then(
          (stopped) => {
            pending.reject(
              stopped.status === "incomplete"
                ? new AnalysisCancelledError("gdb_console", {
                    cause: new Error(stopped.reason),
                    cleanup: {
                      reason: stopped.reason,
                      resources: [session.id],
                    },
                    partialObservation: evidence,
                  })
                : new AnalysisCancelledError("gdb_console", {
                    partialObservation: evidence,
                  }),
            );
          },
          (cause: unknown) =>
            pending.reject(
              new AnalysisCancelledError("gdb_console", {
                cause,
                partialObservation: evidence,
              }),
            ),
        );
      };
      signal?.addEventListener("abort", abortListener, { once: true });
      if (signal?.aborted) {
        abortListener();
        return;
      }
      try {
        session.launched.process.stdin?.write(
          `${token}${command}\n`,
          "utf8",
          (cause?: Error | null) => {
            if (cause)
              this.#failProtocol(
                session,
                `GDB stdin write failed: ${cause.message}`,
              );
          },
        );
      } catch (cause) {
        this.#failProtocol(
          session,
          `GDB stdin write failed: ${cause instanceof Error ? cause.message : "unknown error"}`,
        );
      }
    }).then((result) => ({ ...result, command }));
  }
}

const miQuote = (value: string): string =>
  `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\r", "\\r").replaceAll("\n", "\\n").replaceAll("\t", "\\t")}"`;

const miStringField = (record: string, field: string): string | undefined => {
  const escapedField = field.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const valuePattern = `((?:\\\\.|[^"\\\\])*)`;
  const fieldPattern = new RegExp(
    `(?:^|,)${escapedField}="${valuePattern}"`,
    "gu",
  );
  const matches = [...record.matchAll(fieldPattern)];
  if (matches.length !== 1) return undefined;
  const match = new RegExp(
    `^\\d+\\^done,${escapedField}="${valuePattern}"$`,
    "u",
  ).exec(record);
  const raw = match?.[1];
  if (raw === undefined) return undefined;
  const bytes: number[] = [];
  for (let index = 0; index < raw.length;) {
    const character = raw[index]!;
    if (character !== "\\") {
      const codePoint = raw.codePointAt(index);
      if (
        codePoint === undefined ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      )
        return undefined;
      const value = String.fromCodePoint(codePoint);
      bytes.push(...Buffer.from(value, "utf8"));
      index += value.length;
      continue;
    }
    const escaped = raw[++index];
    if (escaped === undefined) return undefined;
    const simple: Readonly<Record<string, number>> = {
      a: 7,
      b: 8,
      f: 12,
      n: 10,
      r: 13,
      t: 9,
      v: 11,
      "\\": 92,
      '"': 34,
      "'": 39,
      "?": 63,
    };
    const simpleByte = simple[escaped];
    if (simpleByte !== undefined) {
      bytes.push(simpleByte);
      index += 1;
      continue;
    }
    if (escaped === "x") {
      const hex = /^[0-9a-f]+/iu.exec(raw.slice(index + 1))?.[0];
      if (hex === undefined) return undefined;
      bytes.push(Number.parseInt(hex, 16) & 0xff);
      index += hex.length;
      index += 1;
      continue;
    }
    if (/[0-7]/u.test(escaped)) {
      const octal = `${escaped}${/^[0-7]{0,2}/u.exec(raw.slice(index + 1))?.[0] ?? ""}`;
      bytes.push(Number.parseInt(octal, 8) & 0xff);
      index += octal.length;
      continue;
    }
    return undefined;
  }
  const decoded = Buffer.from(bytes).toString("utf8");
  return Buffer.from(decoded, "utf8").equals(Buffer.from(bytes))
    ? decoded
    : undefined;
};

const commandMayChangeInferiorOutput = (command: string): boolean =>
  /^\s*with(?:\s|$)/iu.test(command) ||
  /\binferior-tty\b/iu.test(command) ||
  /^\s*(?:tty(?:\s|$)|source\b|python(?:\s|$)|define\b)/iu.test(command) ||
  /^\s*(?:run|r|start|starti)\b[^\n;]*(?:^|\s)(?:\d?>|>>|<|&>)/iu.test(command);

/** Terminate only the directly owned debugger process, never its process group or inferiors. */
export const waitForGdbCommandTurn = (
  previous: Promise<void>,
  signal?: AbortSignal,
): Promise<void> => {
  if (signal === undefined) return previous;
  if (signal.aborted)
    return Promise.reject(new AnalysisCancelledError("gdb_console"));
  return new Promise<void>((resolve, reject) => {
    const onAbort = (): void =>
      reject(new AnalysisCancelledError("gdb_console"));
    signal.addEventListener("abort", onAbort, { once: true });
    previous.then(
      () => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      },
      (cause: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(cause);
      },
    );
  });
};
