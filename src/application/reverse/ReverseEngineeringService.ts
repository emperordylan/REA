import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat as statPath } from "node:fs/promises";
import type { Stats } from "node:fs";
import { resolve } from "node:path";

import {
  AnalysisAccessDeniedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import type {
  AnalysisCleanupObservation,
  AnalysisError,
} from "../../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  objdumpInputSchema,
  rizinInputSchema,
} from "../../domain/reverseEngineering.js";
import type {
  ReverseEngineeringCommandPort,
  ReverseEngineeringProviderCommand,
} from "./ReverseEngineeringCommandPort.js";
import {
  execFileOutput,
  execFileOutputFailure,
} from "../../process/ExecFileOutput.js";
import { OwnedCommandFailure, runOwnedCommand } from "../../process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";

export type ReverseEngineeringOperation =
  | "inspect_with_objdump"
  | "execute_rizin_command";

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_COMBINED_OUTPUT_BYTES = 16 * 1024 * 1024;

export interface ReverseEngineeringServiceOptions {
  readonly environment?: Readonly<NodeJS.ProcessEnv>;
  readonly commands: ReverseEngineeringCommandPort;
  readonly run?: ReverseEngineeringCommandRunner;
  readonly runOwned?: typeof runOwnedCommand;
  readonly digest?: typeof digestFile;
  readonly stat?: (path: string) => Promise<Stats>;
}

interface ReverseEngineeringCommandRunner {
  (
    command: string,
    arguments_: readonly string[],
    options?: Parameters<typeof execFileOutput>[2],
  ): Promise<{
    readonly stdout: string;
    readonly stderr: string;
    readonly stdoutInvalidUtf8?: boolean;
    readonly stderrInvalidUtf8?: boolean;
  }>;
}

export type ReverseEngineeringServiceRuntimeOptions = Omit<
  ReverseEngineeringServiceOptions,
  "commands" | "environment"
>;

/** Shared application workflow for caller-selected local analysis commands. */
export class ReverseEngineeringService {
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #commands: ReverseEngineeringCommandPort;
  readonly #run: ReverseEngineeringCommandRunner;
  readonly #digest: typeof digestFile;
  readonly #stat: (path: string) => Promise<Stats>;
  readonly #pendingCleanup = new Map<
    ProviderProcessSupervisor,
    AnalysisCleanupObservation
  >();
  readonly #activeOperations = new Map<
    AbortController,
    Promise<Result<Evidence, AnalysisError>>
  >();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(
    options: ReverseEngineeringServiceOptions,
  ) {
    this.#environment = options.environment ?? process.env;
    this.#commands = options.commands;
    this.#run =
      options.run ??
      runOwnedCommandOutput(
        options.runOwned ?? runOwnedCommand,
        (owner, cleanup) => this.#pendingCleanup.set(owner, cleanup),
      );
    this.#digest = options.digest ?? digestFile;
    this.#stat = options.stat ?? statPath;
  }

  /** Retry cleanup for provider process groups retained after an incomplete stop. */
  close(): Promise<void> {
    this.#closing = true;
    this.#closePromise ??= this.#closeActiveOperationsAndCleanup().catch((cause: unknown) => {
      this.#closePromise = undefined;
      throw cause;
    });
    return this.#closePromise;
  }

  async #closeActiveOperationsAndCleanup(): Promise<void> {
    const active = [...this.#activeOperations.entries()];
    for (const [controller] of active) controller.abort();
    await Promise.allSettled(active.map(([, operation]) => operation));

    const failures: AnalysisCleanupObservation[] = [];
    for (const [owner, previous] of this.#pendingCleanup) {
      let result: Awaited<ReturnType<ProviderProcessSupervisor["stop"]>>;
      try {
        result = await owner.stop();
      } catch (cause) {
        result = {
          status: "incomplete",
          reason: cause instanceof Error ? cause.message : String(cause),
        };
      }
      if (result.status === "incomplete") {
        const cleanup = {
          reason: result.reason,
          resources: previous.resources,
        };
        this.#pendingCleanup.set(owner, cleanup);
        failures.push(cleanup);
      } else {
        this.#pendingCleanup.delete(owner);
      }
    }
    if (failures.length > 0) {
      const cleanup = failures[0]!;
      throw new AnalysisOutputError(
        "reverse_engineering_cleanup",
        "Provider process cleanup remains incomplete.",
        { cleanup },
      );
    }
  }

  inspectWithObjdump(
    rawInput: unknown,
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = objdumpInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return Promise.resolve(
        err(new AnalysisInputError("inspect_with_objdump")),
      );
    const input = parsed.data;
    const command = this.#commands.objdump(input);
    return this.#observe(
      "inspect_with_objdump",
      command,
      input.path,
      input,
      options.signal,
    );
  }

  executeRizinCommand(
    rawInput: unknown,
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = rizinInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return Promise.resolve(
        err(new AnalysisInputError("execute_rizin_command")),
      );
    const input = parsed.data;
    const command = this.#commands.rizin(input);
    return this.#observe(
      "execute_rizin_command",
      command,
      input.path,
      input,
      options.signal,
    );
  }

  #observe(
    operation: ReverseEngineeringOperation,
    profile: ReverseEngineeringProviderCommand,
    path: string,
    parameters: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (this.#closing)
      return Promise.resolve(
        err(new AnalysisOutputError(operation, "Reverse-engineering service is closed.")),
      );
    const controller = new AbortController();
    const relayAbort = (): void => controller.abort(signal?.reason);
    if (signal !== undefined && signal instanceof AbortSignal) {
      if (signal.aborted) relayAbort();
      else signal.addEventListener("abort", relayAbort, { once: true });
    }
    const operationSignal =
      signal === undefined || signal instanceof AbortSignal
        ? controller.signal
        : signal;
    const running = this.#observeProvider(
      operation,
      profile,
      path,
      parameters,
      operationSignal,
    );
    const tracked = running.finally(() => {
      signal?.removeEventListener("abort", relayAbort);
      this.#activeOperations.delete(controller);
    });
    this.#activeOperations.set(controller, tracked);
    return tracked;
  }

  async #observeProvider(
    operation: ReverseEngineeringOperation,
    profile: ReverseEngineeringProviderCommand,
    path: string,
    parameters: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
  ): Promise<Result<Evidence, AnalysisError>> {
    const { executable: command, arguments: args } = profile;
    if (signal?.aborted) return err(new AnalysisCancelledError(operation));
    for (const [owner, previous] of this.#pendingCleanup) {
      let stopped: Awaited<ReturnType<ProviderProcessSupervisor["stop"]>>;
      try {
        stopped = await owner.stop();
      } catch (cause) {
        stopped = {
          status: "incomplete",
          reason: cause instanceof Error ? cause.message : String(cause),
        };
      }
      if (stopped.status === "incomplete") {
        const cleanup = { reason: stopped.reason, resources: previous.resources };
        this.#pendingCleanup.set(owner, cleanup);
        return err(
          new AnalysisOutputError(
            operation,
            "A previous provider process still requires cleanup.",
            { cleanup },
          ),
        );
      }
      this.#pendingCleanup.delete(owner);
    }
    const absolutePath = resolve(path);
    let digest: string;
    try {
      digest = await this.#digest(absolutePath, signal, this.#stat);
    } catch (cause) {
      const code = (cause as NodeJS.ErrnoException).code;
      if (signal?.aborted)
        return err(new AnalysisCancelledError(operation, { cause }));
      if (code === "EACCES" || code === "EPERM")
        return err(
          new AnalysisAccessDeniedError(operation, absolutePath, code, {
            cause,
          }),
        );
      if (code === "ETIMEDOUT")
        return err(
          new AnalysisTimeoutError(operation, DEFAULT_TIMEOUT_MS, { cause }),
        );
      return err(new AnalysisInputError(operation, { cause }));
    }
    let stdout = "";
    let stderr = "";
    let exitCode: number | string | null = 0;
    let signalName: string | null = null;
    let outputTruncated = false;
    let stdoutInvalidUtf8 = false;
    let stderrInvalidUtf8 = false;
    let cleanupIncomplete = false;
    let completionStatus: "complete" | "unknown" = "complete";
    let failure: AnalysisError | undefined;
    try {
      const output = await this.#run(command, args, {
        env: {
          ...process.env,
          ...this.#environment,
          ...profile.environmentOverrides,
        },
        signal,
        timeout: DEFAULT_TIMEOUT_MS,
        stopSignal: "SIGTERM",
        maxBuffer: MAX_COMBINED_OUTPUT_BYTES,
      });
      stdout = output.stdout;
      stderr = output.stderr;
      stdoutInvalidUtf8 = output.stdoutInvalidUtf8 === true;
      stderrInvalidUtf8 = output.stderrInvalidUtf8 === true;
    } catch (cause) {
      if (
        cause instanceof OwnedOutputFailure &&
        cause.capabilityError !== undefined
      )
        return err(cause.capabilityError);
      const capture = execFileOutputFailure(cause);
      const code =
        capture?.code ?? (cause as NodeJS.ErrnoException).code ?? undefined;
      if (code === "E2BIG")
        return err(
          new AnalysisResourceConstraintError(
            operation,
            "transport",
            "The host rejected the provider command because its argument list exceeds the process launch limit.",
            { argument_bytes: Buffer.byteLength(args.join("\0")) },
            { cause },
          ),
        );
      if (
        capture === undefined ||
        code === "ENOENT" ||
        code === "ERR_PROVIDER_LAUNCH"
      ) {
        if (signal?.aborted || code === "ABORT_ERR")
          return err(new AnalysisCancelledError(operation, { cause }));
        if (code === "ETIMEDOUT")
          return err(
            new AnalysisTimeoutError(operation, DEFAULT_TIMEOUT_MS, { cause }),
          );
        if (code === "EACCES" || code === "EPERM")
          return err(
            new AnalysisAccessDeniedError(operation, command, code, { cause }),
          );
        return err(
          new AnalysisCapabilityUnavailableError(
            operation === "inspect_with_objdump" ? "objdump" : "rizin",
            operation,
            `Unable to run configured command (${String(code ?? "unknown error")})`,
            { cause },
          ),
        );
      }
      stdout = capture.stdout;
      stderr = capture.stderr;
      exitCode = capture.code;
      signalName = capture.signal;
      outputTruncated = capture.outputTruncated;
      if (capture.collectionFailure) {
        exitCode = null;
        completionStatus = "unknown";
      }
      const capturedOutput = {
        stdout,
        stderr,
        truncated: outputTruncated,
        stdout_bytes:
          cause instanceof OwnedOutputFailure
            ? cause.stdoutBytes
            : Buffer.byteLength(stdout),
        stderr_bytes:
          cause instanceof OwnedOutputFailure
            ? cause.stderrBytes
            : Buffer.byteLength(stderr),
        exit_code:
          !capture.collectionFailure && typeof capture.code === "number"
            ? capture.code
            : null,
        signal: capture.signal,
      };
      if (signal?.aborted || code === "ABORT_ERR")
        failure = new AnalysisCancelledError(operation, {
          cause,
          capturedOutput,
          ...ownedCleanupOptions(cause),
        });
      else if (code === "ETIMEDOUT")
        failure = new AnalysisTimeoutError(operation, DEFAULT_TIMEOUT_MS, {
          cause,
          capturedOutput,
          ...ownedCleanupOptions(cause),
        });
      else if (code === "EACCES" || code === "EPERM")
        failure = new AnalysisAccessDeniedError(operation, command, code, {
          cause,
          capturedOutput,
        });
      if (cause instanceof OwnedOutputFailure && cause.cleanup !== undefined) {
        cleanupIncomplete = true;
        if (failure === undefined)
          failure = new AnalysisOutputError(
            operation,
            "Provider process cleanup remains incomplete.",
            { cause, capturedOutput, cleanup: cause.cleanup },
          );
      }
      if (
        failure === undefined &&
        cause instanceof OwnedOutputFailure &&
        cause.collectionFailure
      )
        failure = new AnalysisOutputError(
          operation,
          "Provider output collection failed.",
          { cause, capturedOutput },
        );
      if (capture.signal !== null || typeof capture.code !== "number") {
        exitCode = null;
        completionStatus = "unknown";
      }
      if (cause instanceof OwnedOutputFailure) {
        stdoutInvalidUtf8 = cause.stdoutInvalidUtf8;
        stderrInvalidUtf8 = cause.stderrInvalidUtf8;
      }
    }
    let digestAfter: string | null = null;
    if (cleanupIncomplete) {
      completionStatus = "unknown";
    } else {
      try {
        digestAfter = await this.#digest(absolutePath, signal, this.#stat);
      } catch {
        // Preserve the provider's collected observations if the artifact vanished or became unreadable.
      }
    }
    if (signal?.aborted && failure === undefined) {
      failure = new AnalysisCancelledError(operation, {
        capturedOutput: {
          stdout,
          stderr,
          truncated: outputTruncated,
          stdout_bytes: Buffer.byteLength(stdout),
          stderr_bytes: Buffer.byteLength(stderr),
          exit_code: typeof exitCode === "number" ? exitCode : null,
          signal: signalName,
        },
      });
      exitCode = null;
      completionStatus = "unknown";
    }
    const artifactChanged =
      digestAfter === null ? null : digestAfter !== digest;
    const result = {
      stdout,
      stderr,
      exit_code: exitCode,
      signal: signalName,
      output_truncated: outputTruncated,
      completion_status: completionStatus,
      artifact_sha256_after: digestAfter,
      artifact_changed: artifactChanged,
    };
    const limitations = [
      "The executable version and supported formats are reported as unknown because no reliable version probe was performed.",
      "A non-zero process exit is preserved as an observed command result.",
      ...(operation === "inspect_with_objdump" &&
      parameters.follow_debug_links === true
        ? [
            "DWARF output may include local debug-link files whose identities are not bound to Evidence.",
          ]
        : []),
      ...(operation === "execute_rizin_command"
        ? [
            "Rizin commands and retained plugins may read files or access network resources outside the selected artifact; those external inputs are not bound to Evidence.",
          ]
        : []),
      ...(stdoutInvalidUtf8 || stderrInvalidUtf8
        ? [
            `Captured ${[
              ...(stdoutInvalidUtf8 ? ["stdout"] : []),
              ...(stderrInvalidUtf8 ? ["stderr"] : []),
            ].join(" and ")} bytes contain invalid or incomplete UTF-8; replacement characters in the text capture do not preserve the original bytes.`,
          ]
        : []),
      ...(outputTruncated
        ? [
            "The provider command ended before completion could be confirmed; captured output is partial.",
          ]
        : []),
      ...(signalName === null
        ? []
        : [
            `The provider process terminated by signal ${signalName}; captured output may be partial and command completion is unknown.`,
          ]),
      ...(failure === undefined
        ? []
        : [
            `Command completion is unknown because the operation failed with ${failure._tag}: ${failure.message}`,
          ]),
      "When both are available, pre-run and post-run digests detect artifact changes across the provider call but cannot prove the exact bytes consumed during the call.",
      ...(artifactChanged === true
        ? [
            "The provider command may have changed the artifact while analysis was running; pre-run and post-run digests are both reported.",
          ]
        : []),
      ...(digestAfter === null
        ? [
            cleanupIncomplete
              ? "The post-run artifact digest is unknown because owned provider cleanup is incomplete; a remaining process may still change the artifact."
              : signal?.aborted
                ? "The post-run artifact digest is unknown because cancellation interrupted the digest."
                : "The post-run artifact digest is unknown because the artifact could not be read after the provider call.",
          ]
        : []),
    ];
    const evidence = createEvidence(
      { path: absolutePath, sha256: digest, format: "unknown" },
      profile.identity,
      {
        predicateType: "rea.reverse-engineering.command-observation",
        operation,
        parameters: {
          ...parameters,
          provider_executable: command,
          command_arguments: [...args],
        },
        rawResult: result,
        result,
        limitations,
        locations: [{ kind: "artifact-path", path: absolutePath }],
      },
    );
    return failure === undefined
      ? ok(evidence)
      : err(failure.retainPartialObservation(evidence));
  }
}

interface OwnedOutputFailureOptions {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | string | null;
  readonly signal: string | null;
  readonly outputTruncated: boolean;
  readonly stdoutInvalidUtf8?: boolean;
  readonly stderrInvalidUtf8?: boolean;
  readonly stdoutBytes?: number;
  readonly stderrBytes?: number;
  readonly capabilityError?: AnalysisCapabilityUnavailableError;
  readonly collectionFailure?: boolean;
  readonly cleanup?: AnalysisCleanupObservation;
  readonly cause?: unknown;
}

class OwnedOutputFailure extends Error {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | string | null;
  readonly signal: string | null;
  readonly outputTruncated: boolean;
  readonly stdoutInvalidUtf8: boolean;
  readonly stderrInvalidUtf8: boolean;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly capabilityError: AnalysisCapabilityUnavailableError | undefined;
  readonly collectionFailure: boolean;
  readonly cleanup: AnalysisCleanupObservation | undefined;

  constructor(options: OwnedOutputFailureOptions) {
    super("Owned provider command did not produce a complete result.", {
      cause: options.cause,
    });
    this.stdout = options.stdout;
    this.stderr = options.stderr;
    this.code = options.code;
    this.signal = options.signal;
    this.outputTruncated = options.outputTruncated;
    this.stdoutInvalidUtf8 = options.stdoutInvalidUtf8 ?? false;
    this.stderrInvalidUtf8 = options.stderrInvalidUtf8 ?? false;
    this.stdoutBytes = options.stdoutBytes ?? Buffer.byteLength(options.stdout);
    this.stderrBytes = options.stderrBytes ?? Buffer.byteLength(options.stderr);
    this.capabilityError = options.capabilityError;
    this.collectionFailure = options.collectionFailure ?? false;
    this.cleanup = options.cleanup;
  }
}

const runOwnedCommandOutput = (
  runOwned: typeof runOwnedCommand,
  onCleanupOwner: (
    owner: ProviderProcessSupervisor,
    cleanup: AnalysisCleanupObservation,
  ) => void,
): ReverseEngineeringCommandRunner => async (
  command,
  args,
  options = {},
) => {
  const spawnEnv = { ...options.env };
  try {
    const snapshot = await runOwned(
      {
        command,
        arguments: [...args],
        runId: randomUUID(),
        expectedCommand: null,
        env: spawnEnv,
        hostEnvironment: {},
        sweepTokenOwnedProcesses: true,
      },
      {
        timeoutMs: DEFAULT_TIMEOUT_MS,
        diagnosticBytes: MAX_COMBINED_OUTPUT_BYTES,
        acceptNonZeroExit: true,
      },
      {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    );
    // Stryker disable next-line ConditionalExpression,EqualityOperator -- null and undefined both mean no signal; wrapping a successful snapshot with those values is observationally equivalent after normalization.
    if (snapshot.signal !== null && snapshot.signal !== undefined)
      throw new OwnedOutputFailure({
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        code: snapshot.exitCode ?? null,
        signal: snapshot.signal,
        outputTruncated: snapshot.diagnosticTruncated === true,
        stdoutInvalidUtf8: snapshot.stdout.invalidUtf8 === true,
        stderrInvalidUtf8: snapshot.stderr.invalidUtf8 === true,
        stdoutBytes: snapshot.stdout.bytes,
        stderrBytes: snapshot.stderr.bytes,
      });
    if (snapshot.exitCode !== 0)
      throw new OwnedOutputFailure({
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        code: snapshot.exitCode ?? null,
        signal: null,
        outputTruncated: snapshot.diagnosticTruncated === true,
        stdoutInvalidUtf8: snapshot.stdout.invalidUtf8 === true,
        stderrInvalidUtf8: snapshot.stderr.invalidUtf8 === true,
        stdoutBytes: snapshot.stdout.bytes,
        stderrBytes: snapshot.stderr.bytes,
      });
    return {
      stdout: snapshot.stdout.text,
      stderr: snapshot.stderr.text,
      stdoutInvalidUtf8: snapshot.stdout.invalidUtf8 === true,
      stderrInvalidUtf8: snapshot.stderr.invalidUtf8 === true,
    };
  } catch (cause) {
    if (!(cause instanceof OwnedCommandFailure)) throw cause;
    if (cause.cleanupOwner !== undefined && cause.cleanupFailure !== null)
      onCleanupOwner(cause.cleanupOwner, {
        reason: cause.cleanupFailure,
        resources: cause.resources,
      });
    const snapshot = cause.snapshot;
    const launchErrorCode =
      cause.cause instanceof Error
        ? Reflect.get(cause.cause, "code")
        : undefined;
    const code =
      cause.reason === "cancelled"
        ? "ABORT_ERR"
        : cause.reason === "timeout"
          ? "ETIMEDOUT"
          : cause.reason === "output-limit"
            ? "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"
            : launchErrorCode === "E2BIG"
              ? "E2BIG"
          : snapshot === null
            ? "ERR_PROVIDER_LAUNCH"
            : (snapshot.exitCode ?? null);
    throw new OwnedOutputFailure({
      stdout: snapshot?.stdout.text ?? "",
      stderr: snapshot?.stderr.text ?? "",
      code,
      signal: snapshot?.signal ?? null,
      outputTruncated: snapshot?.diagnosticTruncated === true,
      stdoutInvalidUtf8: snapshot?.stdout.invalidUtf8 === true,
      stderrInvalidUtf8: snapshot?.stderr.invalidUtf8 === true,
      stdoutBytes: snapshot?.stdout.bytes ?? 0,
      stderrBytes: snapshot?.stderr.bytes ?? 0,
      ...(cause.cause instanceof AnalysisCapabilityUnavailableError
        ? { capabilityError: cause.cause }
        : {}),
      ...(cause.collectionFailure ? { collectionFailure: true } : {}),
      ...(cause.cleanupFailure === null
        ? {}
        : {
            cleanup: {
              reason: cause.cleanupFailure,
              resources: cause.resources,
            },
          }),
      cause,
    });
  }
};

const ownedCleanupOptions = (
  cause: unknown,
): { readonly cleanup?: AnalysisCleanupObservation } =>
  cause instanceof OwnedOutputFailure && cause.cleanup !== undefined
    ? { cleanup: cause.cleanup }
    : {};

const digestFile = async (
  path: string,
  signal?: AbortSignal,
  stat: (path: string) => Promise<Stats> = statPath,
): Promise<string> => {
  const info = await statWithDeadline(path, signal, stat);
  if (!info.isFile())
    throw Object.assign(new Error("Artifact digest requires a regular file"), {
      code: "EINVAL",
    });
  return new Promise<string>((resolveDigest, rejectDigest) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    const timer = setTimeout(
      () =>
        stream.destroy(
          Object.assign(new Error("Artifact digest timed out"), {
            code: "ETIMEDOUT",
          }),
        ),
      DEFAULT_TIMEOUT_MS,
    );
    const abort = (): void => {
      stream.destroy(new AnalysisCancelledError("artifact_digest"));
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    };
    if (signal?.aborted) {
      cleanup();
      stream.destroy();
      rejectDigest(new AnalysisCancelledError("artifact_digest"));
      return;
    }
    signal?.addEventListener("abort", abort, { once: true });
    stream.on("data", (chunk: Buffer | string) => hash.update(chunk));
    stream.once("error", (cause: Error) => {
      cleanup();
      rejectDigest(cause);
    });
    stream.once("end", () => {
      cleanup();
      resolveDigest(hash.digest("hex"));
    });
  });
};

const statWithDeadline = (
  path: string,
  signal: AbortSignal | undefined,
  stat: (path: string) => Promise<Stats>,
): Promise<Stats> => {
  if (signal?.aborted)
    return Promise.reject(new AnalysisCancelledError("artifact_digest"));
  return new Promise<Stats>((resolveStat, rejectStat) => {
    let settled = false;
    const finish = (cause?: unknown, value?: Stats): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (cause !== undefined) rejectStat(cause);
      else resolveStat(value!);
    };
    const abort = (): void =>
      finish(new AnalysisCancelledError("artifact_digest"));
    const timer = setTimeout(
      () =>
        finish(
          Object.assign(new Error("Artifact stat timed out"), {
            code: "ETIMEDOUT",
          }),
        ),
      DEFAULT_TIMEOUT_MS,
    );
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) {
      abort();
      return;
    }
    // Promise handlers stay attached after timeout/cancellation so a delayed
    // stat rejection is observed and cannot become an unhandled rejection.
    try {
      void stat(path).then(
        (info) => finish(undefined, info),
        (cause: unknown) => finish(cause),
      );
    } catch (cause) {
      finish(cause);
    }
  });
};
