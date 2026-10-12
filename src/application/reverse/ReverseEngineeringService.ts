import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat as statPath } from "node:fs/promises";
import { resolve } from "node:path";

import {
  AnalysisAccessDeniedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import type {
  AnalysisCleanupObservation,
  AnalysisError,
} from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  objdumpInputSchema,
  rizinInputSchema,
} from "../../domain/reverseEngineering.js";
import { objdumpCommand } from "../../objdump/ObjdumpCommand.js";
import { OBJDUMP_PROVIDER_IDENTITY } from "../../objdump/ObjdumpCommand.js";
import {
  execFileOutput,
  execFileOutputFailure,
} from "../../process/ExecFileOutput.js";
import { OwnedCommandFailure, runOwnedCommand } from "../../process/OwnedCommand.js";
import { rizinCommand } from "../../rizin/RizinCommand.js";
import { RIZIN_PROVIDER_IDENTITY } from "../../rizin/RizinCommand.js";

export type ReverseEngineeringOperation =
  | "inspect_with_objdump"
  | "execute_rizin_command";

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_BYTES_PER_STREAM = 16 * 1024 * 1024;

/** Shared application workflow for caller-selected local analysis commands. */
export class ReverseEngineeringService {
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #run: typeof execFileOutput;
  readonly #digest: typeof digestFile;

  constructor(
    options: {
      readonly environment?: Readonly<NodeJS.ProcessEnv>;
      readonly run?: typeof execFileOutput;
      readonly runOwned?: typeof runOwnedCommand;
      readonly digest?: typeof digestFile;
    } = {},
  ) {
    this.#environment = options.environment ?? process.env;
    this.#run =
      options.run ??
      runOwnedCommandOutput(options.runOwned ?? runOwnedCommand);
    this.#digest = options.digest ?? digestFile;
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
    return this.#observe(
      "inspect_with_objdump",
      this.#environment.REA_OBJDUMP_COMMAND ?? "objdump",
      objdumpCommand(input),
      input.path,
      input,
      options.signal,
      { DEBUGINFOD_URLS: "" },
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
    return this.#observe(
      "execute_rizin_command",
      this.#environment.REA_RIZIN_COMMAND ?? "rizin",
      rizinCommand(input),
      input.path,
      input,
      options.signal,
    );
  }

  async #observe(
    operation: ReverseEngineeringOperation,
    command: string,
    args: readonly string[],
    path: string,
    parameters: Readonly<Record<string, JsonValue>>,
    signal?: AbortSignal,
    environmentOverrides: Readonly<NodeJS.ProcessEnv> = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    if (signal?.aborted) return err(new AnalysisCancelledError(operation));
    const absolutePath = resolve(path);
    let digest: string;
    try {
      digest = await this.#digest(absolutePath, signal);
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
    let completionStatus: "complete" | "unknown" = "complete";
    let failure: AnalysisError | undefined;
    try {
      const output = await this.#run(command, args, {
        env: {
          ...process.env,
          ...this.#environment,
          ...environmentOverrides,
        },
        signal,
        timeout: DEFAULT_TIMEOUT_MS,
        stopSignal: "SIGTERM",
        maxBuffer: MAX_OUTPUT_BYTES_PER_STREAM,
      });
      stdout = output.stdout;
      stderr = output.stderr;
    } catch (cause) {
      const capture = execFileOutputFailure(cause);
      const code =
        capture?.code ?? (cause as NodeJS.ErrnoException).code ?? undefined;
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
      const capturedOutput = {
        stdout,
        stderr,
        truncated: outputTruncated,
        stdout_bytes: Buffer.byteLength(stdout),
        stderr_bytes: Buffer.byteLength(stderr),
        exit_code: typeof capture.code === "number" ? capture.code : null,
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
      if (capture.signal !== null || typeof capture.code !== "number") {
        exitCode = null;
        completionStatus = "unknown";
      }
    }
    let digestAfter: string | null = null;
    try {
      digestAfter = await this.#digest(absolutePath, signal);
    } catch {
      // Preserve the provider's collected observations if the artifact vanished or became unreadable.
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
      "Pre-run and post-run digests detect artifact changes across the provider call but cannot prove the exact bytes consumed during the call.",
      ...(artifactChanged === true
        ? [
            "The provider command may have changed the artifact while analysis was running; pre-run and post-run digests are both reported.",
          ]
        : []),
      ...(digestAfter === null
        ? [
            signal?.aborted
              ? "The post-run artifact digest is unknown because cancellation interrupted the digest."
              : "The post-run artifact digest is unknown because the artifact could not be read after the provider call.",
          ]
        : []),
    ];
    const evidence = createEvidence(
      { path: absolutePath, sha256: digest, format: "unknown" },
      operation === "inspect_with_objdump"
        ? OBJDUMP_PROVIDER_IDENTITY
        : RIZIN_PROVIDER_IDENTITY,
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
  readonly cleanup?: AnalysisCleanupObservation;
  readonly cause?: unknown;
}

class OwnedOutputFailure extends Error {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | string | null;
  readonly signal: string | null;
  readonly outputTruncated: boolean;
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
    this.cleanup = options.cleanup;
  }
}

const runOwnedCommandOutput = (
  runOwned: typeof runOwnedCommand,
): typeof execFileOutput => async (
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
      },
      {
        timeoutMs: DEFAULT_TIMEOUT_MS,
        diagnosticBytes: MAX_OUTPUT_BYTES_PER_STREAM,
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
      });
    if (snapshot.exitCode !== 0)
      throw new OwnedOutputFailure({
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        code: snapshot.exitCode ?? null,
        signal: null,
        outputTruncated: snapshot.diagnosticTruncated === true,
      });
    return { stdout: snapshot.stdout.text, stderr: snapshot.stderr.text };
  } catch (cause) {
    if (!(cause instanceof OwnedCommandFailure)) throw cause;
    const snapshot = cause.snapshot;
    const code =
      cause.reason === "cancelled"
        ? "ABORT_ERR"
        : cause.reason === "timeout"
          ? "ETIMEDOUT"
          : cause.reason === "output-limit"
            ? "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"
          : snapshot === null
            ? "ERR_PROVIDER_LAUNCH"
            : (snapshot.exitCode ?? null);
    throw new OwnedOutputFailure({
      stdout: snapshot?.stdout.text ?? "",
      stderr: snapshot?.stderr.text ?? "",
      code,
      signal: snapshot?.signal ?? null,
      outputTruncated: snapshot?.diagnosticTruncated === true,
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
): Promise<string> => {
  const info = await statPath(path);
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
