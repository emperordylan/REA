import { mkdtemp, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import type { Stats } from "node:fs";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { TestReverseEngineeringService as ReverseEngineeringService } from "../support/reverseEngineeringService.js";
import { AnalysisCapabilityUnavailableError } from "../../src/domain/analysisErrorCore.js";
import { objdumpCommand } from "../../src/objdump/ObjdumpCommand.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../src/process/OwnedCommand.js";
import type { ProviderProcessSnapshot } from "../../src/process/ProviderProcess.js";
import type { ProviderProcessSupervisor } from "../../src/process/ProviderProcess.js";

const createArtifact = async (): Promise<{
  directory: string;
  path: string;
}> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-reverse-edge-"));
  const path = join(directory, "sample.bin");
  await writeFile(path, "initial artifact");
  return { directory, path };
};

it("uses the local-only DWARF option when debug links are disabled", () => {
  expect(
    objdumpCommand({
      path: "./sample.bin",
      operation: "dwarf",
      follow_debug_links: false,
    }),
  ).toEqual(["-W", "-WN", expect.stringMatching(/sample\.bin$/u)]);
});

it("does not follow DWARF debug links by default", async () => {
  const { directory, path } = await createArtifact();
  const calls: string[][] = [];
  const service = new ReverseEngineeringService({
    run: async (_command, args) => {
      calls.push([...args]);
      return { stdout: "DWARF output", stderr: "" };
    },
  });

  try {
    const result = await service.inspectWithObjdump({ path, operation: "dwarf" });
    expect(result.ok).toBe(true);
    expect(calls[0]).toEqual(["-W", "-WN", path]);
    if (result.ok)
      expect(result.value.parameters.follow_debug_links).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("marks opted-in external DWARF debug files as unbound Evidence sources", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    run: async () => ({ stdout: "DWARF output", stderr: "" }),
  });

  try {
    const result = await service.inspectWithObjdump({
      path,
      operation: "dwarf",
      follow_debug_links: true,
    });
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.limitations).toContain(
        "DWARF output may include local debug-link files whose identities are not bound to Evidence.",
      );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("rejects malformed objdump requests before touching the provider", async () => {
  let invoked = false;
  const service = new ReverseEngineeringService({
    run: async () => {
      invoked = true;
      return { stdout: "", stderr: "" };
    },
  });

  const result = await service.inspectWithObjdump({ path: "/tmp/a" });

  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError", operation: "inspect_with_objdump" },
  });
  expect(invoked).toBe(false);
});

it("rejects NUL in a Rizin command before touching the provider", async () => {
  const { directory, path } = await createArtifact();
  let invoked = false;
  const service = new ReverseEngineeringService({
    run: async () => {
      invoked = true;
      return { stdout: "", stderr: "" };
    },
  });

  try {
    const result = await service.executeRizinCommand({
      path,
      command: "wx\u0000 00",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", operation: "execute_rizin_command" },
    });
    expect(invoked).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("returns cancellation that arrived before the artifact digest starts", async () => {
  const controller = new AbortController();
  controller.abort();
  const service = new ReverseEngineeringService();

  const result = await service.inspectWithObjdump(
    { path: "/tmp/a", operation: "file_headers" },
    { signal: controller.signal },
  );

  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});

it.each(["cancellation", "deadline"] as const)(
  "interrupts a pending stat on %s and observes its eventual rejection",
  async (interruption) => {
    const { directory, path } = await createArtifact();
    const controller = new AbortController();
    let rejectStat: ((cause: Error) => void) | undefined;
    let announceStat: (() => void) | undefined;
    const statStarted = new Promise<void>((resolve) => {
      announceStat = resolve;
    });
    const service = new ReverseEngineeringService({
      stat: async () => {
        announceStat?.();
        return await new Promise<Stats>((_resolve, reject) => {
          rejectStat = reject;
        });
      },
      run: async () => ({ stdout: "", stderr: "" }),
    });

    try {
      if (interruption === "deadline") vi.useFakeTimers();
      const resultPromise = service.inspectWithObjdump(
        { path, operation: "file_headers" },
        { signal: controller.signal },
      );
      await statStarted;
      if (interruption === "cancellation") controller.abort();
      else await vi.advanceTimersByTimeAsync(120_000);
      await expect(resultPromise).resolves.toMatchObject({
        ok: false,
        error: {
          _tag:
            interruption === "cancellation"
              ? "AnalysisCancelledError"
              : "AnalysisTimeoutError",
        },
      });
      rejectStat?.(new Error("late stat failure"));
      await Promise.resolve();
    } finally {
      vi.useRealTimers();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it.each([
  ["EACCES", "AnalysisAccessDeniedError"],
  ["EPERM", "AnalysisAccessDeniedError"],
  ["ETIMEDOUT", "AnalysisTimeoutError"],
  ["EINVAL", "AnalysisInputError"],
])(
  "maps artifact digest failure %s to its tagged analysis error",
  async (code, tag) => {
    const { directory, path } = await createArtifact();
    const service = new ReverseEngineeringService({
      digest: async () => {
        throw Object.assign(new Error("digest failure"), { code });
      },
    });

    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "file_headers",
      });
      expect(result).toMatchObject({ ok: false, error: { _tag: tag } });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("retains and retries an owned cleanup after an output-limit failure", async () => {
  const { directory, path } = await createArtifact();
  const stop = vi
    .fn()
    .mockResolvedValueOnce({ status: "incomplete", reason: "still running" })
    .mockResolvedValueOnce({ status: "incomplete", reason: "still running" })
    .mockResolvedValueOnce({ status: "incomplete", reason: "still running" })
    .mockResolvedValueOnce({ status: "verified-cleanup" });
  await stop(); // The owned-command runner's first cleanup attempt failed.
  const cleanupOwner = { stop } as unknown as ProviderProcessSupervisor;
  const runOwned = vi.fn<typeof runOwnedCommand>(async () => {
    throw new OwnedCommandFailure(
      "output-limit",
      "output limit",
      providerSnapshot({ diagnosticTruncated: true }),
      "still running",
      undefined,
      ["run-id", "pid:42"],
      cleanupOwner,
    );
  });
  const service = new ReverseEngineeringService({
    runOwned,
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "wx 00" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        cleanupIncomplete: true,
        cleanup: { reason: "still running", resources: ["run-id", "pid:42"] },
        partialObservation: {
          raw_result: {
            stdout: "captured owned output",
            output_truncated: true,
            completion_status: "unknown",
          },
        },
      },
    });
    expect(stop).toHaveBeenCalledTimes(1);
    const blocked = await service.executeRizinCommand({
      path,
      command: "iI",
    });
    expect(blocked).toMatchObject({
      ok: false,
      error: { cleanupIncomplete: true },
    });
    expect(stop).toHaveBeenCalledTimes(2);
    expect(runOwned).toHaveBeenCalledTimes(1);
    await expect(service.close()).rejects.toMatchObject({
      cleanupIncomplete: true,
      cleanup: { reason: "still running", resources: ["run-id", "pid:42"] },
    });
    expect(stop).toHaveBeenCalledTimes(3);
    await service.close();
    expect(stop).toHaveBeenCalledTimes(4);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("maps cancellation during the initial digest to a cancellation error", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  const service = new ReverseEngineeringService({
    digest: async () => {
      controller.abort();
      throw new Error("digest cancelled");
    },
  });

  try {
    const result = await service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal: controller.signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("cancels an in-progress file digest through its abort listener", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  Object.defineProperty(controller.signal, "addEventListener", {
    value: (
      type: string,
      listener: Parameters<EventTarget["addEventListener"]>[1],
      options?: boolean | AddEventListenerOptions,
    ): void => {
      EventTarget.prototype.addEventListener.call(
        controller.signal,
        type,
        listener,
        options,
      );
      if (type === "abort") {
        controller.abort();
      }
    },
  });
  const service = new ReverseEngineeringService();

  try {
    const resultPromise = service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal: controller.signal },
    );
    const result = await resultPromise;
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("rejects a digest when cancellation arrives before stream listeners attach", async () => {
  const { directory, path } = await createArtifact();
  let reads = 0;
  const signal = {
    get aborted() {
      reads += 1;
      return reads > 1;
    },
    addEventListener() {},
    removeEventListener() {},
    throwIfAborted() {},
    onabort: null,
    reason: undefined,
    dispatchEvent: () => true,
  } as AbortSignal;
  const service = new ReverseEngineeringService();

  try {
    const result = await service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    expect(reads).toBe(3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("maps the artifact digest deadline to a timeout error", async () => {
  const { directory, path } = await createArtifact();
  await truncate(path, 64 * 1024 * 1024);
  const service = new ReverseEngineeringService();
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

  try {
    const resultPromise = service.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    await vi.advanceTimersByTimeAsync(120_000);
    const result = await resultPromise;
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisTimeoutError" },
    });
  } finally {
    vi.useRealTimers();
    await rm(directory, { recursive: true, force: true });
  }
});

it.each([
  ["ETIMEDOUT", "AnalysisTimeoutError"],
  ["EACCES", "AnalysisAccessDeniedError"],
  ["EPERM", "AnalysisAccessDeniedError"],
  ["ABORT_ERR", "AnalysisCancelledError"],
  ["unknown", "AnalysisCapabilityUnavailableError"],
])(
  "maps provider failure %s to its tagged analysis error",
  async (code, tag) => {
    const { directory, path } = await createArtifact();
    const service = new ReverseEngineeringService({
      run: async () => {
        if (code === "unknown") throw new Error("provider failure");
        throw Object.assign(new Error("provider failure"), { code });
      },
    });

    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "file_headers",
      });
      expect(result).toMatchObject({
        ok: false,
        error: {
          _tag: tag,
          operation: "inspect_with_objdump",
          cause: { message: "provider failure" },
          ...(code === "ETIMEDOUT" ? { timeoutMs: 120_000 } : {}),
          ...(code === "EACCES" || code === "EPERM"
            ? { path: "objdump", systemCode: code }
            : {}),
          ...(code === "unknown"
            ? {
                providerId: "objdump",
                reason: "Unable to run configured command (unknown error)",
              }
            : {}),
        },
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("records a changed artifact and unknown post-run digest separately", async () => {
  const { directory, path } = await createArtifact();
  const changed = new ReverseEngineeringService({
    run: async () => {
      await writeFile(path, "changed during provider execution");
      return { stdout: "observed", stderr: "" };
    },
  });
  const removed = new ReverseEngineeringService({
    run: async () => {
      await rm(path);
      return { stdout: "observed", stderr: "" };
    },
  });

  try {
    const changedResult = await changed.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    expect(changedResult).toMatchObject({
      ok: true,
      value: {
        raw_result: { artifact_changed: true },
        limitations: expect.arrayContaining([
          expect.stringContaining("may have changed"),
        ]),
      },
    });

    await writeFile(path, "restore for second digest");
    const removedResult = await removed.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    expect(removedResult).toMatchObject({
      ok: true,
      value: {
        raw_result: { artifact_sha256_after: null, artifact_changed: null },
        limitations: expect.arrayContaining([
          expect.stringContaining("post-run artifact digest"),
        ]),
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it.each(["EACCES", "EPERM"] as const)(
  "retains captured output on a permission-denied provider result (%s)",
  async (code) => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    run: async () => {
      throw Object.assign(new Error("provider permission denied"), {
        stdout: "partial provider output",
        stderr: "permission diagnostic",
        code,
        signal: null,
        killed: false,
      });
    },
  });

  try {
    const result = await service.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisAccessDeniedError",
        capturedOutput: {
          stdout: "partial provider output",
          stderr: "permission diagnostic",
        },
        partialObservation: {
          raw_result: { stdout: "partial provider output" },
        },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
  },
);

it("cancels after captured output when a provider reports a non-numeric status", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  let digests = 0;
  const service = new ReverseEngineeringService({
    digest: async () => {
      digests += 1;
      if (digests === 2) controller.abort();
      return digests === 1 ? "a".repeat(64) : "b".repeat(64);
    },
    run: async () => {
      throw Object.assign(new Error("provider status unavailable"), {
        stdout: "captured output",
        stderr: "",
        code: "provider-status-unknown",
        signal: null,
        killed: false,
      });
    },
  });

  try {
    const result = await service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal: controller.signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCancelledError",
        partialObservation: {
          raw_result: { exit_code: null, completion_status: "unknown" },
        },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("maps an unavailable Rizin command to the Rizin capability error", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    run: async () => {
      throw Object.assign(new Error("not found"), { code: "ENOENT" });
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "rizin",
        operation: "execute_rizin_command",
        reason: "Unable to run configured command (ENOENT)",
        cause: { message: "not found" },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("classifies a captured ENOENT as provider unavailability", async () => {
  const { directory, path } = await createArtifact();
  const cause = Object.assign(new Error("launch failed"), {
    stdout: "",
    stderr: "",
    code: "ENOENT",
    signal: null,
    killed: false,
  });
  const service = new ReverseEngineeringService({ run: async () => { throw cause; } });

  try {
    const result = await service.inspectWithObjdump({ path, operation: "file_headers" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "objdump",
        reason: "Unable to run configured command (ENOENT)",
        cause: { message: "launch failed" },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

const providerSnapshot = (
  overrides: Partial<ProviderProcessSnapshot> = {},
): ProviderProcessSnapshot => ({
  stdout: {
    text: "captured owned output",
    bytes: 21,
    observedBytes: 21,
  },
  stderr: { text: "diagnostic", bytes: 10, observedBytes: 10 },
  exitCode: 0,
  signal: null,
  ...overrides,
});

it("preserves raw retained byte counts when output text replaces invalid UTF-8", async () => {
  const { directory, path } = await createArtifact();
  const snapshot = providerSnapshot({
    stdout: { text: "�", bytes: 1, observedBytes: 1, invalidUtf8: true },
    stderr: { text: "�", bytes: 2, observedBytes: 2, invalidUtf8: true },
    exitCode: 7,
  });
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw new OwnedCommandFailure(
        "cancelled",
        "Command was cancelled after output capture",
        snapshot,
      );
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCancelledError",
        capturedOutput: {
          stdout: "�",
          stderr: "�",
          stdout_bytes: 1,
          stderr_bytes: 2,
        },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("preserves the provider remediation when owned process preparation fails", async () => {
  const { directory, path } = await createArtifact();
  const remediation = new AnalysisCapabilityUnavailableError(
    "rizin",
    "execute_rizin_command",
    "Rizin needs permission to inspect this process",
    { userMessage: "Grant process inspection permission, then retry." },
  );
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw new OwnedCommandFailure(
        "process",
        "Could not prepare process ownership",
        null,
        null,
        { cause: remediation },
      );
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "rizin",
        reason: remediation.reason,
        userMessage: remediation.userMessage,
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("waits for active provider cleanup during shutdown and rejects new work", async () => {
  const { directory, path } = await createArtifact();
  let signal: AbortSignal | undefined;
  let announceStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => {
    announceStarted = resolve;
  });
  let releaseProvider: (() => void) | undefined;
  const providerGate = new Promise<void>((resolve) => {
    releaseProvider = resolve;
  });
  const stop = vi
    .fn()
    .mockResolvedValueOnce({ status: "incomplete", reason: "still running" })
    .mockResolvedValueOnce({ status: "verified-cleanup" });
  const cleanupOwner = { stop } as unknown as ProviderProcessSupervisor;
  const runOwned = vi.fn<typeof runOwnedCommand>(async (_spawn, _limits, options) => {
    signal = options?.signal;
    announceStarted?.();
    await providerGate;
    throw new OwnedCommandFailure(
      "cancelled",
      "Command cancelled during shutdown.",
      providerSnapshot({ exitCode: null }),
      "still running",
      undefined,
      ["run-id", "pid:42"],
      cleanupOwner,
    );
  });
  const service = new ReverseEngineeringService({ runOwned });

  try {
    const operation = service.executeRizinCommand({ path, command: "iI" });
    await started;
    let closeSettled = false;
    const closing = service.close().finally(() => {
      closeSettled = true;
    });
    expect(signal?.aborted).toBe(true);
    await Promise.resolve();
    expect(closeSettled).toBe(false);
    releaseProvider?.();

    await expect(operation).resolves.toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError", cleanupIncomplete: true },
    });
    await expect(closing).rejects.toMatchObject({
      cleanupIncomplete: true,
      cleanup: { reason: "still running" },
    });
    expect(stop).toHaveBeenCalledTimes(1);
    await expect(
      service.executeRizinCommand({ path, command: "iI" }),
    ).resolves.toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
    expect(runOwned).toHaveBeenCalledTimes(1);

    await service.close();
    expect(stop).toHaveBeenCalledTimes(2);
  } finally {
    releaseProvider?.();
    await rm(directory, { recursive: true, force: true });
  }
});

it.each([
  ["normal exit", providerSnapshot(), "complete", 0, false],
  [
    "non-zero exit",
    providerSnapshot({ exitCode: 7, diagnosticTruncated: true }),
    "complete",
    7,
    true,
  ],
  [
    "signal termination",
    providerSnapshot({
      exitCode: null,
      signal: "SIGSEGV",
      diagnosticTruncated: true,
    }),
    "unknown",
    null,
    true,
  ],
  [
    "signal termination with a numeric exit snapshot",
    providerSnapshot({ exitCode: 7, signal: "SIGSEGV" }),
    "unknown",
    null,
    false,
  ],
  [
    "signal termination without truncation",
    providerSnapshot({ exitCode: null, signal: "SIGTERM" }),
    "unknown",
    null,
    false,
  ],
  ["unknown exit status", providerSnapshot({ exitCode: null }), "unknown", null, false],
] as const)(
  "maps an owned command %s into provider Evidence",
  async (_name, snapshot, completion, exitCode, outputTruncated) => {
    const { directory, path } = await createArtifact();
    const runOwned = vi.fn(async () => snapshot);
    const service = new ReverseEngineeringService({
      runOwned,
      environment: { REA_RIZIN_COMMAND: "rizin-test" },
    });

    try {
      const result = await service.executeRizinCommand({ path, command: "iI" });
      expect(runOwned).toHaveBeenCalledOnce();
      expect(runOwned).toHaveBeenCalledWith(
        expect.objectContaining({
          command: "rizin-test",
          arguments: expect.arrayContaining(["-q", "-c", "iI"]),
          expectedCommand: null,
          env: expect.objectContaining({ REA_RIZIN_COMMAND: "rizin-test" }),
          hostEnvironment: {},
          sweepTokenOwnedProcesses: true,
        }),
        {
          timeoutMs: 120_000,
          diagnosticBytes: 16 * 1024 * 1024,
          acceptNonZeroExit: true,
        },
        { signal: expect.any(AbortSignal) },
      );
      expect(result).toMatchObject({
        ok: true,
        value: {
          raw_result: {
            stdout: "captured owned output",
            completion_status: completion,
            exit_code: exitCode,
            output_truncated: outputTruncated,
          },
        },
      });
      if (!result.ok) throw new Error("Expected provider Evidence");
      expect(result.value.parameters).toMatchObject({
        command: "iI",
        provider_executable: "rizin-test",
        command_arguments: expect.arrayContaining(["-q", "-c", "iI"]),
      });
      expect(result.value.locations).toContainEqual({
        kind: "artifact-path",
        path,
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it.each([
  ["cancelled", "AnalysisCancelledError", "ABORT_ERR"],
  ["timeout", "AnalysisTimeoutError", "ETIMEDOUT"],
  ["output-limit", "evidence", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"],
  ["process", "evidence", 7],
] as const)(
  "maps an owned command %s failure while retaining its snapshot",
  async (reason, expected, mappedCode) => {
    const { directory, path } = await createArtifact();
    const snapshot = providerSnapshot({
      ...(reason === "process" ? { exitCode: 7 } : {}),
      ...(reason === "output-limit"
        ? {}
        : reason === "cancelled"
          ? {}
          : { diagnosticTruncated: true }),
    });
    const service = new ReverseEngineeringService({
      runOwned: async () => {
        throw new OwnedCommandFailure(
          reason,
          "owned command failed",
          snapshot,
          reason === "timeout" ? "cleanup pending" : null,
          undefined,
          reason === "timeout" ? ["run-id", "pid:7"] : [],
        );
      },
    });

    try {
      const result = await service.executeRizinCommand({ path, command: "iI" });
      if (expected === "evidence") {
        expect(result).toMatchObject({
          ok: true,
          value: {
            raw_result: {
              stdout: "captured owned output",
              exit_code: mappedCode === 7 ? 7 : null,
              completion_status:
                reason === "output-limit" ? "unknown" : "complete",
              output_truncated: true,
            },
          },
        });
      } else {
        expect(result).toMatchObject({
          ok: false,
          error: {
            _tag: expected,
            partialObservation: {
              raw_result: {
                stdout: "captured owned output",
                exit_code: null,
                completion_status: "unknown",
                output_truncated: reason !== "cancelled",
              },
            },
            ...(reason === "timeout"
              ? {
                  cleanup: {
                    reason: "cleanup pending",
                    resources: ["run-id", "pid:7"],
                  },
                }
              : {}),
          },
        });
        if (result.ok) throw new Error("Expected a tagged command failure");
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("maps an uncaptured owned launcher error to provider unavailability", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw Object.assign(new Error("missing provider"), { code: "ENOENT" });
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCapabilityUnavailableError", providerId: "rizin" },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("forwards a caller abort signal to the owned command supervisor", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  const runOwned = vi.fn<typeof runOwnedCommand>(async () => providerSnapshot());
  const service = new ReverseEngineeringService({ runOwned });

  try {
    const result = await service.executeRizinCommand(
      { path, command: "iI" },
      { signal: controller.signal },
    );
    expect(result.ok).toBe(true);
    expect(runOwned.mock.calls[0]?.[2]).toMatchObject({
      signal: expect.any(AbortSignal),
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("does not classify a completed provider call as cancelled for a live signal", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  const service = new ReverseEngineeringService({
    run: async () => ({ stdout: "completed output", stderr: "" }),
  });

  try {
    const result = await service.executeRizinCommand(
      { path, command: "iI" },
      { signal: controller.signal },
    );
    expect(result).toMatchObject({
      ok: true,
      value: { raw_result: { stdout: "completed output", completion_status: "complete" } },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("preserves a provider timeout when cancellation arrives during the final digest", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  let digests = 0;
  const service = new ReverseEngineeringService({
    digest: async () => {
      digests += 1;
      if (digests === 2) controller.abort();
      return "a".repeat(64);
    },
    run: async () => {
      throw Object.assign(new Error("provider timed out"), {
        stdout: "partial timeout output",
        stderr: "timeout diagnostic",
        code: "ETIMEDOUT",
        signal: null,
        killed: true,
      });
    },
  });

  try {
    const result = await service.executeRizinCommand(
      { path, command: "iI" },
      { signal: controller.signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisTimeoutError",
        capturedOutput: {
          stdout: "partial timeout output",
          stderr: "timeout diagnostic",
        },
        partialObservation: {
          raw_result: {
            stdout: "partial timeout output",
            completion_status: "unknown",
          },
          limitations: expect.arrayContaining([
            expect.stringContaining("AnalysisTimeoutError"),
          ]),
        },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("classifies E2BIG as a provider command resource constraint", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw new OwnedCommandFailure(
        "process",
        "Command launch failed.",
        null,
        null,
        { cause: Object.assign(new Error("argument list too long"), { code: "E2BIG" }) },
      );
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisResourceConstraintError",
        resource: "transport",
        operation: "execute_rizin_command",
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("classifies an owned launcher failure without a process snapshot", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw new OwnedCommandFailure("process", "no process snapshot");
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "rizin",
        partialObservation: undefined,
        reason: "Unable to run configured command (ERR_PROVIDER_LAUNCH)",
        cause: {
          message: "Owned provider command did not produce a complete result.",
          stdout: "",
          stderr: "",
          cause: { reason: "process", message: "no process snapshot" },
        },
        capturedOutput: undefined,
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("retains an owned process failure snapshot with an unknown exit code", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw new OwnedCommandFailure(
        "process",
        "process ended before reporting an exit code",
        providerSnapshot({ exitCode: null }),
      );
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: true,
      value: {
        raw_result: {
          stdout: "captured owned output",
          exit_code: null,
          completion_status: "unknown",
        },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("fails with partial unknown Evidence when owned output collection fails after exit 0", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw Object.assign(
        new OwnedCommandFailure(
          "process",
          "stdout stream failed: fixture read failure",
          providerSnapshot({ exitCode: 0 }),
        ),
        { collectionFailure: true },
      );
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisOutputError",
        partialObservation: {
          raw_result: {
            stdout: "captured owned output",
            stderr: "diagnostic",
            exit_code: null,
            completion_status: "unknown",
          },
        },
      },
    });
    if (result.ok) throw new Error("Expected collection failure");
    expect(result.error.cause).toMatchObject({
      collectionFailure: true,
      cause: { reason: "process" },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("does not claim provider completion or a final digest while owned cleanup is incomplete", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    runOwned: async () => {
      throw new OwnedCommandFailure(
        "process",
        "Owned process cleanup remains incomplete.",
        providerSnapshot({ exitCode: 0 }),
        "descendant remains active",
        undefined,
        ["run-id", "pid:42"],
      );
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisOutputError",
        partialObservation: {
          raw_result: {
            exit_code: 0,
            completion_status: "unknown",
            artifact_sha256_after: null,
            artifact_changed: null,
          },
          limitations: expect.arrayContaining([
            expect.stringContaining("owned provider cleanup is incomplete"),
          ]),
        },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("records an explicit loss marker when provider bytes are invalid UTF-8", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    runOwned: async () =>
      providerSnapshot({
        stdout: {
          text: "captured � output",
          bytes: 17,
          observedBytes: 17,
          invalidUtf8: true,
        },
      }),
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({
        raw_result: { stdout: "captured � output" },
      });
      expect(result.value.limitations).toContain(
        "Captured stdout bytes contain invalid or incomplete UTF-8; replacement characters in the text capture do not preserve the original bytes.",
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
