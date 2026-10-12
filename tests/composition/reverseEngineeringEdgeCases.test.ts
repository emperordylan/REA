import { mkdtemp, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { ReverseEngineeringService } from "../../src/application/reverse/ReverseEngineeringService.js";
import { objdumpCommand } from "../../src/objdump/ObjdumpCommand.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../src/process/OwnedCommand.js";
import type { ProviderProcessSnapshot } from "../../src/process/ProviderProcess.js";

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
        }),
        {
          timeoutMs: 120_000,
          diagnosticBytes: 16 * 1024 * 1024,
          acceptNonZeroExit: true,
        },
        {},
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
    expect(runOwned.mock.calls[0]?.[2]).toEqual({ signal: controller.signal });
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
        },
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
