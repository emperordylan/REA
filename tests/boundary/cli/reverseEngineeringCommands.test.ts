import pino from "pino";
import { afterEach, expect, it, vi } from "vitest";

import { createReverseEngineeringService } from "../../../src/composition/reverseEngineering.js";
import { registerReverseEngineeringCommands } from "../../../src/cli/reverseEngineeringCommands.js";
import { CLI_COMMANDS } from "../../../src/cliCommandNames.js";
import { AnalysisCancelledError, AnalysisTimeoutError, AnalysisOutputError } from "../../../src/domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import { err } from "../../../src/domain/result.js";
import type { CliInstance } from "../../../src/cli/types.js";
import type { ReverseEngineeringService } from "../../../src/application/reverse/ReverseEngineeringService.js";

vi.mock("../../../src/composition/reverseEngineering.js", () => ({
  createReverseEngineeringService: vi.fn(),
}));

const originalExitCode = process.exitCode;

afterEach(() => {
  vi.resetAllMocks();
  process.exitCode = originalExitCode;
});

const observation = (completionStatus: "complete" | "unknown") =>
  createEvidence(undefined, { id: "gnu.objdump", name: "GNU objdump", version: null }, {
    predicateType: "rea.reverse-engineering.command-observation",
    operation: "inspect_with_objdump",
    parameters: { operation: "file_headers" },
    result: { completion_status: completionStatus },
    rawResult: { completion_status: completionStatus },
  });

const runObjdump = async (service: Partial<ReverseEngineeringService>) => {
  const commands = new Map<string, { run(input: { args: { path: string; operation: string }; options: { followDebugLinks: boolean } }): Promise<unknown> }>();
  const cli = {
    command: (name: string, definition: { run(input: { args: { path: string; operation: string }; options: { followDebugLinks: boolean } }): Promise<unknown> }) => {
      commands.set(name, definition);
      return cli;
    },
  } as unknown as CliInstance;
  vi.mocked(createReverseEngineeringService).mockReturnValue(service as ReverseEngineeringService);
  registerReverseEngineeringCommands(cli, pino({ enabled: false }), {});
  const command = commands.get(CLI_COMMANDS.inspectWithObjdump);
  if (command === undefined) throw new Error("objdump CLI command was not registered");
  return command.run({ args: { path: "/tmp/sample", operation: "file_headers" }, options: { followDebugLinks: false } });
};

it("returns complete Evidence after a successful retry of cleanup-only failure", async () => {
  const evidence = observation("complete");
  const error = Object.assign(
    new AnalysisOutputError("inspect_with_objdump", "Provider process cleanup remains incomplete.", {
      cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
      partialObservation: evidence,
    }),
    { cleanupOnly: true },
  );
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  const result = await runObjdump(service);

  expect(result).toEqual(evidence);
  expect(service.close).toHaveBeenCalledOnce();
});

it("clears recovered cleanup state without promoting unknown Evidence", async () => {
  const evidence = observation("unknown");
  const error = Object.assign(
    new AnalysisOutputError("inspect_with_objdump", "Provider process cleanup remains incomplete.", {
      cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
      partialObservation: evidence,
    }),
    { cleanupOnly: true },
  );
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  const result = await runObjdump(service);

  expect(result).toMatchObject({ code: "unreadable_output", details: { partial_observation: { normalized_result: { completion_status: "unknown" } } } });
});

it("preserves an independent timeout after cleanup succeeds", async () => {
  const evidence = observation("unknown");
  const error = new AnalysisTimeoutError("inspect_with_objdump", 1_000, {
    cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
    partialObservation: evidence,
  });
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  const result = await runObjdump(service);

  expect(result).toMatchObject({ code: "provider_timeout", details: { partial_observation: { normalized_result: { completion_status: "unknown" } } } });
  expect(error.cleanupIncomplete).toBe(false);
  expect(projectAnalysisError(error).details).not.toHaveProperty("cleanup");
});

it("does not project cancellation cleanup as incomplete after a successful retry", async () => {
  const error = new AnalysisCancelledError("inspect_with_objdump", {
    cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
    partialObservation: observation("unknown"),
  });
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  await runObjdump(service);

  expect(error.cleanupIncomplete).toBe(false);
  expect(projectAnalysisError(error).details).toMatchObject({ cleanup: "complete" });
});
