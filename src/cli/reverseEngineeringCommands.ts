import { z } from "incur";
import type { Logger } from "pino";

import { createReverseEngineeringService } from "../composition/reverseEngineering.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import type { Result } from "../domain/result.js";
import { err } from "../domain/result.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { logCliCommand } from "../cliLogging.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { ReverseEngineeringService } from "../application/reverse/ReverseEngineeringService.js";

const executeWithCleanup = async <Value>(
  service: ReverseEngineeringService,
  execute: () => Promise<Result<Value, AnalysisError>>,
): Promise<Result<Value, AnalysisError>> => {
  let result: Result<Value, AnalysisError>;
  try {
    result = await execute();
  } catch (cause) {
    await service.close().catch(() => undefined);
    throw cause;
  }
  try {
    await service.close();
  } catch (cause) {
    if (result.ok)
      return err(
        cause instanceof AnalysisError
          ? cause
          : new AnalysisOutputError(
              "reverse_engineering_cleanup",
              "Provider process cleanup failed.",
              { cause },
            ),
      );
  }
  return result;
};

/** Add one-shot reverse-engineering commands using the shared service layer. */
export const registerReverseEngineeringCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const service = createReverseEngineeringService(environment);
  cli.command(CLI_COMMANDS.inspectWithObjdump, {
    description:
      "Inspect a local artifact with GNU objdump and retain its raw output as Evidence",
    args: z.object({
      path: z
        .string()
        .min(1)
        .describe("Path to the local artifact to inspect."),
      operation: z
        .enum([
          "file_headers",
          "section_headers",
          "symbols",
          "relocations",
          "dwarf",
          "disassemble",
          "disassemble_all",
          "architectures",
        ])
        .describe("GNU objdump inspection operation to run."),
    }),
    options: z.object({
      followDebugLinks: z
        .boolean()
        .default(false)
        .describe(
          "Follow local DWARF debug links. External debug-file identity is not bound to Evidence.",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectWithObjdump, async () => {
          const result = await executeWithCleanup(service, () =>
            service.inspectWithObjdump(
              {
                ...args,
                follow_debug_links: options.followDebugLinks,
              },
              { signal },
            ),
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
  cli.command(CLI_COMMANDS.executeRizinCommand, {
    description: "Execute one Rizin command against a local artifact",
    args: z.object({
      path: z
        .string()
        .min(1)
        .describe("Path to the local artifact to analyze."),
      command: z.string().min(1).describe("One caller-selected Rizin command."),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.executeRizinCommand, async () => {
          const result = await executeWithCleanup(service, () =>
            service.executeRizinCommand(args, { signal }),
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
};
