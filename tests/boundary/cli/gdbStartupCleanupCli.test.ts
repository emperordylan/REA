import pino from "pino";
import { expect, it, vi } from "vitest";

import { AnalysisOutputError } from "../../../src/domain/analysisErrorCore.js";
import { err } from "../../../src/domain/result.js";
import { registerReverseEngineeringCommands } from "../../../src/cli/reverseEngineeringCommands.js";
import { CLI_COMMANDS } from "../../../src/cliCommandNames.js";
import type { CliInstance } from "../../../src/cli/types.js";
import type { GdbSessionManager } from "../../../src/gdb/GdbSessionManager.js";

it("retries retained GDB cleanup when CLI session startup fails", async () => {
  const commands = new Map<string, { run(input: { args: { command: string }; options: { inferiorTty: string } }): Promise<unknown> }>();
  const cli = {
    command: (name: string, definition: { run(input: { args: { command: string }; options: { inferiorTty: string } }): Promise<unknown> }) => {
      commands.set(name, definition);
      return cli;
    },
  } as unknown as CliInstance;
  const closeAll = vi.fn(async () => undefined);
  const manager = {
    start: vi.fn(async () => err(new AnalysisOutputError("start_gdb_session", "startup failed"))),
    closeAll,
  } as unknown as GdbSessionManager;
  const originalExitCode = process.exitCode;
  registerReverseEngineeringCommands(
    cli,
    pino({ enabled: false }),
    {},
    () => manager,
  );

  try {
    const command = commands.get(CLI_COMMANDS.debugWithGdb);
    if (command === undefined) throw new Error("GDB CLI command was not registered");
    const result = await command.run({ args: { command: "info files" }, options: { inferiorTty: "/dev/pts/42" } });
    expect(result).toMatchObject({ code: "unreadable_output" });
    expect(manager.start).toHaveBeenCalledOnce();
    expect(manager.start).toHaveBeenCalledWith(expect.anything(), { inferiorTty: "/dev/pts/42" });
    expect(closeAll).toHaveBeenCalledOnce();
  } finally {
    process.exitCode = originalExitCode;
  }
});

it("marks the CLI failed when retained GDB cleanup remains incomplete", async () => {
  const commands = new Map<string, { run(input: { args: { command: string }; options: { inferiorTty: string } }): Promise<unknown> }>();
  const cli = {
    command: (name: string, definition: { run(input: { args: { command: string }; options: { inferiorTty: string } }): Promise<unknown> }) => {
      commands.set(name, definition);
      return cli;
    },
  } as unknown as CliInstance;
  const manager = {
    start: vi.fn(async () => err(new AnalysisOutputError("start_gdb_session", "startup failed"))),
    closeAll: vi.fn(async () => { throw new Error("process still owned"); }),
  } as unknown as GdbSessionManager;
  const originalExitCode = process.exitCode;
  registerReverseEngineeringCommands(cli, pino({ enabled: false }), {}, () => manager);

  try {
    const command = commands.get(CLI_COMMANDS.debugWithGdb);
    if (command === undefined) throw new Error("GDB CLI command was not registered");
    const result = await command.run({ args: { command: "info files" }, options: { inferiorTty: "/dev/pts/42" } });
    expect(result).toMatchObject({ code: "unreadable_output" });
    expect(manager.closeAll).toHaveBeenCalledOnce();
    expect(process.exitCode).toBe(1);
  } finally {
    process.exitCode = originalExitCode;
  }
});
