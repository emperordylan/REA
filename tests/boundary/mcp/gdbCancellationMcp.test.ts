import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { z } from "zod";

import { toolContract } from "../../../src/contracts/toolContracts.js";
import { AnalysisTimeoutError } from "../../../src/domain/analysisErrorCore.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import { err, ok } from "../../../src/domain/result.js";
import { GdbSessionManager } from "../../../src/gdb/GdbSessionManager.js";
import { silentLogger } from "../../../src/logger.js";
import { registerGdbTools } from "../../../src/server/registerGdbTools.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";

const waitForFile = async (path: string): Promise<void> => {
  await expect
    .poll(() => readFile(path, "utf8").catch(() => ""))
    .toBe("started");
};

const validateStatusResponse = async (
  client: Client,
  name: "gdb_session_status",
  sessionId: string,
): Promise<Record<string, unknown>> => {
  const listed = (await client.listTools()).tools.find(
    (tool) => tool.name === name,
  );
  if (listed?.outputSchema === undefined)
    throw new Error(`Missing advertised ${name} output schema`);
  const response = await client.callTool({
    name,
    arguments: { session_id: sessionId },
  });
  expect(response.isError).not.toBe(true);
  const contract = toolContract(name);
  const parsed = contract.outputSchema.parse(response.structuredContent);
  expect(
    new Ajv2020({ strict: false, validateFormats: false }).validate(
      z.record(z.string(), z.unknown()).parse(listed.outputSchema),
      parsed,
    ),
  ).toBe(true);
  return z.record(z.string(), z.unknown()).parse(parsed);
};

it.skipIf(process.platform === "win32")(
  "propagates MCP cancellation into a running GDB command",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-gdb-mcp-cancel-"));
    const provider = join(directory, "fake-gdb.mjs");
    const commandPath = join(directory, "command-started");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
process.stdin.setEncoding("utf8");
process.stdin.on("data", async (chunk) => {
  for (const line of chunk.split("\\n")) {
    const match = /^(\\d+)/.exec(line);
    if (!match) continue;
    if (line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
    else await import("node:fs/promises").then((fs) => fs.writeFile(${JSON.stringify(commandPath)}, "started"));
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    const server = new McpServer({ name: "gdb-cancellation", version: "1" });
    registerGdbTools(
      server,
      manager,
      silentLogger,
      createToolResultDelivery(undefined),
    );
    const client = new Client({ name: "gdb-cancellation", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const started = await client.callTool({
        name: "start_gdb_session",
        arguments: {},
      });
      const sessionId = z
        .object({ session_id: z.string().uuid() })
        .parse(started.structuredContent).session_id;
      const controller = new AbortController();
      const command = client.callTool(
        {
          name: "gdb_console",
          arguments: { session_id: sessionId, command: "shell sleep 600" },
        },
        { signal: controller.signal },
      );
      await waitForFile(commandPath);
      controller.abort();
      await expect(command).rejects.toThrow(/abort/iu);
      const status = await validateStatusResponse(
        client,
        "gdb_session_status",
        sessionId,
      );
      expect(status.state).toBe("closed");
      expect(status).toHaveProperty("diagnostics_truncated");
    } finally {
      await Promise.allSettled([client.close(), server.close()]);
      await manager.closeAll().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it.skipIf(process.platform === "win32")(
  "accepts caller-selected inferior_tty and exposes verified sink status through MCP",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-gdb-mcp-tty-"));
    const provider = join(directory, "fake-gdb.mjs");
    const tty = `${directory}/inferior-"terminal-Ω"`;
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  for (const line of chunk.split("\\n")) {
    const match = /^(\\d+)/.exec(line);
    if (!match) continue;
    if (line.includes("inferior-tty-show")) process.stdout.write(match[1] + "^done,inferior_tty_terminal=" + ${JSON.stringify(JSON.stringify(tty))} + "\\n");
    else if (line.includes("list-thread-groups")) process.stdout.write(match[1] + "^done,groups=[]\\n");
    else process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    const server = new McpServer({ name: "gdb-inferior-tty", version: "1" });
    registerGdbTools(
      server,
      manager,
      silentLogger,
      createToolResultDelivery(undefined),
    );
    const client = new Client({ name: "gdb-inferior-tty", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const contract = toolContract("start_gdb_session");
      expect(contract.inputSchema.safeParse({}).success).toBe(true);
      expect(
        contract.inputSchema.safeParse({ inferior_tty: tty }).success,
      ).toBe(true);
      expect(contract.inputSchema.safeParse({ inferior_tty: "" }).success).toBe(
        false,
      );
      const listed = (await client.listTools()).tools.find(
        (tool) => tool.name === "start_gdb_session",
      );
      expect(listed?.inputSchema).toBeDefined();
      expect(
        new Ajv2020({ strict: false, validateFormats: false }).validate(
          z.record(z.string(), z.unknown()).parse(listed?.inputSchema),
          { inferior_tty: tty },
        ),
      ).toBe(true);
      const started = await client.callTool({
        name: "start_gdb_session",
        arguments: { inferior_tty: tty },
      });
      const sessionId = z
        .object({ session_id: z.string().uuid() })
        .parse(started.structuredContent).session_id;
      const status = await validateStatusResponse(
        client,
        "gdb_session_status",
        sessionId,
      );
      expect(status).toMatchObject({
        inferior_tty: tty,
        inferior_tty_verified: true,
      });
    } finally {
      await Promise.allSettled([client.close(), server.close()]);
      await manager.closeAll().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("records partial GDB Evidence from an MCP command error", async () => {
  const evidence = createEvidence(
    undefined,
    {
      id: "gnu.gdb",
      name: "GNU GDB",
      version: null,
    },
    {
      predicateType: "rea.debugger.console-observation",
      operation: "gdb_console",
      parameters: {
        session_id: "00000000-0000-4000-8000-000000000001",
        command: "info registers",
      },
      result: {
        command: "info registers",
        mi: "",
        records: ["~partial"],
        console: "~partial",
        target: "",
        log: "",
        process_exit_observed: true,
        process_exit_code: 7,
        process_exit_signal: null,
        output_truncated: false,
        completion_status: "unknown",
      },
      rawResult: {
        command: "info registers",
        mi: "",
        records: ["~partial"],
        console: "~partial",
        target: "",
        log: "",
        process_exit_observed: true,
        process_exit_code: 7,
        process_exit_signal: null,
        output_truncated: false,
        completion_status: "unknown",
      },
      subjectUnavailableReason:
        "The debugger session does not identify an inferior.",
    },
  );
  expect(
    toolContract("gdb_console").outputSchema.parse(evidence),
  ).toMatchObject({
    normalized_result: {
      process_exit_observed: true,
      process_exit_code: 7,
      process_exit_signal: null,
    },
  });
  const manager = {
    start: async () =>
      ok({
        session_id: "00000000-0000-4000-8000-000000000001",
        mi_version: "mi3" as const,
      }),
    execute: async () =>
      err(
        new AnalysisTimeoutError("gdb_console", 10, {
          partialObservation: evidence,
          cleanup: {
            reason: "MI output was unsynchronized",
            resources: [evidence.parameters.session_id as string],
          },
        }),
      ),
    status: () => undefined,
    close: async () => ok({ target_state: "unknown" as const }),
  } as unknown as GdbSessionManager;
  const recorded: string[] = [];
  const server = new McpServer({ name: "gdb-partial-evidence", version: "1" });
  registerGdbTools(
    server,
    manager,
    silentLogger,
    createToolResultDelivery(undefined),
    (value) => {
      recorded.push(value.evidence_id);
      return ok("added");
    },
  );
  const client = new Client({ name: "gdb-partial-evidence", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const response = await client.callTool({
      name: "gdb_console",
      arguments: {
        session_id: "00000000-0000-4000-8000-000000000001",
        command: "info registers",
      },
    });
    expect(recorded).toEqual([evidence.evidence_id]);
    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({
      error: {
        details: { partial_observation: { evidence_id: evidence.evidence_id } },
      },
    });
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

it("records partial GDB startup Evidence from an MCP start error", async () => {
  const evidence = createEvidence(
    undefined,
    {
      id: "gnu.gdb",
      name: "GNU GDB",
      version: null,
    },
    {
      predicateType: "rea.debugger.startup-observation",
      operation: "start_gdb_session",
      parameters: { command: "GDB startup" },
      result: {
        command: "GDB startup",
        mi: "",
        records: ["~startup output"],
        console: "~startup output",
        target: "",
        log: "",
        process_exit_observed: true,
        process_exit_code: 7,
        process_exit_signal: null,
        output_truncated: false,
        completion_status: "unknown",
      },
      rawResult: {
        command: "GDB startup",
        mi: "",
        records: ["~startup output"],
        console: "~startup output",
        target: "",
        log: "",
        process_exit_observed: true,
        process_exit_code: 7,
        process_exit_signal: null,
        output_truncated: false,
        completion_status: "unknown",
      },
      subjectUnavailableReason:
        "No debugger session became ready before GDB exited.",
    },
  );
  const manager = {
    start: async () =>
      err(
        new AnalysisTimeoutError("start_gdb_session", 10, {
          partialObservation: evidence,
        }),
      ),
    execute: async () => ok(undefined),
    status: () => undefined,
    close: async () => ok({ target_state: "unknown" as const }),
  } as unknown as GdbSessionManager;
  const recorded: string[] = [];
  const server = new McpServer({
    name: "gdb-startup-partial-evidence",
    version: "1",
  });
  registerGdbTools(
    server,
    manager,
    silentLogger,
    createToolResultDelivery(undefined),
    (value) => {
      recorded.push(value.evidence_id);
      return ok("added");
    },
  );
  const client = new Client({
    name: "gdb-startup-partial-evidence",
    version: "1",
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const response = await client.callTool({
      name: "start_gdb_session",
      arguments: {},
    });
    expect(recorded).toEqual([evidence.evidence_id]);
    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({
      error: {
        details: { partial_observation: { evidence_id: evidence.evidence_id } },
      },
    });
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});
