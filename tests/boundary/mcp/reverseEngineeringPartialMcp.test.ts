import pino from "pino";
import type { McpServer } from "@modelcontextprotocol/server";
import { expect, it, vi } from "vitest";

import { TestReverseEngineeringService as ReverseEngineeringService } from "../../support/reverseEngineeringService.js";
import { AnalysisInputError } from "../../../src/domain/analysisErrorCore.js";
import type { AnalysisOperationPort } from "../../../src/application/AnalysisProvider.js";
import { EvidenceIntegrityError } from "../../../src/domain/evidenceErrors.js";
import { err, ok } from "../../../src/domain/result.js";
import type { WithAdmittedAnalysis } from "../../../src/server/analysisAdmission.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import { registerReverseEngineeringTools } from "../../../src/server/registerReverseEngineeringTools.js";

it("records partial Evidence and references it in the original MCP error", async () => {
  const registrations = new Map<
    string,
    (input: unknown, context: unknown) => Promise<unknown>
  >();
  const server = {
    registerTool: (
      name: string,
      _options: unknown,
      handler: (input: unknown, context: unknown) => Promise<unknown>,
    ) => registrations.set(name, handler),
  } as unknown as McpServer;
  const service = new ReverseEngineeringService({
    run: async () => {
      throw Object.assign(new Error("timed out"), {
        stdout: "partial provider output",
        stderr: "",
        code: "ETIMEDOUT",
        signal: null,
        killed: true,
      });
    },
  });
  const recordEvidence = vi.fn(() => ok("added" as const));
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
  );
  const invoke = registrations.get("execute_rizin_command");
  if (invoke === undefined) throw new Error("Rizin MCP handler was not registered");

  const response = (await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as {
    readonly isError?: boolean;
    readonly structuredContent?: {
      readonly error?: {
        readonly details?: Readonly<Record<string, unknown>>;
      };
    };
  };

  expect(response.isError).toBe(true);
  expect(recordEvidence).toHaveBeenCalledTimes(1);
  expect(response.structuredContent?.error?.details).toMatchObject({
    partial_observation: {
      kind: "retained-evidence",
      evidence_id: expect.any(String),
    },
  });
});

it("preserves a partial MCP error without claiming failed Evidence retention", async () => {
  const registrations = new Map<
    string,
    (input: unknown, context: unknown) => Promise<unknown>
  >();
  const server = {
    registerTool: (
      name: string,
      _options: unknown,
      handler: (input: unknown, context: unknown) => Promise<unknown>,
    ) => registrations.set(name, handler),
  } as unknown as McpServer;
  const service = new ReverseEngineeringService({
    run: async () => {
      throw Object.assign(new Error("timed out"), {
        stdout: "partial provider output",
        stderr: "",
        code: "ETIMEDOUT",
        signal: null,
        killed: true,
      });
    },
  });
  const recordEvidence = vi.fn((_evidence: unknown) =>
    err(new EvidenceIntegrityError("retention failed")),
  );
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
  );
  const invoke = registrations.get("execute_rizin_command");
  if (invoke === undefined) throw new Error("Rizin MCP handler was not registered");

  const response = (await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as {
    readonly isError?: boolean;
    readonly structuredContent?: {
      readonly error?: {
        readonly details?: Readonly<Record<string, unknown>>;
      };
    };
  };

  expect(response.isError).toBe(true);
  expect(response.structuredContent?.error?.details).toMatchObject({
    partial_observation: expect.objectContaining({
      operation: "execute_rizin_command",
    }),
  });
  expect(
    JSON.stringify(response.structuredContent?.error?.details),
  ).not.toContain("retained-evidence");
});

it("delivers objdump Evidence and ordinary input errors through their named tools", async () => {
  const registrations = new Map<
    string,
    (input: unknown, context: unknown) => Promise<unknown>
  >();
  const server = {
    registerTool: (
      name: string,
      _options: unknown,
      handler: (input: unknown, context: unknown) => Promise<unknown>,
    ) => registrations.set(name, handler),
  } as unknown as McpServer;
  const service = new ReverseEngineeringService({
    run: async () => ({ stdout: "objdump output", stderr: "" }),
  });
  const delivery = createToolResultDelivery(2 * 1024 * 1024);
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    delivery,
  );
  const context = { mcpReq: { signal: new AbortController().signal } };
  const objdump = registrations.get("inspect_with_objdump");
  const rizin = registrations.get("execute_rizin_command");
  if (objdump === undefined || rizin === undefined)
    throw new Error("Reverse-engineering MCP handlers were not registered");

  const success = (await objdump(
    { path: "package.json", operation: "file_headers" },
    context,
  )) as { readonly isError?: boolean };
  const objdumpFailure = (await objdump({}, context)) as {
    readonly isError?: boolean;
  };
  const failure = (await rizin({}, context)) as {
    readonly isError?: boolean;
    readonly structuredContent?: { readonly error?: { readonly code?: string } };
  };
  const cancelled = new AbortController();
  cancelled.abort();
  const cancelledContext = { mcpReq: { signal: cancelled.signal } };
  const cancelledObjdump = (await objdump(
    { path: "package.json", operation: "file_headers" },
    cancelledContext,
  )) as { readonly isError?: boolean };
  const cancelledRizin = (await rizin(
    { path: "package.json", command: "iI" },
    cancelledContext,
  )) as { readonly isError?: boolean };

  expect(success.isError).not.toBe(true);
  expect(objdumpFailure.isError).toBe(true);
  expect(failure.isError).toBe(true);
  expect(cancelledObjdump.isError).toBe(true);
  expect(cancelledRizin.isError).toBe(true);
});

it("does not treat a malformed partial observation as retained Evidence", async () => {
  const registrations = new Map<
    string,
    (input: unknown, context: unknown) => Promise<unknown>
  >();
  const server = {
    registerTool: (
      name: string,
      _options: unknown,
      handler: (input: unknown, context: unknown) => Promise<unknown>,
    ) => registrations.set(name, handler),
  } as unknown as McpServer;
  const invalidError = Object.assign(
    new AnalysisInputError("execute_rizin_command"),
    { partialObservation: { evidence_id: 42 } },
  );
  const service = {
    inspectWithObjdump: async () => err(invalidError),
    executeRizinCommand: async () => err(invalidError),
  } as unknown as ReverseEngineeringService;
  const recordEvidence = vi.fn(() => ok("added" as const));
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
  );
  const invoke = registrations.get("execute_rizin_command");
  if (invoke === undefined) throw new Error("Rizin MCP handler was not registered");

  const response = (await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as { readonly isError?: boolean };

  expect(response.isError).toBe(true);
  expect(recordEvidence).not.toHaveBeenCalled();
});

it("keeps provider execution and Evidence recording inside analysis admission", async () => {
  const registrations = new Map<
    string,
    (input: unknown, context: unknown) => Promise<unknown>
  >();
  const server = {
    registerTool: (
      name: string,
      _options: unknown,
      handler: (input: unknown, context: unknown) => Promise<unknown>,
    ) => registrations.set(name, handler),
  } as unknown as McpServer;
  const events: string[] = [];
  const service = new ReverseEngineeringService({
    run: async () => {
      events.push("provider");
      return { stdout: "objdump output", stderr: "" };
    },
  });
  const recordEvidence = vi.fn(() => {
    events.push("record");
    return ok("added" as const);
  });
  const admission: WithAdmittedAnalysis = async (_name, _signal, operation) => {
    events.push("admission-start");
    const result = await operation({} as AnalysisOperationPort);
    events.push("admission-end");
    return ok(result);
  };
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
    admission,
  );
  const invoke = registrations.get("inspect_with_objdump");
  if (invoke === undefined) throw new Error("objdump MCP handler was not registered");

  await invoke(
    { path: "package.json", operation: "file_headers" },
    { mcpReq: { signal: new AbortController().signal } },
  );

  expect(events).toEqual([
    "admission-start",
    "provider",
    "record",
    "admission-end",
  ]);
});
