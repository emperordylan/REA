import { describe, expect, it } from "vitest";

import { createEvidence } from "../../../src/domain/evidence.js";
import { evaluateAgentTranscript } from "../../../src/evaluation/AgentEval.js";
import {
  parseClaudeCodeEvents,
  parseGeminiCliEvents,
} from "../../../src/evaluation/AgentTranscript.js";

const evidence = createEvidence(
  { path: "/tmp/app.asar", sha256: "1".repeat(64), format: "asar" },
  { id: "javascript", name: "JavaScript analysis", version: null },
  {
    operation: "analyze_javascript_application",
    parameters: {},
    result: { observed: true },
    evidenceLinks: [],
    authority: "shipped-artifact",
  },
);
const answer = `Observed shipped-artifact evidence ${evidence.evidence_id} establishes the preload bridge; runtime behavior remains unknown.`;

// Shapes trimmed from `claude --print --output-format stream-json --verbose` 2.1.296.
const claudeToolUse = (id: string, name: string, input: unknown = {}) => ({
  type: "assistant",
  parent_tool_use_id: null,
  message: { content: [{ type: "tool_use", id, name, input }] },
});
const claudeToolResult = (
  id: string,
  toolUseResult: unknown,
  isError = false,
) => ({
  type: "user",
  parent_tool_use_id: null,
  message: {
    content: [
      {
        type: "tool_result",
        tool_use_id: id,
        // Oversized results are replaced by a spill notice in model-visible content.
        content: "Error: result exceeds maximum allowed tokens.",
        ...(isError ? { is_error: true } : {}),
      },
    ],
  },
  tool_use_result: toolUseResult,
});
const claudeResult = {
  type: "result",
  subtype: "success",
  is_error: false,
  result: answer,
  usage: {
    input_tokens: 12,
    cache_creation_input_tokens: 100,
    cache_read_input_tokens: 900,
    output_tokens: 40,
  },
};

describe("Claude Code transcripts", () => {
  it("pairs MCP calls with raw structured results and reports total input", () => {
    const transcript = parseClaudeCodeEvents([
      { type: "system", subtype: "init" },
      claudeToolUse("toolu_search", "ToolSearch", { query: "select:x" }),
      claudeToolResult("toolu_search", { matches: [] }),
      claudeToolUse("toolu_1", "mcp__rea__analyze_javascript_application", {
        input_path: "/tmp/app.asar",
      }),
      claudeToolResult("toolu_1", {
        content: "Error: result exceeds maximum allowed tokens.",
        structuredContent: evidence,
      }),
      claudeResult,
    ]);
    expect(transcript.calls).toEqual([
      expect.objectContaining({
        id: "toolu_1",
        server: "rea",
        tool: "analyze_javascript_application",
        arguments: { input_path: "/tmp/app.asar" },
        delivered: true,
      }),
    ]);
    expect(transcript.usage).toEqual({
      inputTokens: 1012,
      cachedInputTokens: 900,
      outputTokens: 40,
    });
    const metrics = evaluateAgentTranscript(
      transcript,
      "analyze_javascript_application",
      { requireEvidence: true },
    );
    expect(metrics).toMatchObject({
      firstTool: "analyze_javascript_application",
      evidenceIds: [evidence.evidence_id],
      finalCitesEvidence: true,
      finalMessage: answer,
    });
  });

  it("records client-reported failures without delivering Evidence", () => {
    const transcript = parseClaudeCodeEvents([
      claudeToolUse("toolu_1", "mcp__rea__analyze_javascript_application"),
      claudeToolResult(
        "toolu_1",
        {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: { code: "invalid_request" } }),
            },
          ],
          isError: true,
        },
        true,
      ),
      claudeResult,
    ]);
    const metrics = evaluateAgentTranscript(transcript, null);
    expect(metrics.reaCalls).toEqual([
      expect.objectContaining({ error: true, errorCode: "invalid_request" }),
    ]);
    expect(metrics.evidenceIds).toEqual([]);
  });

  it("ignores other MCP servers and subagent text", () => {
    const transcript = parseClaudeCodeEvents([
      claudeToolUse("toolu_1", "mcp__other__analyze"),
      claudeToolResult("toolu_1", { structuredContent: evidence }),
      {
        type: "assistant",
        parent_tool_use_id: "toolu_task",
        message: { content: [{ type: "text", text: "subagent" }] },
      },
      {
        type: "assistant",
        parent_tool_use_id: null,
        message: { content: [{ type: "text", text: "top-level" }] },
      },
    ]);
    expect(transcript.finalMessage).toBe("top-level");
    expect(transcript.usage.inputTokens).toBe(0);
    const metrics = evaluateAgentTranscript(transcript, null);
    expect(metrics.reaCalls).toEqual([]);
  });
});

// Shapes from Gemini CLI 0.63.0 `--output-format stream-json`.
describe("Gemini CLI transcripts", () => {
  const toolUse = (id: string, name: string) => ({
    type: "tool_use",
    tool_name: name,
    tool_id: id,
    parameters: { input_path: "/tmp/app.asar" },
  });

  it("pairs MCP calls with complete text results and joins the final answer", () => {
    const transcript = parseGeminiCliEvents([
      { type: "init", model: "gemini" },
      { type: "message", role: "user", content: "prompt" },
      { type: "message", role: "assistant", content: "Let me ", delta: true },
      { type: "message", role: "assistant", content: "look.", delta: true },
      toolUse("call-1", "mcp_rea_analyze_javascript_application"),
      toolUse("call-2", "read_file"),
      {
        type: "tool_result",
        tool_id: "call-1",
        status: "success",
        output: JSON.stringify(evidence),
      },
      { type: "message", role: "assistant", content: "Observed ", delta: true },
      {
        type: "message",
        role: "assistant",
        content: answer.slice("Observed ".length),
        delta: true,
      },
      {
        type: "result",
        status: "success",
        stats: { input_tokens: 500, cached: 200, output_tokens: 30 },
      },
    ]);
    expect(transcript.finalMessage).toBe(answer);
    expect(transcript.usage).toEqual({
      inputTokens: 500,
      cachedInputTokens: 200,
      outputTokens: 30,
    });
    const metrics = evaluateAgentTranscript(
      transcript,
      "analyze_javascript_application",
      { requireEvidence: true },
    );
    expect(metrics).toMatchObject({
      reaCalls: [expect.objectContaining({ id: "call-1", error: false })],
      evidenceIds: [evidence.evidence_id],
      finalCitesEvidence: true,
    });
  });

  it("treats error results as failed calls and keeps REA error codes", () => {
    const transcript = parseGeminiCliEvents([
      toolUse("call-1", "mcp_rea_analyze_javascript_application"),
      {
        type: "tool_result",
        tool_id: "call-1",
        status: "error",
        output: JSON.stringify({ error: { code: "invalid_request" } }),
        error: { type: "MCP_TOOL_ERROR", message: "failed" },
      },
    ]);
    const metrics = evaluateAgentTranscript(transcript, null);
    expect(metrics.reaCalls).toEqual([
      expect.objectContaining({ error: true, errorCode: "invalid_request" }),
    ]);
    expect(metrics.evidenceIds).toEqual([]);
    expect(metrics.inputTokens).toBe(0);
  });
});
