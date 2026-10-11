import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";

/** One MCP result in the representations the client retained in its transcript. */
export interface AgentToolResult {
  /** MCP `structuredContent` when the client retained it. */
  readonly structuredContent: unknown;
  /** Text only when the client retained exactly one complete text block. */
  readonly text: string | undefined;
  /** MCP `isError` as reported by the server. */
  readonly isError: boolean;
}

/** One MCP invocation observed in an agent client transcript. */
export interface AgentToolCall {
  readonly id: string | null;
  readonly server: string | null;
  readonly tool: string;
  readonly arguments: unknown;
  /** The client reported a completed call whose retained result is consistent. */
  readonly delivered: boolean;
  /** The client reported a failed call independent of the MCP result. */
  readonly clientFailed: boolean;
  /** A client-side error record; REA's own result error is preferred when present. */
  readonly clientError: unknown;
  readonly result: AgentToolResult | undefined;
}

/** Client-reported model token usage. Input includes cached input. */
export interface AgentTokenUsage {
  readonly inputTokens: number;
  readonly cachedInputTokens: number;
  readonly outputTokens: number;
}

/** A client-neutral agent transcript produced once at the client boundary. */
export interface AgentTranscript {
  readonly calls: readonly AgentToolCall[];
  readonly finalMessage: string;
  readonly usage: AgentTokenUsage;
}

/** Agent clients whose transcripts REA evaluation can parse. */
export type AgentClient = "codex" | "claude-code" | "gemini-cli";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const record = (value: unknown): Record<string, unknown> | undefined =>
  isRecord(value) ? value : undefined;

/** Object entries of an untrusted transcript array; other values are ignored. */
const records = (values: readonly unknown[]): Record<string, unknown>[] =>
  values.filter(isRecord);

const textValue = (value: unknown): string | undefined =>
  typeof value === "string" && value.length > 0 ? value : undefined;

const numberValue = (value: unknown): number =>
  typeof value === "number" && Number.isFinite(value) ? value : 0;

/** Key-order independent value used for call identity and repetition signatures. */
export const canonicalValue = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(canonicalValue);
  const object = record(value);
  if (object === undefined) return value;
  return Object.fromEntries(
    Object.entries(object)
      .sort(([left], [right]) => compareUnicodeCodePoints(left, right))
      .map(([key, child]) => [key, canonicalValue(child)]),
  );
};

const sameValue = (left: unknown, right: unknown): boolean =>
  JSON.stringify(canonicalValue(left)) ===
  JSON.stringify(canonicalValue(right));

const absent = (value: unknown): boolean =>
  value === undefined || value === null;

const consistentAliases = (
  value: Record<string, unknown>,
  left: string,
  right: string,
): boolean =>
  absent(value[left]) ||
  absent(value[right]) ||
  sameValue(value[left], value[right]);

/** A single complete MCP text block; previews, prose lists, and replacements are not results. */
const singleTextBlock = (content: unknown): string | undefined => {
  if (!Array.isArray(content) || content.length !== 1) return undefined;
  const block = record(content[0]);
  return block?.type === "text" && typeof block.text === "string"
    ? block.text
    : undefined;
};

/** Parse a raw MCP `CallToolResult`; conflicting duplicate representations are not retained. */
const mcpResult = (value: unknown): AgentToolResult | undefined => {
  const result = record(value);
  if (
    result === undefined ||
    !consistentAliases(result, "structuredContent", "structured_content")
  )
    return undefined;
  return {
    structuredContent: result.structuredContent ?? result.structured_content,
    text: singleTextBlock(result.content),
    isError: result.isError === true,
  };
};

const callIdentity = (call: AgentToolCall): string =>
  call.id ??
  `${call.server ?? ""}:${call.tool}:${JSON.stringify(canonicalValue(call.arguments))}`;

/**
 * Clients may report one call more than once. The first report is retained;
 * conflicting reports of one call cannot establish which result was delivered.
 */
const uniqueCalls = (calls: readonly AgentToolCall[]): AgentToolCall[] => {
  const unique = new Map<string, AgentToolCall>();
  for (const call of calls) {
    const identity = callIdentity(call);
    const previous = unique.get(identity);
    if (previous === undefined) unique.set(identity, call);
    else if (
      previous.delivered !== call.delivered ||
      !sameValue(previous.result, call.result)
    )
      unique.set(identity, { ...previous, delivered: false });
  }
  return [...unique.values()];
};

const NO_USAGE: AgentTokenUsage = {
  inputTokens: 0,
  cachedInputTokens: 0,
  outputTokens: 0,
};

const codexItem = (
  event: Record<string, unknown>,
): Record<string, unknown> | undefined => {
  if (event.type === "item.completed") return record(event.item);
  return event.type === "mcp_tool_call" ? event : undefined;
};

const codexClientError = (
  item: Record<string, unknown>,
  result: Record<string, unknown> | undefined,
): unknown => {
  if (!absent(item.error)) return item.error;
  return absent(result?.error) ? undefined : result?.error;
};

const codexCall = (
  event: Record<string, unknown>,
): AgentToolCall | undefined => {
  const item = codexItem(event);
  if (item?.type !== "mcp_tool_call") return undefined;
  const tool = textValue(item.tool) ?? textValue(item.name);
  if (tool === undefined) return undefined;
  const consistent =
    consistentAliases(item, "server", "server_name") &&
    consistentAliases(item, "tool", "name") &&
    consistentAliases(item, "result", "output");
  const resultValue = record(item.result ?? item.output);
  const clientError = codexClientError(item, resultValue);
  // A bare streaming item has no completion until it reports one.
  const completed =
    item.status === "completed" ||
    (event.type === "item.completed" && item.status === undefined);
  return {
    id: textValue(item.id) ?? null,
    server: textValue(item.server) ?? textValue(item.server_name) ?? null,
    tool,
    arguments: item.arguments ?? item.input ?? {},
    delivered: consistent && completed && clientError === undefined,
    clientFailed: item.status === "failed" || !absent(item.error),
    clientError,
    result: consistent ? mcpResult(resultValue) : undefined,
  };
};

const codexAgentText = (value: unknown): string | undefined => {
  const item = record(value);
  if (item?.type !== "agent_message") return undefined;
  const direct = textValue(item.text) ?? textValue(item.message);
  if (direct !== undefined) return direct;
  if (!Array.isArray(item.content)) return undefined;
  const parts = item.content.flatMap((part) => {
    const text = textValue(record(part)?.text);
    return text === undefined ? [] : [text];
  });
  return parts.length === 0 ? undefined : parts.join("\n");
};

/** Codex reports cumulative turn usage; cached input is part of input. */
const codexUsage = (
  previous: AgentTokenUsage,
  event: Record<string, unknown>,
): AgentTokenUsage => {
  if (event.type !== "turn.completed") return previous;
  const usage = record(event.usage);
  return {
    inputTokens: Math.max(
      previous.inputTokens,
      numberValue(usage?.input_tokens),
    ),
    cachedInputTokens: Math.max(
      previous.cachedInputTokens,
      numberValue(usage?.cached_input_tokens),
    ),
    outputTokens: Math.max(
      previous.outputTokens,
      numberValue(usage?.output_tokens),
    ),
  };
};

/** Parse `codex exec --json` events. */
export const parseCodexEvents = (
  events: readonly unknown[],
): AgentTranscript => {
  const calls: AgentToolCall[] = [];
  const messages: string[] = [];
  let usage = NO_USAGE;
  for (const event of records(events)) {
    const call = codexCall(event);
    if (call !== undefined) calls.push(call);
    const message =
      event.type === "item.completed" ? codexAgentText(event.item) : undefined;
    if (message !== undefined) messages.push(message);
    usage = codexUsage(usage, event);
  }
  return {
    calls: uniqueCalls(calls),
    finalMessage: messages.at(-1) ?? "",
    usage,
  };
};

interface McpRequest {
  readonly id: string;
  readonly server: string;
  readonly tool: string;
  readonly arguments: unknown;
}

/** Split a client-qualified MCP tool name with the client's own grammar. */
const mcpRequest = (
  pattern: RegExp,
  id: unknown,
  name: unknown,
  arguments_: unknown,
): McpRequest | undefined => {
  const callId = textValue(id);
  const match = pattern.exec(textValue(name) ?? "");
  const server = match?.[1];
  const tool = match?.[2];
  return callId === undefined || server === undefined || tool === undefined
    ? undefined
    : { id: callId, server, tool, arguments: arguments_ ?? {} };
};

/** Claude Code names MCP tools `mcp__<server>__<tool>`. */
const CLAUDE_MCP_NAME = /^mcp__(.+?)__(.+)$/u;

interface ClaudeState {
  readonly requests: McpRequest[];
  readonly results: Map<
    string,
    { readonly isError: boolean; readonly raw: unknown }
  >;
  readonly messages: string[];
  resultText: string | undefined;
  usage: AgentTokenUsage;
}

const contentBlocks = (
  event: Record<string, unknown>,
): Record<string, unknown>[] => {
  const content = record(event.message)?.content;
  return Array.isArray(content) ? records(content) : [];
};

const consumeClaudeAssistant = (
  state: ClaudeState,
  event: Record<string, unknown>,
): void => {
  const texts: string[] = [];
  for (const block of contentBlocks(event)) {
    if (block.type === "text" && typeof block.text === "string")
      texts.push(block.text);
    const request =
      block.type === "tool_use"
        ? mcpRequest(CLAUDE_MCP_NAME, block.id, block.name, block.input)
        : undefined;
    if (request !== undefined) state.requests.push(request);
  }
  // Subagent messages carry a parent tool ID and are not the top-level answer.
  if (absent(event.parent_tool_use_id) && texts.length > 0)
    state.messages.push(texts.join("\n"));
};

const consumeClaudeUser = (
  state: ClaudeState,
  event: Record<string, unknown>,
): void => {
  const toolResults = contentBlocks(event).filter(
    (block) => block.type === "tool_result",
  );
  // The raw MCP result accompanies a user event that carries one tool result.
  const raw = toolResults.length === 1 ? event.tool_use_result : undefined;
  for (const block of toolResults) {
    const id = textValue(block.tool_use_id);
    if (id !== undefined && !state.results.has(id))
      state.results.set(id, { isError: block.is_error === true, raw });
  }
};

/** Claude reports uncached, cache-creation, and cache-read input separately. */
const claudeUsage = (event: Record<string, unknown>): AgentTokenUsage => {
  const usage = record(event.usage);
  const cacheRead = numberValue(usage?.cache_read_input_tokens);
  return {
    inputTokens:
      numberValue(usage?.input_tokens) +
      numberValue(usage?.cache_creation_input_tokens) +
      cacheRead,
    cachedInputTokens: cacheRead,
    outputTokens: numberValue(usage?.output_tokens),
  };
};

/** Parse `claude --print --output-format stream-json --verbose` events. */
export const parseClaudeCodeEvents = (
  events: readonly unknown[],
): AgentTranscript => {
  const state: ClaudeState = {
    requests: [],
    results: new Map(),
    messages: [],
    resultText: undefined,
    usage: NO_USAGE,
  };
  for (const event of records(events)) {
    if (event.type === "assistant") consumeClaudeAssistant(state, event);
    else if (event.type === "user") consumeClaudeUser(state, event);
    else if (event.type === "result") {
      state.resultText = textValue(event.result);
      state.usage = claudeUsage(event);
    }
  }
  const calls = state.requests.map((request): AgentToolCall => {
    const reported = state.results.get(request.id);
    return {
      ...request,
      delivered: reported !== undefined && !reported.isError,
      clientFailed: reported?.isError === true,
      clientError: undefined,
      result: mcpResult(reported?.raw),
    };
  });
  return {
    calls: uniqueCalls(calls),
    finalMessage: state.resultText ?? state.messages.at(-1) ?? "",
    usage: state.usage,
  };
};

/** Gemini CLI names MCP tools `mcp_<server>_<tool>`; server names cannot contain `_`. */
const GEMINI_MCP_NAME = /^mcp_([^_]+)_(.+)$/u;

const geminiCall = (
  request: McpRequest,
  reported: Record<string, unknown> | undefined,
): AgentToolCall => {
  const failed = reported !== undefined && reported.status !== "success";
  // Gemini retains only the joined MCP text content, not structured content.
  const text =
    typeof reported?.output === "string" ? reported.output : undefined;
  return {
    ...request,
    delivered: reported !== undefined && !failed,
    clientFailed: failed,
    clientError: absent(reported?.error) ? undefined : reported?.error,
    result:
      text === undefined
        ? undefined
        : { structuredContent: undefined, text, isError: false },
  };
};

/** Gemini reports prompt tokens including cached content tokens. */
const geminiUsage = (event: Record<string, unknown>): AgentTokenUsage => {
  const stats = record(event.stats);
  return {
    inputTokens: numberValue(stats?.input_tokens),
    cachedInputTokens: numberValue(stats?.cached),
    outputTokens: numberValue(stats?.output_tokens),
  };
};

/** Parse `gemini --output-format stream-json` events. */
export const parseGeminiCliEvents = (
  events: readonly unknown[],
): AgentTranscript => {
  const requests: McpRequest[] = [];
  const results = new Map<string, Record<string, unknown>>();
  // Assistant text between tool calls; the last non-empty segment is the answer.
  const segments: string[] = [];
  let segmentOpen = false;
  let usage = NO_USAGE;
  for (const event of records(events)) {
    if (event.type === "message" && event.role === "assistant") {
      const content = typeof event.content === "string" ? event.content : "";
      const continued = segmentOpen && event.delta === true;
      segments.push(`${continued ? (segments.pop() ?? "") : ""}${content}`);
      segmentOpen = true;
    } else if (event.type === "tool_use") {
      segmentOpen = false;
      const request = mcpRequest(
        GEMINI_MCP_NAME,
        event.tool_id,
        event.tool_name,
        event.parameters,
      );
      if (request !== undefined) requests.push(request);
    } else if (event.type === "tool_result") {
      const id = textValue(event.tool_id);
      if (id !== undefined && !results.has(id)) results.set(id, event);
    } else if (event.type === "result") usage = geminiUsage(event);
  }
  return {
    calls: uniqueCalls(
      requests.map((request) => geminiCall(request, results.get(request.id))),
    ),
    finalMessage:
      segments.filter((segment) => segment.trim().length > 0).at(-1) ?? "",
    usage,
  };
};

/** Parse one client's raw transcript events. */
export const parseAgentTranscript = (
  client: AgentClient,
  events: readonly unknown[],
): AgentTranscript => {
  switch (client) {
    case "codex":
      return parseCodexEvents(events);
    case "claude-code":
      return parseClaudeCodeEvents(events);
    case "gemini-cli":
      return parseGeminiCliEvents(events);
  }
};
