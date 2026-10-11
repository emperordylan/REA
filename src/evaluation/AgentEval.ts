import {
  deliveredEvidence,
  evaluateKnownAnswers,
  type FixtureClaimExpectation,
  type KnownAnswerAssessment,
} from "./KnownAnswerEvaluation.js";
import {
  canonicalValue,
  type AgentToolCall,
  type AgentTranscript,
} from "./AgentTranscript.js";
import { TOOL_CONTRACTS } from "../contracts/toolContracts.js";

/** One REA MCP invocation measured in an agent transcript. */
interface AgentMcpCall {
  readonly id: string | null;
  readonly server: string | null;
  readonly tool: string;
  readonly arguments: unknown;
  readonly evidenceIds: readonly string[];
  readonly error: boolean;
  readonly errorCode: string | null;
}

/** Transcript measurements, text heuristics, and optional closed fixture-claim assessment. */
export interface AgentMetrics {
  readonly naturalUse: boolean;
  readonly correctFirstTool: boolean;
  readonly firstTool: string | null;
  readonly reaCalls: readonly AgentMcpCall[];
  readonly repeatedCallCount: number;
  readonly inputValidationFailureCount: number;
  readonly requiredToolSubsequenceMet: boolean;
  readonly inputTokens: number;
  readonly cachedInputTokens: number;
  readonly outputTokens: number;
  readonly finalMessage: string;
  readonly evidenceIds: readonly string[];
  /** Whether the answer contains a produced Evidence ID; claim support is not checked. */
  readonly finalCitesEvidence: boolean;
  /** Case-insensitive substring coverage, including terms in negated claims. */
  readonly answerTermCoverageMet: boolean;
  /** Text length, term/cue coverage, and configured transcript checks only. */
  readonly answerHeuristicsMet: boolean;
  /** Whether an epistemic keyword occurs; this does not establish honest authority use. */
  readonly epistemicCuePresent: boolean;
  /** Limited to configured fixture claims; free-form factual correctness is not assessed. */
  readonly factualCorrectness: KnownAnswerAssessment["status"];
  readonly factualAssessment: KnownAnswerAssessment;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const record = (value: unknown): Record<string, unknown> | undefined =>
  isRecord(value) ? value : undefined;

const textValue = (value: unknown): string | undefined =>
  typeof value === "string" && value.length > 0 ? value : undefined;

/** REA's own error record is preferred over a client wrapper around it. */
const toolResultError = (
  call: AgentToolCall,
): Record<string, unknown> | undefined => {
  const structured = record(call.result?.structuredContent);
  if (structured !== undefined)
    return record(structured.error) ?? record(call.clientError);
  // Some clients preserve REA failures only as one complete JSON text block.
  // A client-truncated preview or SDK prose is not a structured error record.
  const text = call.result?.text;
  if (text !== undefined) {
    try {
      const parsed = record(record(JSON.parse(text))?.error);
      if (parsed !== undefined) return parsed;
    } catch (cause) {
      if (!(cause instanceof SyntaxError || cause instanceof RangeError))
        throw cause;
    }
  }
  return record(call.clientError);
};

const measuredCall = (call: AgentToolCall): AgentMcpCall => {
  const error = toolResultError(call);
  const structured = record(call.result?.structuredContent);
  return {
    id: call.id,
    server: call.server,
    tool: call.tool,
    arguments: call.arguments,
    evidenceIds: deliveredEvidence(call).map(({ evidence_id }) => evidence_id),
    error:
      call.clientFailed ||
      call.clientError !== undefined ||
      call.result?.isError === true ||
      structured?.error !== undefined ||
      error !== undefined,
    errorCode: textValue(error?.code) ?? null,
  };
};

/** Measure agent routing, repetition, model usage, and explicitly limited answer heuristics. */
export const evaluateAgentTranscript = (
  transcript: AgentTranscript,
  expectedFirstTool: string | null,
  options: {
    readonly requireEvidence?: boolean;
    readonly requiredAnswerTermGroups?: readonly (readonly string[])[];
    readonly requiredToolSubsequence?: readonly string[];
    readonly forbidInputValidationFailures?: boolean;
    readonly fixtureClaims?: readonly FixtureClaimExpectation[];
  } = {},
): AgentMetrics => {
  const reaCalls = transcript.calls
    .filter(({ server }) => server === null || server.toLowerCase() === "rea")
    .map(measuredCall);
  const signatures = new Map<string, number>();
  let targetRevision = 0;
  for (const call of reaCalls) {
    // A status read before and after a successful target lifecycle change is
    // useful verification, not a duplicate analysis or unchanged failed retry.
    const context =
      call.tool === "binary_session" ? `${String(targetRevision)}:` : "";
    const signature = `${context}${call.tool}:${JSON.stringify(canonicalValue(call.arguments))}`;
    signatures.set(signature, (signatures.get(signature) ?? 0) + 1);
    if (
      !call.error &&
      (call.tool === "open_binary" || call.tool === "close_binary")
    )
      targetRevision += 1;
  }
  const repeatedCallCount = [...signatures.values()].reduce(
    (total, count) => total + Math.max(0, count - 1),
    0,
  );
  const inputValidationFailureCount = reaCalls.filter(
    (call) =>
      call.errorCode === "invalid_request" ||
      (call.error &&
        TOOL_CONTRACTS.find(
          ({ name }) => name === call.tool,
        )?.inputSchema.safeParse(call.arguments).success === false),
  ).length;
  const requiredToolSubsequenceMet = containsOrderedSubsequence(
    reaCalls.filter(({ error }) => !error).map(({ tool }) => tool),
    options.requiredToolSubsequence ?? [],
  );
  const { finalMessage } = transcript;
  const evidenceIds = [
    ...new Set(reaCalls.flatMap(({ evidenceIds: ids }) => ids)),
  ];
  const finalCitesEvidence = evidenceIds.some((evidenceId) =>
    finalMessage.includes(evidenceId),
  );
  const normalizedFinalMessage = finalMessage.toLocaleLowerCase("en-US");
  const answerTermCoverageMet = (options.requiredAnswerTermGroups ?? []).every(
    (terms) =>
      terms.some((term) =>
        normalizedFinalMessage.includes(term.toLocaleLowerCase("en-US")),
      ),
  );
  const epistemicCuePresent =
    /\b(evidence|observed|inferred|unknown|unavailable|limitation|authority|not configured|could not|requires approval)\b/iu.test(
      finalMessage,
    );
  const factualAssessment = evaluateKnownAnswers(
    transcript.calls,
    finalMessage,
    options.fixtureClaims,
  );
  return {
    naturalUse: reaCalls.length > 0,
    correctFirstTool: (reaCalls[0]?.tool ?? null) === expectedFirstTool,
    firstTool: reaCalls[0]?.tool ?? null,
    reaCalls,
    repeatedCallCount,
    inputValidationFailureCount,
    requiredToolSubsequenceMet,
    ...transcript.usage,
    finalMessage,
    evidenceIds,
    finalCitesEvidence,
    answerTermCoverageMet,
    answerHeuristicsMet:
      finalMessage.trim().length >= 80 &&
      epistemicCuePresent &&
      answerTermCoverageMet &&
      requiredToolSubsequenceMet &&
      (options.forbidInputValidationFailures !== true ||
        inputValidationFailureCount === 0) &&
      (options.requireEvidence !== true || finalCitesEvidence),
    epistemicCuePresent,
    factualCorrectness: factualAssessment.status,
    factualAssessment,
  };
};

const containsOrderedSubsequence = (
  values: readonly string[],
  required: readonly string[],
): boolean => {
  let index = 0;
  for (const value of values) {
    if (value === required[index]) index += 1;
    if (index === required.length) return true;
  }
  return required.length === 0;
};
