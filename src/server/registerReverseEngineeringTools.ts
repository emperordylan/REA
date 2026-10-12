import type {
  CallToolResult,
  McpServer,
  ServerContext,
} from "@modelcontextprotocol/server";
import type { Logger } from "pino";

import type { ReverseEngineeringService } from "../application/reverse/ReverseEngineeringService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { Evidence } from "../domain/evidence.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { ToolContract } from "../contracts/toolContractTypes.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { ToolResultDelivery } from "./toolResult.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Register objdump and Rizin operations against their exact named contracts. */
export const registerReverseEngineeringTools = (
  server: McpServer,
  service: ReverseEngineeringService,
  logger: Logger,
  delivery: ToolResultDelivery,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const objdump = toolContract("inspect_with_objdump");
  const rizin = toolContract("execute_rizin_command");
  server.registerTool(
    objdump.name,
    toolRegistrationOptions(objdump),
    (input, context: ServerContext) =>
      runAdmitted(
        objdump.name,
        context,
        withAdmittedAnalysis,
        delivery,
        async () => {
          const result = await logToolExecution(logger, objdump.name, () =>
            service.inspectWithObjdump(input, {
              signal: context.mcpReq.signal,
            }),
          );
          if (!result.ok)
            return deliverFailure(
              result.error,
              objdump,
              delivery,
              recordEvidence,
            );
          return delivery.toEvidenceToolResult(
            result.value,
            objdump,
            recordEvidence?.(result.value),
          );
        },
      ),
  );
  server.registerTool(
    rizin.name,
    toolRegistrationOptions(rizin),
    (input, context: ServerContext) =>
      runAdmitted(
        rizin.name,
        context,
        withAdmittedAnalysis,
        delivery,
        async () => {
          const result = await logToolExecution(logger, rizin.name, () =>
            service.executeRizinCommand(input, {
              signal: context.mcpReq.signal,
            }),
          );
          if (!result.ok)
            return deliverFailure(
              result.error,
              rizin,
              delivery,
              recordEvidence,
            );
          return delivery.toEvidenceToolResult(
            result.value,
            rizin,
            recordEvidence?.(result.value),
          );
        },
      ),
  );
};

const runAdmitted = async (
  operationName: string,
  context: ServerContext,
  admission: WithAdmittedAnalysis | undefined,
  delivery: ToolResultDelivery,
  operation: () => Promise<CallToolResult>,
): Promise<CallToolResult> => {
  if (admission === undefined) return operation();
  const admitted = await admission(
    operationName,
    context.mcpReq.signal,
    async () => operation(),
  );
  return admitted.ok
    ? admitted.value
    : delivery.toErrorToolResult(admitted.error);
};

const deliverFailure = (
  error: import("../domain/analysisErrorBase.js").AnalysisError,
  contract: ToolContract,
  delivery: ToolResultDelivery,
  recordEvidence?: EvidenceWriter["recordEvidence"],
) => {
  const partial = error.partialObservation;
  if (isEvidence(partial) && recordEvidence !== undefined)
    return delivery.toRecordedPartialErrorToolResult(
      error,
      partial.evidence_id,
      recordEvidence(partial),
    );
  return delivery.toErrorToolResult(error);
};

const isEvidence = (value: unknown): value is Evidence =>
  typeof value === "object" &&
  value !== null &&
  "evidence_id" in value &&
  typeof value.evidence_id === "string";
