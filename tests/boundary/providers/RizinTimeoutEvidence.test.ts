import { expect, it } from "vitest";

import { createRizinCommandTimeoutEvidence } from "../../../src/rizin/RizinDebugSessionManager.js";

it("preserves every field of partial Rizin timeout Evidence", () => {
  const result = {
    command: "dr",
    output: "partial register output",
    output_scope: "command_and_interleaved_session_output" as const,
    output_truncated: true,
    completion_status: "unknown" as const,
    backend: null,
  };

  const evidence = createRizinCommandTimeoutEvidence("session-123", "dr", result);

  expect(evidence.parameters).toEqual({
    session_id: "session-123",
    command: "dr",
  });
  expect(evidence.raw_result).toEqual(result);
  expect(evidence.normalized_result).toEqual(result);
  expect(evidence.limitations).toEqual([
    "The current debugger target identity is not established by the Rizin session identifier.",
    "The command timed out before its completion marker; retained output is partial and completion is unknown.",
    "The owned debugger process was stopped because output correlation could no longer be guaranteed.",
    "The command is unrestricted and may access local files, the shell, network, or mutate the target.",
  ]);
});
