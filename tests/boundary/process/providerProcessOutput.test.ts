import { expect, it, vi } from "vitest";
import type { Socket } from "node:net";
import {
  ProviderProcessSupervisor,
  type ProviderProcessDiagnostic,
} from "../../../src/process/ProviderProcess.js";
import {
  spawnProviderProcessFixture,
  stopProviderProcessFixture,
} from "../../fixtures/providerProcess.js";

it("unreferences inherited output streams without closing them", async () => {
  const child = spawnProviderProcessFixture("stubborn");
  const supervisor = new ProviderProcessSupervisor({
    process: child,
    ownsProcessLifetime: true,
  });
  const stdoutUnref = vi.spyOn(child.stdout as Socket, "unref");
  const stderrUnref = vi.spyOn(child.stderr as Socket, "unref");
  try {
    supervisor.unrefOutputStreams();
    expect(stdoutUnref).toHaveBeenCalledOnce();
    expect(stderrUnref).toHaveBeenCalledOnce();
    expect(child.stdout!.destroyed).toBe(false);
    expect(child.stderr!.destroyed).toBe(false);
  } finally {
    await supervisor.stop();
    await stopProviderProcessFixture(child);
  }
});

it("bounds capture before diagnostic callbacks while draining both output streams", async () => {
  const child = spawnProviderProcessFixture("burst", 70_000);
  const diagnostics: ProviderProcessDiagnostic[] = [];
  const supervisor = new ProviderProcessSupervisor(
    { process: child, ownsProcessLifetime: true },
    {
      maxDiagnosticBytes: 1024,
      onDiagnostic: (event) => {
        const snapshot = supervisor.snapshot();
        expect(
          snapshot.stdout.bytes + snapshot.stderr.bytes,
        ).toBeLessThanOrEqual(1024);
        diagnostics.push(event);
      },
    },
  );
  try {
    expect(await supervisor.waitForOutputClose(2_000)).toBe(true);
    expect(
      diagnostics.some((event) => event.type === "output" && event.truncated),
    ).toBe(true);
    const snapshot = supervisor.snapshot();
    expect(snapshot.stdout.observedBytes).toBe(70_000);
    expect(snapshot.stderr.observedBytes).toBe(70_000);
    expect(snapshot.stdout.bytes + snapshot.stderr.bytes).toBeLessThanOrEqual(
      1024,
    );
    for (const stream of ["stdout", "stderr"])
      expect(
        diagnostics
          .filter((event) => event.type === "output" && event.stream === stream)
          .at(-1),
      ).toMatchObject({ totalBytes: 70_000 });
  } finally {
    await supervisor.stop();
    await stopProviderProcessFixture(child);
  }
});
