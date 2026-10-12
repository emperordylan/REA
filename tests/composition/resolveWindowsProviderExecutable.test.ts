import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { resolveWindowsProviderExecutable } from "../../src/composition/resolveWindowsProviderExecutable.js";
import { createReverseEngineeringCommandPort } from "../../src/composition/reverseEngineering.js";

describe("resolveWindowsProviderExecutable", () => {
  it("resolves a bare name using captured PATH and PATHEXT", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-win-provider-"));
    const tools = join(directory, "tools");
    await mkdir(tools);
    const executable = join(tools, "rizin.EXE");
    await writeFile(executable, "fixture");
    try {
      expect(
        resolveWindowsProviderExecutable("rizin", {
          PATH: `C:\\unrelated;${tools}`,
          PATHEXT: ".COM;.EXE;.BAT",
        }),
      ).toBe(executable);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("skips script extensions in PATHEXT and resolves a later executable", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-win-provider-script-"));
    const script = join(directory, "rizin.CMD");
    const executable = join(directory, "rizin.EXE");
    await writeFile(script, "script fixture");
    await writeFile(executable, "executable fixture");
    try {
      expect(
        resolveWindowsProviderExecutable("rizin", {
          PATH: directory,
          PATHEXT: ".CMD;.BAT;.EXE;.COM",
        }),
      ).toBe(executable);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("uses the resolver for composed providers on Windows", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-win-provider-port-"));
    const executable = join(directory, "objdump.EXE");
    await writeFile(executable, "fixture");
    try {
      const commands = createReverseEngineeringCommandPort(
        { PATH: directory, PATHEXT: ".EXE" },
        "win32",
      );
      expect(
        commands.objdump({ path: "artifact", operation: "file_headers" })
          .executable,
      ).toBe(executable);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("preserves explicit paths and leaves unresolved names unchanged", () => {
    const environment = { PATH: "C:\\tools", PATHEXT: ".EXE" };
    expect(
      resolveWindowsProviderExecutable("C:\\tools\\rizin.exe", environment),
    ).toBe("C:\\tools\\rizin.exe");
    expect(resolveWindowsProviderExecutable("missing-tool", environment)).toBe(
      "missing-tool",
    );
  });
});
