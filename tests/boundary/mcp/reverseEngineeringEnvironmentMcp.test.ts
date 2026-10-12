import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

it("uses the captured server environment to resolve reverse-engineering providers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-provider-environment-"));
  const provider = join(directory, "selected-rizin");
  const artifact = join(directory, "fixture.bin");
  await writeFile(artifact, "fixture");
  await writeFile(
    provider,
    "#!/usr/bin/env node\nprocess.stdout.write('captured-environment-provider');\n",
  );
  await chmod(provider, 0o755);

  const session = createTestBinarySession(() => {
    throw new Error("No binary analysis provider should start");
  });
  const server = createServer(
    { kind: "session", session },
    {
      environment: {
        REA_RIZIN_COMMAND: provider,
      },
    },
  );
  const client = new Client({ name: "reverse-provider-environment", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
    await rm(directory, { recursive: true, force: true });
  });

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const response = await client.callTool({
    name: "execute_rizin_command",
    arguments: { path: artifact, command: "iI" },
  });

  expect(response.isError).not.toBe(true);
  expect(JSON.stringify(response.structuredContent)).toContain(
    "captured-environment-provider",
  );
});

it("prefers an explicit provider environment over the captured server environment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-provider-override-"));
  const configured = join(directory, "captured-rizin");
  const override = join(directory, "override-rizin");
  const artifact = join(directory, "fixture.bin");
  await writeFile(artifact, "fixture");
  for (const [path, output] of [
    [configured, "captured"],
    [override, "explicit-override"],
  ] as const) {
    await writeFile(
      path,
      `#!/usr/bin/env node\nprocess.stdout.write('${output}');\n`,
    );
    await chmod(path, 0o755);
  }
  const session = createTestBinarySession(() => {
    throw new Error("No binary analysis provider should start");
  });
  const server = createServer(
    { kind: "session", session },
    {
      environment: { REA_RIZIN_COMMAND: configured },
      providerEnvironment: { REA_RIZIN_COMMAND: override },
    },
  );
  const client = new Client({ name: "reverse-provider-override", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
    await rm(directory, { recursive: true, force: true });
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const response = await client.callTool({
    name: "execute_rizin_command",
    arguments: { path: artifact, command: "iI" },
  });
  expect(response.isError).not.toBe(true);
  expect(JSON.stringify(response.structuredContent)).toContain("explicit-override");
  expect(JSON.stringify(response.structuredContent)).not.toContain('"captured"');
});

it("snapshots an explicit provider environment when the server is created", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-provider-snapshot-"));
  const configured = join(directory, "captured-rizin");
  const override = join(directory, "explicit-rizin");
  const artifact = join(directory, "fixture.bin");
  await writeFile(artifact, "fixture");
  for (const [path, output] of [
    [configured, "captured"],
    [override, "explicit-snapshot"],
  ] as const) {
    await writeFile(
      path,
      `#!/usr/bin/env node\nprocess.stdout.write('${output}');\n`,
    );
    await chmod(path, 0o755);
  }
  const providerEnvironment = { REA_RIZIN_COMMAND: override };
  const session = createTestBinarySession(() => {
    throw new Error("No binary analysis provider should start");
  });
  const server = createServer(
    { kind: "session", session },
    {
      environment: { REA_RIZIN_COMMAND: configured },
      providerEnvironment,
    },
  );
  providerEnvironment.REA_RIZIN_COMMAND = configured;
  const client = new Client({ name: "reverse-provider-snapshot", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
    await rm(directory, { recursive: true, force: true });
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const response = await client.callTool({
    name: "execute_rizin_command",
    arguments: { path: artifact, command: "iI" },
  });
  expect(response.isError).not.toBe(true);
  expect(JSON.stringify(response.structuredContent)).toContain(
    "explicit-snapshot",
  );
  expect(JSON.stringify(response.structuredContent)).not.toContain('"captured"');
});
