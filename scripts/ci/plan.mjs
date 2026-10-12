import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { matchesGlob } from "node:path";
import { SCOPES } from "./scopes.mjs";

const flags = [
  "code",
  "reverse_tools",
  "runtime",
  "package",
  "apple",
  "fixtures",
  "readiness",
  "docs",
  "workflows",
  ...Object.keys(SCOPES),
];
// Actionlint validates workflow syntax only. The semantic suite asserts these
// workflows' release, publication and self-hosted runner safeguards.
const GUARDED_WORKFLOWS = new Set([
  ".github/workflows/release.yml",
  ".github/workflows/real-ghidra-windows.yml",
]);
// Sources compiled by build-conformance-fixtures.mjs. The readiness journey
// analyzes the built C fixture as well as its own applications.
const FIXTURE_SOURCES = [
  "tests/conformance/c/**",
  "tests/conformance/napi/**",
  "tests/conformance/objc/**",
  "tests/conformance/swift/**",
  "tests/conformance/versions/**",
];
const READINESS_SOURCES = ["tests/conformance/readiness/**"];
const REVERSE_TOOL_SOURCES = [
  "src/application/reverse/**",
  "src/cutter/**",
  "src/gdb/**",
  "src/objdump/**",
  "src/process/ownedDebuggerSession.ts",
  "src/rizin/**",
  "src/contracts/*ToolContracts.ts",
  "src/server/registerCutterTools.ts",
  "src/server/registerGdbTools.ts",
  "src/server/registerReverseEngineeringTools.ts",
  "src/server/providerEnvironment.ts",
  "src/process/ExecFileOutput.ts",
  "src/process/ExecFileOutput.test.ts",
  "tests/boundary/providers/DebuggerSessionManagers.test.ts",
  "tests/boundary/providers/DebuggerSessionReviewRegressions.test.ts",
  "tests/boundary/providers/RizinDebugSessionCoverage.test.ts",
  "src/server/registerRizinDebugTools.ts",
  "tests/boundary/providers/CutterBridge*.test.ts",
  "tests/boundary/providers/GdbSession*.test.ts",
  "tests/boundary/providers/RizinDebugSessionCoverage.part*.test.ts",
  "tests/boundary/providers/RizinCommandTimeout.test.ts",
  "tests/boundary/providers/RizinTimeoutEvidence.test.ts",
  "tests/boundary/providers/RizinDebugSession*.test.ts",
  "tests/boundary/process/ownedDebuggerSession.test.ts",
  "tests/boundary/mcp/cutter*.test.ts",
  "tests/boundary/mcp/gdbCancellationMcp.test.ts",
  "tests/boundary/mcp/debuggerCancellationMcp.test.ts",
  "tests/boundary/mcp/rizinDebuggerCancellationMcp.test.ts",
  "tests/boundary/mcp/reverseEngineeringPartialMcp.test.ts",
  "tests/boundary/mcp/reverseEngineeringEnvironmentMcp.test.ts",
  "tests/processOwnershipRunner.ts",
  "tests/composition/reverseEngineering*.test.ts",
  "vitest.reverse-tools.config.ts",
  "vitest.reverse-tools-semantics.config.ts",
  "stryker.config.json",
  "stryker.semantics.config.json",
  "tsconfig.reverse-tools-mutation.json",
  "vitest.timeout.config.ts",
  "scripts/prepare-reverse-tools-mutation.mjs",
];
const matchesAny = (file, patterns) =>
  patterns.some((pattern) => matchesGlob(file, pattern));
const selected = Object.fromEntries(flags.map((flag) => [flag, false]));
const reasons = [];
const full = (reason) => {
  for (const flag of flags) selected[flag] = true;
  reasons.push(reason);
};
const git = (...args) =>
  execFileSync("git", args, { encoding: "utf8" }).trimEnd();
function classifyPackage(base, head) {
  const before = JSON.parse(git("show", `${base}:package.json`));
  const after = JSON.parse(git("show", `${head}:package.json`));
  const { scripts: beforeScripts, ...beforeRest } = before;
  const { scripts: afterScripts, ...afterRest } = after;
  if (JSON.stringify(beforeRest) !== JSON.stringify(afterRest)) {
    full("Package metadata or dependencies changed");
    return;
  }
  selected.code = true;
  const changed = [
    ...new Set([
      ...Object.keys(beforeScripts ?? {}),
      ...Object.keys(afterScripts ?? {}),
    ]),
  ].filter((key) => beforeScripts?.[key] !== afterScripts?.[key]);
  for (const script of changed) {
    if (/^test:(coverage|mutation):reverse-tools$/.test(script))
      selected.reverse_tools = true;
    if (
      /^(test(?::|$)|check(?::|$)|lint(?::|$)|format(?::|$)|knip$|jscpd$)/.test(
        script,
      )
    )
      continue;
    if (
      ["compile:termux", "build:termux", "build:termux:run"].includes(script)
    ) {
      selected.workflows = true;
      reasons.push(
        `Android build script changed; real Android verification remains manual: ${script}`,
      );
      continue;
    }
    // Verify scripts own provider setup as well as execution. Reuse their
    // existing source-file ownership rather than maintaining a second map.
    const entrypoint = (command) =>
      /^(?:npm run build:cached && )?node (scripts\/[\w/-]+\.mjs)(?: [\w./=-]+)*$/.exec(
        command ?? "",
      )?.[1];
    const beforeEntry = entrypoint(beforeScripts?.[script]);
    const afterEntry = entrypoint(afterScripts?.[script]);
    const entries = [beforeEntry, afterEntry].filter(Boolean);
    const simple =
      (!beforeScripts?.[script] || beforeEntry) &&
      (!afterScripts?.[script] || afterEntry);
    const scriptOwners =
      simple &&
      entries.every((entry) =>
        Object.values(SCOPES).some((patterns) => patterns.includes(entry)),
      )
        ? Object.entries(SCOPES)
            .filter(([, patterns]) =>
              entries.some((entry) => patterns.includes(entry)),
            )
            .map(([owner]) => owner)
        : [];
    if (scriptOwners.length)
      for (const owner of scriptOwners) selected[owner] = true;
    else full(`Shared or unknown package script: ${script}`);
  }
}

const event = process.env.GITHUB_EVENT_NAME;
let files = [];
if (
  event === "push" ||
  event === "schedule" ||
  event === "workflow_dispatch" ||
  process.env.CI_FULL === "true"
) {
  full("Full baseline requested by event or ci:full label");
} else if (event === "pull_request") {
  const base = git("merge-base", process.env.BASE_SHA, process.env.HEAD_SHA);
  const head = process.env.HEAD_SHA;
  // Disable rename detection so both the removed and added paths participate.
  files = git("diff", "--name-only", "--no-renames", "-z", base, head)
    .split("\0")
    .filter(Boolean);
  for (const file of files) {
    if (matchesAny(file, REVERSE_TOOL_SOURCES)) selected.reverse_tools = true;
    if (
      /^(README(?:_[^/]+)?\.md|AGENTS\.md|CONTRIBUTING\.md)$/.test(file) ||
      file.startsWith("docs/")
    ) {
      selected.docs = true;
      selected.website ||= matchesAny(file, SCOPES.website);
      continue;
    }
    if (/^(src|tests)\/.*\.(?:test|spec)\.[cm]?[jt]sx?$/.test(file)) {
      selected.code = true;
      continue;
    }
    const owners = Object.entries(SCOPES)
      .filter(([, patterns]) =>
        patterns.some((pattern) => matchesGlob(file, pattern)),
      )
      .map(([owner]) => owner);
    for (const owner of owners) selected[owner] = true;
    if (
      file.startsWith(".github/workflows/") ||
      file === ".github/actionlint.yaml"
    ) {
      selected.workflows = true;
      if (GUARDED_WORKFLOWS.has(file)) selected.code = true;
      if (file !== ".github/workflows/ci.yml") continue;
    }
    if (owners.length === 1 && owners[0] === "website") continue;
    if (/^src\/(contracts|domain)\//.test(file)) selected.docs = true;
    if (file === "package.json") {
      classifyPackage(base, head);
      continue;
    }
    selected.code = true;
    if (matchesAny(file, FIXTURE_SOURCES)) {
      selected.fixtures = true;
      selected.readiness = true;
    }
    if (matchesAny(file, READINESS_SOURCES)) selected.readiness = true;
    if (file.startsWith("tests/")) continue;
    if (
      /^(src\/process\/|src\/filesystem\/|src\/contracts\/tool|src\/server\/createServer|src\/cli\.ts|scripts\/ci\/)/.test(
        file,
      )
    ) {
      full(`Shared boundary: ${file}`);
    } else if (owners.length) {
      if (file.startsWith("src/") || file.startsWith("bridge/"))
        selected.runtime = true;
    } else {
      full(`Unclassified input: ${file}`);
    }
  }
} else throw new Error(`Unsupported CI event: ${event}`);
selected.runtime ||= selected.package;
const linux = { os: "ubuntu-latest", platform: "linux", architecture: "x64" };
const matrix = {
  include: selected.package
    ? [
        linux,
        { os: "ubuntu-24.04-arm", platform: "linux", architecture: "arm64" },
        { os: "macos-15", platform: "darwin", architecture: "arm64" },
        { os: "macos-15-intel", platform: "darwin", architecture: "x64" },
      ]
    : [linux],
};
const plan = { ...selected, matrix, files, reasons };
if (process.env.GITHUB_OUTPUT)
  appendFileSync(
    process.env.GITHUB_OUTPUT,
    Object.entries({ ...selected, matrix: JSON.stringify(matrix) })
      .map(([key, value]) => `${key}=${value}\n`)
      .join(""),
  );
if (process.env.GITHUB_STEP_SUMMARY)
  appendFileSync(
    process.env.GITHUB_STEP_SUMMARY,
    `### Selected CI lanes\n\n${flags.filter((flag) => selected[flag]).join(", ") || "Formatting only"}\n\n${reasons.join("\n\n")}\n`,
  );
console.log(JSON.stringify(plan));
