import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { TOOL_CONTRACTS } from "../../dist/contracts/toolContracts.js";

/**
 * Real-model clients the agent evaluation can drive. Each one runs in an
 * isolated home configured only through public `rea setup`; only the caller's
 * authentication is reused.
 */
const CLIENTS = {
  codex: {
    setupClient: "codex",
    commandVariable: "REA_CODEX_CLI",
    defaultCommand: "codex",
  },
  "claude-code": {
    setupClient: "claude_code",
    commandVariable: "REA_VERIFY_CLAUDE_COMMAND",
    defaultCommand: "claude",
  },
  "gemini-cli": {
    setupClient: "gemini_cli",
    commandVariable: "REA_VERIFY_GEMINI_COMMAND",
    defaultCommand: "gemini",
  },
};

const SKILL = "reverse-engineer-anything";

/** Resolve `REA_AGENT_EVAL_CLIENT`; Codex remains the default. */
export const selectAgentEvalClient = (value = "codex") => {
  const client = Object.hasOwn(CLIENTS, value) ? CLIENTS[value] : undefined;
  if (client === undefined)
    throw new Error(
      `REA_AGENT_EVAL_CLIENT must be one of ${Object.keys(CLIENTS).join(", ")}`,
    );
  return {
    id: value,
    ...client,
    command: process.env[client.commandVariable] ?? client.defaultCommand,
  };
};

/**
 * REA tools a non-Codex client may run without a scenario approval: tools
 * whose audited annotations are read-only, or neither destructive nor open
 * world. Other tools are refused unless the scenario approves them by name.
 */
const allowedTools = (approvedTools) => [
  ...new Set([
    ...TOOL_CONTRACTS.filter(
      ({ annotations }) =>
        annotations.readOnlyHint ||
        !(annotations.destructiveHint || annotations.openWorldHint),
    ).map(({ name }) => name),
    ...approvedTools,
  ]),
];

const modelArguments = (model) =>
  model === undefined ? [] : ["--model", model];

const apiKey = (name) =>
  process.env[name] === undefined ? {} : { [name]: process.env[name] };

/** Copy one credential file; a missing file leaves environment authentication. */
const copyAuthentication = async (source, destination) => {
  try {
    await copyFile(source, destination);
    await chmod(destination, 0o600);
    return [destination];
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
    return [];
  }
};

const prepareCodex = async (profile, { evaluationRoot, account, model }) => {
  const authPaths = await copyAuthentication(
    join(process.env.CODEX_HOME ?? join(homedir(), ".codex"), "auth.json"),
    join(profile, "auth.json"),
  );
  await writeFile(
    join(profile, "config.toml"),
    'approval_policy = "never"\nsandbox_mode = "read-only"\nweb_search = "disabled"\n[features]\nmulti_agent = false\nshell_snapshot = false\n[history]\npersistence = "none"\n',
    { mode: 0o600 },
  );
  return {
    environment: { CODEX_HOME: profile },
    authPaths,
    // Codex has no own skill path and reads the shared agent skill root.
    skillDirectory: join(account, ".agents/skills", SKILL),
    arguments: (prompt, approvedTools) => [
      "--no-daemon",
      "exec",
      "--ephemeral",
      "--skip-git-repo-check",
      "--sandbox",
      "read-only",
      "--json",
      "--color",
      "never",
      "-C",
      evaluationRoot,
      "-c",
      'approval_policy="never"',
      ...approvedTools.flatMap((name) => [
        "-c",
        `mcp_servers.rea.tools.${name}.approval_mode="approve"`,
      ]),
      ...modelArguments(model),
      prompt,
    ],
  };
};

const prepareClaudeCode = async (profile, { model }) => ({
  environment: {
    CLAUDE_CONFIG_DIR: profile,
    DISABLE_AUTOUPDATER: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    // Account-level claude.ai connectors are user configuration.
    ENABLE_CLAUDEAI_MCP_SERVERS: "false",
    ...apiKey("ANTHROPIC_API_KEY"),
  },
  authPaths: await copyAuthentication(
    join(
      process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"),
      ".credentials.json",
    ),
    join(profile, ".credentials.json"),
  ),
  skillDirectory: join(profile, "skills", SKILL),
  arguments: (prompt, approvedTools) => [
    "--print",
    "--output-format",
    "stream-json",
    "--verbose",
    "--no-session-persistence",
    "--setting-sources",
    "user",
    // Read-only built-ins match the Codex read-only sandbox: no shell, edits,
    // web access, or subagents.
    "--tools",
    "Read,Grep,Glob,Skill,ToolSearch",
    "--permission-mode",
    "dontAsk",
    "--settings",
    JSON.stringify({
      permissions: {
        allow: [
          "Skill",
          ...allowedTools(approvedTools).map((name) => `mcp__rea__${name}`),
        ],
      },
    }),
    ...modelArguments(model),
    prompt,
  ],
});

const geminiSettings = (selectedType) => ({
  security: { auth: { selectedType } },
  privacy: { usageStatisticsEnabled: false },
  telemetry: { enabled: false },
});

/**
 * Reuse only the caller's selected authentication type. Gemini CLI can keep
 * the credential itself outside its settings directory, such as an API key in
 * the OS keychain.
 */
const callerGeminiAuthType = async (geminiDirectory) => {
  try {
    const settings = JSON.parse(
      await readFile(join(geminiDirectory, "settings.json"), "utf8"),
    );
    const selected = settings?.security?.auth?.selectedType;
    return typeof selected === "string" ? selected : undefined;
  } catch (cause) {
    if (cause?.code === "ENOENT" || cause instanceof SyntaxError)
      return undefined;
    throw cause;
  }
};

const prepareGeminiCli = async (profile, { model }) => {
  const gemini = join(profile, ".gemini");
  await mkdir(gemini, { mode: 0o700 });
  const callerGemini = join(
    process.env.GEMINI_CLI_HOME ?? homedir(),
    ".gemini",
  );
  const authPaths = await copyAuthentication(
    join(callerGemini, "oauth_creds.json"),
    join(gemini, "oauth_creds.json"),
  );
  let authType = "oauth-personal";
  if (process.env.GEMINI_API_KEY !== undefined) authType = "gemini-api-key";
  else if (authPaths.length === 0)
    authType = (await callerGeminiAuthType(callerGemini)) ?? authType;
  const empty = join(profile, "empty-settings.json");
  const policy = join(profile, "rea-evaluation-policy.toml");
  await writeFile(empty, "{}\n", { mode: 0o600 });
  await writeFile(
    join(gemini, "settings.json"),
    `${JSON.stringify(geminiSettings(authType), null, 2)}\n`,
    { mode: 0o600 },
  );
  return {
    environment: {
      GEMINI_CLI_HOME: profile,
      GEMINI_CLI_SYSTEM_SETTINGS_PATH: empty,
      GEMINI_CLI_SYSTEM_DEFAULTS_PATH: empty,
      GEMINI_CLI_NO_RELAUNCH: "1",
      GEMINI_CLI_TRUST_WORKSPACE: "true",
      ...apiKey("GEMINI_API_KEY"),
    },
    authPaths,
    skillDirectory: join(profile, ".agents/skills", SKILL),
    arguments: async (prompt, approvedTools) => {
      await writeFile(
        policy,
        [
          // Headless mode otherwise refuses skill activation, which the
          // installed REA skill needs; Claude Code allows `Skill` likewise.
          '[[rule]]\ntoolName = "activate_skill"\ndecision = "allow"\npriority = 100\n',
          ...allowedTools(approvedTools).map(
            (name) =>
              `[[rule]]\nmcpName = "rea"\ntoolName = "${name}"\ndecision = "allow"\npriority = 100\n`,
          ),
        ].join("\n"),
        { mode: 0o600 },
      );
      return [
        // Headless default mode refuses shell and edit tools needing approval.
        "--approval-mode",
        "default",
        "--policy",
        policy,
        "--allowed-mcp-server-names",
        "rea",
        "--output-format",
        "stream-json",
        ...modelArguments(model),
        "--prompt",
        prompt,
      ];
    },
  };
};

const PREPARERS = {
  codex: prepareCodex,
  "claude-code": prepareClaudeCode,
  "gemini-cli": prepareGeminiCli,
};

/**
 * Prepare one client's isolated profile below `evaluationRoot`. Returns the
 * environment additions, copied credential files to remove after the run,
 * the installed skill directory, and the client's spawn arguments.
 */
export const prepareAgentEvalClient = async (client, options) => {
  const profile = join(options.evaluationRoot, client.id);
  await mkdir(profile, { mode: 0o700 });
  return PREPARERS[client.id](profile, options);
};
