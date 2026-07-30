import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import http from "node:http";
import { arch, platform, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const claudeExecutable =
  process.env.SECURE_ONBOARD_CLAUDE_BIN ??
  "/Users/kimchanhyung98/.local/share/claude/versions/2.1.220";
const codexExecutable =
  process.env.SECURE_ONBOARD_CODEX_BIN ?? "/opt/homebrew/bin/codex";
const nodeExecutable =
  process.env.SECURE_ONBOARD_NODE_BIN ??
  "/opt/homebrew/Cellar/node/26.5.0/bin/node";
const targetHelper = join(
  repositoryRoot,
  "tests/fixtures/m0/helpers/m0-target.mjs",
);
const runRoot = realpathSync(
  mkdtempSync(join(tmpdir(), "secure-onboard-adapter-fault-observations.")),
);
chmodSync(runRoot, 0o700);
const faultWorker = join(runRoot, "fault-adapter.mjs");
const wholeChildTimeoutMs = 20_000;
const declaredHookTimeoutSeconds = 1;
const maximumChildOutputBytes = 16 * 1024 * 1024;

const commonCases = [
  ["T05-D", "spawn-failure"],
  ["T05-E", "signal-crash"],
  ["T05-F", "timeout"],
  ["T05-G", "malformed-stdout"],
  ["T05-I", "exit-1"],
  ["T05-J", "exit-2-stderr"],
  ["T05-K", "exit-2-invalid-json"],
];
const codexOnlyCases = [["T05-H-Codex", "unsupported-ask"]];

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
  });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`,
  );
  return result.stdout.trim();
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function exactBytes(buffer) {
  const decoded = buffer.toString("utf8");
  return {
    length: buffer.length,
    sha256: sha256(buffer),
    base64: buffer.toString("base64"),
    utf8: Buffer.from(decoded, "utf8").equals(buffer) ? decoded : null,
  };
}

function writeExact(path, buffer) {
  writeFileSync(path, buffer, { mode: 0o600 });
  return {
    path,
    ...exactBytes(buffer),
  };
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

async function listen(server) {
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return server.address().port;
}

async function closeServer(server) {
  server.closeAllConnections?.();
  await new Promise((resolveClose, reject) => {
    server.close((error) => (error ? reject(error) : resolveClose()));
  });
}

function streamEvents(response, events) {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  for (const event of events) {
    response.write(`event: ${event.type}\n`);
    response.write(`data: ${JSON.stringify(event)}\n\n`);
  }
  response.end();
}

function claudeToolEvents(command) {
  return [
    {
      type: "message_start",
      message: {
        id: "msg_secure_onboard_fault_tool",
        type: "message",
        role: "assistant",
        model: "claude-sonnet-4-5-20250929",
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 0 },
      },
    },
    {
      type: "content_block_start",
      index: 0,
      content_block: {
        type: "tool_use",
        id: "toolu_secure_onboard_fault",
        name: "Bash",
        input: {},
      },
    },
    {
      type: "content_block_delta",
      index: 0,
      delta: {
        type: "input_json_delta",
        partial_json: JSON.stringify({
          command,
          description: "Secure Onboard adapter fault observation",
        }),
      },
    },
    { type: "content_block_stop", index: 0 },
    {
      type: "message_delta",
      delta: { stop_reason: "tool_use", stop_sequence: null },
      usage: { output_tokens: 1 },
    },
    { type: "message_stop" },
  ];
}

function claudeFinalEvents() {
  return [
    {
      type: "message_start",
      message: {
        id: "msg_secure_onboard_fault_done",
        type: "message",
        role: "assistant",
        model: "claude-sonnet-4-5-20250929",
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 0 },
      },
    },
    {
      type: "content_block_start",
      index: 0,
      content_block: { type: "text", text: "" },
    },
    {
      type: "content_block_delta",
      index: 0,
      delta: { type: "text_delta", text: "fault observation complete" },
    },
    { type: "content_block_stop", index: 0 },
    {
      type: "message_delta",
      delta: { stop_reason: "end_turn", stop_sequence: null },
      usage: { output_tokens: 1 },
    },
    { type: "message_stop" },
  ];
}

function claudeHasToolResult(body) {
  try {
    return JSON.parse(body).messages.some(
      (message) =>
        Array.isArray(message.content) &&
        message.content.some((content) => content.type === "tool_result"),
    );
  } catch {
    return false;
  }
}

function codexResponseEvents(item, responseId) {
  return [
    {
      type: "response.output_item.done",
      sequence_number: 0,
      output_index: 0,
      item,
    },
    {
      type: "response.completed",
      sequence_number: 1,
      response: {
        id: responseId,
        object: "response",
        created_at: Math.floor(Date.now() / 1000),
        status: "completed",
        output: [item],
        error: null,
        incomplete_details: null,
        usage: {
          input_tokens: 1,
          input_tokens_details: { cached_tokens: 0 },
          output_tokens: 1,
          output_tokens_details: { reasoning_tokens: 0 },
          total_tokens: 2,
        },
      },
    },
  ];
}

function startMockApi(client, command) {
  const requests = [];
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks);
      requests.push({
        method: request.method,
        url: request.url,
        body: exactBytes(body),
      });
      if (client === "claude") {
        streamEvents(
          response,
          claudeHasToolResult(body.toString("utf8"))
            ? claudeFinalEvents()
            : claudeToolEvents(command),
        );
        return;
      }
      const hasToolOutput = body.includes(
        Buffer.from('"type":"function_call_output"'),
      );
      const item = hasToolOutput
        ? {
            id: "msg_secure_onboard_fault_done",
            type: "message",
            status: "completed",
            role: "assistant",
            content: [
              {
                type: "output_text",
                text: "fault observation complete",
                annotations: [],
              },
            ],
          }
        : {
            id: "fc_secure_onboard_fault",
            type: "function_call",
            status: "completed",
            name: "exec_command",
            call_id: "call_secure_onboard_fault",
            arguments: JSON.stringify({
              cmd: command,
              workdir: repositoryRoot,
              yield_time_ms: 10_000,
              max_output_tokens: 1_000,
            }),
          };
      streamEvents(
        response,
        codexResponseEvents(
          item,
          hasToolOutput
            ? "resp_secure_onboard_fault_done"
            : "resp_secure_onboard_fault_tool",
        ),
      );
    });
  });
  return { server, requests };
}

function startProxyTrap() {
  const attempts = [];
  const server = http.createServer((request, response) => {
    attempts.push({ method: request.method, url: request.url });
    response.writeHead(502, { "content-type": "text/plain" });
    response.end("external egress rejected");
  });
  server.on("connect", (request, socket) => {
    attempts.push({ method: "CONNECT", url: request.url });
    socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
  });
  return { server, attempts };
}

function spawnCaptured(command, args, options, timeoutMs) {
  return new Promise((resolveChild) => {
    const started = process.hrtime.bigint();
    const { input, ...spawnOptions } = options;
    const child = spawn(command, args, {
      ...spawnOptions,
      detached: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let spawnError = null;
    let timedOut = false;
    let settled = false;
    let outputLimitExceeded = false;
    let capturedOutputBytes = 0;
    let forceSettlement;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceSettlement);
      resolveChild(result);
    };
    const terminateProcessGroup = () => {
      if (forceSettlement !== undefined) return;
      forceSettlement = setTimeout(() => {
        settle({
          status: null,
          signal: "SIGKILL",
          timed_out: timedOut,
          output_limit_exceeded: outputLimitExceeded,
          elapsed_ms: Number(process.hrtime.bigint() - started) / 1_000_000,
          spawn_error: spawnError,
          stdout: Buffer.concat(stdout),
          stderr: Buffer.concat(stderr),
        });
      }, 2_000);
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const capture = (target, chunk) => {
      if (outputLimitExceeded) return;
      capturedOutputBytes += chunk.length;
      if (capturedOutputBytes > maximumChildOutputBytes) {
        outputLimitExceeded = true;
        terminateProcessGroup();
        return;
      }
      target.push(chunk);
    };
    child.stdout?.on("data", (chunk) => capture(stdout, chunk));
    child.stderr?.on("data", (chunk) => capture(stderr, chunk));
    child.on("error", (error) => {
      spawnError = {
        name: error.name,
        code: error.code ?? null,
        errno: error.errno ?? null,
        syscall: error.syscall ?? null,
        path: error.path ?? null,
        message: error.message,
      };
    });
    const timer = setTimeout(() => {
      timedOut = true;
      terminateProcessGroup();
    }, timeoutMs);
    child.on("close", (status, signal) => {
      settle({
        status,
        signal,
        timed_out: timedOut,
        output_limit_exceeded: outputLimitExceeded,
        elapsed_ms: Number(process.hrtime.bigint() - started) / 1_000_000,
        spawn_error: spawnError,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      });
    });
    if (input !== undefined && child.stdin) {
      child.stdin.end(input);
    } else {
      child.stdin?.end();
    }
  });
}

function writeFaultWorker() {
  writeFileSync(
    faultWorker,
    `import { appendFileSync } from "node:fs";

const [mode, logPath] = process.argv.slice(2);
let input = Buffer.alloc(0);
for await (const chunk of process.stdin) {
  input = Buffer.concat([input, chunk]);
}
appendFileSync(logPath, JSON.stringify({
  event: "started",
  mode,
  pid: process.pid,
  epoch_ms: Date.now(),
  input_base64: input.toString("base64")
}) + "\\n", { mode: 0o600 });

switch (mode) {
  case "signal-crash":
    appendFileSync(logPath, JSON.stringify({
      event: "before_signal",
      signal: "SIGKILL",
      epoch_ms: Date.now()
    }) + "\\n");
    process.stderr.write("adapter-crash\\n", () => {
      process.kill(process.pid, "SIGKILL");
    });
    break;
  case "timeout":
    process.stderr.write("adapter-timeout\\n");
    setInterval(() => {}, 60_000);
    break;
  case "malformed-stdout":
    process.stdout.write("MALFORMED\\n");
    break;
  case "unsupported-ask":
    process.stdout.write('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask"}}\\n');
    break;
  case "exit-1":
    process.stderr.write("adapter-exit-1\\n");
    process.exitCode = 1;
    break;
  case "exit-2-stderr":
    process.stderr.write("adapter-exit-2\\n");
    process.exitCode = 2;
    break;
  case "exit-2-invalid-json":
    process.stdout.write("{invalid-json\\n");
    process.stderr.write("adapter-exit-2-invalid-json\\n");
    process.exitCode = 2;
    break;
  default:
    process.stderr.write("unknown fault mode\\n");
    process.exitCode = 64;
}
`,
    { mode: 0o700 },
  );
}

async function characterizeAdapter(mode, caseRoot) {
  if (mode === "spawn-failure") {
    const missing = join(caseRoot, "missing-adapter");
    const result = await spawnCaptured(
      missing,
      [],
      { cwd: caseRoot, env: {} },
      1_000,
    );
    return {
      invocation: { executable: missing, argv: [] },
      status: result.status,
      signal: result.signal,
      timed_out: result.timed_out,
      output_limit_exceeded: result.output_limit_exceeded,
      spawn_error: result.spawn_error,
      stdout: exactBytes(result.stdout),
      stderr: exactBytes(result.stderr),
    };
  }
  const directLog = join(caseRoot, "direct-adapter.jsonl");
  const result = await spawnCaptured(
    nodeExecutable,
    [faultWorker, mode, directLog],
    {
      cwd: caseRoot,
      env: {
        PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      },
      input: Buffer.from("{}\n"),
    },
    mode === "timeout" ? 250 : 2_000,
  );
  return {
    invocation: {
      executable: nodeExecutable,
      argv: [faultWorker, mode, directLog],
    },
    status: result.status,
    signal: result.signal,
    timed_out: result.timed_out,
    output_limit_exceeded: result.output_limit_exceeded,
    spawn_error: result.spawn_error,
    stdout: exactBytes(result.stdout),
    stderr: exactBytes(result.stderr),
    side_log: existsSync(directLog)
      ? exactBytes(readFileSync(directLog))
      : exactBytes(Buffer.alloc(0)),
  };
}

function claudePlugin(caseRoot, mode, sideLog) {
  const pluginRoot = join(caseRoot, "plugin");
  mkdirSync(join(pluginRoot, ".claude-plugin"), { recursive: true });
  mkdirSync(join(pluginRoot, "hooks"), { recursive: true });
  const missing = join(caseRoot, "missing-adapter");
  const hook =
    mode === "spawn-failure"
      ? {
          type: "command",
          command: missing,
          timeout: declaredHookTimeoutSeconds,
        }
      : {
          type: "command",
          command: nodeExecutable,
          args: [faultWorker, mode, sideLog],
          timeout: declaredHookTimeoutSeconds,
        };
  writeFileSync(
    join(pluginRoot, ".claude-plugin/plugin.json"),
    `${JSON.stringify({
      name: `secure-onboard-${mode}`,
      version: "0.0.0",
      description: "Synthetic adapter fault observation only",
    })}\n`,
  );
  const config = Buffer.from(
    `${JSON.stringify(
      {
        description: "Synthetic adapter fault observation only",
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [hook],
            },
          ],
        },
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(join(pluginRoot, "hooks/hooks.json"), config);
  return { pluginRoot, config, invocation: hook };
}

function codexProject(caseRoot, mode, sideLog) {
  const projectRoot = join(caseRoot, "project");
  mkdirSync(join(projectRoot, ".codex"), { recursive: true });
  const missing = join(caseRoot, "missing-adapter");
  const command =
    mode === "spawn-failure"
      ? shellQuote(missing)
      : [
          "exec",
          shellQuote(nodeExecutable),
          shellQuote(faultWorker),
          shellQuote(mode),
          shellQuote(sideLog),
        ].join(" ");
  const hook = {
    type: "command",
    command,
    timeout: declaredHookTimeoutSeconds,
  };
  const config = Buffer.from(
    `${JSON.stringify(
      {
        description: "Synthetic adapter fault observation only",
        hooks: {
          PreToolUse: [
            {
              matcher: "^Bash$",
              hooks: [hook],
            },
          ],
        },
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(join(projectRoot, ".codex/hooks.json"), config);
  return { projectRoot, config, invocation: hook };
}

function codexConfig(codexHome, apiPort) {
  mkdirSync(codexHome, { recursive: true });
  writeFileSync(
    join(codexHome, "config.toml"),
    `model = "mock-model"
model_provider = "localmock"
approval_policy = "never"
sandbox_mode = "read-only"
web_search = "disabled"
check_for_update_on_startup = false

[analytics]
enabled = false

[feedback]
enabled = false

[features]
apps = false
auth_elicitation = false
browser_use = false
browser_use_external = false
browser_use_full_cdp_access = false
computer_use = false
guardian_approval = false
image_generation = false
in_app_browser = false
multi_agent = false
plugin_sharing = false
plugins = false
remote_compaction_v2 = false
remote_plugin = false
skill_mcp_dependency_install = false
skill_search = false
tool_call_mcp_elicitation = false
tool_suggest = false
workspace_dependencies = false

[model_providers.localmock]
name = "Local mock"
base_url = "http://127.0.0.1:${apiPort}/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
stream_idle_timeout_ms = 5000
`,
  );
}

function diagnosticLines(buffer) {
  return buffer
    .toString("utf8")
    .split("\n")
    .filter((line) =>
      /hook|adapter|PreToolUse|timeout|timed out|failed|error|exit code/i.test(
        line,
      ),
    );
}

async function runNative({
  client,
  caseId,
  mode,
  control = false,
  apiPort,
  proxyPort,
  caseRoot,
}) {
  const marker = join(caseRoot, "target.marker");
  const sideLog = join(caseRoot, "adapter.jsonl");
  let args;
  let env;
  let config = Buffer.alloc(0);
  let invocation = null;
  if (client === "claude") {
    const configDirectory = join(caseRoot, "claude-config");
    mkdirSync(configDirectory, { recursive: true });
    let pluginRoot = null;
    if (!control) {
      const plugin = claudePlugin(caseRoot, mode, sideLog);
      pluginRoot = plugin.pluginRoot;
      config = plugin.config;
      invocation = plugin.invocation;
    }
    args = [
      "--print",
      "--verbose",
      "--output-format",
      "stream-json",
      "--include-hook-events",
      "--permission-mode",
      "bypassPermissions",
      ...(pluginRoot === null ? [] : ["--plugin-dir", pluginRoot]),
      "--tools",
      "Bash",
    ];
    env = {
      PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      TMPDIR: runRoot,
      CLAUDE_CONFIG_DIR: configDirectory,
      ANTHROPIC_API_KEY: "local-adapter-fault-key",
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${apiPort}`,
      DISABLE_TELEMETRY: "1",
      DISABLE_AUTOUPDATER: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      CLAUDE_CODE_ENABLE_TELEMETRY: "0",
    };
  } else {
    const codexHome = join(caseRoot, "codex-home");
    let projectRoot = join(caseRoot, "project");
    if (control) {
      mkdirSync(projectRoot, { recursive: true });
    } else {
      const project = codexProject(caseRoot, mode, sideLog);
      projectRoot = project.projectRoot;
      config = project.config;
      invocation = project.invocation;
    }
    codexConfig(codexHome, apiPort);
    args = [
      "exec",
      "--ephemeral",
      "--skip-git-repo-check",
      "--dangerously-bypass-approvals-and-sandbox",
      "--dangerously-bypass-hook-trust",
      "--ignore-rules",
      "-C",
      projectRoot,
      "--strict-config",
      "--json",
      "Run the single supplied adapter fault observation command.",
    ];
    env = {
      PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      CODEX_HOME: codexHome,
      TMPDIR: runRoot,
    };
  }
  Object.assign(env, {
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
    HTTP_PROXY: `http://127.0.0.1:${proxyPort}`,
    HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
    ALL_PROXY: `http://127.0.0.1:${proxyPort}`,
    http_proxy: `http://127.0.0.1:${proxyPort}`,
    https_proxy: `http://127.0.0.1:${proxyPort}`,
    all_proxy: `http://127.0.0.1:${proxyPort}`,
  });
  const executable =
    client === "claude" ? claudeExecutable : codexExecutable;
  const result = await spawnCaptured(
    executable,
    args,
    {
      cwd: caseRoot,
      env,
      input:
        client === "claude"
          ? Buffer.from("Run the supplied command exactly once.\n")
          : undefined,
    },
    wholeChildTimeoutMs,
  );
  const stdoutEvidence = writeExact(
    join(caseRoot, "client-stdout.bin"),
    result.stdout,
  );
  const stderrEvidence = writeExact(
    join(caseRoot, "client-stderr.bin"),
    result.stderr,
  );
  const sideLogBuffer = existsSync(sideLog)
    ? readFileSync(sideLog)
    : Buffer.alloc(0);
  const hookStartedAt = sideLogBuffer.length
    ? JSON.parse(sideLogBuffer.toString("utf8").split("\n")[0]).epoch_ms
    : null;
  const targetStartedAt = existsSync(marker) ? statSync(marker).mtimeMs : null;
  return {
    case_id: caseId,
    mode,
    control,
    hook_config: exactBytes(config),
    hook_invocation: invocation,
    declared_hook_timeout_seconds:
      control || mode !== "timeout" ? null : declaredHookTimeoutSeconds,
    whole_child_timeout_ms: wholeChildTimeoutMs,
    client_status: result.status,
    client_signal: result.signal,
    whole_child_timed_out: result.timed_out,
    whole_child_output_limit_exceeded: result.output_limit_exceeded,
    client_spawn_error: result.spawn_error,
    client_elapsed_ms: result.elapsed_ms,
    client_stdout: stdoutEvidence,
    client_stderr: stderrEvidence,
    client_diagnostic_lines: [
      ...diagnosticLines(result.stdout).map((line) => ({
        stream: "stdout",
        line,
      })),
      ...diagnosticLines(result.stderr).map((line) => ({
        stream: "stderr",
        line,
      })),
    ],
    adapter_side_log: exactBytes(sideLogBuffer),
    target_marker_exists: existsSync(marker),
    target_marker_after_hook_start_ms:
      hookStartedAt === null || targetStartedAt === null
        ? null
        : targetStartedAt - hookStartedAt,
    target_process_started: null,
    target_process_observer: "unavailable_not_instrumented",
    approval_boundary:
      "unverified_noninteractive_bypass_mode_no_operator_approval",
    protection_claim: false,
  };
}

async function observe(client, caseId, mode) {
  const caseRoot = join(runRoot, client, caseId);
  mkdirSync(caseRoot, { recursive: true });
  const marker = join(caseRoot, "target.marker");
  rmSync(marker, { force: true });
  const targetCommand = [
    shellQuote(nodeExecutable),
    shellQuote(targetHelper),
    "info",
    shellQuote(marker),
  ].join(" ");
  const mock = startMockApi(client, targetCommand);
  const proxy = startProxyTrap();
  const apiPort = await listen(mock.server);
  const proxyPort = await listen(proxy.server);
  let result;
  try {
    result = await runNative({
      client,
      caseId,
      mode,
      apiPort,
      proxyPort,
      caseRoot,
    });
  } finally {
    await Promise.all([closeServer(mock.server), closeServer(proxy.server)]);
  }
  result.api_request_count = mock.requests.length;
  result.api_requests = mock.requests;
  result.proxy_egress_attempts = proxy.attempts;
  result.egress_trap_status =
    proxy.attempts.length === 0 ? "no_attempt_observed" : "attempts_trapped";
  result.adapter_direct_characterization = await characterizeAdapter(
    mode,
    caseRoot,
  );
  assert.equal(
    result.whole_child_timed_out,
    false,
    `${client} ${caseId}: whole CLI timed out`,
  );
  assert.equal(
    result.whole_child_output_limit_exceeded,
    false,
    `${client} ${caseId}: whole CLI exceeded the output limit`,
  );
  result.canonical_oracle_match = null;
  result.marker_only_observation =
    caseId === "T05-J" ? !result.target_marker_exists : null;
  writeFileSync(
    join(caseRoot, "observation.json"),
    `${JSON.stringify(result, null, 2)}\n`,
  );
  return result;
}

async function control(client) {
  const caseRoot = join(runRoot, client, "native-control");
  mkdirSync(caseRoot, { recursive: true });
  const marker = join(caseRoot, "target.marker");
  const targetCommand = [
    shellQuote(nodeExecutable),
    shellQuote(targetHelper),
    "info",
    shellQuote(marker),
  ].join(" ");
  const mock = startMockApi(client, targetCommand);
  const proxy = startProxyTrap();
  const apiPort = await listen(mock.server);
  const proxyPort = await listen(proxy.server);
  let result;
  try {
    result = await runNative({
      client,
      caseId: "native-control",
      mode: "plugin-off",
      control: true,
      apiPort,
      proxyPort,
      caseRoot,
    });
  } finally {
    await Promise.all([closeServer(mock.server), closeServer(proxy.server)]);
  }
  result.api_request_count = mock.requests.length;
  result.proxy_egress_attempts = proxy.attempts;
  result.egress_trap_status =
    proxy.attempts.length === 0 ? "no_attempt_observed" : "attempts_trapped";
  assert.equal(result.whole_child_timed_out, false);
  assert.equal(result.whole_child_output_limit_exceeded, false);
  assert.equal(
    result.target_marker_exists,
    true,
    `${client}: plugin-off bypass control target did not start`,
  );
  if (client === "claude") {
    assert.equal(
      result.client_diagnostic_lines.some(({ line }) =>
        line.includes('"subtype":"hook_started"'),
      ),
      false,
      "claude: plugin-off control loaded an unrelated hook",
    );
  }
  writeFileSync(
    join(caseRoot, "observation.json"),
    `${JSON.stringify(result, null, 2)}\n`,
  );
  return result;
}

assert.equal(platform(), "darwin", "native observation is macOS-only");
assert.equal(arch(), "arm64", "native observation is arm64-only");
for (const executable of [
  claudeExecutable,
  codexExecutable,
  nodeExecutable,
  targetHelper,
]) {
  assert.ok(existsSync(executable), `required executable missing: ${executable}`);
}
writeFaultWorker();

const clients = {
  claude: {
    executable: claudeExecutable,
    version: run(claudeExecutable, ["--version"]),
    control: await control("claude"),
    observations: [],
  },
  codex: {
    executable: codexExecutable,
    version: run(codexExecutable, ["--version"]),
    control: await control("codex"),
    observations: [],
  },
};
for (const [caseId, mode] of commonCases) {
  clients.claude.observations.push(await observe("claude", caseId, mode));
  clients.codex.observations.push(await observe("codex", caseId, mode));
}
for (const [caseId, mode] of codexOnlyCases) {
  clients.codex.observations.push(await observe("codex", caseId, mode));
}

const observationalFailures = [];
for (const [client, result] of Object.entries(clients)) {
  for (const observation of [result.control, ...result.observations]) {
    if (observation.proxy_egress_attempts.length > 0) {
      observationalFailures.push({
        client,
        case_id: observation.case_id,
        failure: "external_egress_attempted_and_trapped",
        attempts: observation.proxy_egress_attempts,
      });
    }
    if (observation.canonical_oracle_match === false) {
      observationalFailures.push({
        client,
        case_id: observation.case_id,
        failure: "canonical_oracle_mismatch",
      });
    }
  }
}

const summary = {
  schema_version: "m0-adapter-fault-observations/v1",
  run_root: runRoot,
  host: {
    platform: platform(),
    architecture: arch(),
    node_executable: nodeExecutable,
    node_version: run(nodeExecutable, ["--version"]),
  },
  network: {
    api: "localhost_mock_only",
    external_egress_proxy_trap: true,
    kernel_network_confinement:
      "unavailable_sandbox_exec_operation_not_permitted",
  },
  approval_boundary:
    "unverified_noninteractive_bypass_mode_no_operator_approval",
  interpretation:
    "Native fault observations only. No case is a Secure Onboard protection success claim.",
  observational_failures: observationalFailures,
  unsupported_or_unverified: [
    {
      case_id: "T05-H-Claude",
      status: "not_applicable",
      reason: "The canonical contract limits unsupported ask output to Codex.",
    },
    {
      case_id: "T05-D~K-interactive-approval",
      status: "unverified",
      reason:
        "No interactive operator approval was supplied; bypass mode only observes target reachability.",
    },
  ],
  clients,
};
const summaryPath = join(runRoot, "summary.json");
const summaryBytes = Buffer.from(`${JSON.stringify(summary, null, 2)}\n`);
writeFileSync(summaryPath, summaryBytes);
appendFileSync(
  join(runRoot, "README.txt"),
  `Exact observation summary: ${summaryPath}\n`,
);
process.stdout.write(
  `${JSON.stringify(
    {
      schema_version: "m0-adapter-fault-observation-run/v1",
      summary_path: summaryPath,
      summary_bytes: summaryBytes.length,
      summary_sha256: sha256(summaryBytes),
      observational_failures: observationalFailures,
    },
    null,
    2,
  )}\n`,
);
