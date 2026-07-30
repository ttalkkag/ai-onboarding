import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const nodeExecutable = "/opt/homebrew/Cellar/node/26.5.0/bin/node";
const claudeExecutable =
  process.env.SECURE_ONBOARD_CLAUDE_BIN ??
  "/Users/kimchanhyung98/.local/share/claude/versions/2.1.220";
const codexExecutable =
  process.env.SECURE_ONBOARD_CODEX_BIN ?? "/opt/homebrew/bin/codex";
const captureHelper = join(
  repositoryRoot,
  "tests/native-harness/capture-sequenced-hook.mjs",
);
const runRoot = realpathSync(
  mkdtempSync(join(tmpdir(), "secure-onboard-prompt-observations.")),
);
chmodSync(runRoot, 0o700);
const humanPrompt = "SECURE_ONBOARD_HUMAN_PROMPT";
const continuationReason = "M0_CONTINUATION";
const childTimeoutMs = 30_000;
const maximumChildOutputBytes = 16 * 1024 * 1024;

function run(command, commandArguments) {
  const result = spawnSync(command, commandArguments, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
  });
  assert.equal(
    result.status,
    0,
    `${command} ${commandArguments.join(" ")} failed\n${result.stdout}\n${result.stderr}`,
  );
  assert.equal(result.signal, null);
  return result;
}

function assertPinnedVersions() {
  assert.equal(run(nodeExecutable, ["--version"]).stdout.trim(), "v26.5.0");
  assert.equal(
    run(claudeExecutable, ["--version"]).stdout.trim(),
    "2.1.220 (Claude Code)",
  );
  assert.equal(
    run(codexExecutable, ["--version"]).stdout.trim(),
    "codex-cli 0.146.0",
  );
}

function execute(command, commandArguments, { cwd, env, input = null }) {
  return new Promise((resolveChild) => {
    let settled = false;
    let forceSettlement;
    const child = spawn(command, commandArguments, {
      cwd,
      detached: true,
      env,
      stdio: [input === null ? "ignore" : "pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let spawnError = null;
    let timedOut = false;
    let outputLimitExceeded = false;
    let capturedOutputBytes = 0;
    const settle = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      clearTimeout(forceSettlement);
      resolveChild(result);
    };
    const terminateProcessGroup = () => {
      if (forceSettlement !== undefined) {
        return;
      }
      forceSettlement = setTimeout(() => {
        settle({
          status: null,
          signal: "SIGKILL",
          stdout,
          stderr,
          spawn_error:
            spawnError?.message ?? "child process group did not terminate",
          timed_out: timedOut,
          output_limit_exceeded: outputLimitExceeded,
        });
      }, 2_000);
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const capture = (current, chunk) => {
      if (outputLimitExceeded) {
        return current;
      }
      capturedOutputBytes += Buffer.byteLength(chunk);
      if (capturedOutputBytes > maximumChildOutputBytes) {
        outputLimitExceeded = true;
        terminateProcessGroup();
        return current;
      }
      return current + chunk;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = capture(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = capture(stderr, chunk);
    });
    child.on("error", (error) => {
      spawnError = error;
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      terminateProcessGroup();
    }, childTimeoutMs);
    if (input !== null) {
      child.stdin.end(input);
    }
    child.on("close", (status, signal) => {
      settle({
        status,
        signal,
        stdout,
        stderr,
        spawn_error: spawnError?.message ?? null,
        timed_out: timedOut,
        output_limit_exceeded: outputLimitExceeded,
      });
    });
  });
}

async function listen(server) {
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return server.address().port;
}

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolveClose, rejectClose) => {
    server.close((error) => {
      if (error) {
        rejectClose(error);
      } else {
        resolveClose();
      }
    });
  });
}

function createProxyTrap(log) {
  const server = http.createServer((request, response) => {
    log.push({ method: request.method, url: request.url });
    response.writeHead(502, { "content-type": "text/plain" });
    response.end("external egress rejected");
  });
  server.on("connect", (request, socket) => {
    log.push({ method: "CONNECT", url: request.url });
    socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
  });
  return server;
}

function proxyEnvironment(port) {
  const proxy = `http://127.0.0.1:${port}`;
  return {
    HTTP_PROXY: proxy,
    HTTPS_PROXY: proxy,
    ALL_PROXY: proxy,
    http_proxy: proxy,
    https_proxy: proxy,
    all_proxy: proxy,
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
  };
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function captures(directory) {
  assert.ok(existsSync(directory), `missing capture directory: ${directory}`);
  return readdirSync(directory)
    .filter((entry) => entry.endsWith(".json"))
    .sort()
    .map((entry) => {
      const bytes = readFileSync(join(directory, entry));
      const raw = bytes.toString("utf8");
      return {
        file: entry,
        raw,
        raw_bytes: bytes.length,
        raw_sha256: sha256(bytes),
        payload: JSON.parse(raw),
      };
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

function claudeFinalResponse() {
  return [
    {
      type: "message_start",
      message: {
        id: "msg_prompt_observation",
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
      delta: { type: "text_delta", text: "Prompt observation complete" },
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

function responseEvents(item, responseId) {
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

function codexFinalResponse(sequence) {
  return responseEvents(
    {
      id: `msg_prompt_observation_${sequence}`,
      type: "message",
      status: "completed",
      role: "assistant",
      content: [
        {
          type: "output_text",
          text: `Prompt observation complete ${sequence}`,
          annotations: [],
        },
      ],
    },
    `resp_prompt_observation_${sequence}`,
  );
}

function claudeHook(captureDirectory, response = "{}") {
  return {
    type: "command",
    command: nodeExecutable,
    args: [captureHelper, captureDirectory, response],
    timeout: 5,
    statusMessage: "Secure Onboard native prompt observation",
  };
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function codexHook(captureDirectory, response = "{}", onceState = "") {
  const parts = [nodeExecutable, captureHelper, captureDirectory, response];
  if (onceState.length > 0) {
    parts.push(onceState);
  }
  return {
    type: "command",
    command: parts.map(shellQuote).join(" "),
    timeout: 5,
    statusMessage: "Secure Onboard native prompt observation",
  };
}

async function observeClaude() {
  const clientRoot = join(runRoot, "claude");
  const configRoot = join(clientRoot, "config");
  const pluginRoot = join(clientRoot, "plugin");
  const projectRoot = join(clientRoot, "project");
  const promptDirectory = join(clientRoot, "captures/prompt");
  const stopDirectory = join(clientRoot, "captures/stop");
  for (const directory of [
    configRoot,
    join(pluginRoot, ".claude-plugin"),
    join(pluginRoot, "hooks"),
    projectRoot,
  ]) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  writeJson(join(pluginRoot, ".claude-plugin/plugin.json"), {
    name: "secure-onboard-prompt-observation",
    version: "0.0.0",
    description: "Local-only prompt provenance observation",
    author: { name: "Secure Onboard" },
  });
  writeJson(join(pluginRoot, "hooks/hooks.json"), {
    description: "Local-only prompt provenance observation",
    hooks: {
      UserPromptSubmit: [
        {
          hooks: [claudeHook(promptDirectory)],
        },
      ],
      Stop: [
        {
          hooks: [claudeHook(stopDirectory)],
        },
      ],
    },
  });

  const requestLog = [];
  const proxyLog = [];
  const apiServer = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      requestLog.push({ method: request.method, url: request.url, body });
      streamEvents(response, claudeFinalResponse());
    });
  });
  const proxyServer = createProxyTrap(proxyLog);
  const apiPort = await listen(apiServer);
  const proxyPort = await listen(proxyServer);
  const result = await execute(
    claudeExecutable,
    [
      "--print",
      "--verbose",
      "--output-format",
      "stream-json",
      "--include-hook-events",
      "--permission-mode",
      "bypassPermissions",
      "--plugin-dir",
      pluginRoot,
    ],
    {
      cwd: projectRoot,
      env: {
        PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        TMPDIR: runRoot,
        CLAUDE_CONFIG_DIR: configRoot,
        ANTHROPIC_API_KEY: "local-prompt-observation-key",
        ANTHROPIC_BASE_URL: `http://127.0.0.1:${apiPort}`,
        DISABLE_TELEMETRY: "1",
        DISABLE_AUTOUPDATER: "1",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        CLAUDE_CODE_ENABLE_TELEMETRY: "0",
        ...proxyEnvironment(proxyPort),
      },
      input: `${humanPrompt}\n`,
    },
  );
  await Promise.all([close(apiServer), close(proxyServer)]);

  writeFileSync(join(clientRoot, "stdout.jsonl"), result.stdout);
  writeFileSync(join(clientRoot, "stderr.log"), result.stderr);
  writeJson(join(clientRoot, "requests.json"), requestLog);
  writeJson(join(clientRoot, "proxy-log.json"), proxyLog);

  assert.equal(result.timed_out, false, "Claude child timed out");
  assert.equal(result.output_limit_exceeded, false, "Claude output limit");
  assert.equal(result.spawn_error, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(proxyLog.length, 0, "Claude external proxy traffic");
  assert.equal(requestLog.length, 1, "Claude local API request count");
  const promptCaptures = captures(promptDirectory);
  const stopCaptures = captures(stopDirectory);
  assert.equal(promptCaptures.length, 1);
  assert.equal(stopCaptures.length, 1);
  assert.equal(
    promptCaptures[0].payload.hook_event_name,
    "UserPromptSubmit",
  );
  assert.equal(promptCaptures[0].payload.prompt, `${humanPrompt}\n`);
  assert.equal(stopCaptures[0].payload.hook_event_name, "Stop");
  assert.equal(stopCaptures[0].payload.stop_hook_active, false);
  return {
    executable: claudeExecutable,
    version: "2.1.220 (Claude Code)",
    local_api_request_count: requestLog.length,
    proxy_egress_observations: proxyLog.length,
    child_timed_out: result.timed_out,
    prompt_observations: promptCaptures.map((capture) => ({
      ...capture,
      source_assurance: "unverified",
    })),
    stop_observations: stopCaptures,
  };
}

function codexConfig(apiPort) {
  return `model = "mock-model"
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
`;
}

async function observeCodex() {
  const clientRoot = join(runRoot, "codex");
  const homeRoot = join(clientRoot, "home");
  const projectRoot = join(clientRoot, "project");
  const hooksRoot = join(projectRoot, ".codex");
  const promptDirectory = join(clientRoot, "captures/prompt");
  const stopDirectory = join(clientRoot, "captures/stop");
  const stopOnceState = join(clientRoot, "state/stop-block-returned");
  for (const directory of [homeRoot, hooksRoot]) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  writeJson(join(hooksRoot, "hooks.json"), {
    description: "Local-only prompt provenance observation",
    hooks: {
      UserPromptSubmit: [
        {
          hooks: [codexHook(promptDirectory)],
        },
      ],
      Stop: [
        {
          hooks: [
            codexHook(
              stopDirectory,
              JSON.stringify({
                decision: "block",
                reason: continuationReason,
              }),
              stopOnceState,
            ),
          ],
        },
      ],
    },
  });

  const requestLog = [];
  const proxyLog = [];
  const apiServer = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      requestLog.push({ method: request.method, url: request.url, body });
      streamEvents(response, codexFinalResponse(requestLog.length));
    });
  });
  const proxyServer = createProxyTrap(proxyLog);
  const apiPort = await listen(apiServer);
  const proxyPort = await listen(proxyServer);
  writeFileSync(join(homeRoot, "config.toml"), codexConfig(apiPort), {
    encoding: "utf8",
    mode: 0o600,
  });
  const result = await execute(
    codexExecutable,
    [
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
      humanPrompt,
    ],
    {
      cwd: projectRoot,
      env: {
        PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        CODEX_HOME: homeRoot,
        TMPDIR: runRoot,
        ...proxyEnvironment(proxyPort),
      },
    },
  );
  await Promise.all([close(apiServer), close(proxyServer)]);

  writeFileSync(join(clientRoot, "stdout.jsonl"), result.stdout);
  writeFileSync(join(clientRoot, "stderr.log"), result.stderr);
  writeJson(join(clientRoot, "requests.json"), requestLog);
  writeJson(join(clientRoot, "proxy-log.json"), proxyLog);

  assert.equal(result.timed_out, false, "Codex child timed out");
  assert.equal(result.output_limit_exceeded, false, "Codex output limit");
  assert.equal(result.spawn_error, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(proxyLog.length, 0, "Codex external proxy traffic");
  assert.equal(requestLog.length, 2, "Codex local API request count");
  const promptCaptures = captures(promptDirectory);
  const stopCaptures = captures(stopDirectory);
  assert.equal(
    promptCaptures.length,
    1,
    "Codex Stop continuation unexpectedly emitted UserPromptSubmit",
  );
  assert.equal(stopCaptures.length, 2);
  for (const capture of promptCaptures) {
    assert.equal(capture.payload.hook_event_name, "UserPromptSubmit");
    assert.equal(typeof capture.payload.turn_id, "string");
    assert.notEqual(capture.payload.turn_id.length, 0);
  }
  assert.equal(promptCaptures[0].payload.prompt, humanPrompt);
  assert.equal(stopCaptures[0].payload.hook_event_name, "Stop");
  assert.equal(stopCaptures[0].payload.stop_hook_active, false);
  assert.equal(stopCaptures[1].payload.hook_event_name, "Stop");
  assert.equal(stopCaptures[1].payload.stop_hook_active, true);
  assert.equal(
    promptCaptures[0].payload.turn_id,
    stopCaptures[0].payload.turn_id,
  );
  assert.equal(
    stopCaptures[0].payload.turn_id,
    stopCaptures[1].payload.turn_id,
  );
  const secondRequest = JSON.parse(requestLog[1].body);
  const automaticContinuationInputs = secondRequest.input
    .filter((item) => item.type === "message" && item.role === "user")
    .flatMap((item) => item.content)
    .filter(
      (content) =>
        content.type === "input_text" &&
        content.text.startsWith("<hook_prompt ") &&
        content.text.endsWith(`>${continuationReason}</hook_prompt>`),
    )
    .map((content) => content.text);
  assert.equal(automaticContinuationInputs.length, 1);
  const automaticContinuation = automaticContinuationInputs[0];
  return {
    executable: codexExecutable,
    version: "codex-cli 0.146.0",
    local_api_request_count: requestLog.length,
    proxy_egress_observations: proxyLog.length,
    child_timed_out: result.timed_out,
    prompt_observations: promptCaptures.map((capture) => ({
      ...capture,
      observed_origin: "initial_human_submission",
      source_assurance: "unverified",
    })),
    automatic_continuation: {
      local_api_input: automaticContinuation,
      local_api_input_bytes: Buffer.byteLength(automaticContinuation, "utf8"),
      local_api_input_sha256: sha256(
        Buffer.from(automaticContinuation, "utf8"),
      ),
      user_prompt_submit_observed: false,
      source_assurance: "unverified",
    },
    stop_observations: stopCaptures,
    prompt_and_stop_turn_ids_equal: true,
    stop_turn_ids_equal:
      stopCaptures[0].payload.turn_id === stopCaptures[1].payload.turn_id,
  };
}

assert.equal(process.platform, "darwin", "native harness is macOS-only");
assert.equal(process.arch, "arm64", "native harness is arm64-only");
for (const executable of [
  nodeExecutable,
  claudeExecutable,
  codexExecutable,
  captureHelper,
]) {
  assert.ok(
    existsSync(executable),
    `required executable is missing: ${executable}`,
  );
}
assertPinnedVersions();

const summary = {
  schema_version: "m0-prompt-observations/v1",
  run_root: runRoot,
  human_prompt: humanPrompt,
  codex_stop_block_response: {
    decision: "block",
    reason: continuationReason,
  },
  child_timeout_ms: childTimeoutMs,
  kernel_network_confinement:
    "unavailable_sandbox_exec_operation_not_permitted",
  claude: await observeClaude(),
  codex: await observeCodex(),
};
writeJson(join(runRoot, "summary.json"), summary);
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
