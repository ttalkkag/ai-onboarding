import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const codexExecutable =
  process.env.SECURE_ONBOARD_CODEX_BIN ?? "/opt/homebrew/bin/codex";
const runRoot = realpathSync(
  mkdtempSync(join(tmpdir(), "secure-onboard-codex-m0-live.")),
);
chmodSync(runRoot, 0o700);
const fixtureRoot = join(runRoot, "trusted");
const targetRoot = join(runRoot, "target");
const stateRoot = join(runRoot, "state");
const evidenceRoot = join(runRoot, "evidence");
const markerPath = join(fixtureRoot, "markers/run-live/T-LIVE.marker");
const pluginRoot = join(runRoot, "plugin");
const projectRoot = join(runRoot, "project");
const codexHome = join(runRoot, "codex-home");
const resultFailureProbe =
  process.env.SECURE_ONBOARD_M0_RESULT_FAILURE === "1";
const maximumChildOutputBytes = 16 * 1024 * 1024;
const maximumRequestBodyBytes = 4 * 1024 * 1024;
const maximumApiRequests = 8;
const maximumProxyEvents = 32;

function sha256File(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function makePrivateDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function assertPrivateDirectory(path) {
  const metadata = lstatSync(path);
  assert.equal(metadata.isDirectory(), true, `not a directory: ${path}`);
  assert.equal(metadata.uid, process.geteuid(), `wrong owner: ${path}`);
  assert.equal(metadata.mode & 0o777, 0o700, `wrong mode: ${path}`);
  assert.equal(realpathSync(path), path, `non-physical directory path: ${path}`);
  assert.equal(
    path === runRoot || path.startsWith(`${runRoot}/`),
    true,
    `directory escaped run root: ${path}`,
  );
}

function makeTreeDirectoriesPrivate(root) {
  chmodSync(root, 0o700);
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    assert.equal(
      entry.isSymbolicLink(),
      false,
      `symlink in private tree: ${join(root, entry.name)}`,
    );
    if (entry.isDirectory()) {
      makeTreeDirectoriesPrivate(join(root, entry.name));
    }
  }
}

function containedRegularFileExists(path) {
  if (!existsSync(path)) {
    return false;
  }
  const metadata = lstatSync(path);
  assert.equal(metadata.isFile(), true, `not a regular file: ${path}`);
  assert.equal(metadata.uid, process.geteuid(), `wrong owner: ${path}`);
  assert.equal(realpathSync(path), path, `non-physical file path: ${path}`);
  assert.equal(
    path.startsWith(`${runRoot}/`),
    true,
    `file escaped run root: ${path}`,
  );
  return true;
}

function createPrivateFile(path, contents) {
  writeFileSync(path, contents, { flag: "wx", mode: 0o600 });
  chmodSync(path, 0o600);
}

function overwritePrivateRegularFile(path, contents) {
  const metadata = lstatSync(path);
  assert.equal(metadata.isFile(), true, `not a regular file: ${path}`);
  assert.equal(metadata.uid, process.geteuid(), `wrong owner: ${path}`);
  assert.equal(metadata.mode & 0o777, 0o600, `wrong mode: ${path}`);
  assert.equal(realpathSync(path), path, `non-physical file path: ${path}`);
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW,
  );
  try {
    writeFileSync(descriptor, contents);
  } finally {
    closeSync(descriptor);
  }
}

function copyRegularFile(source, target, mode) {
  assert.equal(
    lstatSync(source).isFile(),
    true,
    `not a regular file: ${source}`,
  );
  writeFileSync(target, readFileSync(source), { flag: "wx", mode });
  chmodSync(target, mode);
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function replaceHookPlaceholders(value, replacements) {
  if (typeof value === "string") {
    let materialized = value;
    for (const [placeholder, path] of replacements) {
      materialized = materialized.replaceAll(placeholder, shellQuote(path));
    }
    return materialized;
  }
  if (Array.isArray(value)) {
    return value.map((item) => replaceHookPlaceholders(item, replacements));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        replaceHookPlaceholders(item, replacements),
      ]),
    );
  }
  return value;
}

function materializeHookConfig(path) {
  const source = readFileSync(path, "utf8");
  const replacements = new Map([
    ["__SECURE_ONBOARD_M0_TRUSTED_ROOT__", fixtureRoot],
    ["__SECURE_ONBOARD_M0_TARGET_ROOT__", targetRoot],
    ["__SECURE_ONBOARD_M0_STATE_ROOT__", stateRoot],
    ["__SECURE_ONBOARD_M0_EVIDENCE_ROOT__", evidenceRoot],
  ]);
  for (const placeholder of replacements.keys()) {
    assert.ok(
      source.includes(placeholder),
      `missing hook placeholder: ${placeholder}`,
    );
  }
  const materialized = `${JSON.stringify(
    replaceHookPlaceholders(JSON.parse(source), replacements),
    null,
    2,
  )}\n`;
  assert.equal(
    materialized.includes("__SECURE_ONBOARD_M0_"),
    false,
    "unresolved hook placeholder",
  );
  overwritePrivateRegularFile(path, materialized);
}

function run(command, commandArguments) {
  const result = spawnSync(command, commandArguments, {
    cwd: repositoryRoot,
    detached: true,
    encoding: "utf8",
    env: { ...process.env, TMPDIR: runRoot },
    killSignal: "SIGKILL",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
  });
  if (
    result.error !== undefined ||
    result.signal !== null ||
    result.status !== 0
  ) {
    try {
      process.kill(-result.pid, "SIGKILL");
    } catch {}
  }
  assert.equal(
    result.error,
    undefined,
    `${command} ${commandArguments.join(" ")} could not complete: ${result.error?.message}`,
  );
  assert.equal(
    result.signal,
    null,
    `${command} ${commandArguments.join(" ")} terminated by ${result.signal}`,
  );
  assert.equal(
    result.status,
    0,
    `${command} ${commandArguments.join(" ")} failed\n${result.stdout}\n${result.stderr}`,
  );
  return result;
}

function prepareProductBundle() {
  run("cargo", [
    "build",
    "--locked",
    "--offline",
    "--release",
    "--features",
    "m0-test-profile",
    "--bin",
    "secure-onboard-m0-core",
    "--bin",
    "secure-onboard-m0-hook",
  ]);
  makePrivateDirectory(pluginRoot);
  makePrivateDirectory(join(pluginRoot, "bin"));
  makePrivateDirectory(join(pluginRoot, "hooks"));
  copyRegularFile(
    join(repositoryRoot, "target/release/secure-onboard-m0-core"),
    join(pluginRoot, "bin/secure-onboard-m0-core"),
    0o700,
  );
  copyRegularFile(
    join(repositoryRoot, "target/release/secure-onboard-m0-hook"),
    join(pluginRoot, "bin/secure-onboard-m0-hook"),
    0o700,
  );
  copyRegularFile(
    join(repositoryRoot, "plugins/codex-m0/hooks/hooks.json"),
    join(pluginRoot, "hooks/hooks.json"),
    0o600,
  );

  for (const directory of [
    fixtureRoot,
    join(fixtureRoot, "helpers"),
    join(fixtureRoot, "profiles"),
    join(fixtureRoot, "markers/run-live"),
    stateRoot,
    evidenceRoot,
    targetRoot,
    codexHome,
    projectRoot,
  ]) {
    makePrivateDirectory(directory);
  }
  copyRegularFile(
    join(repositoryRoot, "tests/fixtures/m0/helpers/m0-target.mjs"),
    join(fixtureRoot, "helpers/m0-target.mjs"),
    0o600,
  );
  copyRegularFile(
    join(repositoryRoot, "tests/fixtures/m0/helpers/m0-target-fail.mjs"),
    join(fixtureRoot, "helpers/m0-target-fail.mjs"),
    0o600,
  );
  copyRegularFile(
    join(
      repositoryRoot,
      "tests/fixtures/m0/profiles/codex-0.146.0-macos-arm64.json",
    ),
    join(fixtureRoot, "profiles/codex.json"),
    0o600,
  );
  materializeHookConfig(join(pluginRoot, "hooks/hooks.json"));
  makeTreeDirectoriesPrivate(pluginRoot);
  makeTreeDirectoriesPrivate(fixtureRoot);
  makePrivateDirectory(join(projectRoot, ".codex"));
  copyRegularFile(
    join(pluginRoot, "hooks/hooks.json"),
    join(projectRoot, ".codex/hooks.json"),
    0o600,
  );
}

function assertPrivateHarnessRoots() {
  for (const directory of [
    runRoot,
    fixtureRoot,
    join(fixtureRoot, "helpers"),
    join(fixtureRoot, "profiles"),
    join(fixtureRoot, "markers"),
    join(fixtureRoot, "markers/run-live"),
    targetRoot,
    stateRoot,
    evidenceRoot,
    pluginRoot,
    projectRoot,
    join(projectRoot, ".codex"),
    codexHome,
  ]) {
    assertPrivateDirectory(directory);
  }
}

function responseEvents(item, completedId) {
  const completed = {
    id: completedId,
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
  };
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
      response: completed,
    },
  ];
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

async function listen(server) {
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return server.address().port;
}

async function closeServer(server, name) {
  await new Promise((resolveClose, rejectClose) => {
    let settled = false;
    const timeout = setTimeout(() => {
      server.closeAllConnections();
      if (!settled) {
        settled = true;
        rejectClose(new Error(`${name} did not close within 2 seconds`));
      }
    }, 2_000);
    server.close((error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (error) {
        rejectClose(error);
      } else {
        resolveClose();
      }
    });
    server.closeAllConnections();
  });
}

function executeCodex(environment) {
  return new Promise((resolveChild) => {
    let settled = false;
    let timedOut = false;
    let outputLimitExceeded = false;
    let capturedOutputBytes = 0;
    let forceSettlement;
    const child = spawn(
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
        "Run the single supplied M0 fixture command.",
      ],
      {
        cwd: projectRoot,
        detached: true,
        env: {
          ...environment,
          PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
          CODEX_HOME: codexHome,
          TMPDIR: runRoot,
          PLUGIN_ROOT: pluginRoot,
          NO_PROXY: "127.0.0.1,localhost",
          no_proxy: "127.0.0.1,localhost",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    const settle = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      clearTimeout(forceSettlement);
      resolveChild(result);
    };
    const terminateProcessGroup = (failureMessage) => {
      if (forceSettlement !== undefined) {
        return;
      }
      forceSettlement = setTimeout(() => {
        settle({
          status: null,
          signal: "SIGKILL",
          stdout,
          stderr,
          timedOut,
          outputLimitExceeded,
          spawnError: failureMessage,
        });
      }, 2_000);
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminateProcessGroup(
        "Codex did not close after its process group timed out",
      );
    }, 30_000);
    const captureOutput = (current, chunk) => {
      if (outputLimitExceeded) {
        return current;
      }
      capturedOutputBytes += Buffer.byteLength(chunk);
      if (capturedOutputBytes > maximumChildOutputBytes) {
        outputLimitExceeded = true;
        terminateProcessGroup(
          "Codex did not close after exceeding the output limit",
        );
        return current;
      }
      return current + chunk;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = captureOutput(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = captureOutput(stderr, chunk);
    });
    child.on("close", (status, signal) => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
      settle({
        status,
        signal,
        stdout,
        stderr,
        timedOut,
        outputLimitExceeded,
      });
    });
    child.on("error", (error) => {
      settle({
        status: null,
        signal: null,
        stdout,
        stderr,
        timedOut,
        outputLimitExceeded,
        spawnError: error.message,
      });
    });
  });
}

function evidenceCount(kind) {
  const directory = join(evidenceRoot, kind);
  if (!existsSync(directory)) {
    return 0;
  }
  assertPrivateDirectory(directory);
  return readdirSync(directory).length;
}

assert.equal(process.platform, "darwin", "native harness is macOS-only");
assert.equal(process.arch, "arm64", "native harness is arm64-only");
assert.ok(existsSync(codexExecutable), "pinned Codex executable is missing");
const codexResolvedExecutable = realpathSync(codexExecutable);
const codexVersion = run(codexExecutable, ["--version"]).stdout.trim();
const environmentBinding = {
  os_build: run("/usr/bin/sw_vers", ["-buildVersion"]).stdout.trimEnd(),
  architecture: run("/usr/bin/uname", ["-m"]).stdout.trimEnd(),
  client_invoked_path: codexExecutable,
  client_resolved_path: codexResolvedExecutable,
  client_sha256: sha256File(codexResolvedExecutable),
  client_version_output: codexVersion,
};
assert.equal(environmentBinding.os_build, "25F84");
assert.equal(environmentBinding.architecture, "arm64");
assert.equal(codexVersion, "codex-cli 0.146.0");
prepareProductBundle();
assertPrivateHarnessRoots();

const command = [
  "/opt/homebrew/Cellar/node/26.5.0/bin/node",
  join(
    fixtureRoot,
    resultFailureProbe
      ? "helpers/m0-target-fail.mjs"
      : "helpers/m0-target.mjs",
  ),
  resultFailureProbe ? "low" : "high",
  markerPath,
].join(" ");
const requestLog = [];
const proxyLog = [];
const proxyTunnelSockets = new Set();
let apiRequestLimitExceeded = false;
let requestBodyLimitExceeded = false;
let proxyEventLimitExceeded = false;
const apiServer = http.createServer((request, response) => {
  let body = "";
  let bodyBytes = 0;
  let bodyRejected = false;
  request.setEncoding("utf8");
  request.on("data", (chunk) => {
    if (bodyRejected) {
      return;
    }
    bodyBytes += Buffer.byteLength(chunk);
    if (bodyBytes > maximumRequestBodyBytes) {
      bodyRejected = true;
      requestBodyLimitExceeded = true;
      response.writeHead(413, { "content-type": "text/plain" });
      response.end("request body limit exceeded");
      return;
    }
    body += chunk;
  });
  request.on("end", () => {
    if (bodyRejected) {
      return;
    }
    if (requestLog.length >= maximumApiRequests) {
      apiRequestLimitExceeded = true;
      response.writeHead(429, { "content-type": "text/plain" });
      response.end("request count limit exceeded");
      return;
    }
    requestLog.push({ method: request.method, url: request.url, body });
    const hasToolOutput = body.includes('"type":"function_call_output"');
    const item = hasToolOutput
      ? {
          id: "msg_secure_onboard_done",
          type: "message",
          status: "completed",
          role: "assistant",
          content: [
            {
              type: "output_text",
              text: "M0 probe complete",
              annotations: [],
            },
          ],
        }
      : {
          id: "fc_secure_onboard_m0",
          type: "function_call",
          status: "completed",
          name: "exec_command",
          call_id: "call_secure_onboard_m0",
          arguments: JSON.stringify({
            cmd: command,
            workdir: targetRoot,
            yield_time_ms: 10_000,
            max_output_tokens: 1_000,
          }),
        };
    streamEvents(
      response,
      responseEvents(
        item,
        hasToolOutput
          ? "resp_secure_onboard_done"
          : "resp_secure_onboard_tool",
      ),
    );
  });
});
apiServer.maxConnections = 4;
apiServer.requestTimeout = 5_000;
apiServer.headersTimeout = 5_000;
apiServer.keepAliveTimeout = 1_000;
apiServer.maxRequestsPerSocket = 4;
const proxyServer = http.createServer((request, response) => {
  if (proxyLog.length < maximumProxyEvents) {
    proxyLog.push({ method: request.method, url: request.url });
  } else {
    proxyEventLimitExceeded = true;
  }
  response.writeHead(502, { "content-type": "text/plain" });
  response.end("external egress rejected");
});
proxyServer.on("connect", (request, socket) => {
  proxyTunnelSockets.add(socket);
  socket.setTimeout(2_000, () => {
    socket.destroy();
  });
  socket.on("error", () => {
    socket.destroy();
  });
  socket.on("close", () => {
    proxyTunnelSockets.delete(socket);
  });
  if (proxyLog.length < maximumProxyEvents) {
    proxyLog.push({ method: "CONNECT", url: request.url });
  } else {
    proxyEventLimitExceeded = true;
  }
  socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
});
proxyServer.maxConnections = 4;
proxyServer.requestTimeout = 5_000;
proxyServer.headersTimeout = 5_000;
proxyServer.keepAliveTimeout = 1_000;
proxyServer.maxRequestsPerSocket = 4;
const apiPort = await listen(apiServer);
const proxyPort = await listen(proxyServer);
createPrivateFile(
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
const result = await executeCodex({
  HTTP_PROXY: `http://127.0.0.1:${proxyPort}`,
  HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
  ALL_PROXY: `http://127.0.0.1:${proxyPort}`,
  http_proxy: `http://127.0.0.1:${proxyPort}`,
  https_proxy: `http://127.0.0.1:${proxyPort}`,
  all_proxy: `http://127.0.0.1:${proxyPort}`,
});
for (const socket of proxyTunnelSockets) {
  socket.destroy();
}
await Promise.all([
  closeServer(apiServer, "API server"),
  closeServer(proxyServer, "proxy server"),
]);

assertPrivateHarnessRoots();
createPrivateFile(join(runRoot, "stdout.jsonl"), result.stdout);
createPrivateFile(join(runRoot, "stderr.log"), result.stderr);
createPrivateFile(
  join(runRoot, "requests.json"),
  `${JSON.stringify(requestLog, null, 2)}\n`,
);
createPrivateFile(
  join(runRoot, "proxy-log.json"),
  `${JSON.stringify(proxyLog, null, 2)}\n`,
);

assert.equal(result.timedOut, false, "Codex execution timed out");
assert.equal(
  result.outputLimitExceeded,
  false,
  "Codex execution exceeded the output limit",
);
assert.equal(result.spawnError, undefined, result.spawnError);
assert.equal(
  apiRequestLimitExceeded,
  false,
  "API request count limit exceeded",
);
assert.equal(
  requestBodyLimitExceeded,
  false,
  "API request body limit exceeded",
);
assert.equal(proxyEventLimitExceeded, false, "proxy event limit exceeded");
assert.equal(result.status, 0, result.stderr);
assert.equal(result.signal, null);
assert.equal(proxyLog.length, 0, "external proxy traffic");
assert.equal(requestLog.length, 2, "API request count");
assert.equal(
  containedRegularFileExists(markerPath),
  true,
  "Codex excluded path did not run",
);
assert.equal(evidenceCount("native-input") >= 3, true);
assert.equal(evidenceCount("hook-envelope"), 2);
assert.equal(evidenceCount("native-output"), 1);
assert.equal(evidenceCount("m0-action-request"), 0);
assert.equal(evidenceCount("m0-action-decision"), 0);
assert.equal(evidenceCount("m0-event"), 0);
assert.equal(result.stdout.includes("Secure Onboard M0:"), false);
assert.equal(result.stderr.includes("Secure Onboard M0 hook failed"), false);
assert.equal(
  sha256File(codexResolvedExecutable),
  environmentBinding.client_sha256,
  "Codex launcher changed during the observation",
);

const summary = {
  schema_version: "m0-codex-native-harness-result/v1",
  codex_executable: codexExecutable,
  codex_version: codexVersion,
  environment_binding: environmentBinding,
  product_artifacts: {
    hook_sha256: sha256File(join(pluginRoot, "bin/secure-onboard-m0-hook")),
    core_sha256: sha256File(join(pluginRoot, "bin/secure-onboard-m0-core")),
  },
  run_root: runRoot,
  kernel_network_confinement: "unavailable_sandbox_exec_operation_not_permitted",
  proxy_egress_observations: proxyLog.length,
  cwd_binding: "unverified",
  coverage: "excluded",
  probe_kind: resultFailureProbe ? "result_failure" : "high_pre_tool",
  target_marker_exists: true,
  high_marker_exists: resultFailureProbe ? null : true,
  system_message_observed: false,
  result_outcome: "unverified",
  evidence_counts: Object.fromEntries(
    [
      "native-input",
      "native-output",
      "hook-envelope",
      "m0-action-request",
      "m0-action-decision",
      "m0-event",
    ].map((kind) => [kind, evidenceCount(kind)]),
  ),
};
createPrivateFile(
  join(runRoot, "summary.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
);
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
