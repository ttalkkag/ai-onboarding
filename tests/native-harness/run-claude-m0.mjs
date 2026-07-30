import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const claudeExecutable =
  process.env.SECURE_ONBOARD_CLAUDE_BIN ??
  "/Users/kimchanhyung98/.local/share/claude/versions/2.1.220";
const runRoot = realpathSync(
  mkdtempSync(join(tmpdir(), "secure-onboard-claude-m0-live.")),
);
chmodSync(runRoot, 0o700);
const fixtureRoot = join(runRoot, "trusted");
const targetRoot = join(runRoot, "target");
const stateRoot = join(runRoot, "state");
const evidenceRoot = join(runRoot, "evidence");
const markerPath = join(fixtureRoot, "markers/run-live/T-LIVE.marker");
const pluginBaseRoot = join(runRoot, "plugin-base");
const expectedClaudeVersion = "2.1.220 (Claude Code)";
const maximumChildOutputBytes = 16 * 1024 * 1024;

function sha256File(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function run(command, commandArguments, options = {}) {
  const result = spawnSync(command, commandArguments, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
    ...options,
  });
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
  cpSync(join(repositoryRoot, "plugins/claude-m0"), pluginBaseRoot, {
    recursive: true,
  });
  mkdirSync(join(pluginBaseRoot, "bin"), { recursive: true });
  cpSync(
    join(repositoryRoot, "target/release/secure-onboard-m0-core"),
    join(pluginBaseRoot, "bin/secure-onboard-m0-core"),
  );
  cpSync(
    join(repositoryRoot, "target/release/secure-onboard-m0-hook"),
    join(pluginBaseRoot, "bin/secure-onboard-m0-hook"),
  );
  const hooksPath = join(pluginBaseRoot, "hooks/hooks.json");
  writeFileSync(
    hooksPath,
    readFileSync(hooksPath, "utf8")
      .replaceAll("__SECURE_ONBOARD_M0_TRUSTED_ROOT__", fixtureRoot)
      .replaceAll("__SECURE_ONBOARD_M0_TARGET_ROOT__", targetRoot)
      .replaceAll("__SECURE_ONBOARD_M0_STATE_ROOT__", stateRoot)
      .replaceAll("__SECURE_ONBOARD_M0_EVIDENCE_ROOT__", evidenceRoot),
  );

  for (const directory of [
    fixtureRoot,
    join(fixtureRoot, "helpers"),
    join(fixtureRoot, "profiles"),
    join(fixtureRoot, "markers"),
    join(fixtureRoot, "markers/run-live"),
    stateRoot,
    evidenceRoot,
    targetRoot,
  ]) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
  }
  cpSync(
    join(repositoryRoot, "tests/fixtures/m0/helpers/m0-target.mjs"),
    join(fixtureRoot, "helpers/m0-target.mjs"),
  );
  chmodSync(join(fixtureRoot, "helpers/m0-target.mjs"), 0o600);
  cpSync(
    join(repositoryRoot, "tests/fixtures/m0/helpers/m0-target-fail.mjs"),
    join(fixtureRoot, "helpers/m0-target-fail.mjs"),
  );
  chmodSync(join(fixtureRoot, "helpers/m0-target-fail.mjs"), 0o600);
  cpSync(
    join(
      repositoryRoot,
      "tests/fixtures/m0/profiles/claude-2.1.220-macos-arm64.json",
    ),
    join(fixtureRoot, "profiles/claude.json"),
  );
  chmodSync(join(fixtureRoot, "profiles/claude.json"), 0o600);
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

function toolResponse(command) {
  return [
    {
      type: "message_start",
      message: {
        id: "msg_secure_onboard_tool",
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
        id: "toolu_secure_onboard_m0",
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
          description: "Secure Onboard M0 native product probe",
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

function finalResponse() {
  return [
    {
      type: "message_start",
      message: {
        id: "msg_secure_onboard_done",
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
      delta: { type: "text_delta", text: "M0 probe complete" },
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

function hasToolResult(body) {
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
      server.closeAllConnections?.();
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
    server.closeAllConnections?.();
  });
}

function executeClaude(environment, configDirectory, pluginRoot) {
  return new Promise((resolveChild) => {
    let settled = false;
    let timedOut = false;
    let outputLimitExceeded = false;
    let capturedOutputBytes = 0;
    let forceSettlement;
    const child = spawn(
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
        "--tools",
        "Bash",
      ],
      {
        cwd: targetRoot,
        detached: true,
        env: {
          PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
          TMPDIR: runRoot,
          CLAUDE_CONFIG_DIR: configDirectory,
          ANTHROPIC_API_KEY: "local-m0-test-key",
          DISABLE_TELEMETRY: "1",
          DISABLE_AUTOUPDATER: "1",
          CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
          CLAUDE_CODE_ENABLE_TELEMETRY: "0",
          NO_PROXY: "127.0.0.1,localhost",
          no_proxy: "127.0.0.1,localhost",
          ...environment,
        },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stdoutBuffer = "";
    let stderr = "";
    const timedLines = [];
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
          timedLines,
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
        "Claude did not close after its process group timed out",
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
          "Claude did not close after exceeding the output limit",
        );
        return current;
      }
      return current + chunk;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = captureOutput(stdout, chunk);
      if (outputLimitExceeded) {
        return;
      }
      stdoutBuffer += chunk;
      let newline;
      while ((newline = stdoutBuffer.indexOf("\n")) !== -1) {
        timedLines.push({
          received_monotonic_ns: process.hrtime.bigint().toString(),
          line: stdoutBuffer.slice(0, newline),
        });
        stdoutBuffer = stdoutBuffer.slice(newline + 1);
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr = captureOutput(stderr, chunk);
    });
    child.stdin.end("Run the single supplied M0 fixture command.\n");
    child.on("close", (status, signal) => {
      if (stdoutBuffer.length > 0) {
        timedLines.push({
          received_monotonic_ns: process.hrtime.bigint().toString(),
          line: stdoutBuffer,
        });
      }
      settle({
        status,
        signal,
        stdout,
        stderr,
        timedLines,
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
        timedLines,
        timedOut,
        outputLimitExceeded,
        spawnError: error.message,
      });
    });
  });
}

function resetCaseState() {
  rmSync(markerPath, { force: true });
  rmSync(stateRoot, { recursive: true, force: true });
  rmSync(evidenceRoot, { recursive: true, force: true });
  mkdirSync(stateRoot, { mode: 0o700 });
  mkdirSync(evidenceRoot, { mode: 0o700 });
}

function evidenceCount(kind) {
  const directory = join(evidenceRoot, kind);
  return existsSync(directory) ? readdirSync(directory).length : 0;
}

function evidenceObjects(kind) {
  const directory = join(evidenceRoot, kind);
  if (!existsSync(directory)) {
    return [];
  }
  return readdirSync(directory)
    .sort()
    .map((name) => JSON.parse(readFileSync(join(directory, name), "utf8")));
}

function observeTargetProcesses() {
  const observations = [];
  let availability = "available";
  const sample = () => {
    const result = spawnSync("/bin/ps", ["-axo", "pid=,command="], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      timeout: 1_000,
    });
    if (result.status !== 0) {
      availability = "unavailable_operation_not_permitted";
      return;
    }
    for (const line of result.stdout.split("\n")) {
      if (
        line.includes("/opt/homebrew/Cellar/node/26.5.0/bin/node") &&
        line.includes(markerPath) &&
        line.includes(join(fixtureRoot, "helpers/m0-target"))
      ) {
        observations.push({
          observed_monotonic_ns: process.hrtime.bigint().toString(),
          process: line.trim(),
        });
      }
    }
  };
  sample();
  const interval = setInterval(sample, 20);
  return {
    stop() {
      clearInterval(interval);
      sample();
      return { availability, observations };
    },
  };
}

function prepareCasePlugin(caseRoot, coreFault, siblingMarker) {
  const pluginRoot = join(caseRoot, "plugin");
  cpSync(pluginBaseRoot, pluginRoot, { recursive: true });
  const hooksPath = join(pluginRoot, "hooks/hooks.json");
  const hooks = JSON.parse(readFileSync(hooksPath, "utf8"));
  const preHooks = hooks.hooks.PreToolUse[0].hooks;
  const argumentsList = preHooks[0].args;
  const faultIndex = argumentsList.indexOf("--core-fault");
  assert.notEqual(faultIndex, -1);
  argumentsList[faultIndex + 1] = coreFault;
  if (siblingMarker !== null) {
    preHooks.push({
      type: "command",
      command: "/opt/homebrew/Cellar/node/26.5.0/bin/node",
      args: [
        join(fixtureRoot, "helpers/m0-target.mjs"),
        "info",
        siblingMarker,
      ],
      timeout: 5,
      statusMessage: "Secure Onboard M0 sibling observation",
    });
  }
  writeFileSync(hooksPath, `${JSON.stringify(hooks, null, 2)}\n`);
  return pluginRoot;
}

async function runCase({
  sentinel,
  helper = "default",
  coreFault = "none",
  sibling = false,
}) {
  resetCaseState();
  const caseName = [
    sentinel,
    helper === "failure" ? "failure-helper" : null,
    coreFault === "none" ? null : `core-${coreFault}`,
    sibling ? "sibling" : null,
  ]
    .filter(Boolean)
    .join("-");
  const caseRoot = join(runRoot, caseName);
  mkdirSync(caseRoot, { recursive: true });
  const siblingMarker = sibling ? join(caseRoot, "sibling.marker") : null;
  const pluginRoot = prepareCasePlugin(caseRoot, coreFault, siblingMarker);
  const helperName =
    helper === "failure" ? "m0-target-fail.mjs" : "m0-target.mjs";
  const command = [
    "/opt/homebrew/Cellar/node/26.5.0/bin/node",
    join(fixtureRoot, `helpers/${helperName}`),
    sentinel,
    markerPath,
  ].join(" ");
  const requestLog = [];
  const proxyLog = [];
  const apiServer = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      requestLog.push({
        method: request.method,
        url: request.url,
        body,
      });
      streamEvents(
        response,
        hasToolResult(body) ? finalResponse() : toolResponse(command),
      );
    });
  });
  const proxyServer = http.createServer((request, response) => {
    proxyLog.push({ method: request.method, url: request.url });
    response.writeHead(502, { "content-type": "text/plain" });
    response.end("external egress rejected");
  });
  proxyServer.on("connect", (request, socket) => {
    proxyLog.push({ method: "CONNECT", url: request.url });
    socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
  });
  const apiPort = await listen(apiServer);
  const proxyPort = await listen(proxyServer);
  const configDirectory = join(caseRoot, "config");
  mkdirSync(configDirectory, { recursive: true });
  const processObserver = observeTargetProcesses();
  const result = await executeClaude(
    {
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${apiPort}`,
      HTTP_PROXY: `http://127.0.0.1:${proxyPort}`,
      HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
      ALL_PROXY: `http://127.0.0.1:${proxyPort}`,
      http_proxy: `http://127.0.0.1:${proxyPort}`,
      https_proxy: `http://127.0.0.1:${proxyPort}`,
      all_proxy: `http://127.0.0.1:${proxyPort}`,
    },
    configDirectory,
    pluginRoot,
  );
  const processObservation = processObserver.stop();
  const targetProcessObservations = processObservation.observations;
  await Promise.all([
    closeServer(apiServer, `${caseName} API server`),
    closeServer(proxyServer, `${caseName} proxy server`),
  ]);

  writeFileSync(join(caseRoot, "stdout.jsonl"), result.stdout);
  writeFileSync(join(caseRoot, "stderr.log"), result.stderr);
  writeFileSync(
    join(caseRoot, "requests.json"),
    `${JSON.stringify(requestLog, null, 2)}\n`,
  );
  writeFileSync(
    join(caseRoot, "proxy-log.json"),
    `${JSON.stringify(proxyLog, null, 2)}\n`,
  );
  cpSync(evidenceRoot, join(caseRoot, "evidence"), {
    recursive: true,
  });

  assert.equal(result.status, 0, `${sentinel}: ${result.stderr}`);
  assert.equal(result.signal, null);
  assert.equal(result.spawnError, undefined);
  assert.equal(result.timedOut, false);
  assert.equal(result.outputLimitExceeded, false);
  assert.equal(proxyLog.length, 0, `${sentinel}: external proxy traffic`);
  assert.equal(requestLog.length, 2, `${sentinel}: API request count`);
  const outputEvents = result.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const hookResponses = outputEvents.filter(
    (event) => event.type === "system" && event.subtype === "hook_response",
  );
  assert.ok(
    hookResponses.some((event) => event.hook_event === "PreToolUse"),
    `${sentinel}: missing PreToolUse hook response`,
  );
  const envelopes = evidenceObjects("hook-envelope");
  const requests = evidenceObjects("m0-action-request");
  const decisions = evidenceObjects("m0-action-decision");
  const events = evidenceObjects("m0-event");
  const actionEnvelopes = envelopes.filter(
    ({ hook_event }) => hook_event !== "assistant_stop",
  );
  const stopEnvelopes = envelopes.filter(
    ({ hook_event }) => hook_event === "assistant_stop",
  );
  assert.equal(stopEnvelopes.length, 1, `${caseName}: Stop envelope count`);
  assert.equal(
    stopEnvelopes[0].last_assistant_message,
    "M0 probe complete",
    `${caseName}: Stop message fidelity`,
  );
  assert.equal(requests.length, 1, `${caseName}: action request count`);
  assert.equal(decisions.length, 1, `${caseName}: action decision count`);
  assert.equal(events.length, 2, `${caseName}: event count`);
  assert.equal(requests[0].action_id, decisions[0].action_id);
  assert.equal(
    requests[0].native_tool_call_id,
    decisions[0].native_tool_call_id,
  );
  assert.equal(
    events.every(
      (event) =>
        event.action_id === decisions[0].action_id &&
        event.native_tool_call_id === decisions[0].native_tool_call_id &&
        event.rule_id === decisions[0].rule_id &&
        event.severity === decisions[0].severity,
    ),
    true,
    `${caseName}: event correlation`,
  );
  const markerExists = existsSync(markerPath);
  const targetProcessStarted =
    processObservation.availability === "available"
      ? targetProcessObservations.length > 0
      : null;
  let warningBeforeTarget = null;
  if (coreFault !== "none") {
    assert.equal(markerExists, false, `${coreFault}: target started`);
    if (processObservation.availability === "available") {
      assert.equal(targetProcessStarted, false, `${coreFault}: target process observed`);
    }
    assert.equal(actionEnvelopes.length, 1);
    assert.equal(actionEnvelopes[0].hook_event, "pre_tool_use");
    assert.equal(decisions[0].severity, "HIGH");
    assert.equal(decisions[0].gate_decision, "deny");
    assert.equal(decisions[0].rule_id, "guardrail.scan_failure");
    assert.equal(decisions[0].decision_source, "adapter_fallback");
    assert.equal(
      decisions[0].failure_code,
      {
        timeout: "core_timeout",
        nonzero: "core_nonzero",
        "schema-invalid": "core_schema_invalid",
      }[coreFault],
    );
    assert.deepEqual(
      new Set(events.map(({ event_type }) => event_type)),
      new Set(["high_detected", "high_blocked"]),
    );
    assert.ok(
      hookResponses.some(
        (event) =>
          event.hook_event === "PreToolUse" &&
          event.output.includes('"permissionDecision":"deny"') &&
          event.output.includes("Secure Onboard M0 core failure"),
      ),
      `${coreFault}: adapter fallback deny was not observed`,
    );
  } else if (sentinel === "high") {
    assert.equal(markerExists, false, "HIGH target started");
    if (processObservation.availability === "available") {
      assert.equal(targetProcessStarted, false, "HIGH target process observed");
    }
    assert.equal(actionEnvelopes.length, 1);
    assert.equal(actionEnvelopes[0].hook_event, "pre_tool_use");
    assert.equal(decisions[0].severity, "HIGH");
    assert.equal(decisions[0].gate_decision, "deny");
    assert.equal(decisions[0].rule_id, "m0.sentinel.high");
    assert.equal(decisions[0].decision_source, "core");
    assert.equal(decisions[0].failure_code, null);
    assert.deepEqual(
      new Set(events.map(({ event_type }) => event_type)),
      new Set(["high_detected", "high_blocked"]),
    );
    assert.ok(
      hookResponses.some(
        (event) =>
          event.hook_event === "PreToolUse" &&
          event.output.includes('"permissionDecision":"deny"') &&
          event.output.includes("Secure Onboard M0: HIGH action blocked."),
      ),
      "HIGH deny response was not observed",
    );
  } else {
    assert.equal(markerExists, true, `${sentinel}: target did not start`);
    if (processObservation.availability === "available") {
      assert.equal(targetProcessStarted, true, `${sentinel}: target process not observed`);
    }
    assert.equal(actionEnvelopes.length, 2);
    assert.deepEqual(
      new Set(actionEnvelopes.map(({ hook_event }) => hook_event)),
      new Set(["pre_tool_use", "tool_result"]),
    );
    const resultEnvelope = actionEnvelopes.find(
      ({ hook_event }) => hook_event === "tool_result",
    );
    assert.equal(
      resultEnvelope.native_tool_call_id,
      decisions[0].native_tool_call_id,
      `${caseName}: result correlation`,
    );
    const expectedSeverity = sentinel === "low" ? "LOW" : "INFO";
    const expectedRule = `m0.sentinel.${sentinel}`;
    const expectedInitialEvent =
      sentinel === "low" ? "warned_low" : "allowed_info";
    const expectedResultEvent =
      helper === "failure" ? "tool_failed" : "tool_completed";
    assert.equal(decisions[0].severity, expectedSeverity);
    assert.equal(decisions[0].gate_decision, "continue");
    assert.equal(decisions[0].rule_id, expectedRule);
    assert.equal(decisions[0].decision_source, "core");
    assert.equal(decisions[0].failure_code, null);
    assert.equal(
      resultEnvelope.outcome,
      helper === "failure" ? "failure" : "success",
    );
    assert.deepEqual(
      new Set(events.map(({ event_type }) => event_type)),
      new Set([expectedInitialEvent, expectedResultEvent]),
    );
    const resultEvent = events.find(
      ({ event_type }) => event_type === expectedResultEvent,
    );
    assert.equal(
      resultEvent.outcome,
      helper === "failure" ? "failure" : "success",
    );
    if (sentinel === "low") {
      const warning = hookResponses.find(
          (event) =>
            event.hook_event === "PreToolUse" &&
            event.output.includes("Secure Onboard M0: LOW warning."),
      );
      assert.ok(warning, "LOW warning response was not observed");
      const warningLine = result.timedLines.find(({ line }) => {
        try {
          const event = JSON.parse(line);
          return (
            event.type === "system" &&
            event.subtype === "hook_response" &&
            event.hook_event === "PreToolUse" &&
            event.output.includes("Secure Onboard M0: LOW warning.")
          );
        } catch {
          return false;
        }
      });
      assert.ok(warningLine, "LOW warning receipt time was not captured");
      const marker = JSON.parse(readFileSync(markerPath, "utf8"));
      warningBeforeTarget =
        BigInt(warningLine.received_monotonic_ns) <
        BigInt(marker.started_monotonic_ns);
      assert.equal(
        warningBeforeTarget,
        true,
        "LOW warning stream receipt was not before target marker creation",
      );
    }
  }
  if (siblingMarker !== null) {
    assert.equal(
      existsSync(siblingMarker),
      true,
      "sibling hook side effect was not observed",
    );
  }
  return {
    case: caseName,
    sentinel,
    helper,
    core_fault: coreFault,
    marker_exists: markerExists,
    target_process_started: targetProcessStarted,
    target_process_observation_count: targetProcessObservations.length,
    target_process_observer: processObservation.availability,
    sibling_marker_exists:
      siblingMarker === null ? null : existsSync(siblingMarker),
    warning_stream_received_before_target: warningBeforeTarget,
    hook_response_count: hookResponses.length,
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
}

assert.equal(process.platform, "darwin", "native harness is macOS-only");
assert.equal(process.arch, "arm64", "native harness is arm64-only");
assert.ok(existsSync(claudeExecutable), "pinned Claude executable is missing");
const claudeVersion = run(claudeExecutable, ["--version"]).stdout.trimEnd();
assert.equal(claudeVersion, expectedClaudeVersion, "unexpected Claude version");
const claudeResolvedExecutable = realpathSync(claudeExecutable);
const environmentBinding = {
  os_build: run("/usr/bin/sw_vers", ["-buildVersion"]).stdout.trimEnd(),
  architecture: run("/usr/bin/uname", ["-m"]).stdout.trimEnd(),
  client_invoked_path: claudeExecutable,
  client_resolved_path: claudeResolvedExecutable,
  client_sha256: sha256File(claudeResolvedExecutable),
  client_version_output: claudeVersion,
  shell_path: "/bin/zsh",
  shell_sha256: sha256File("/bin/zsh"),
};
assert.equal(environmentBinding.architecture, "arm64");
prepareProductBundle();
const results = [];
for (const sentinel of ["high", "low", "info"]) {
  results.push(await runCase({ sentinel }));
}
for (const sentinel of ["low", "info"]) {
  results.push(await runCase({ sentinel, helper: "failure" }));
}
for (const coreFault of ["timeout", "nonzero", "schema-invalid"]) {
  results.push(await runCase({ sentinel: "info", coreFault }));
}
results.push(await runCase({ sentinel: "high", sibling: true }));
assert.equal(
  sha256File(claudeResolvedExecutable),
  environmentBinding.client_sha256,
  "Claude executable changed during the observation",
);
const summary = {
  schema_version: "m0-claude-native-harness-result/v1",
  claude_executable: claudeExecutable,
  claude_version: claudeVersion,
  environment_binding: environmentBinding,
  product_artifacts: {
    hook_sha256: sha256File(
      join(pluginBaseRoot, "bin/secure-onboard-m0-hook"),
    ),
    core_sha256: sha256File(
      join(pluginBaseRoot, "bin/secure-onboard-m0-core"),
    ),
  },
  run_root: runRoot,
  kernel_network_confinement: "unavailable_sandbox_exec_operation_not_permitted",
  proxy_egress_observations: 0,
  results,
};
writeFileSync(join(runRoot, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
