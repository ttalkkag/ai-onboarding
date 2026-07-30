import assert from "node:assert/strict";
import {
  closeSync,
  mkdirSync,
  openSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

const [captureDirectory, response = "{}", responseOnceState = ""] =
  process.argv.slice(2);
assert.ok(captureDirectory, "capture directory is required");
JSON.parse(response);

const chunks = [];
for await (const chunk of process.stdin) {
  chunks.push(chunk);
}
const input = Buffer.concat(chunks);
JSON.parse(input.toString("utf8"));

mkdirSync(captureDirectory, { recursive: true, mode: 0o700 });
let captureDescriptor;
for (let sequence = 0; sequence < 10_000; sequence += 1) {
  try {
    captureDescriptor = openSync(
      join(captureDirectory, `${String(sequence).padStart(6, "0")}.json`),
      "wx",
      0o600,
    );
    break;
  } catch (error) {
    if (error.code !== "EEXIST") {
      throw error;
    }
  }
}
assert.notEqual(captureDescriptor, undefined, "capture sequence exhausted");
try {
  writeFileSync(captureDescriptor, input);
} finally {
  closeSync(captureDescriptor);
}

let selectedResponse = response;
if (responseOnceState.length > 0) {
  mkdirSync(dirname(responseOnceState), { recursive: true, mode: 0o700 });
  try {
    const stateDescriptor = openSync(responseOnceState, "wx", 0o600);
    closeSync(stateDescriptor);
  } catch (error) {
    if (error.code !== "EEXIST") {
      throw error;
    }
    selectedResponse = "{}";
  }
}
process.stdout.write(`${selectedResponse}\n`);
