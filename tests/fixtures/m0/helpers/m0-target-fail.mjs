import { writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";

const [sentinel, markerPath] = process.argv.slice(2);
if (!["low", "info"].includes(sentinel) || !markerPath) {
  process.exit(64);
}

writeFileSync(
  markerPath,
  `${JSON.stringify({
    sentinel,
    expected_exit_code: 23,
    started_monotonic_ns: process.hrtime.bigint().toString(),
  })}\n`,
  { encoding: "utf8", flag: "wx", mode: 0o600 },
);
await delay(250);
process.exit(23);
