// ithildin process entry: `ithildin check`, `ithildin selftest`, or the proxy
// itself. Split out of server.ts so line and function coverage measure the
// proxy library, not process bootstrap (`import.meta.main` never runs under
// `bun test`, and the SIGTERM handlers would kill the test runner).
// Excluded from coverage gates in checks/coverage.ts, like bench and tests.
import { existsSync } from "node:fs";
import { runCheck } from "./check.ts";
import { DRAIN_MS, readOptions, selfTestCli, start } from "./server.ts";

if (import.meta.main && process.argv[2] === "check") {
  // exitCode, not exit(): stdout may still be draining into a pipe.
  process.exitCode = runCheck(process.argv.slice(3), (text) => process.stdout.write(text));
} else if (import.meta.main && process.argv[2] === "selftest") {
  process.exit(await selfTestCli(readOptions(process.argv, process.env, existsSync).port));
} else if (import.meta.main) {
  const { drain } = start(readOptions(process.argv, process.env, existsSync));
  // systemd's TimeoutStopSec is the backstop past DRAIN_MS.
  process.on("SIGTERM", () => {
    void drain().then(() => process.exit(0));
    setTimeout(() => process.exit(0), DRAIN_MS).unref();
  });
}
