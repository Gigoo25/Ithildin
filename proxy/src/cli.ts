// ithildin process entry: `ithildin check`, `ithildin selftest`, or the proxy
// itself. Split out of server.ts so line and function coverage measure the
// proxy library, not process bootstrap (`import.meta.main` never runs under
// `bun test`, and the SIGTERM handlers would kill the test runner).
// Excluded from coverage gates in checks/coverage.ts, like bench and tests.
import { existsSync } from "node:fs";
import { runCheck } from "./check.ts";
import { bunTooOld, DRAIN_MS, MIN_BUN, readOptions, selfTestCli, start } from "./server.ts";

// Refused before anything is served: on an older Bun the scan deadlines do not
// fire, so a large conversation hangs the proxy for minutes instead of seconds.
if (import.meta.main && bunTooOld(Bun.version)) {
  console.error(
    `ithildin: needs Bun ${MIN_BUN} or newer, and this is ${Bun.version}.\n` +
      "On an older Bun the engine's scan deadlines do not fire, so a long " +
      "conversation hangs the proxy for minutes instead of seconds.",
  );
  process.exit(1);
}

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
