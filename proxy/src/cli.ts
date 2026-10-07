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
  process.exit(await selfTestCli(options().port));
} else if (import.meta.main) {
  let started: ReturnType<typeof start>;
  try {
    started = start(options());
  } catch (error) {
    // A bad port, routes file, or a port in use: say which, without a stack.
    console.error((error as Error).message);
    process.exit(1);
  }
  const { drain } = started;
  // systemd's TimeoutStopSec is the backstop past DRAIN_MS. Ctrl-C drains too,
  // so the scan cache is saved either way; a second one exits at once.
  const stop = (): void => {
    process.removeListener("SIGINT", stop);
    process.once("SIGINT", () => process.exit(130));
    void drain().then(() => process.exit(0));
    setTimeout(() => process.exit(0), DRAIN_MS).unref();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

function options(): ReturnType<typeof readOptions> {
  try {
    return readOptions(process.argv, process.env, existsSync);
  } catch (error) {
    console.error((error as Error).message);
    process.exit(1);
  }
}
