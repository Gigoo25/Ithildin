// Imported first by anything that drives the proxy: points every file the
// engine reads or writes at a fresh directory, so a simulation never sees this
// machine's inventory, keys or learned values, and never writes to them.
// ES modules run in import order, so this runs before the proxy's own modules
// read their settings.
//
// The alias keys are fixed, not drawn: stand-ins come from them, and a replay
// that minted different stand-ins each time would not be the same run twice,
// which shrinking a failure depends on.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const given = process.env.ITHILDIN_SIM_DIR;
export const SIM_DIR = given ?? mkdtempSync(join(tmpdir(), "ithildin-sim-"));
// A directory this process made is this process's to remove.
if (!given) process.on("exit", () => rmSync(SIM_DIR, { recursive: true, force: true }));
mkdirSync(join(SIM_DIR, "state"), { recursive: true });
process.env.XDG_STATE_HOME = join(SIM_DIR, "state");
process.env.XDG_CONFIG_HOME = join(SIM_DIR, "config");
process.env.ITHILDIN_CONFIG = join(SIM_DIR, "missing-config.json");
process.env.ITHILDIN_ALIAS_KEY_FILE = join(SIM_DIR, "state", "alias-key");
process.env.ITHILDIN_PROXY_KEY_FILE = join(SIM_DIR, "state", "proxy-alias-key");
process.env.ITHILDIN_INFRA_INVENTORY = "off";
process.env.ITHILDIN_REPO_ROOTS = join(SIM_DIR, "repos");

for (const name of ["alias-key", "proxy-alias-key"]) {
  const key = createHash("sha256").update(`ithildin-sim ${name}`).digest("hex");
  try {
    writeFileSync(join(SIM_DIR, "state", name), `${key}\n`, { mode: 0o600, flag: "wx" });
  } catch {
    // Already there: a directory given to reuse keeps its keys.
  }
}
