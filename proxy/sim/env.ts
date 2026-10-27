// Imported first by anything that drives the proxy: points every file the
// engine reads or writes at a fresh directory, so a simulation never sees this
// machine's inventory, keys or learned values, and never writes to them.
// ES modules run in import order, so this runs before the proxy's own modules
// read their settings.
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const SIM_DIR = process.env.ITHILDIN_SIM_DIR ?? mkdtempSync(join(tmpdir(), "ithildin-sim-"));
mkdirSync(join(SIM_DIR, "state"), { recursive: true });
process.env.XDG_STATE_HOME = join(SIM_DIR, "state");
process.env.XDG_CONFIG_HOME = join(SIM_DIR, "config");
process.env.ITHILDIN_CONFIG = join(SIM_DIR, "missing-config.json");
process.env.ITHILDIN_ALIAS_KEY_FILE = join(SIM_DIR, "state", "alias-key");
process.env.ITHILDIN_PROXY_KEY_FILE = join(SIM_DIR, "state", "proxy-alias-key");
process.env.ITHILDIN_INFRA_INVENTORY = "off";
process.env.ITHILDIN_REPO_ROOTS = join(SIM_DIR, "repos");
