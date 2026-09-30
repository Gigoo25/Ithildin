// Tests never touch the real inventory, stand-in keys, or ~/.ssh/config.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "ithildin-test-"));
process.env.ITHILDIN_CONFIG ??= join(dir, "missing-config.json");
process.env.ITHILDIN_ALIAS_KEY_FILE ??= join(dir, "alias-key");
process.env.ITHILDIN_PROXY_KEY_FILE ??= join(dir, "proxy-alias-key");
process.env.ITHILDIN_INFRA_INVENTORY ??= "off";
