// Tests never touch the real inventory, stand-in keys, or ~/.ssh/config.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "canary-engine-test-"));
process.env.SENSITIVE_CANARY_CONFIG ??= join(dir, "missing-config.json");
process.env.SENSITIVE_CANARY_ALIAS_KEY_FILE ??= join(dir, "alias-key");
process.env.SENSITIVE_CANARY_INFRA_INVENTORY ??= "off";
