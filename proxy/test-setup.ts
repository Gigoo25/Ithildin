// Tests never touch the real inventory, stand-in keys, or ~/.ssh/config.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "ithildin-test-"));
process.env.ITHILDIN_CONFIG ??=
  process.env.SENSITIVE_CANARY_CONFIG ?? join(dir, "missing-config.json");
process.env.ITHILDIN_ALIAS_KEY_FILE ??=
  process.env.SENSITIVE_CANARY_ALIAS_KEY_FILE ?? join(dir, "alias-key");
process.env.ITHILDIN_PROXY_KEY_FILE ??=
  process.env.SENSITIVE_CANARY_PROXY_KEY_FILE ?? join(dir, "proxy-alias-key");
process.env.ITHILDIN_INFRA_INVENTORY ??= process.env.SENSITIVE_CANARY_INFRA_INVENTORY ?? "off";
// Legacy names are read after the current ones (lib/names.ts); cleared so a
// test that unsets a setting sees it unset.
for (const key of Object.keys(process.env))
  if (key.startsWith("SENSITIVE_CANARY_")) delete process.env[key];
