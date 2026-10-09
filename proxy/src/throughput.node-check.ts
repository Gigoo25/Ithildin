// Run with both Node and Bun (checks/proxy.nix): the proxy runs on Bun, and
// JSC and V8 fail differently. Bun turned the old matcher down outright as
// "regular expression too large", which omitted the whole string.
//
// Throughput gate for the request path. A long session masks thousands of
// values, and a scan whose cost grows with that number runs a request past
// its budget: the rest of it is omitted ("scan budget exceeded") and the
// model works blind. Unit tests run with a handful of values and never see
// it, so this drives a long-session request through redactRequest and fails
// on any omission, on a slow request, and on a cost that grows with the
// number of masked values.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// As test-setup.ts: never the real inventory, keys or ssh config.
const dir = mkdtempSync(join(tmpdir(), "ithildin-throughput-"));
process.env.ITHILDIN_CONFIG = join(dir, "missing-config.json");
process.env.ITHILDIN_ALIAS_KEY_FILE = join(dir, "alias-key");
process.env.ITHILDIN_PROXY_KEY_FILE = join(dir, "proxy-alias-key");
process.env.ITHILDIN_INFRA_INVENTORY = "off";

const { aliases, clearCaches, setAliasBook } = await import("../engine/core.ts");
const { AliasBook } = await import("../engine/lib/aliases.ts");
const { clearWindowCache } = await import("../engine/lib/rules.ts");
const { redactRequest } = await import("./redact.ts");

// Well under the 30 s production budget: a request this size took about a
// second when this was written, and a 2x regression should still pass on a
// slow builder while a 10x one cannot.
const REQUEST_MS_MAX = 8_000;
// Cost with many values over cost with few. Flat matching sits near 1.
const VALUES_RATIO_MAX = 2.5;

// The values a long session has masked: hosts, emails, handles.
function maskValues(count: number): void {
  setAliasBook(new AliasBook(Buffer.alloc(32, 7)));
  for (let i = 0; i < count; i++) {
    const tag = (i * 7919).toString(36);
    aliases().standIn("pii-email", `user${tag}.qa${i}@example.com`);
    aliases().standIn("pii-custom-handle", `zq${tag}handle${i}`, "handle");
  }
}

// What an agent session carries: code, logs full of numbers, escapes and
// byte lists (the shapes spelled copies are looked for in), and prose.
const CHUNKS = [
  "const result = await fetch(url, { headers }); // retry 3 times, 250 ms apart\n",
  "printf '\\x48\\x65\\x6c\\x6c\\x6f' | od -tu1 # 72 101 108 108 111\n",
  "GET /api/v1/items?page=12&q=a%20b%2Fc 200 OK 1532 bytes in 0.042s\n",
  "    at Object.<anonymous> (/app/src/server.ts:118:23), [0x1f, 0x8b, 0x08]\n",
  "The test failed because the fixture expected 1, 2, 3 but received 3, 2, 1.\n",
  'JSON.parse("{\\"a\\":\\"\\u0041\\u0042\\"}") \\101\\102 \\0103 rot13 Uryyb jbeyq\n',
];

function session(bytes: number): Record<string, unknown> {
  const messages: unknown[] = [];
  let size = 0;
  for (let turn = 0; size < bytes; turn++) {
    const text = Array.from({ length: 400 }, (_, i) => CHUNKS[(turn + i) % CHUNKS.length]).join("");
    size += text.length;
    messages.push(
      { role: "user", content: [{ type: "tool_result", tool_use_id: `t${turn}`, content: text }] },
      {
        role: "assistant",
        content: [{ type: "text", text: `Step ${turn}: ${text.slice(0, 500)}` }],
      },
    );
  }
  messages.push({ role: "user", content: "keep going" });
  return { model: "claude-opus-5-5", max_tokens: 1024, messages };
}

// One cold request: no window cache, so every string is scanned.
function timeRequest(values: number, body: Record<string, unknown>): { ms: number; out: string } {
  // Clearing the caches empties the alias book too, so values go in after.
  clearCaches();
  clearWindowCache();
  maskValues(values);
  const started = performance.now();
  const out = JSON.stringify(redactRequest("anthropic", structuredClone(body)).body);
  assert.ok(aliases().values().length >= values, "masked values were dropped before the request");
  return { ms: performance.now() - started, out };
}

test("a long session's request is scanned whole, well inside the budget", () => {
  const { ms, out } = timeRequest(2_000, session(3_000_000));
  assert.ok(!out.includes("scan budget exceeded"), "part of the request was omitted");
  assert.ok(ms < REQUEST_MS_MAX, `3 MB request with 4,000 masked values took ${ms.toFixed(0)} ms`);
});

test("the cost of a request does not grow with the number of masked values", () => {
  const body = session(1_000_000);
  timeRequest(10, body); // warm the JIT
  const few = Math.min(timeRequest(10, body).ms, timeRequest(10, body).ms);
  const many = Math.min(timeRequest(5_000, body).ms, timeRequest(5_000, body).ms);
  assert.ok(
    many / few < VALUES_RATIO_MAX,
    `20 values: ${few.toFixed(0)} ms, 10,000 values: ${many.toFixed(0)} ms`,
  );
});
