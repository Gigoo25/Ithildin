import { describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dataFile, PROVIDERS, ratiosFrom, update } from "./prices-update.ts";

const cost = (input: number, cache_read?: number, cache_write?: number) => ({
  cost: { input, cache_read, cache_write },
});

// models.dev's shape: each provider's models, each with its cost per million.
function api(models: Record<string, unknown>) {
  return Object.fromEntries(PROVIDERS.map((provider) => [provider, { models }]));
}

describe("price table update", () => {
  it("lists each model that caches, as its prices over input", () => {
    const tables = ratiosFrom(
      api({
        "b-model": cost(4, 0.2, 5),
        "a-model": cost(0.15, 0.003),
        "no-cache": cost(2),
        free: cost(0, 0),
      }),
    );
    expect(tables["opencode-go"]).toEqual({ "a-model": [0.02, 1], "b-model": [0.05, 1.25] });
    expect(Object.keys(tables["opencode-go"]!)).toEqual(["a-model", "b-model"]);
  });

  it("refuses a list that is missing a provider", () => {
    expect(() => ratiosFrom({ anthropic: { models: {} } })).toThrow('models.dev has no "openai"');
    expect(() => ratiosFrom(undefined)).toThrow("models.dev has no");
  });

  it("writes the table as a module, keys quoted only where they must be", () => {
    const text = dataFile(
      { anthropic: { "claude-x": [0.1, 1.25] }, openai: { o3: [0.25, 1] } },
      "2026-10-28",
    );
    expect(text).toContain('export const FETCHED = "2026-10-28";');
    expect(text).toContain('  anthropic: {\n    "claude-x": [0.1, 1.25],\n  },');
    expect(text).toContain("  openai: {\n    o3: [0.25, 1],\n  },");
  });

  it("fetches, converts and writes the file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ithildin-prices-update-"));
    try {
      const path = join(dir, "prices.data.ts");
      const tables = await update(async () => api({ m: cost(2, 0.1) }), path, "2026-10-28");
      expect(tables["google"]).toEqual({ m: [0.05, 1] });
      expect(readFileSync(path, "utf8")).toContain("    m: [0.05, 1],");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
