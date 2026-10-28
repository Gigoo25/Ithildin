import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CACHE_PRICES } from "./prices.data.ts";
import { cachePrices, COMMON, parseReadPrices } from "./prices.ts";

const saved = process.env.ITHILDIN_CONFIG;
let dir = "";
let config = "";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ithildin-prices-"));
  config = join(dir, "config.json");
  process.env.ITHILDIN_CONFIG = config;
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  if (saved === undefined) delete process.env.ITHILDIN_CONFIG;
  else process.env.ITHILDIN_CONFIG = saved;
});

describe("cache prices", () => {
  it("knows the current models, with a date or a variant after the name", () => {
    expect(cachePrices("claude-opus-5-5", "anthropic")).toEqual({ read: 0.05, write: 1.25 });
    expect(cachePrices("claude-opus-5-5[1m]", "anthropic").read).toBe(0.05);
    expect(cachePrices("claude-opus-5-5-20260401", "anthropic").read).toBe(0.05);
    expect(cachePrices("claude-fable-5-1", "anthropic").read).toBe(0.025);
    expect(cachePrices("claude-sonnet-5-5", "anthropic").read).toBe(0.05);
    // A shorter name is a different model, not a prefix of a longer one.
    expect(cachePrices("claude-opus-5", "anthropic").read).toBe(0.1);
  });

  it("prices a route at what its provider charges", () => {
    expect(cachePrices("deepseek-v4.1-flash", "opencode-go")).toEqual({ read: 0.02, write: 1 });
    expect(cachePrices("gpt-6-luna", "openai-codex")).toEqual({ read: 0.1, write: 1.25 });
  });

  it("takes a model's maker's price on a route the table does not know", () => {
    expect(cachePrices("claude-opus-5-5", "litellm-lan").read).toBe(0.05);
    expect(cachePrices("gpt-6-luna")).toEqual({ read: 0.1, write: 1.25 });
    const log = spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      expect(cachePrices("ornith-1.5-35b", "litellm-lan")).toEqual(COMMON);
      expect(log).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
    }
  });

  it("gives a model its route's list does not name the cautious price, and says so once", () => {
    const listed = Object.values(CACHE_PRICES["anthropic"]!);
    const cautious = {
      read: Math.min(...listed.map(([read]) => read)),
      write: Math.max(...listed.map(([, write]) => write)),
    };
    const log = spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      expect(cachePrices("claude-opus-6", "anthropic")).toEqual(cautious);
      expect(cachePrices("claude-opus-6", "anthropic")).toEqual(cautious);
      const said = log.mock.calls.map(([text]) => String(text));
      expect(said).toHaveLength(1);
      expect(said[0]).toContain("claude-opus-6 on anthropic");
      expect(said[0]).toContain('"cacheReadPrices"');
      // The proxy's own self-test: priced the same, but nothing to warn about.
      expect(cachePrices("selftest", "anthropic")).toEqual(cautious);
      expect(log.mock.calls).toHaveLength(1);
    } finally {
      log.mockRestore();
    }
  });

  it("takes the common price when the request names no model", () => {
    expect(cachePrices(undefined, "anthropic")).toEqual(COMMON);
    expect(cachePrices("", "anthropic")).toEqual(COMMON);
  });

  it("lists only prices that are ratios to input", () => {
    for (const table of Object.values(CACHE_PRICES))
      for (const [read, write] of Object.values(table)) {
        expect(read).toBeGreaterThan(0);
        expect(read).toBeLessThanOrEqual(1);
        expect(write).toBeGreaterThan(0);
      }
  });

  it("lets the user config set a read price, with no warning for a model it names", () => {
    writeFileSync(
      config,
      JSON.stringify({ cacheReadPrices: { "claude-opus-7*": 0.04, "claude-opus-5-5": 0.08 } }),
    );
    const log = spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      expect(cachePrices("claude-opus-7-1", "anthropic").read).toBe(0.04);
      expect(cachePrices("claude-opus-5-5", "anthropic")).toEqual({ read: 0.08, write: 1.25 });
      expect(log).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
    }
  });

  it("leaves out entries that are not a price", () => {
    expect(parseReadPrices({ cacheReadPrices: { a: 0.05, b: 0, c: 2, d: "x" } })).toEqual({
      entries: [["a", 0.05]],
      problems: [
        'cacheReadPrices: "b" must be a number above 0, at most 1',
        'cacheReadPrices: "c" must be a number above 0, at most 1',
        'cacheReadPrices: "d" must be a number above 0, at most 1',
      ],
    });
    expect(parseReadPrices({ cacheReadPrices: [] }).problems).toEqual([
      '"cacheReadPrices" must be an object',
    ]);
    expect(parseReadPrices({})).toEqual({ entries: [], problems: [] });
  });

  it("logs a bad entry in the config file and ignores it", () => {
    writeFileSync(config, JSON.stringify({ cacheReadPrices: { "claude-opus-5-5": "cheap" } }));
    const log = spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      expect(cachePrices("claude-opus-5-5", "anthropic").read).toBe(0.05);
      expect(log.mock.calls.map(([text]) => String(text)).join("")).toContain("ignoring");
    } finally {
      log.mockRestore();
    }
  });
});
