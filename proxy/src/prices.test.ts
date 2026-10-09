import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BUILT_IN, cacheReadPrice, DEFAULT_READ, parseReadPrices } from "./prices.ts";

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

describe("cache read prices", () => {
  it("knows the current models, with a date or a variant after the name", () => {
    expect(cacheReadPrice("claude-opus-5-5")).toBe(0.05);
    expect(cacheReadPrice("claude-opus-5-5[1m]")).toBe(0.05);
    expect(cacheReadPrice("claude-opus-5-5-20260401")).toBe(0.05);
    expect(cacheReadPrice("claude-fable-5-1")).toBe(0.025);
    expect(cacheReadPrice("claude-sonnet-5-5")).toBe(0.1);
    // A shorter name is a different model, not a prefix of a longer one.
    expect(cacheReadPrice("claude-opus-5")).toBe(0.1);
  });

  it("never prices a read above a tenth, so no entry makes a step look better", () => {
    for (const [model, price] of BUILT_IN) {
      expect(price).toBeLessThanOrEqual(0.1);
      expect(cacheReadPrice(model)).toBe(price);
    }
  });

  it("gives a model it does not know the lowest price, and says so once", () => {
    const log = spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      expect(cacheReadPrice("claude-opus-6")).toBe(0.025);
      expect(cacheReadPrice("claude-opus-6")).toBe(0.025);
      const said = log.mock.calls.map(([text]) => String(text));
      expect(said.filter((text) => text.includes("claude-opus-6"))).toHaveLength(1);
      expect(said[0]).toContain('"cacheReadPrices"');
      // Not a Claude model: priced the same, but nothing to warn about.
      expect(cacheReadPrice("selftest")).toBe(0.025);
      expect(log.mock.calls).toHaveLength(1);
    } finally {
      log.mockRestore();
    }
  });

  it("takes the common price when the request names no model", () => {
    expect(cacheReadPrice(undefined)).toBe(DEFAULT_READ);
    expect(cacheReadPrice("")).toBe(DEFAULT_READ);
  });

  it("lets the user config add a model or override one", () => {
    writeFileSync(
      config,
      JSON.stringify({ cacheReadPrices: { "claude-opus-7*": 0.04, "claude-opus-5-5": 0.08 } }),
    );
    expect(cacheReadPrice("claude-opus-7-1")).toBe(0.04);
    expect(cacheReadPrice("claude-opus-5-5")).toBe(0.08);
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
      expect(cacheReadPrice("claude-opus-5-5")).toBe(0.05);
      expect(log.mock.calls.map(([text]) => String(text)).join("")).toContain("ignoring");
    } finally {
      log.mockRestore();
    }
  });
});
