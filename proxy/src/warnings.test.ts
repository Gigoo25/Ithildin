import { describe, expect, it } from "bun:test";
import { allowAllWarning, COLD_WRITE_MIN, coldWarning, Warmth } from "./warnings.ts";

const usage = (cacheRead: number, cacheWrite: number) => ({
  input: 2,
  cacheRead,
  cacheWrite,
  output: 10,
});
const MIN = 60_000;

describe("cold start", () => {
  it("warns when a pause outlived the cache and the prompt was written again", () => {
    let now = 0;
    const warmth = new Warmth(() => now);
    expect(warmth.idle("s")).toBeUndefined();
    warmth.heard("s", "s2,m10");
    now = 61 * MIN;
    const idle = warmth.idle("s");
    expect(idle).toEqual({ ms: 61 * MIN, ttl: 60 * MIN });
    expect(coldWarning(idle, usage(8_000, 40_000))).toBe(
      "warning: cold start: 61 min since this session's last reply, longer than its cache " +
        "lives (an hour); its prompt was written again (40000 tokens)",
    );
  });

  it("is quiet within the TTL, on a small write, or when most was read", () => {
    const hour = { ms: 30 * MIN, ttl: 60 * MIN };
    expect(coldWarning(hour, usage(0, 40_000))).toBe("");
    const late = { ms: 90 * MIN, ttl: 60 * MIN };
    expect(coldWarning(late, usage(0, COLD_WRITE_MIN - 1))).toBe("");
    expect(coldWarning(late, usage(80_000, 20_000))).toBe("");
    expect(coldWarning(undefined, usage(0, 40_000))).toBe("");
  });

  it("takes five minutes for a session whose markers ask for the short TTL", () => {
    let now = 0;
    const warmth = new Warmth(() => now);
    warmth.heard("s", "s2:5m,m10:5m");
    now = 6 * MIN;
    expect(coldWarning(warmth.idle("s"), usage(0, 30_000))).toContain("(5 minutes)");
  });

  it("forgets the oldest session past its limit", () => {
    const warmth = new Warmth(() => 0);
    for (let i = 0; i <= 256; i++) warmth.heard(`s${i}`, "");
    expect(warmth.idle("s0")).toBeUndefined();
    expect(warmth.idle("s256")).toBeDefined();
  });
});

describe("one-time [allow-all]", () => {
  it("warns for the prompt's tag, not for a session grant", () => {
    const all = new Set(["all", "pii", "secret"]);
    expect(allowAllWarning(all, new Set())).toContain("[allow-all:session] writes it once");
    expect(allowAllWarning(all, new Set(["all"]))).toBe("");
    expect(allowAllWarning(new Set(["pii"]), new Set())).toBe("");
  });

  it("is warned once per typed prompt, as every request of its turn carries it", () => {
    const warmth = new Warmth();
    expect(warmth.firstOf("s", 3)).toBe(true);
    expect(warmth.firstOf("s", 3)).toBe(false);
    expect(warmth.firstOf("s", 4)).toBe(true);
    expect(warmth.firstOf("t", 4)).toBe(true);
    for (let i = 0; i <= 256; i++) warmth.firstOf(`u${i}`, 1);
    expect(warmth.firstOf("s", 4)).toBe(true);
  });
});
