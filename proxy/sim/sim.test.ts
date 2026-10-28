import { describe, expect, test } from "bun:test";
import { Cache } from "./cache.ts";
import { simulate } from "./sim.ts";
import { generated, requestsOf } from "./workload.ts";

// A few short seeds per format on every run; `bun proxy/sim/run.ts` runs
// hundreds of long ones.
describe("shaping simulator", () => {
  for (const format of ["anthropic", "responses", "chat", "gemini"] as const)
    test(`${format}: shaped requests are pure, valid and stepped`, () => {
      for (const seed of [1, 2, 3]) {
        const report = simulate(format, generated(format, seed, 70));
        expect(report.violations).toEqual([]);
        expect(report.breaks.unexplained).toBe(0);
        expect(report.requests).toBeGreaterThan(60);
      }
    });

  test("the same seed builds the same session", () => {
    expect(generated("anthropic", 7, 30)).toEqual(generated("anthropic", 7, 30));
    expect(generated("anthropic", 7, 30)).not.toEqual(generated("anthropic", 8, 30));
  });

  test("a session is cut into the requests the agent sent, each extending the last", () => {
    const requests = requestsOf("chat", generated("chat", 3, 20));
    for (let i = 1; i < requests.length; i++) {
      const before = requests[i - 1]!.messages as unknown[];
      const now = requests[i]!.messages as unknown[];
      expect(now.slice(0, before.length)).toEqual(before);
    }
  });

  // Found by the sweep: a new typed prompt changed a replayed past decision,
  // and the cutoff jumped 0 to 10 with no step taken.
  test("a typed prompt does not move a cutoff the requests before it settled", () => {
    for (const seed of [1029, 1048]) {
      const report = simulate("chat", generated("chat", seed, 60));
      expect(report.violations).toEqual([]);
    }
  });

  test("the Anthropic cache reads within 20 blocks of a marker, and writes up to it", () => {
    const cache = new Cache("anthropic");
    const text = (n: number) => ({ type: "text", text: "x".repeat(400 + n) });
    const body = (n: number) => ({
      model: "m",
      messages: [
        {
          role: "user",
          content: [
            ...Array.from({ length: n }, (_, i) => text(i)),
            { ...text(n), cache_control: { type: "ephemeral" } },
          ],
        },
      ],
    });
    expect(cache.send(body(5)).read).toBe(0);
    expect(cache.send(body(10)).read).toBeGreaterThan(0);
    // Thirty blocks past the last entry is past the lookback: all written again.
    const far = cache.send(body(41));
    expect(far.read).toBe(0);
    expect(far.write).toBeGreaterThan(0);
  });
});
