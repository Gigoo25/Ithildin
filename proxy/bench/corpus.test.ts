import { describe, expect, it } from "bun:test";
import { FIXTURES, FROZEN_IDS, fixtureById, fakeToken } from "./corpus.ts";
import { runFixture, summarize } from "./harness.ts";

describe("benchmark corpus integrity", () => {
  it("has stable frozen ids and no duplicates", () => {
    expect(new Set(FROZEN_IDS).size).toBe(FIXTURES.length);
    expect(FIXTURES.length).toBeGreaterThan(8);
  });
  it("generates deterministic tokens", () => {
    expect(fakeToken("ab", 8, 42)).toBe(fakeToken("ab", 8, 42));
  });
  it("fixtures resolve and report value-free counts", () => {
    const f = fixtureById(FROZEN_IDS[0]!);
    const r = runFixture(f);
    expect(r.id).toBe(f.id);
    expect(typeof r.misses.length).toBe("number");
    expect(r.rendered).not.toContain("exposed-secret-dump");
  });
  it("separates unsupported and limitation fixtures from misses", () => {
    const results = FIXTURES.map(runFixture);
    const summary = summarize(results);
    expect(summary.fixtures).toBe(FIXTURES.length);
    expect(summary.unsupported + summary.limitations).toBeGreaterThan(0);
  });
  it("detects both a miss-path and a preserve-path with fake detectors", () => {
    // Controlled check: harness distinguishes misses from false redactions.
    const miss = runFixture({
      id: "synthetic-miss",
      group: "test",
      description: "test",
      representation: "text",
      support: "supported",
      input: "nothing matches this invented marker",
      expectedSecrets: ["nothing matches this invented marker"],
      mustPreserve: [],
    });
    // The real engine should not flag ordinary prose; harness records a miss.
    expect(miss.misses.length).toBe(1);
    const preserve = runFixture({
      id: "synthetic-preserve",
      group: "test",
      description: "test",
      representation: "text",
      support: "supported",
      input: "whichKeyWritable = pkgs.stdenv.hostPlatform.system;",
      expectedSecrets: [],
      mustPreserve: ["whichKeyWritable = pkgs.stdenv.hostPlatform.system;"],
    });
    expect(preserve.falsePreserveViolations.length).toBe(0);
  });
});
