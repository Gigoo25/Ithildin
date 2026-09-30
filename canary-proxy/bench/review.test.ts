import { expect, it } from "bun:test";
import { assess, runFixture, summarize } from "./harness.ts";
import { REVIEW_FIXTURES, EXPECTED_RANGES } from "./review-corpus.ts";
import type { BenchFixture } from "./corpus.ts";
const fixture: BenchFixture = {
  id: "controlled",
  group: "metrics",
  description: "Invented controlled transformation",
  input: "abcd keep abcd",
  expectedSecrets: ["abcd"],
  mustPreserve: ["keep"],
  representation: "text",
  support: "supported",
};
const audit = (
  detections: Array<{ start: number; end: number }>,
  replacements = detections,
  omissions: Array<{ start: number; end: number }> = [],
) => ({
  sourceLength: fixture.input.length,
  detections,
  replacements,
  omissions,
  coordinateSystem: "original" as const,
});
it("controlled missing, excessive, partial and omission transformations are distinguished", () => {
  const missing = assess(fixture, fixture.input, [audit([])]);
  expect(missing.misses).toHaveLength(2);
  expect(missing.exposedChars).toBe(8);
  const excess = assess(fixture, "X X X", [audit([{ start: 0, end: fixture.input.length }])]);
  expect(excess.falsePreserveViolations).toHaveLength(1);
  const partial = assess(fixture, "Xcd keep abcd", [audit([{ start: 0, end: 2 }])]);
  expect(partial.misses).toHaveLength(2);
  expect(partial.exposedChars).toBe(6);
  const omitted = assess(fixture, "[omitted]", [
    audit([], [], [{ start: 0, end: fixture.input.length }]),
  ]);
  expect(omitted.misses).toHaveLength(2);
  expect(omitted.hits).toBe(0);
  expect(omitted.trips).toBe(1);
  expect(omitted.omittedChars).toBe(fixture.input.length);
  expect(omitted.exposedChars).toBe(0);
});
it("review set: exact authored ranges, no privacy or usability regressions", () => {
  const fixtures = REVIEW_FIXTURES.map((f) => ({ ...f, expectedRanges: EXPECTED_RANGES[f.id] }));
  for (const f of fixtures) {
    for (const value of [...f.expectedSecrets, ...f.mustPreserve]) expect(f.input).toContain(value);
    for (const r of f.expectedRanges ?? [])
      expect(f.expectedSecrets).toContain(f.input.slice(r.start, r.end));
  }
  const results = fixtures.map(runFixture);
  for (const r of results) {
    expect({
      id: r.id,
      misses: r.misses.length,
      exposure: r.exposedChars,
      falseRedactions: r.falsePreserveViolations.length,
      omissions: r.trips,
      syntax: r.syntaxFailures,
      unavailable: r.measurementUnavailable,
    }).toEqual({
      id: r.id,
      misses: 0,
      exposure: 0,
      falseRedactions: 0,
      omissions: 0,
      syntax: 0,
      unavailable: false,
    });
  }
  expect(summarize(results).fixtures).toBe(fixtures.length);
});
