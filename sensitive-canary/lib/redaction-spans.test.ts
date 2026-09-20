import { describe, expect, it } from "bun:test";
import { planRedaction } from "./redaction-spans.ts";
import type { LocatedFinding } from "./rules.ts";

function loc(partial: Partial<LocatedFinding> & { start: number; end: number; secretValue: string }): LocatedFinding {
  return {
    ruleId: "test",
    description: "test",
    category: "pii",
    matchRedacted: "****",
    score: 1,
    ...partial,
  };
}

describe("redaction spans", () => {
  it("redacts only the intended span, not longer identifiers", () => {
    const text = `username = "sampler"\nconst samplerCount = 3;`;
    const start = text.indexOf("sampler");
    const out = planRedaction({
      text,
      findings: [loc({ ruleId: "u", category: "pii", secretValue: "sampler", start, end: start + 7 })],
      trips: [],
      replacementFor: () => "<test-user-1>",
    });
    expect(out.text).toContain("samplerCount");
    expect(out.text).not.toContain(`"sampler"`);
  });
  it("keeps standalone PII repetitions hidden", () => {
    const text = `peer abc then abc done`;
    const out = planRedaction({
      text,
      findings: [loc({ secretValue: "abc", start: 5, end: 8 })],
      trips: [],
      replacementFor: () => "XYZ",
    });
    expect(out.text.split("XYZ").length - 1).toBe(2);
  });
  it("does not propagate single-character fragments", () => {
    const text = `q x q`;
    const start = text.indexOf("x");
    const out = planRedaction({
      text,
      findings: [loc({ secretValue: "x", start, end: start + 1 })],
      trips: [],
      replacementFor: () => "X",
    });
    expect(out.text).toBe("q X q");
  });
  it("hides every repeated secret even when embedded", () => {
    const text = `tok AAA embedded AAABBB`;
    const out = planRedaction({
      text,
      findings: [loc({ category: "secret", secretValue: "AAA", start: 4, end: 7 })],
      trips: [],
      replacementFor: () => "SSS",
    });
    expect(out.text).not.toContain("AAA");
  });
  it("unions overlapping findings and prefers secret treatment", () => {
    const text = "abcdefghij";
    const out = planRedaction({
      text,
      findings: [
        loc({ ruleId: "a", category: "pii", secretValue: "cde", start: 2, end: 5 }),
        loc({ ruleId: "b", category: "secret", secretValue: "defg", start: 3, end: 7 }),
      ],
      trips: [],
      replacementFor: (f) => (f.category === "secret" ? "S" : "P"),
    });
    expect(out.text).toBe("abS hij".replace(" ", ""));
  });
  it("omission swallows intersecting findings without fragments", () => {
    const text = "xxSECRETyy";
    const out = planRedaction({
      text,
      findings: [loc({ category: "secret", secretValue: "SECRET", start: 2, end: 8 })],
      trips: [{ start: 0, end: 4 }],
      replacementFor: () => "S",
    });
    expect(out.text).not.toContain("SECRET");
    expect(out.text).not.toContain("SEC");
    expect(out.text).toContain("omitted");
  });
  it("fails closed on invalid offsets", () => {
    const out = planRedaction({
      text: "hello",
      findings: [loc({ secretValue: "zzz", start: 0, end: 3 })],
      trips: [],
      replacementFor: () => "X",
    });
    expect(out.text).toContain("omitted 5 chars (invalid scan offsets)");
  });
});
