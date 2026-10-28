import { describe, expect, it } from "bun:test";
import { occurrences, planRedaction } from "./redaction-spans.ts";
import type { LocatedFinding } from "./rules.ts";

function loc(
  partial: Partial<LocatedFinding> & { start: number; end: number; secretValue: string },
): LocatedFinding {
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
  it("mints the stand-in for the rule that found the whole span", () => {
    const text = "cd /home/qorvalt/x";
    const start = text.indexOf("/home/");
    const user = text.indexOf("qorvalt");
    const out = planRedaction({
      text,
      findings: [
        loc({ ruleId: "pii-fleet-user", secretValue: "qorvalt", start: user, end: user + 7 }),
        loc({ ruleId: "pii-home-user", secretValue: "qorvalt", start: user, end: user + 7 }),
        loc({
          ruleId: "pii-inventory-runtime-home",
          secretValue: "/home/qorvalt",
          start,
          end: user + 7,
        }),
      ],
      trips: [],
      replacementFor: (finding) => `<${finding.ruleId}:${finding.secretValue}>`,
    });
    expect(out.text).toBe("cd <pii-inventory-runtime-home:/home/qorvalt>/x");
  });

  it("edits a value inside a JSON string in place, and the whole string past an escape", () => {
    const plan = (text: string, value: string) => {
      const start = text.indexOf(value);
      const scalars = [...text.matchAll(/"(?:[^"\\]|\\.)*"/g)].map((m) => ({
        start: m.index,
        end: m.index + m[0].length,
        jsonKind: "json-string" as const,
      }));
      return planRedaction({
        text,
        findings: [loc({ secretValue: value, start, end: start + value.length })],
        trips: [],
        scalars,
        replacementFor: (finding) =>
          "jsonKind" in finding && finding.jsonKind ? '"<whole>"' : '<"part">',
      }).text;
    };
    // Promoted always, the whole command went out as one made-up word.
    expect(plan('{"command":"ls host.internal/api"}', "host.internal")).toBe(
      '{"command":"ls <\\"part\\">/api"}',
    );
    expect(plan('{"a":"x\\nhost.internal"}', "nhost.internal")).toBe('{"a":"<whole>"}');
    expect(plan('{"a":"\\u0041host.internal"}', "041host.internal")).toBe('{"a":"<whole>"}');
    expect(plan('{"a":"x\\"host\\" y"}', 'host\\" y')).toBe('{"a":"<whole>"}');
    expect(plan('{"a":"x\\\\host"}', "host")).toBe('{"a":"x\\\\<\\"part\\">"}');
  });

  it("prefers a scanning rule over a value remembered for the same span", () => {
    const text = "cd /home/qorvalt/x";
    const start = text.indexOf("/home/");
    const end = start + "/home/qorvalt".length;
    const out = planRedaction({
      text,
      findings: [
        loc({
          ruleId: "pii-fleet-user",
          matchRedacted: "[swapped]",
          secretValue: "/home/qorvalt",
          start,
          end,
        }),
        loc({ ruleId: "pii-inventory-runtime-home", secretValue: "/home/qorvalt", start, end }),
      ],
      trips: [],
      replacementFor: (finding) => `<${finding.ruleId}:${finding.secretValue}>`,
    });
    expect(out.text).toBe("cd <pii-inventory-runtime-home:/home/qorvalt>/x");
  });

  it("keeps the home directory once it was remembered under a user rule", async () => {
    const { clearCaches, redactText, rememberSwapped } = await import("../core.ts");
    const { setRuntimeInventory } = await import("./rules.ts");
    const { collectRuntimeIdentity } = await import("./runtime-inventory.ts");
    setRuntimeInventory(collectRuntimeIdentity({ username: "qorvalt", homedir: "/home/qorvalt" }));
    try {
      rememberSwapped("/home/qorvalt", "pii-fleet-user");
      const out = redactText("Working directory: /home/qorvalt/Projects/x").text;
      expect(out).toStartWith("Working directory: /home/");
      expect(out).not.toContain("qorvalt");
    } finally {
      setRuntimeInventory([]);
      clearCaches();
    }
  });

  it("keeps the home directory's own name when masking a user's home", async () => {
    const { redactText } = await import("../core.ts");
    const { setRuntimeInventory } = await import("./rules.ts");
    const { collectRuntimeIdentity } = await import("./runtime-inventory.ts");
    setRuntimeInventory(collectRuntimeIdentity({ username: "qorvalt", homedir: "/home/qorvalt" }));
    try {
      const out = redactText("Working directory: /home/qorvalt/Projects/x").text;
      expect(out).toStartWith("Working directory: /home/");
      expect(out).not.toContain("qorvalt");
    } finally {
      setRuntimeInventory([]);
    }
  });

  it("redacts only the intended span, not longer identifiers", () => {
    const text = `username = "sampler"\nconst samplerCount = 3;`;
    const start = text.indexOf("sampler");
    const out = planRedaction({
      text,
      findings: [
        loc({ ruleId: "u", category: "pii", secretValue: "sampler", start, end: start + 7 }),
      ],
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
  it("fails closed when rendering throws", () => {
    const out = planRedaction({
      text: "hello world",
      findings: [loc({ secretValue: "hello", start: 0, end: 5 })],
      trips: [],
      replacementFor: () => {
        throw new Error("test");
      },
    });
    expect(out.text).toContain("omitted 11 chars (invalid scan offsets)");
  });
  it("fails closed when the budget check throws", () => {
    let calls = 0;
    const out = planRedaction({
      text: "hello world",
      findings: [loc({ secretValue: "hello", start: 0, end: 5 })],
      trips: [],
      replacementFor: () => "X",
      checkBudget: () => {
        if (++calls > 1) throw new Error("budget");
      },
    });
    expect(out.text).toContain("omitted 11 chars (invalid scan offsets)");
  });
});

describe("occurrences", () => {
  // Every start, overlapping ones included, whichever search finds them.
  const naive = (text: string, value: string): number[] => {
    const found: number[] = [];
    for (let at = text.indexOf(value); at >= 0; at = text.indexOf(value, at + 1)) found.push(at);
    return found;
  };

  it("finds overlapping starts of a short and a long value alike", () => {
    const unit = "abcabd".repeat(20);
    const text = `x${unit.repeat(9)}y${unit.slice(0, 50)}`;
    for (const value of ["abcab", unit.slice(0, 70), unit.repeat(2) + "a", "q".repeat(80)])
      expect(occurrences(text, value, () => {})).toEqual(naive(text, value));
  });

  it("checks the budget at each one it finds", () => {
    let checks = 0;
    occurrences("ab".repeat(100), "ab".repeat(40), () => checks++);
    expect(checks).toBe(61);
  });
});
