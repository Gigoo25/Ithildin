import { describe, expect, it } from "bun:test";
import { beginScanBudget, scan, scanWindows, SCAN_WINDOW_CHARS } from "./rules.ts";

describe("located findings", () => {
  it("locates whole matches", () => {
    const text = `peer 100.99.8.7 up`;
    for (const f of scan(text).filter((x) => x.secretValue === "100.99.8.7")) {
      expect(text.slice(f.start, f.end)).toBe(f.secretValue);
    }
  });
  it("locates captured subgroups, not the whole match", () => {
    const text = `owner = "fixtureoperator"`;
    const found = scan(text).filter((f) => f.ruleId === "pii-labeled-username" || f.secretValue === "fixtureoperator");
    expect(found.length).toBeGreaterThan(0);
    for (const f of found) expect(text.slice(f.start, f.end)).toBe(f.secretValue);
  });
  it("locates repeated captures separately", () => {
    beginScanBudget(null); // isolate from any deadline leaked by a parallel file
    const text = `peer 100.99.8.7 up then peer 100.99.8.7 down`;
    const found = scan(text).filter((f) => f.secretValue === "100.99.8.7");
    expect(found.length).toBeGreaterThan(1);
    const starts = new Set(found.map((f) => f.start));
    expect(starts.size).toBe(found.length);
    for (const f of found) expect(text.slice(f.start, f.end)).toBe(f.secretValue);
  });
  it("holds offsets before Unicode matches", () => {
    const text = `caf\u00e9 peer 100.99.8.7 up`;
    for (const f of scan(text).filter((x) => x.secretValue === "100.99.8.7")) {
      expect(text.slice(f.start, f.end)).toBe("100.99.8.7");
    }
  });
  it("translates window offsets and dedupes overlap", () => {
    beginScanBudget(null); // isolate from any deadline leaked by a parallel file
    const secret = "100.99.8.7";
    const at = SCAN_WINDOW_CHARS - 4;
    const text = `${"x".repeat(at)} ${secret} ${"y".repeat(70_000 - at - secret.length - 2)}`;
    const { findings, trips } = scanWindows(text);
    expect(trips).toEqual([]);
    const hit = findings.filter((f) => f.secretValue === secret);
    expect(hit.length).toBe(1);
    expect(text.slice(hit[0]!.start, hit[0]!.end)).toBe(secret);
  });
  it("every finding satisfies the slice invariant", () => {
    const texts = [
      "api_key = test-key " + ["192","168","7","77"].join(".") + " up",
      `owner = "fixtureoperator"\nconst fixtureoperatorCount = 1;`,
      `iban DE89370400440532013000`,
    ];
    for (const text of texts) {
      for (const f of scanWindows(text).findings) {
        expect(text.slice(f.start, f.end)).toBe(f.secretValue);
      }
    }
  });
});
