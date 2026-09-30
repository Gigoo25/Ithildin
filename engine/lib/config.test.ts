import { describe, expect, it } from "bun:test";
import {
  applyUserOverrides,
  compileInventoryEntry,
  compileInventoryList,
  compileRule,
} from "./rules.ts";

describe("user rule precedence", () => {
  it("overrides one default rule and one local rule by id", () => {
    const base = [
      { id: "d1", description: "d", regex: /aaa/g, category: "pii" as const },
      { id: "generic-secret", description: "g", regex: /bbb/g, category: "secret" as const },
    ];
    const out = applyUserOverrides(base, [
      { id: "d1", description: "d2", regex: "zzz", category: "pii" },
      { id: "generic-secret", description: "g2", regex: "yyy", category: "secret" },
    ]);
    expect(out.map((r) => r.id).sort()).toEqual(["d1", "generic-secret"]);
    expect(out.find((r) => r.id === "d1")!.regex.source).toBe("zzz");
    expect(out.find((r) => r.id === "generic-secret")!.regex.source).toBe("yyy");
  });
  it("keeps the built-in when an override drops its validator", () => {
    const base = [
      {
        id: "iban",
        description: "i",
        regex: /\bX\b/g,
        category: "pii" as const,
        validate: () => true,
      },
    ];
    const out = applyUserOverrides(base, [
      { id: "iban", description: "i2", regex: "\\bX\\b", category: "pii" },
    ]);
    expect(out[0]!.validate).toBeDefined();
  });
  it("a malformed new rule does not remove unrelated built-ins", () => {
    const base = [{ id: "ok", description: "o", regex: /ok/g, category: "pii" as const }];
    const out = applyUserOverrides(base, [
      { id: "bad", description: "", regex: "", category: "pii" } as never,
    ]);
    expect(out.map((r) => r.id)).toEqual(["ok"]);
  });
  it("last duplicate custom id wins without duplicating findings", () => {
    const out = applyUserOverrides(
      [],
      [
        { id: "x", description: "a", regex: "aa", category: "pii" },
        { id: "x", description: "b", regex: "bb", category: "pii" },
      ],
    );
    expect(out).toHaveLength(1);
    expect(out[0]!.regex.source).toBe("bb");
  });
  it("invalid values are not printed in diagnostics", () => {
    const err: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: (s: string) => boolean }).write = (s: string) => {
      err.push(s);
      return true;
    };
    try {
      applyUserOverrides(
        [],
        [
          {
            id: "private-fixture-id",
            description: "fixture",
            regex: "(private-regex-body",
            category: "pii",
          } as never,
        ],
      );
      applyUserOverrides(
        [],
        [
          {
            id: "private-fixture-id",
            description: "fixture",
            regex: "private-regex-body",
            validate: "private-validator",
            category: "pii",
          },
        ],
      );
      compileInventoryList([
        { id: "private-inventory-id", literal: "private-inventory-body", match: "invalid" },
      ]);
    } finally {
      process.stderr.write = orig as never;
    }
    expect(err.length).toBeGreaterThan(0);
    for (const value of [
      "private-fixture-id",
      "private-regex-body",
      "private-validator",
      "private-inventory-id",
      "private-inventory-body",
    ])
      expect(err.join("")).not.toContain(value);
  });
});

describe("private literal inventory", () => {
  it("matches exact names and escapes metacharacters", () => {
    const rule = compileInventoryEntry({ id: "t1", literal: "Acme.Co+", match: "token" });
    expect("call Acme.Co+ today".match(rule.regex)?.[0]).toBe("Acme.Co+");
    expect("call AcmeXCo today".match(rule.regex)).toBeNull();
  });
  it("uses unicode token boundaries and exact case by default", () => {
    const rule = compileInventoryEntry({ id: "t2", literal: "Käse", match: "token" });
    expect("Käse!".match(rule.regex)?.[0]).toBe("Käse");
    expect("käse".match(rule.regex)).toBeNull();
    expect("Käsebrett".match(rule.regex)).toBeNull();
  });
  it("supports case-insensitive and phrase modes", () => {
    const ci = compileInventoryEntry({
      id: "t3",
      literal: "Acme",
      match: "token",
      caseSensitive: false,
    });
    expect("acme".match(ci.regex)?.[0]).toBe("acme");
    const phrase = compileInventoryEntry({ id: "t4", literal: "Acme Corp", match: "phrase" });
    expect("Acme Corp!".match(phrase.regex)?.[0]).toBe("Acme Corp");
  });
  it("rejects empty literals, bad modes, and duplicates", () => {
    expect(() => compileInventoryEntry({ id: "e", literal: "   ", match: "token" })).toThrow();
    expect(() => compileInventoryEntry({ id: "e", literal: "x", match: "nope" })).toThrow();
    const list = compileInventoryList([
      { id: "d", literal: "Alpha", match: "token" },
      { id: "d", literal: "Beta", match: "token" },
    ]);
    expect(list).toHaveLength(1);
    expect(list[0]!.regex.source).toContain("Alpha");
  });
  it("inventory ids never override built-ins", () => {
    const list = compileInventoryList([{ id: "x", literal: "Zed", match: "token" }]);
    expect(list[0]!.id.startsWith("pii-inventory-")).toBe(true);
    expect(list[0]!.category).toBe("pii");
  });
  it("file overrides share one pass over defaults and locals", () => {
    // Safe pure-function equivalent of the file-override path: the module
    // init calls applyUserOverrides(defaults + locals, fileRules), so one
    // custom id replaces a local rule instead of duplicating it.
    const out = applyUserOverrides(
      [
        { id: "d1", description: "d", regex: /aaa/g, category: "pii" as const },
        { id: "generic-secret", description: "g", regex: /bbb/g, category: "secret" as const },
      ],
      [{ id: "generic-secret", description: "t", regex: "zzz-only-in-test", category: "secret" }],
    );
    expect(out.filter((r) => r.id === "generic-secret")).toHaveLength(1);
    expect(out.find((r) => r.id === "generic-secret")!.regex.source).toBe("zzz-only-in-test");
    expect(out.some((r) => r.id === "d1")).toBe(true);
  });
  it("example config stays inert", async () => {
    const config = (await Bun.file(`${import.meta.dir}/../user-config.example.json`).json()) as {
      rules: Array<{ id: string }>;
    };
    for (const rule of config.rules) expect(() => compileRule(rule as never)).not.toThrow();
  });
});
