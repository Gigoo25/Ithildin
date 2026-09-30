import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  compileGeneralizeList,
  compileInventoryList,
  compileRule,
  generalizeList,
  MAX_INVENTORY_ENTRIES,
  readConfigFile,
  readUserSettings,
  type RuleConfig,
} from "./rules.ts";

// Config loading runs once at import; these call its pieces directly so each
// branch runs in this process. Warnings go to stderr and are captured here.
let warnings: string[] = [];
let stderr: ReturnType<typeof spyOn>;
beforeEach(() => {
  warnings = [];
  stderr = spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
    warnings.push(String(chunk));
    return true;
  });
});
afterEach(() => stderr.mockRestore());

describe("readConfigFile", () => {
  let dir = "";
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "canary-config-file-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("reads JSON, and is silent when the file is absent", () => {
    writeFileSync(join(dir, "ok.json"), '{"rules":[]}');
    expect(readConfigFile(join(dir, "ok.json"), "user config")).toEqual({ rules: [] });
    expect(readConfigFile(join(dir, "none.json"), "user config")).toBeUndefined();
    expect(warnings).toEqual([]);
  });

  it("warns without details on a non-file or broken JSON", () => {
    mkdirSync(join(dir, "sub"));
    expect(readConfigFile(join(dir, "sub"), "user config")).toBeUndefined();
    writeFileSync(join(dir, "bad.json"), '{"rules": [ zzzq-private');
    expect(readConfigFile(join(dir, "bad.json"), "generalize file")).toBeUndefined();
    expect(warnings).toEqual([
      "sensitive-canary: user config is not a regular file, ignoring\n",
      "sensitive-canary: could not read generalize file (details withheld)\n",
    ]);
    expect(warnings.join("")).not.toContain("zzzq");
  });
});

describe("readUserSettings", () => {
  it("takes every valid setting", () => {
    const rules = [{ id: "r", description: "d", regex: "x", category: "pii" }];
    const settings = readUserSettings(
      {
        contextWindow: 5,
        rules,
        inventory: [{ id: "i" }],
        generalize: [{ id: "g" }],
        aliasKey: "shared",
        aliases: "tokens",
        scanBudgetMs: 45000,
      },
      null,
    );
    expect(settings).toEqual({
      contextWindow: 5,
      ruleConfigs: rules as RuleConfig[],
      inventory: [{ id: "i" }],
      generalize: [{ id: "g" }],
      aliasKey: "shared",
      aliases: "tokens",
      scanBudgetMs: 45000,
    });
    expect(warnings).toEqual([]);
  });

  it("defaults for a missing or non-object config", () => {
    const defaults = {
      contextWindow: null,
      ruleConfigs: [],
      inventory: [],
      generalize: [],
      aliasKey: "session",
      aliases: "stand-ins",
      scanBudgetMs: null,
    };
    for (const config of [undefined, null, 5, "text", {}])
      expect(readUserSettings(config, null)).toEqual(defaults as never);
    expect(warnings).toEqual([]);
  });

  it("ignores each invalid setting with a warning", () => {
    const settings = readUserSettings(
      {
        contextWindow: 0,
        rules: {},
        inventory: "x",
        generalize: 1,
        aliasKey: "global",
        aliases: "names",
        scanBudgetMs: "12ms",
      },
      null,
    );
    expect(settings).toEqual({
      contextWindow: null,
      ruleConfigs: [],
      inventory: [],
      generalize: [],
      aliasKey: "session",
      aliases: "stand-ins",
      scanBudgetMs: null,
    });
    expect(warnings).toHaveLength(7);
    for (const warning of warnings) expect(warning).toMatch(/^sensitive-canary: .*, ignoring\n$/);
    expect(readUserSettings({ contextWindow: 2.5 }, null).contextWindow).toBeNull();
  });

  it("lets the environment budget win, without judging the file's", () => {
    expect(readUserSettings({ scanBudgetMs: 45000 }, 1000).scanBudgetMs).toBe(1000);
    expect(readUserSettings({ scanBudgetMs: "junk" }, 1000).scanBudgetMs).toBe(1000);
    expect(readUserSettings({ scanBudgetMs: "2500" }, null).scanBudgetMs).toBe(2500);
    expect(warnings).toEqual([]);
  });
});

describe("generalize and inventory lists", () => {
  it("reads a bare array or a wrapped one", () => {
    expect(generalizeList(undefined)).toEqual([]);
    expect(generalizeList([{ id: "a" }])).toEqual([{ id: "a" }]);
    expect(generalizeList({ generalize: [{ id: "b" }] })).toEqual([{ id: "b" }]);
    expect(warnings).toEqual([]);
    expect(generalizeList({ generalize: "x" })).toEqual([]);
    expect(generalizeList(null)).toEqual([]);
    expect(warnings).toHaveLength(2);
  });

  it("keeps the first of duplicate ids and drops invalid entries", () => {
    const rules = compileGeneralizeList([
      { id: "fruit", terms: ["zqxapple"], replace: "a fruit" },
      { id: "fruit", terms: ["zqxpear"], replace: "a fruit" },
      { id: "bad id", terms: ["x"], replace: "y" },
    ]);
    expect(rules.map((rule) => rule.regex.test("zqxapple"))).toEqual([true]);
    expect(warnings).toHaveLength(2);
    expect(warnings.join("")).not.toContain("zqx");
  });

  it("rejects each malformed generalize entry", () => {
    const long = "x".repeat(81);
    const bad = [
      null,
      { id: "a" },
      { id: "a", terms: [] },
      { id: "a", terms: ["line\nbreak"], replace: "y" },
      { id: "a", terms: ["t"], replace: long },
      { id: "a", terms: ["t"], replace: "y", caseSensitive: "yes" },
      { id: "a", terms: ["t"], replace: "y", scope: "nowhere" },
    ];
    expect(compileGeneralizeList(bad)).toEqual([]);
    expect(warnings).toHaveLength(bad.length);
  });

  it("truncates an inventory over the cap", () => {
    const entries = Array.from({ length: MAX_INVENTORY_ENTRIES + 1 }, (_, i) => ({
      id: `e${i}`,
      literal: `Zqxentry${i}`,
      match: "token",
    }));
    expect(compileInventoryList(entries)).toHaveLength(MAX_INVENTORY_ENTRIES);
    expect(warnings[0]).toContain("truncating");
  });
});

describe("compileRule", () => {
  const base = { id: "r", description: "d", regex: "zqx\\d+", category: "pii" } as RuleConfig;

  it("compiles a minimal rule with the global and indices flags", () => {
    const rule = compileRule({ ...base, flags: "i", validate: "luhn", label: "card" });
    expect(rule.regex.flags).toContain("g");
    expect(rule.regex.flags).toContain("i");
    expect(typeof rule.validate).toBe("function");
  });

  it("rejects each malformed field", () => {
    const cases: Array<[unknown, RegExp]> = [
      [null, /must be an object/],
      [{ ...base, id: "" }, /"id"/],
      [{ ...base, description: 1 }, /"description"/],
      [{ ...base, regex: "" }, /"regex"/],
      [{ ...base, category: "other" }, /"category"/],
      [{ ...base, flags: 1 }, /"flags"/],
      [{ ...base, secretGroup: -1 }, /"secretGroup"/],
      [{ ...base, secretGroup: 1.5 }, /"secretGroup"/],
      [{ ...base, entropyThreshold: -1 }, /"entropyThreshold"/],
      [{ ...base, validate: 3 }, /"validate"/],
      [{ ...base, excludeContext: [""] }, /"excludeContext"/],
      [{ ...base, contextWords: "word" }, /"contextWords"/],
      [{ ...base, requireContext: "yes" }, /"requireContext"/],
      [{ ...base, contextWindow: 0 }, /"contextWindow"/],
      [{ ...base, requireContext: true, contextWords: [] }, /"requireContext" is true/],
      [{ ...base, label: "Two Words" }, /label/],
      [{ ...base, validate: "no-such" }, /unknown validator/],
      [{ ...base, regex: "(" }, /./],
    ];
    for (const [config, message] of cases)
      expect(() => compileRule(config as RuleConfig)).toThrow(message);
  });
});
