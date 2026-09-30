import { expect, it } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyUserOverrides, compileInventoryEntry } from "./rules.ts";

const RULES_URL = JSON.stringify(new URL("./rules.ts", import.meta.url).href);

it("loads file overrides and inventory before import in an isolated fresh process", () => {
  // Unique system-temp directory. Intentionally retained; no recursive deletion.
  const home = mkdtempSync(join(tmpdir(), "ithildin-config-check-"));
  const file = join(home, "config.json");
  const defaultConfig = JSON.parse(
    readFileSync(new URL("./default-config.json", import.meta.url), "utf8"),
  );
  const defaultRule = defaultConfig.rules.find((r: { validate?: string }) => !r.validate);
  const overrides = [
    {
      id: defaultRule.id,
      description: "fixture",
      regex: "fixture-default-only",
      category: defaultRule.category,
    },
    {
      id: "generic-secret",
      description: "fixture",
      regex: "fixture-local-only",
      category: "secret",
    },
  ];
  writeFileSync(
    file,
    JSON.stringify({
      rules: overrides,
      inventory: [{ id: "fixture", literal: "Invented Tenant", match: "phrase" }],
    }),
    { mode: 0o600 },
  );
  const ids = JSON.stringify(overrides.map((r) => r.id));
  const script =
    `const m=await import(${RULES_URL}); console.log(JSON.stringify({ rules: ${ids}` +
    ".map(id=>m.RULES.filter(r=>r.id===id).map(r=>r.regex.source)), " +
    "inventory:m.RULES.filter(r=>r.id==='pii-inventory-fixture').length }));";
  const child = Bun.spawnSync({
    cmd: [process.execPath, "-e", script],
    env: {
      ...process.env,
      HOME: home,
      XDG_CACHE_HOME: join(home, "cache"),
      ITHILDIN_CONFIG: file,
    },
    timeout: 10000,
  });
  expect(child.exitCode).toBe(0);
  const report = JSON.parse(child.stdout.toString());
  expect(report.rules).toEqual(overrides.map((r) => [r.regex]));
  expect(report.inventory).toBe(1);
});

it("rejects unknown validators and invalid regexes without replacing built-ins", () => {
  const original = {
    id: "fixture",
    description: "fixture",
    regex: /retain/g,
    category: "pii" as const,
    validate: () => true,
  };
  for (const bad of [{ regex: "(" }, { regex: "private", validate: "not-a-validator" }]) {
    expect(
      applyUserOverrides(
        [original],
        [{ id: "fixture", description: "fixture", category: "pii", ...bad }],
      ),
    ).toEqual([original]);
  }
  const rules = applyUserOverrides(
    [original],
    [
      { id: "new-fixture", description: "fixture", regex: "retain-last-valid", category: "pii" },
      { id: "new-fixture", description: "fixture", regex: "(", category: "pii" },
    ],
  );
  expect(rules.find((r) => r.id === "new-fixture")?.regex.source).toBe("retain-last-valid");
});
it("literal inventory preserves phrase spacing, domain punctuation and field types", () => {
  const rule = compileInventoryEntry({
    id: "fixture",
    literal: ["invented", "example", "invalid"].join("."),
    match: "token",
  });
  expect(rule.regex.test(["invented", "example", "invalid"].join("."))).toBe(true);
  expect(rule.regex.test("inventedXexampleXinvalid")).toBe(false);
  const phrase = compileInventoryEntry({
    id: "phrase",
    literal: "Invented  Team",
    match: "phrase",
  });
  expect(phrase.regex.test("Invented Team")).toBe(false);
  expect(() =>
    compileInventoryEntry({ id: "bad", literal: "Fixture", match: "token", caseSensitive: null }),
  ).toThrow();
});
it("honors scanBudgetMs from the user config and the environment override", () => {
  const home = mkdtempSync(join(tmpdir(), "ithildin-budget-check-"));
  const file = join(home, "config.json");
  const script =
    `const m=await import(${RULES_URL}); ` +
    "console.log(JSON.stringify({budget:m.currentScanBudgetMs()," +
    "default:m.DEFAULT_SCAN_BUDGET_MS}));";
  const base: Record<string, string | undefined> = {
    ...process.env,
    HOME: home,
    XDG_CACHE_HOME: join(home, "cache"),
    ITHILDIN_CONFIG: file,
  };
  delete base.ITHILDIN_SCAN_BUDGET_MS;
  writeFileSync(file, JSON.stringify({ scanBudgetMs: 45000, rules: [] }), { mode: 0o600 });
  const fromConfig = Bun.spawnSync({
    cmd: [process.execPath, "-e", script],
    env: base,
    timeout: 10000,
  });
  expect(fromConfig.exitCode).toBe(0);
  expect(JSON.parse(fromConfig.stdout.toString()).budget).toBe(45000);
  // The environment is the per-invocation override and wins over the file.
  const fromEnv = Bun.spawnSync({
    cmd: [process.execPath, "-e", script],
    env: { ...base, ITHILDIN_SCAN_BUDGET_MS: "60000" },
    timeout: 10000,
  });
  expect(JSON.parse(fromEnv.stdout.toString()).budget).toBe(60000);
  // An invalid file value falls back to the default, never to zero.
  writeFileSync(file, JSON.stringify({ scanBudgetMs: -5, rules: [] }), { mode: 0o600 });
  const invalid = Bun.spawnSync({
    cmd: [process.execPath, "-e", script],
    env: base,
    timeout: 10000,
  });
  const report = JSON.parse(invalid.stdout.toString());
  expect(report.budget).toBe(report.default);
});
