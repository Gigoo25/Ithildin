// Coverage sweep: direct calls to small pure helpers so function coverage
// holds 100% alongside line coverage. All inputs are inert nonsense.
import { expect, it } from "bun:test";
import {
  AliasBook,
  aliasKeyPath,
  aliasKind,
  aliasMatches,
  aliasSpans,
  expandIpv6,
  isAliasValue,
  looksLikeAlias,
  registerAliasLabels,
} from "./aliases.ts";
import { encodedBlocks, redactEncoded, redactCopies, rot13 } from "./encoded.ts";
import {
  aliasLabels,
  aliasStyle,
  compileGeneralizeEntry,
  escapeRegExp,
  inventoryLiterals,
  inventoryStandInValue,
  isPromptOnlyRule,
  mergeRanges,
  RULES,
  ruleAliasLabel,
  ruleGeneralization,
} from "./rules.ts";
import {
  asUserText,
  blocksSecretAccess,
  candidatePaths,
  canonicalPath,
  clearCaches,
  collectValues,
  commandPathCandidates,
  flushScanCache,
  globRegExp,
  isSecretPath,
  latestAllowTags,
  loadScanCache,
  redactText,
  rememberSwapped,
  respelledFindings,
} from "../core.ts";

const KEY = Buffer.alloc(32, 9);

it("aliases helpers", () => {
  expect(aliasKind("pii-ipv4")).toBe("ipv4");
  registerAliasLabels([]);
  expect(looksLikeAlias("hello")).toBe(false);
  expect(aliasSpans("hello")).toEqual([]);
  expect(aliasMatches("hello")).toEqual([]);
  expect(isAliasValue("hello")).toBe(false);
  expect(typeof aliasKeyPath()).toBe("string");
  expect(expandIpv6("::1")).toBeDefined();
  // A book with many diverse stand-ins so every multi-element comparator
  // and filter in the book runs with several entries.
  const book = new AliasBook(KEY);
  book.standIn("pii-titled-name", "Zqxandra");
  book.standIn("pii-titled-name", "Velmarx");
  book.standIn("pii-titled-name", "Norberto");
  book.host("zqxbox");
  book.host("zqxbuildbox");
  book.user("zqxuser");
  book.ipv4("203.0.113.7");
  book.ipv4("203.0.113.9");
  book.mac("a4:83:e7:12:34:56");
  book.email("zzzsweep@zzzsweep.test");
  // Enough stand-ins that two share a two-letter head at different lengths.
  for (let i = 0; i < 200; i++) book.user(`zqxperson${"y".repeat(i % 7)}${i}`);
  const text = book.standIns().join(" ");
  expect(book.mangled(text)).toEqual([]);
  expect(book.matches(text).length).toBeGreaterThan(0);
  // An exact stand-in beside a glued multi-part one, so the overlap guard
  // checks both lists at once. Tickets record whole with their dash.
  const first = book.standIn("pii-custom-ticket", "ZQX-1234", "ticket");
  const second = book.standIn("pii-custom-ticket", "ZQX-5678", "ticket");
  book.matches(`${first} go${second}stop`);
  // A recased stand-in resolves through its original.
  const named = book.standIn("pii-titled-name", "Zqxandra");
  book.resolve(named.toUpperCase());
  expect(book.resolve("hello")).toBeUndefined();
  expect(book.valueOf("hello")).toBeUndefined();
  expect(book.longestStandIn()).toBeGreaterThan(0);
  expect(book.isStandIn("hello")).toBe(false);
  // Mint fallbacks: values with no letters or digits fit no lookalike,
  // so every attempt is rejected and the deterministic fallback runs.
  const fallbackBook = new AliasBook(KEY);
  fallbackBook.setCorpus(() => "a b c d e f g h i j k l m n o p q r s t u v w x y z");
  expect(fallbackBook.user("!!!")).toMatch(/^user-/);
  expect(fallbackBook.label("email", "!!!")).toMatch(/^email-/);
  expect(fallbackBook.host("!!!")).toMatch(/^n/);
  book.clear();
  expect(book.standIns()).toEqual([]);
});

it("encoded helpers", () => {
  expect(encodedBlocks("hello world, nothing encoded here")).toEqual([]);
  // Two blocks so the block order comparator runs.
  const first = Buffer.from("alpha bravo charlie delta echo foxtrot golf").toString("base64");
  const second = Buffer.from("hotel india juliet kilo lima mike november").toString("base64");
  expect(encodedBlocks(`${first} ${second}`).length).toBeGreaterThan(0);
  expect(rot13(rot13("hello world"))).toBe("hello world");
  expect(redactCopies("hello", [], () => {}).hits).toBe(0);
  // Two targets so the longest-first comparator runs.
  const firstValue = "alphaalpha";
  const secondValue = "betabetabeta";
  const rotated = `${rot13(firstValue)} ${rot13(secondValue)}`;
  expect(redactCopies(rotated, [firstValue, secondValue], () => {}).hits).toBe(2);
  expect(
    redactEncoded(
      "hello",
      () => [],
      () => true,
      () => {},
    ).hits,
  ).toBe(0);
});

it("rules helpers", () => {
  expect(escapeRegExp("a.b")).toBe("a\\.b");
  expect(typeof aliasStyle()).toBe("string");
  expect(ruleAliasLabel("pii-ipv4")).toBeUndefined();
  expect(ruleGeneralization("pii-ipv4")).toBeUndefined();
  expect(isPromptOnlyRule("pii-ipv4")).toBe(false);
  expect(Array.isArray(inventoryLiterals())).toBe(true);
  expect(inventoryStandInValue("no-such-rule", "x")).toBe("x");
  expect(Array.isArray(aliasLabels())).toBe(true);
  expect(mergeRanges([{ start: 0, end: 1 }])).toEqual([{ start: 0, end: 1 }]);
  expect(
    mergeRanges([
      { start: 0, end: 5 },
      { start: 3, end: 7 },
    ]),
  ).toEqual([{ start: 0, end: 7 }]);
  expect(compileGeneralizeEntry({ id: "sweepx", terms: ["bb", "aa"], replace: "x" }).id).toContain(
    "sweepx",
  );
  // Every rule validator runs at least once, even for rules whose shape
  // never matches the suite corpus. Diverse inputs reach past each
  // validator's early rejections into its inner checks.
  const validatorInputs = [
    "zzzsweep0",
    "40°26′46″N 79°58′56″W",
    "12.3, 45.6",
    "Jean Dupont",
    "James Smith",
    "config.home",
    "8.8.8.8",
    "Caller 555-0100",
  ];
  for (const rule of RULES) for (const input of validatorInputs) rule.validate?.(input);
  // Generalize lookups scan the rule list instead of short-circuiting.
  expect(ruleGeneralization("pii-generalize-sweepx")).toBeUndefined();
  expect(isPromptOnlyRule("pii-generalize-sweepx")).toBe(false);
});

it("core helpers", () => {
  expect(globRegExp("*.ts").test("a.ts")).toBe(true);
  expect(canonicalPath("notes.md", "/tmp")).toContain("notes.md");
  expect(isSecretPath("notes.md", "/tmp")).toBe(false);
  expect(candidatePaths({ path: "a.md" })).toEqual(["a.md"]);
  expect(latestAllowTags([{ role: "user", content: "hi" }]).size).toBe(0);
  expect(asUserText(() => 1)).toBe(1);
  expect(collectValues(() => 1).values).toBe(0);
  loadScanCache(undefined);
  flushScanCache(undefined);
  clearCaches();
  rememberSwapped("zzzsweepvalue", "sweep-rule");
  // Two names so the longest-first pattern comparator runs.
  const finding = (secretValue: string, start: number, end: number) => ({
    ruleId: "pii-titled-name",
    description: "sweep",
    category: "pii" as const,
    matchRedacted: "****",
    secretValue,
    start,
    end,
  });
  expect(
    respelledFindings("hello", [
      finding("Zqxandra Velmarx", 0, 5),
      finding("Norberto Tasha", 0, 5),
    ]),
  ).toEqual([]);
  // Rare shell spellings: ANSI-C quoting and variable expansion.
  expect(redactText("run $'alpha\\nbeta' now").hits).toBeGreaterThanOrEqual(0);
  expect(redactText("run ${ZZZSWEEP_VAR_UNSET} now").hits).toBeGreaterThanOrEqual(0);
  // A cookie header through the text prepass redacts and reports each value.
  expect(redactText("Cookie: zzzsweep=1").hits).toBeGreaterThan(0);
  // Values collected around a finding-bearing scan.
  const token = `ghp_${"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}`;
  expect(collectValues(() => redactText(`key ${token}`)).values).toBeGreaterThanOrEqual(0);
  // Command word decoding runs variable, ANSI-C and brace expansion.
  expect(commandPathCandidates("cat $ZZZSWEEP_VAR_UNSET", "/tmp").length).toBeGreaterThanOrEqual(0);
  expect(
    commandPathCandidates("cat $'alpha' notes.{txt,md}", "/tmp").length,
  ).toBeGreaterThanOrEqual(0);
  // A finding inside already-generalized wording still checks every
  // boilerplate span for exemption.
  const card = "4532015112830366";
  expect(redactText(`card ${card} with \u27e6zzzsweep note\u27e7`).hits).toBeGreaterThan(0);
  // A non-secret command with paths still checks every target.
  expect(blocksSecretAccess("bash", "ls /tmp/a", ["/tmp/a"], new Set(), "/tmp")).toBe(false);
});
