import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import {
  entropy,
  isNotSecretShaped,
  isPlaceholder,
  keyDescribesRatherThanHolds,
} from "./shapes.ts";
import { getValidator, isReservedIpv4 } from "./validators.ts";
import { FIRST_NAMES } from "./first-names.ts";
import { ALIAS_LABEL } from "./aliases.ts";

export type Category = "secret" | "pii";

export interface Finding {
  ruleId: string;
  description: string;
  category: Category;
  matchRedacted: string;
  secretValue: string;
  score?: number;
}

// Half-open UTF-16 offsets into the exact text that was scanned:
// text.slice(start, end) === secretValue.
export interface LocatedFinding extends Finding {
  start: number;
  end: number;
}

// Normalize a rule regex once so match indices are always available.
// Preserves every other flag and matching semantics. It only adds g/d.
function ensureIndices(re: RegExp): RegExp {
  let flags = re.flags;
  if (!flags.includes("g")) flags += "g";
  if (!flags.includes("d")) flags += "d";
  if (flags === re.flags) return re;
  return new RegExp(re.source, flags);
}

interface Rule {
  id: string;
  description: string;
  regex: RegExp;
  secretGroup?: number;
  entropyThreshold?: number;
  validate?: (str: string) => boolean;
  category: Category;
  contextWords?: string[];
  requireContext?: boolean;
  // Words that, found near a match, say it is not what the rule is looking for —
  // the mirror of contextWords. The postal-code rule uses it: `65536 bytes` and
  // `max 3` are five-digit numbers beside a word that says they are not places.
  excludeContext?: string[];
  contextWindow?: number;
  // Stand-in label for PII findings (`person` -> person-3c9d0e).
  label?: string;
  // Exact inventory value, kept in memory so its stand-in can be minted at
  // session start and swapped back even when it has not appeared yet.
  inventoryLiteral?: string;
  // Generalized wording that replaces every match (see GeneralizeEntry).
  generalize?: string;
  generalizeScope?: "everywhere" | "prompts";
}

// JSON representation of a rule, as written in config files. The `regex` is a
// source string (not a RegExp literal), compiled at load time. `validate` is a
// name into the VALIDATORS registry.
export interface RuleConfig {
  id: string;
  description: string;
  regex: string;
  flags?: string;
  secretGroup?: number;
  entropyThreshold?: number;
  validate?: string;
  category: Category;
  contextWords?: string[];
  requireContext?: boolean;
  // See Rule.excludeContext.
  excludeContext?: string[];
  contextWindow?: number;
  // See Rule.label.
  label?: string;
}

// Top-level config file: a context window override plus a list of rules.
// User config files use the same shape and can override built-in rules by id.
export interface CanaryConfig {
  contextWindow?: number;
  // Per-hook scan envelope in milliseconds. Optional: the default is sized
  // for multi-megabyte sessions, and SENSITIVE_CANARY_SCAN_BUDGET_MS wins.
  scanBudgetMs?: number;
  // "stand-ins" (default): meaningful, stable replacements for PII.
  // "tokens": the older __CANARY_<TYPE>_<N>__ placeholders.
  aliases?: "stand-ins" | "tokens";
  // "session" (default): a new stand-in key per session, so stand-ins cannot
  // be linked across sessions. "shared": one key for every session.
  aliasKey?: "session" | "shared";
  rules: RuleConfig[];
  inventory?: InventoryEntry[];
  generalize?: GeneralizeEntry[];
}

// Words replaced by a general phrase, so meaning survives without the
// specifics: { id: "medical", terms: ["migraine", "headache"],
// replace: "minor neurological condition" }. Whole words, case-insensitive
// unless caseSensitive. One phrase stands for many terms, so it can never be
// swapped back.
export interface GeneralizeEntry {
  id: string;
  terms: string[];
  replace: string;
  caseSensitive?: boolean;
  // "everywhere" (default): prompts, tool output, and the provider payload.
  // "prompts": only text you type, so files that use these words (code,
  // configs) stay readable and editable.
  scope?: "everywhere" | "prompts";
}

export const GENERALIZE_ID_PREFIX = "pii-generalize-";
const MAX_GENERALIZE_TERMS = 1_000;

export interface InventoryEntry {
  id: string;
  literal: string;
  match: "token" | "phrase";
  caseSensitive?: boolean;
  label?: string;
}

export const INVENTORY_ID_PREFIX = "pii-inventory-";
export const MAX_INVENTORY_ENTRIES = 500;

// Key names that pair with "Press" or "Click" in prose and never with a real
// surname. The gazetteer rule compares its second word against this set.
const KEY_WORDS = new Set([
  "alt", "backspace", "cmd", "command", "control", "ctrl", "delete", "down",
  "end", "enter", "esc", "escape", "home", "insert", "left", "option",
  "pagedown", "pageup", "return", "right", "shift", "space", "tab", "up",
]);

export function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function compileInventoryEntry(entry: unknown): Rule {
  if (typeof entry !== "object" || entry === null) throw new Error("inventory entry must be an object");
  const { id, literal, match, caseSensitive, label } = entry as Record<string, unknown>;
  if (typeof id !== "string" || id.length === 0 || /\s/.test(id)) throw new Error('inventory entry needs a whitespace-free "id"');
  if (typeof literal !== "string" || literal.trim().length === 0) throw new Error(`inventory "${String(id)}" has an empty literal`);
  if (match !== "token" && match !== "phrase") throw new Error(`inventory "${String(id)}" needs match "token" or "phrase"`);
  if (caseSensitive !== undefined && typeof caseSensitive !== "boolean") throw new Error(`inventory "${String(id)}" needs boolean caseSensitive`);
  if (label !== undefined && (typeof label !== "string" || !ALIAS_LABEL.test(label))) throw new Error(`inventory "${String(id)}" needs a lowercase one-word label`);
  const sensitive = caseSensitive ?? true;
  const body = escapeRegExp(literal);
  // Unicode letter/number/underscore boundaries, not ASCII-only \b.
  const source = match === "token"
    ? `(?<![\\p{L}\\p{N}_])${body}(?![\\p{L}\\p{N}_])`
    : body;
  return {
    id: `${INVENTORY_ID_PREFIX}${id}`,
    description: `Private inventory "${id}" (exact match)`,
    regex: ensureIndices(new RegExp(source, sensitive ? "gu" : "giu")),
    category: "pii",
    inventoryLiteral: literal,
    ...(label === undefined ? {} : { label }),
  };
}

const ALL_CATEGORIES: ReadonlySet<Category> = new Set(["secret", "pii"]);

// Parse the SENSITIVE_CANARY_CATEGORIES env var: a comma-separated list of
// "secret", "pii", or "all" (e.g. "secret" or "secret,pii"). Unset, empty, or
// containing no valid token means all categories are enabled.
export function parseCategories(value: string | undefined): Set<Category> {
  const categories = new Set<Category>();
  for (const token of (value ?? "").split(",")) {
    const normalized = token.trim().toLowerCase();
    if (normalized === "all") return new Set(ALL_CATEGORIES);
    if (normalized === "secret" || normalized === "pii")
      categories.add(normalized);
  }
  return categories.size > 0 ? categories : new Set(ALL_CATEGORIES);
}

// Rule categories enabled for this process, from SENSITIVE_CANARY_CATEGORIES
// ("secret", "pii", "secret,pii", or "all", with "all" as default).
export function enabledCategoriesFromEnv(): Set<Category> {
  const { SENSITIVE_CANARY_CATEGORIES } = process.env;
  return parseCategories(SENSITIVE_CANARY_CATEGORIES);
}

// ── Context enhancement ──────────────────────────────────────────────────────

// Set from the default config during module initialisation (see buildRules).
let effectiveContextWindow = 3;

export function getDefaultContextWindow(): number {
  return effectiveContextWindow;
}

// Words as they were written, with only the punctuation around them removed.
// Splitting on punctuation made `extract-zip` supply "zip" and
// `golang.org/x/mobile` supply "mobile", so a version number beside either read
// as a postal code or a telephone number — which is to say lockfiles and
// `go.sum` could not be read.
function contextTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.split(/\s+/)) {
    const word = raw
      .replace(/^[\p{P}\p{S}]+/gu, "")
      .replace(/[\p{P}\p{S}]+$/gu, "")
      .toLowerCase();
    if (word) out.add(word);
  }
  return out;
}

function hasNearbyContextWord(
  text: string,
  matchStart: number,
  matchEnd: number,
  contextWords: string[],
  windowTokens: number,
): boolean {
  if (contextWords.length === 0) return true;
  const charWindow = windowTokens * 8;
  const before = text.slice(Math.max(0, matchStart - charWindow), matchStart);
  const after = text.slice(matchEnd, matchEnd + charWindow);
  const window = `${before} ${after}`;
  const nearby = contextTokens(window);
  const lowered = window.toLowerCase();
  return contextWords.some((raw) => {
    const word = raw.toLowerCase();
    // A label in a language that does not put spaces around its words is
    // written against the number, so it is looked for as written.
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the ASCII range is the test
    if (!/^[\x00-\x7f]+$/.test(word)) return lowered.includes(word);
    return nearby.has(word);
  });
}

// Detector blocks mirror the upstream sensitive-canary rules.
// Local rules are appended below.
// Keep default-config.json and upstream helper modules in sync with that commit.
// ── Config loading ───────────────────────────────────────────────────────────

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONFIG_PATH = join(MODULE_DIR, "default-config.json");
const { SENSITIVE_CANARY_CONFIG: userConfigPath } = process.env;
const USER_CONFIG_PATH =
  userConfigPath ??
  join(homedir(), ".config", "sensitive-canary", "config.json");
// Generalize lists can live in their own file beside the config, so they can
// be edited (and shared) without touching the private inventory.
export const GENERALIZE_PATH =
  process.env.SENSITIVE_CANARY_GENERALIZE ?? join(dirname(USER_CONFIG_PATH), "generalize.json");

function readJsonFile(filePath: string): unknown {
  return JSON.parse(readFileSync(filePath, "utf-8"));
}

// Validate a raw JSON object against the RuleConfig schema. Throws with a
// descriptive message when a required field is missing, a type is wrong, or a
// cross-field constraint is violated.
function validateRuleConfig(rc: unknown): asserts rc is RuleConfig {
  if (typeof rc !== "object" || rc === null) {
    throw new Error("rule must be an object");
  }
  const {
    id,
    description,
    regex: source,
    category,
    flags,
    secretGroup,
    entropyThreshold,
    validate: validateName,
    contextWords,
    excludeContext,
    requireContext,
    contextWindow,
  } = rc as Record<string, unknown>;

  if (typeof id !== "string" || id.length === 0) {
    throw new Error('missing or empty "id" field');
  }
  if (typeof description !== "string" || description.length === 0) {
    throw new Error('missing or empty "description" field');
  }
  if (typeof source !== "string" || source.length === 0) {
    throw new Error('missing or empty "regex" field');
  }
  if (category !== "secret" && category !== "pii") {
    throw new Error(
      `invalid "category" ${JSON.stringify(category)} (must be "secret" or "pii")`,
    );
  }
  if (flags != null && typeof flags !== "string") {
    throw new Error('"flags" must be a string');
  }
  if (
    secretGroup != null &&
    (typeof secretGroup !== "number" ||
      !Number.isInteger(secretGroup) ||
      secretGroup < 0)
  ) {
    throw new Error('"secretGroup" must be a non-negative integer');
  }
  if (
    entropyThreshold != null &&
    (typeof entropyThreshold !== "number" || entropyThreshold < 0)
  ) {
    throw new Error('"entropyThreshold" must be a non-negative number');
  }
  if (validateName != null && typeof validateName !== "string") {
    throw new Error('"validate" must be a string');
  }
  if (excludeContext != null) {
    if (
      !Array.isArray(excludeContext) ||
      excludeContext.some((w) => typeof w !== "string" || w.length === 0)
    ) {
      throw new Error('"excludeContext" must be an array of non-empty strings');
    }
  }
  if (contextWords != null) {
    if (
      !Array.isArray(contextWords) ||
      contextWords.some((w) => typeof w !== "string" || w.length === 0)
    ) {
      throw new Error('"contextWords" must be an array of non-empty strings');
    }
  }
  if (requireContext != null && typeof requireContext !== "boolean") {
    throw new Error('"requireContext" must be a boolean');
  }
  if (
    contextWindow != null &&
    (typeof contextWindow !== "number" ||
      !Number.isInteger(contextWindow) ||
      contextWindow < 1)
  ) {
    throw new Error('"contextWindow" must be a positive integer');
  }

  // Cross-field: requireContext is meaningless without contextWords
  if (
    requireContext === true &&
    (!Array.isArray(contextWords) || contextWords.length === 0)
  ) {
    throw new Error(
      '"requireContext" is true but "contextWords" is empty — context gating would be disabled and the rule would always fire',
    );
  }
}

// Compile a single RuleConfig (JSON) into a Rule (with compiled RegExp and
// resolved validator function). Throws on invalid regex or missing required
// fields so the caller (buildRules) can catch and warn per-rule.
export function compileRule(rc: RuleConfig): Rule {
  validateRuleConfig(rc);
  if (rc.label !== undefined && (typeof rc.label !== "string" || !ALIAS_LABEL.test(rc.label))) throw new Error("label must be one lowercase word");
  const { regex: source, flags, validate: validateName, ...rest } = rc;
  // matchAll requires the global flag. Make sure it is always present.
  const flagStr = flags ?? "g";
  const withG = flagStr.includes("g") ? flagStr : `${flagStr}g`;
  const rule: Rule = {
    ...rest,
    regex: ensureIndices(new RegExp(source, withG)),
  };
  if (validateName) {
    const fn = getValidator(validateName);
    if (fn) {
      rule.validate = fn;
    } else {
      throw new Error("unknown validator");
    }
  }
  return rule;
}

// Load and compile the built-in default rules from default-config.json.
function loadDefaultConfig(): CanaryConfig {
  return readJsonFile(DEFAULT_CONFIG_PATH) as CanaryConfig;
}

// Load user config if it exists. Returns null when the file is absent (the
// common case). JSON parse errors and permission issues are reported on stderr
// so that a broken config file is not silently ignored.
function loadUserConfig(): CanaryConfig | null {
  try {
    // A FIFO or a device here would block the read until something wrote to
    // it, and a hook that never returns stalls the turn. The transcript reader
    // and the file scanner already check this. This path did not.
    if (!statSync(USER_CONFIG_PATH).isFile()) {
      process.stderr.write(
        "sensitive-canary: user config is not a regular file, ignoring\n",
      );
      return null;
    }
    return readJsonFile(USER_CONFIG_PATH) as CanaryConfig;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
      process.stderr.write(
        "sensitive-canary: could not read user config (details withheld)\n",
      );
    }
    return null;
  }
}

// Raw user rule configs seen at startup. Applied once against defaults PLUS
// local rules (see applyUserOverrides) so a custom override of a local rule
// actually replaces it. buildRules only loads defaults and records these.
const pendingUserRuleConfigs: RuleConfig[] = [];
const pendingInventoryEntries: unknown[] = [];
const pendingGeneralizeEntries: unknown[] = [];

// Scan-budget override recorded while the config loads. Declared before
// buildRules runs (the budget section initializes after it) so module init
// order cannot leave the default in place.
let configuredScanBudgetMs: number | null = null;
let configuredAliases: "stand-ins" | "tokens" = "stand-ins";
let configuredAliasKey: "session" | "shared" = "session";

// A positive whole number of milliseconds, or null for "not configured".
// `Number` rejects trailing junk that parseInt would silently drop.
function parseScanBudget(value: unknown): number | null {
  const parsed = typeof value === "string" ? Number(value) : value;
  return typeof parsed === "number" && Number.isInteger(parsed) && parsed >= 1
    ? parsed
    : null;
}

export function pendingUserConfigsForTest(): { rules: RuleConfig[]; inventory: unknown[] } {
  return { rules: [...pendingUserRuleConfigs], inventory: [...pendingInventoryEntries] };
}

// Build the default rule list and record user configs for the later override
// pass. buildRules skips invalid built-ins with a warning. applyUserOverrides
// and compileInventoryEntry validate user entries later.
function buildRules(): Rule[] {
  const defaultConfig = loadDefaultConfig();
  effectiveContextWindow = defaultConfig.contextWindow ?? 3;

  const defaultRules: Rule[] = [];
  for (const rc of defaultConfig.rules) {
    try {
      defaultRules.push(compileRule(rc));
    } catch (e) {
      process.stderr.write(
        `sensitive-canary: failed to compile built-in rule "${(rc as { id?: unknown })?.id ?? "(unknown)"}": ${e instanceof Error ? e.message : String(e)}\n`,
      );
    }
  }

  const userConfig = loadUserConfig();
  const envBudget = parseScanBudget(process.env.SENSITIVE_CANARY_SCAN_BUDGET_MS);
  if (userConfig) {
    if (
      typeof userConfig.contextWindow === "number" &&
      Number.isInteger(userConfig.contextWindow) &&
      userConfig.contextWindow >= 1
    ) {
      effectiveContextWindow = userConfig.contextWindow;
    } else if (userConfig.contextWindow != null) {
      process.stderr.write(
        `sensitive-canary: invalid contextWindow in user config, ignoring\n`,
      );
    }
    if (userConfig.rules != null && !Array.isArray(userConfig.rules)) {
      process.stderr.write(
        `sensitive-canary: "rules" in user config must be an array, ignoring\n`,
      );
    }
    if (Array.isArray(userConfig.rules) && userConfig.rules.length) {
      for (const rc of userConfig.rules) pendingUserRuleConfigs.push(rc as RuleConfig);
    }
    if (userConfig.inventory != null) {
      if (!Array.isArray(userConfig.inventory)) {
        process.stderr.write(`sensitive-canary: "inventory" in user config must be an array, ignoring\n`);
      } else {
        for (const entry of userConfig.inventory) pendingInventoryEntries.push(entry);
      }
    }
    if (userConfig.generalize != null) {
      if (!Array.isArray(userConfig.generalize)) {
        process.stderr.write(`sensitive-canary: "generalize" in user config must be an array, ignoring\n`);
      } else {
        for (const entry of userConfig.generalize) pendingGeneralizeEntries.push(entry);
      }
    }
    if (userConfig.aliasKey === "session" || userConfig.aliasKey === "shared") {
      configuredAliasKey = userConfig.aliasKey;
    } else if (userConfig.aliasKey != null) {
      process.stderr.write("sensitive-canary: aliasKey in user config must be \"session\" or \"shared\", ignoring\n");
    }
    if (userConfig.aliases === "tokens" || userConfig.aliases === "stand-ins") {
      configuredAliases = userConfig.aliases;
    } else if (userConfig.aliases != null) {
      process.stderr.write("sensitive-canary: aliases in user config must be \"stand-ins\" or \"tokens\", ignoring\n");
    }
    if (envBudget === null) {
      const configBudget = parseScanBudget(userConfig.scanBudgetMs);
      if (configBudget !== null) {
        configuredScanBudgetMs = configBudget;
      } else if (userConfig.scanBudgetMs != null) {
        process.stderr.write(
          "sensitive-canary: invalid scanBudgetMs in user config, ignoring\n",
        );
      }
    }
  }
  // Env wins over the file: it is the per-invocation override.
  if (envBudget !== null) configuredScanBudgetMs = envBudget;

  return defaultRules;
}

export function compileInventoryList(entries: unknown[]): Rule[] {
  const out: Rule[] = [];
  const seen = new Set<string>();
  if (entries.length > MAX_INVENTORY_ENTRIES) {
    process.stderr.write(`sensitive-canary: inventory has ${entries.length} entries (max ${MAX_INVENTORY_ENTRIES}), truncating\n`);
  }
  for (const entry of entries.slice(0, MAX_INVENTORY_ENTRIES)) {
    try {
      const rule = compileInventoryEntry(entry);
      if (seen.has(rule.id)) {
        process.stderr.write("sensitive-canary: duplicate inventory id rejected — keeping first entry\n");
      } else {
        seen.add(rule.id);
        out.push(rule);
      }
    } catch (e) {
      process.stderr.write("sensitive-canary: invalid inventory entry rejected (details withheld)\n");
    }
  }
  return out;
}

export function compileGeneralizeEntry(entry: unknown): Rule {
  if (typeof entry !== "object" || entry === null) throw new Error("generalize entry must be an object");
  const { id, terms, replace, caseSensitive, scope } = entry as Record<string, unknown>;
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]+$/.test(id)) throw new Error('generalize entry needs an "id" of letters, digits, _ or -');
  if (!Array.isArray(terms) || terms.length === 0 || terms.length > MAX_GENERALIZE_TERMS ||
      terms.some((term) => typeof term !== "string" || term.trim().length === 0 || /[\n⟦⟧]/.test(term))) {
    throw new Error(`generalize "${id}" needs 1-${MAX_GENERALIZE_TERMS} non-empty single-line terms`);
  }
  if (typeof replace !== "string" || replace.trim().length === 0 || replace.length > 80 || /[\n⟦⟧]/.test(replace)) {
    throw new Error(`generalize "${id}" needs a single-line replace of at most 80 characters`);
  }
  if (caseSensitive !== undefined && typeof caseSensitive !== "boolean") throw new Error(`generalize "${id}" needs boolean caseSensitive`);
  if (scope !== undefined && scope !== "everywhere" && scope !== "prompts") throw new Error(`generalize "${id}" needs scope "everywhere" or "prompts"`);
  // Longest first, so "chronic migraine" wins over "migraine".
  const body = [...new Set(terms as string[])].sort((left, right) => right.length - left.length).map((term) => escapeRegExp(term.trim())).join("|");
  return {
    id: `${GENERALIZE_ID_PREFIX}${id}`,
    description: `Generalized wording "${id}"`,
    regex: ensureIndices(new RegExp(`(?<![\\p{L}\\p{N}_])(?:${body})(?![\\p{L}\\p{N}_])`, caseSensitive === true ? "gu" : "giu")),
    category: "pii",
    generalize: replace.trim(),
    generalizeScope: scope === "prompts" ? "prompts" : "everywhere",
  };
}

// generalize.json: either a bare array of entries or { "generalize": [...] }.
function loadGeneralizeFile(): unknown[] {
  try {
    if (!statSync(GENERALIZE_PATH).isFile()) {
      process.stderr.write("sensitive-canary: generalize file is not a regular file, ignoring\n");
      return [];
    }
    const parsed = readJsonFile(GENERALIZE_PATH) as unknown;
    const list = Array.isArray(parsed) ? parsed : (parsed as { generalize?: unknown })?.generalize;
    if (Array.isArray(list)) return list;
    process.stderr.write("sensitive-canary: generalize file must hold an array, ignoring\n");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
      process.stderr.write("sensitive-canary: could not read generalize file (details withheld)\n");
    }
  }
  return [];
}

export function compileGeneralizeList(entries: unknown[]): Rule[] {
  const out: Rule[] = [];
  const seen = new Set<string>();
  for (const entry of entries) {
    try {
      const rule = compileGeneralizeEntry(entry);
      if (seen.has(rule.id)) {
        process.stderr.write("sensitive-canary: duplicate generalize id rejected — keeping first entry\n");
        continue;
      }
      seen.add(rule.id);
      out.push(rule);
    } catch {
      process.stderr.write("sensitive-canary: invalid generalize entry rejected (details withheld)\n");
    }
  }
  return out;
}

// IBAN mod-97: rearrange, expand letters (A=10..Z=35), remainder must be 1.
function ibanValid(value: string): boolean {
  const rearranged = value.slice(4) + value.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const code = char >= "0" && char <= "9" ? Number(char) : char.charCodeAt(0) - 55;
    if (code < 0 || code > 35) return false;
    remainder = (remainder * (code > 9 ? 100 : 10) + code) % 97;
  }
  return remainder === 1;
}

// Attribute-path labels that make an internal-host-shaped match Nix code
// (config.home, env.local) rather than a hostname.
const NIX_ATTR_LABELS: ReadonlySet<string> = new Set([
  "config",
  "configs",
  "option",
  "options",
  "cfg",
  "systemd",
  "users",
  "env",
  "pkgs",
  "pkg",
  "lib",
  "nixos",
  "nixosmodules",
  "modules",
  "module",
  "services",
  "service",
  "home-manager",
  "manager",
]);

// Type names that follow a label in annotations (`host: string`,
// `user: str`), which the labeled host/username rules would otherwise take
// for values.
const TYPE_NAMES = /^(?:string|str|number|int|integer|float|double|bool|boolean|any|unknown|never|void|object|bytes|dict|list|tuple|char|symbol|bigint|undefined|option|optional|vec|array|record|promise|map|set|i8|i16|i32|i64|u8|u16|u32|u64|usize|isize|f32|f64)$/i;

const LOCAL_RULES: Rule[] = [
  {
    id: "generic-secret",
    description: "Generic API Key / Secret",
    regex:
      /(api[_-]?key|secret[_-]?key|master[_-]?key|access[_-]?token|api[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_.]{20,})/gi,
    secretGroup: 2,
    entropyThreshold: 3.5,
    category: "secret",
  },
  {
    id: "openai-new",
    description: "OpenAI API Key (svcacct/none)",
    regex: /sk-(?:svcacct|None)-[A-Za-z0-9_-]{40,}/g,
    category: "secret",
  },
  {
    id: "azure-storage",
    description: "Azure Storage Account Key",
    regex: /AccountKey=[A-Za-z0-9+/=]{60,}/g,
    category: "secret",
  },
  {
    id: "huggingface",
    description: "Hugging Face Token",
    regex: /hf_[A-Za-z0-9]{34,}/g,
    category: "secret",
  },
  {
    id: "pypi-upload",
    description: "PyPI Upload Token",
    regex: /pypi-[A-Za-z0-9_-]{50,}/g,
    category: "secret",
  },
  {
    id: "gitlab-runner",
    description: "GitLab Runner Token",
    regex: /glrt-[A-Za-z0-9_-]{20,}/g,
    category: "secret",
  },
  {
    id: "slack-app",
    description: "Slack App Refresh Token",
    regex: /xoxe-[0-9A-Za-z-]{70,}/g,
    category: "secret",
  },
  {
    id: "google-oauth",
    description: "Google OAuth Token",
    regex: /(?:ya29\.|GOCSPX-)[A-Za-z0-9_-]{20,}/g,
    category: "secret",
  },
  {
    id: "stripe-webhook",
    description: "Stripe Webhook Signing Secret",
    regex: /whsec_[A-Za-z0-9]{24,}/g,
    category: "secret",
  },
  {
    id: "shopify",
    description: "Shopify Access Token",
    regex: /shp(?:at|ca|pa|ss)_[A-Za-z0-9]{32}/g,
    category: "secret",
  },
  {
    id: "databricks",
    description: "Databricks API Token",
    regex: /dapi[A-Za-z0-9]{32}/g,
    category: "secret",
  },
  {
    id: "tailscale-key",
    description: "Tailscale Auth/Client/API Key",
    regex: /tskey-(?:auth|client|api)-[A-Za-z0-9_-]{20,}/g,
    category: "secret",
  },
  {
    id: "age-secret-key",
    description: "age Secret Key (e.g. sops-nix)",
    regex: /AGE-SECRET-KEY-1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{52,64}/g,
    category: "secret",
  },
  {
    id: "btc-address",
    description: "Bitcoin address (identifier, not a spending key)",
    regex: /\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
    category: "pii",
  },
  {
    id: "eth-address",
    description: "Ethereum address",
    regex: /\b0x[0-9a-fA-F]{40}\b/g,
    category: "pii",
  },
  {
    id: "wif-private-key",
    description: "Bitcoin WIF private key",
    regex: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g,
    category: "secret",
  },
  {
    id: "iban",
    description: "IBAN (mod-97 validated)",
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    validate: ibanValid,
    category: "pii",
  },
  {
    id: "totp-uri",
    description: "TOTP provisioning URI (seed in otpauth://)",
    regex: /otpauth:\/\/[^\s"'<>]+/gi,
    category: "secret",
  },
  {
    id: "basic-auth-header",
    description: "HTTP Basic Authorization credential",
    regex: /Authorization:\s*Basic\s+([A-Za-z0-9+/=]{8,})/gi,
    secretGroup: 1,
    category: "secret",
  },
  {
    id: "curl-basic-auth",
    description: "Credentials in curl -u/--user (variable references excluded)",
    regex: /(?:^|[\s;|&])(?:-u|--user)\s+([^\s"'`]+:[^\s"'`]+)/g,
    secretGroup: 1,
    category: "secret",
  },
  {
    id: "wifi-psk",
    description: "WiFi preshared key / passphrase assignment",
    regex: /\b(?:psk|passphrase|presharedkey|pre-shared-key)\s*[:=]\s*["']([^"'`\n]{8,64})["']/gi,
    secretGroup: 1,
    category: "secret",
  },
  {
    // Bare secrets with no label (`printenv KEY`, `echo $TOKEN`, base64
    // blobs): every other entropy rule is label-anchored and misses these.
    // Entire line must be one token so code and prose never match. Shape excludes
    // digests, UUIDs, SSH public keys, and nix store hashes.
    id: "lone-token-line",
    description: "Bare high-entropy token on its own line",
    regex: /^([A-Za-z0-9+/=_.-]{24,})\r?$/gim,
    secretGroup: 1,
    entropyThreshold: 4.5,
    validate: (value: string) =>
      !/^[0-9a-f]+$/i.test(value) &&
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) &&
      !/^[a-z0-9]{32}$/.test(value) &&
      !/^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-ssh-)/.test(value),
    category: "secret",
  },
  {
    id: "bearer",
    description: "Bearer Authorization Token",
    regex: /\bbearer\s+([A-Za-z0-9\-._~+/]{20,})/gi,
    secretGroup: 1,
    category: "secret",
  },
  {
    id: "anchored-entropy",
    description: "High-Entropy Value in Secret-Labeled Field",
    regex:
      /\b(?:[A-Za-z0-9_-]*(?:secret|token|password|passwd|credential)|[A-Za-z0-9_-]*(?:(?:api|private|access)[_-]?key|[_-]key)|key)["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_.-]{20,})/gi,
    secretGroup: 1,
    entropyThreshold: 3.5,
    validate: (value: string) =>
      !/^[0-9a-f]{32,}$/i.test(value) && /[0-9A-Z]/.test(value),
    category: "secret",
  },
  {
    id: "pii-ipv4",
    description: "IPv4 Address (private range)",
    regex:
      /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    category: "pii",
  },
  // Fleet inventory PII: exact host/user names from this repo's four hosts.
  // Single-label hostnames and bare login names have no safe generic shape
  // (they fire on github.com, localhost, root, and the verb "rob"), so
  // "rob" and "Mini" only match with an identity label, a home-dir path,
  // or exact case. Structural generics follow below. All are category "pii"
  // so [allow-pii] or [allow-all] in the latest user prompt bypasses them.
  {
    id: "pii-fleet-host",
    description: "Fleet hostname (distinctive)",
    regex: /\b(SNL-DWNGJR3|LittleBoy|FatMan)\b/gi,
    category: "pii",
  },
  {
    id: "pii-fleet-host-short",
    description: "Fleet hostname (common word, case-sensitive)",
    regex: /\b(Mini)\b/g,
    category: "pii",
  },
  {
    id: "pii-fleet-user",
    description: "Fleet username (distinctive)",
    regex: /\b(rstocchi)\b/g,
    category: "pii",
  },
  {
    id: "pii-home-user",
    description: "Username in home-directory path (generic)",
    regex: /\/(?:home|Users)\/([a-z_][a-z0-9_-]{0,30})/gi,
    secretGroup: 1,
    category: "pii",
  },
  // Generic structural patterns. Single-label hostnames and bare login names
  // have no safe generic shape (any word could be one), so the fleet
  // inventory above still covers those. These fire on structure instead:
  // internal-only DNS suffixes, Tailscale CGNAT addresses, home-dir paths,
  // user@host addresses, and labeled username assignments.
  {
    id: "pii-internal-host",
    description: "Internal hostname (generic)",
    // Flat quantifiers only: the nested-label form catastrophized on
    // dot-chains (6.5s per 40KB). Structure is validated in code instead.
    regex: /\b([A-Za-z0-9][A-Za-z0-9.-]{0,300}\.(?:local|lan|home|internal|corp|intranet|ts\.net))\b/gi,
    validate: (value: string) => {
      // Nix attribute paths wear the same shape (config.home, env.local):
      // refuse matches built from Nix-ecosystem labels.
      const labels = value.toLowerCase().split(".");
      labels.pop(); // the TLD-ish suffix is not evidence either way
      return (
        labels.length > 0 &&
        labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
        !labels.some((label) => NIX_ATTR_LABELS.has(label))
      );
    },
    category: "pii",
  },
  {
    id: "pii-tailscale-ip",
    description: "CGNAT/Tailscale IPv4 Address (100.64/10)",
    // A trailing "/N" makes the value a documented range (100.64.0.0/10),
    // not a host address, so the prefix length stays readable.
    regex: /\b(100\.(?:6\d|7\d|8\d|9\d|1[0-2]\d)\.\d{1,3}\.\d{1,3})\b(?!\/\d)/g,
    category: "pii",
  },
  {
    // Bare public IPs with no label (`curl ifconfig.me` output). Version
    // numbers die on the octet check. Private ranges stay with pii-ipv4.
    id: "pii-ipv4-lone",
    description: "Bare public IPv4 on its own line",
    regex: /^(\d{1,3}(?:\.\d{1,3}){3})\r?$/gim,
    validate: (value: string) =>
      value.split(".").every((octet) => Number(octet) <= 255) &&
      !isReservedIpv4(value),
    category: "pii",
  },
  {
    id: "pii-mac",
    description: "MAC address (device fingerprint)",
    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
    category: "pii",
  },
  {
    id: "pii-machine-id",
    description: "Machine ID / NixOS hostId assignment",
    regex: /(?:\bmachine[-_]?id|\bhost-?ids?)\s*[:=]\s*["']?([0-9a-f]{8}(?:[0-9a-f]{24})?)\b/gi,
    secretGroup: 1,
    category: "pii",
  },
  {
    id: "pii-ssid",
    description: "WiFi network name assignment",
    regex: /\bssid\s*[:=]\s*["']([^"'`\n]{1,32})["']/gi,
    secretGroup: 1,
    category: "pii",
  },
  // US financial/travel identifiers have no checksum or fixed prefix, so
  // both require a nearby label. Bare digit runs stay untouched.
  {
    id: "pii-us-bank-account",
    description: "US bank account number (context-gated)",
    regex: /\b\d{8,17}\b/g,
    requireContext: true,
    contextWords: ["bank", "account", "routing", "aba", "ach", "wire", "checking", "savings"],
    category: "pii",
  },
  {
    id: "pii-us-passport",
    description: "US passport number (context-gated)",
    regex: /\b\d{9}\b/g,
    requireContext: true,
    contextWords: ["passport"],
    category: "pii",
  },
  // Institution account numbers are exact-prefix exact-length: no checksum
  // or context needed, and nothing else looks like them.
  {
    id: "pii-bank-account-prefix",
    description: "Bank account number (known prefix)",
    regex: /\b(?:8158|8282)(?:\d{12}|(?:[\s-]?\d{4}){3})\b/g,
    category: "pii",
  },
  {
    id: "pii-11070-identifier",
    description: "Local identifier (11070 prefix)",
    regex: /\b11070(?:\d{8}|(?:[\s-]?\d{4}){2})\b/g,
    category: "pii",
  },
  {
    id: "pii-customer-mac",
    description: "Customer modem MAC: 12-16 hex chars, no separators",
    regex: /\b[0-9A-F]{12,16}\b/g,
    validate: (value: string) => /[A-F]/.test(value),
    category: "pii",
  },
  {
    id: "pii-customer-email",
    description: "Customer email in exported uppercase",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/g,
    category: "pii",
  },
  {
    id: "pii-customer-name",
    description: "Customer name LAST,FIRST in exported uppercase (NULL excluded)",
    regex: /\b(?![A-Z]*NULL[A-Z]*)(?:[A-Z][A-Z.'-]+,[A-Z][A-Z. -]*)\b/g,
    category: "pii",
  },
  {
    id: "pii-customer-phone",
    description: "Customer US phone (10 digits) near a phone label",
    regex: /\b\d{3}[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    requireContext: true,
    contextWords: ["home_phone", "mobile_phone", "business_phone", "call_first_phone", "cell_phone", "work_phone", "phone", "mobile", "cell", "home", "tel"],
    category: "pii",
  },
  {
    id: "pii-customer-id",
    description: "Customer ID (13 digits) near an account/customer label",
    regex: /\b\d{13}\b/g,
    requireContext: true,
    contextWords: ["customer_id", "cu_customer_id", "account_number", "account", "acct", "customer", "hse", "cust_id"],
    category: "pii",
  },
  {
    id: "pii-customer-wo",
    description: "Work/order number (14-20 digits) near a work/order label",
    regex: /\b\d{14,20}\b/g,
    requireContext: true,
    contextWords: ["work_order_number", "wo_nbr", "order_num", "woj_job_number", "work_order", "work", "order", "job", "wo", "job_number", "wo_number"],
    category: "pii",
  },
  // A bare capitalized pair ("Lake House") is prose as often as a name,
  // so names require an identity label. Usernames and hostnames have their
  // own rules and their word-internal boundaries never match \bname here.
  {
    id: "pii-labeled-name",
    description: "Personal name behind an identity label",
    regex: /(?:\bname|\bfull name|\bpatient|\bcustomer|\bcontact|\battn|\bauthor|\bsender|\brecipient|\bregistrant|\bsigner|\bfrom|\bto|\bcc)\s*[:=]\s*([A-Z][a-z]+(?:[ -][A-Z][a-z.]+){1,2})/gi,
    secretGroup: 1,
    category: "pii",
    // The "i" flag makes the value pattern case-insensitive too, so a YAML
    // slug (name: design-discipline) matches on its second word. Require real
    // capitalization instead, which is what the pattern intends.
    validate: (value: string) => value.split(/[ -]/).every((word) => /^[A-Z]/.test(word)),
  },
  // Titles are nearly unambiguous person markers: no prose shape looks
  // like "Dr Smith". Case-sensitive on purpose (lowercase "dr jones" is
  // informal enough to miss). Residual: "Dr Pepper" fires. No clean
  // exclusion exists, and fail-closed beats clever here.
  {
    id: "pii-titled-name",
    description: "Personal name behind a title (Mr/Mrs/Ms/Dr/Prof)",
    regex: /(?:\bMr\.?|\bMrs\.?|\bMs\.?|\bMiss\b|\bDr\.?|\bProf\.?)\s+([A-Z][A-Za-z]{1,24}(?:[ -][A-Z][A-Za-z'.-]{0,28}[A-Za-z]){0,2})/g,
    secretGroup: 1,
    category: "pii",
  },
  // Freeform names with no label at all ("Marie Dubois called yesterday").
  // Shape is a generic 2-3 capitalized-word run. FIRST_NAMES membership on
  // the first word is the gate, so "Lake House" and "White House" stay
  // untouched while real given names fire. Dual-use words that are also
  // common names (Mark, Bill, Grace, Art) fire on prose uses too
  // ("Grace Period"): accepted residual, documented in first-names.ts.
  // Single-word names ("Madonna") stay out: any word could be one.
  {
    id: "pii-gazetteer-name",
    description: "Personal name starting with a gazetteer first name",
    regex: /\b([A-Z][A-Za-z]{1,24}(?:[ -][A-Z][A-Za-z'.-]{1,29}){0,1}(?:[ -][A-Z][A-Za-z'.-]{0,28}[A-Za-z]))(?![A-Za-z'.-]*\+)/g,
    category: "pii",
    validate: (value: string) => {
      if (!FIRST_NAMES.has(value.split(/[ -]/)[0]!.toLowerCase())) return false;
      // "press" is a gazetteer name, so the pair shape alone also matches UI
      // key names and chords. The pattern rejects key chords that carry a "+".
      // The second word catches the rest. Split on non-letters so "Ctrl+Tab"
      // still yields "ctrl".
      const words = value.split(/[^A-Za-z]+/).filter(Boolean);
      return !KEY_WORDS.has((words[1] ?? "").toLowerCase());
    },
  },
  // Street addresses carry their own suffix vocabulary, so the shape is
  // precise without context words: the match must terminate on a suffix,
  // which bare "2 Road" prose never does.
  // Coordinates are only meaningful as pairs. Bare integer pairs ("5, 6")
  // are lists far more often than locations, so decimals are required
  // unless direction letters or degree marks say otherwise. Ranges kill
  // versions and dates that survive the shape.
  {
    id: "pii-geo-decimal",
    description: "Lat/long decimal pair",
    regex: /\b(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([NS])?[\s,;]+(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([EW])?\b/gi,
    validate: (value: string) => {
      const match = /^(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([NS])?[\s,;]+(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([EW])?$/i.exec(value);
      if (!match) return false;
      const [, latRaw, ns, lonRaw, ew] = match;
      if (Math.abs(Number(latRaw)) > 90 || Math.abs(Number(lonRaw)) > 180) return false;
      const frac = (part: string): boolean => part.includes(".");
      const marked = value.includes("°") || ns !== undefined || ew !== undefined;
      return (frac(latRaw) && frac(lonRaw)) || (marked && (frac(latRaw) || frac(lonRaw) || (!!ns && !!ew)));
    },
    category: "pii",
  },
  {
    id: "pii-geo-dms",
    description: "Lat/long degrees-minutes-seconds",
    regex: /\b\d{1,3}°\s*\d{1,2}(?:\.\d+)?'\s*\d{1,2}(?:\.\d+)?"\s*[NS]\s*,?\s*\d{1,3}°\s*\d{1,2}(?:\.\d+)?'\s*\d{1,2}(?:\.\d+)?"\s*[EW]\b/gi,
    category: "pii",
  },
  {
    id: "pii-street-address",
    description: "US street address",
    regex: /\b\d{1,5}[A-Za-z]?\s+[A-Za-z0-9][\w.'-]*(?:\s+[A-Za-z0-9][\w.'-]*){0,3}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Parkway|Pkwy|Terrace|Place|Pl|Plaza)\.?\b/g,
    category: "pii",
  },
  {
    id: "pii-user-at-host",
    description: "Username in user@host address (generic)",
    // The host must contain a letter and must not be a version pin:
    // npm `repo@v1` / `bar@1.0.0` are packages, not addresses.
    regex: /\b([a-z_][a-z0-9_.-]{0,30}[a-z0-9_-]?)@(?![Vv]?\d+(\.\d+)*\b)(?=[A-Za-z0-9.-]*[A-Za-z])/gi,
    secretGroup: 1,
    category: "pii",
  },
  {
    id: "pii-labeled-user",
    description: "Username in labeled assignment (generic)",
    regex: /(?:\buser(?:name)?|\blogin|\bowner)\s*[:=]\s*["']?([A-Za-z0-9._-]{3,32})/gi,
    secretGroup: 1,
    // Common username syntax: lowercase POSIX-style. This keeps display
    // names ("Jane") and booleans out without a per-word denylist.
    validate: (value: string) =>
      /^[a-z0-9._][a-z0-9._-]*$/.test(value) &&
      !/^(?:true|false|null|none|yes|no|on|off)$/.test(value) &&
      !TYPE_NAMES.test(value),
    category: "pii",
  },
  {
    id: "pii-labeled-host",
    description: "Hostname in labeled assignment (generic, single-label)",
    // Single-label values only: a dotted public name (HostName github.com)
    // is public knowledge, not PII, and the trailing guard stops the match
    // from firing on its first label. Internal FQDNs are already covered
    // by pii-internal-host regardless of label.
    regex: /(?:\bhost(?:name)?|\bserver|\bmachine)\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9])(?![\w.\-(<\[])/gi,
    secretGroup: 1,
    // Two-character minimum drops Nix lambda params (`host: u:`). The stem
    // list drops English contractions (`host: don't`) and bare references,
    // TYPE_NAMES drops annotations, and the `<` / `[` guard drops generics.
    validate: (value: string) =>
      !TYPE_NAMES.test(value) &&
      !/^(?:localhost|host|hosts|hostname|hostnames|server|servers|machine|machines|database|db|example|test|testing|local|default|none|null|unknown|url|uri|don|can|won|isn|aren|wasn|weren|doesn|didn|hasn|haven|couldn|wouldn|shouldn|mustn|needn|shan|mayn|oughtn|daren|true|false|yes|no|on|off)$/i.test(value),
    category: "pii",
  },
  {
    id: "pii-fleet-user-context",
    description: "Fleet username (short, requires identity label)",
    regex: /\brob\b/g,
    category: "pii",
    requireContext: true,
    contextWords: ["user", "username", "login", "home", "owner", "account", "author", "email", "ssh", "host"],
    contextWindow: 8,
  },
];

for (const local of LOCAL_RULES) local.regex = ensureIndices(local.regex);

export function applyUserOverrides(base: Rule[], userConfigs: RuleConfig[]): Rule[] {
  const compiled: Rule[] = [];
  for (const rc of userConfigs) {
    try {
      const rule = compileRule(rc);
      if (rule.id.startsWith(INVENTORY_ID_PREFIX)) throw new Error("reserved inventory id");
      if (base.find(original => original.id === rule.id)?.validate && !rule.validate) throw new Error("override drops validator");
      compiled.push(rule);
    } catch (e) {
      process.stderr.write(
        "sensitive-canary: invalid user rule rejected (details withheld)\n",
      );
    }
  }
  const byId = new Map<string, Rule>();
  for (const rule of compiled) {
    if (byId.has(rule.id)) {
      process.stderr.write(
        "sensitive-canary: duplicate user rule id — using the last valid definition\n",
      );
    }
    byId.set(rule.id, rule);
  }
  // An invalid override must not silently disable validation: if the custom
  // rule dropped a validator the built-in had, keep the built-in instead.
  const effective = new Map<string, Rule>(byId);
  for (const original of base) {
    const override = effective.get(original.id);
    if (override && original.validate && !override.validate) {
      process.stderr.write(
        "sensitive-canary: user override drops validator — keeping built-in\n",
      );
      effective.delete(original.id);
    }
  }
  return base.filter((r) => !effective.has(r.id)).concat(Array.from(effective.values()));
}

function dedupeByIdLastWins(rules: Rule[]): Rule[] {
  const byId = new Map<string, Rule>();
  for (const rule of rules) byId.set(rule.id, rule);
  return Array.from(byId.values());
}

const __defaultRules = buildRules();
const __userRuleConfigs: RuleConfig[] = [...pendingUserRuleConfigs];
const __inventoryRules: Rule[] = compileInventoryList([...pendingInventoryEntries]);
const __generalizeRules: Rule[] = compileGeneralizeList([...pendingGeneralizeEntries, ...loadGeneralizeFile()]);
// A local rule with the same id as a default replaces it (previously both
// ran and reported the same occurrence twice).
export const RULES: Rule[] = applyUserOverrides(
  dedupeByIdLastWins(__defaultRules.concat(LOCAL_RULES)),
  __userRuleConfigs,
).concat(__inventoryRules, __generalizeRules);

// Session-start identity rules. Kept off RULES so budget tests can splice the
// built-in list without inheriting the host's username, and so shutdown can
// drop them without rewriting user config.
let runtimeInventoryRules: Rule[] = [];

export function setRuntimeInventory(entries: InventoryEntry[]): void {
  // The active rule list is part of every cached window's identity.
  invalidateWindowCache();
  if (entries.length === 0) {
    runtimeInventoryRules = [];
    return;
  }
  const existing = new Set(RULES.map((r) => `${r.regex.source}\0${r.regex.flags}`));
  const existingIds = new Set(RULES.map((r) => r.id));
  const compiled: Rule[] = [];
  for (const entry of entries) {
    try {
      const rule = compileInventoryEntry(entry);
      const key = `${rule.regex.source}\0${rule.regex.flags}`;
      if (existingIds.has(rule.id) || existing.has(key)) continue;
      existing.add(key);
      existingIds.add(rule.id);
      compiled.push(rule);
    } catch {
      process.stderr.write(
        "sensitive-canary: invalid runtime inventory entry rejected (details withheld)\n",
      );
    }
  }
  runtimeInventoryRules = compiled;
}

// SENSITIVE_CANARY_ALIASES wins over the config file.
export function aliasStyle(): "stand-ins" | "tokens" {
  const env = process.env.SENSITIVE_CANARY_ALIASES;
  if (env === "tokens" || env === "stand-ins") return env;
  return configuredAliases;
}

// SENSITIVE_CANARY_ALIAS_KEY_SCOPE wins over the config file.
export function aliasKeyScope(): "session" | "shared" {
  const env = process.env.SENSITIVE_CANARY_ALIAS_KEY_SCOPE;
  if (env === "session" || env === "shared") return env;
  return configuredAliasKey;
}

// Custom stand-in label for a rule id, when its config set one.
export function ruleAliasLabel(ruleId: string): string | undefined {
  return activeRules().find((rule) => rule.id === ruleId)?.label;
}

export function ruleGeneralization(ruleId: string): string | undefined {
  return ruleId.startsWith(GENERALIZE_ID_PREFIX) ? activeRules().find((rule) => rule.id === ruleId)?.generalize : undefined;
}

export function isPromptOnlyRule(ruleId: string): boolean {
  return ruleId.startsWith(GENERALIZE_ID_PREFIX) && activeRules().find((rule) => rule.id === ruleId)?.generalizeScope === "prompts";
}

export function inventoryLiterals(): Array<{ ruleId: string; literal: string; label?: string }> {
  return activeRules().flatMap((rule) =>
    rule.inventoryLiteral === undefined ? [] : [{ ruleId: rule.id, literal: rule.inventoryLiteral, label: rule.label }],
  );
}

export function aliasLabels(): string[] {
  return activeRules().flatMap((rule) => (rule.label === undefined ? [] : [rule.label]));
}

function activeRules(): Rule[] {
  return runtimeInventoryRules.length === 0 ? RULES : RULES.concat(runtimeInventoryRules);
}

// User rules collected during buildRules so LOCAL_RULES share the same
// override pass. Stored aside because module init order defines LOCAL_RULES
// after buildRules runs.
function pendingUserRules(): RuleConfig[] {
  return [...pendingUserRuleConfigs];
}

// Enough of a value to say which one was found, and no more.
//
// The block reason is written to stderr, which is where Claude reads it, so
// whatever is shown here reaches the API that the block exists to keep it from.
// Four characters at each end returned eight of a nine-character password.
// A quarter of the value, capped at four per end.
export function redact(str: string): string {
  // Code points, not code units. Slicing by unit cuts a surrogate pair in half
  // and writes a lone surrogate to the terminal, which is neither the character
  // nor a redaction of it.
  const characters = [...str];
  const shown = Math.min(4, Math.floor(characters.length / 8));
  if (shown === 0) return "****";
  const head = characters.slice(0, shown).join("");
  const tail = characters.slice(-shown).join("");
  return `${head}****${tail}`;
}

// Default envelope for one hook invocation, in milliseconds. A rule that
// backtracks badly takes minutes on a megabyte, and the check sits between
// rules because a single `matchAll` cannot be interrupted. The patterns that
// did that are bounded. This catches the next one of that shape before it
// repeats.
//
// Pi runs extension handlers inline and has no watchdog (dist/core/extensions/
// runner.js awaits handlers directly). The bound is user-perceived latency,
// not a kill. Too small a value fails closed and omits text a multi-megabyte
// payload cannot finish. Too large a value stalls the turn. 30s covers a cold
// multi-megabyte session, and the window cache below makes the next request
// cheap. Override with SENSITIVE_CANARY_SCAN_BUDGET_MS or the user config's
// `scanBudgetMs` (env wins).
export const DEFAULT_SCAN_BUDGET_MS = 30_000;

// buildRules sets this from the env or the config before the first hook.
// Tests can also set it.
let activeScanBudgetMs = configuredScanBudgetMs ?? DEFAULT_SCAN_BUDGET_MS;

// `null` restores the default.
export function setScanBudgetMs(totalMs: number | null): void {
  activeScanBudgetMs =
    totalMs === null ? DEFAULT_SCAN_BUDGET_MS : Math.max(1, Math.floor(totalMs));
}

export function currentScanBudgetMs(): number {
  return activeScanBudgetMs;
}

export class ScanBudgetExceeded extends Error {
  constructor(ruleId: string, elapsed: number) {
    super(
      `the scan passed ${activeScanBudgetMs}ms (${elapsed}ms at rule "${ruleId}")`,
    );
    this.name = "ScanBudgetExceeded";
  }
}

// The budget belongs to the hook invocation, not to one `scan()` call. A single
// call is a small part of the work: `scanEnvironment` scans once per variable,
// a file is scanned at both ends, and `Object.keys(process.env)` sets the
// multiplier. Per call, each stays inside the budget while the total runs past
// what one hook should spend.
//
// Set once by each hook entry point. Left unset, every call gets the full
// budget, which is what the test suite needs.
let deadline: number | null = null;

// `null` clears it, which is the state a process starts in.
export function beginScanBudget(totalMs: number | null = activeScanBudgetMs): void {
  deadline = totalMs === null ? null : Date.now() + totalMs;
}

// Share one deadline across all strings in a synchronous hook, restoring any
// outer deadline even on failure. Nested sanitizers cannot replenish a budget.
export function withScanBudget<T>(work: () => T, totalMs = activeScanBudgetMs): T {
  const previous = deadline;
  deadline = Math.min(previous ?? Infinity, Date.now() + totalMs);
  try {
    return work();
  } finally {
    deadline = previous;
  }
}

// What is left of the budget, or the whole of it when none was begun.
export function assertScanBudget(): void {
  if (remainingBudget() <= 0) throw new ScanBudgetExceeded("document/render", activeScanBudgetMs);
}

function remainingBudget(): number {
  return deadline === null ? activeScanBudgetMs : deadline - Date.now();
}

// The between-rule check below cannot interrupt a single `matchAll`, and one
// rule from a user config is enough to hang the hook. A V8-side timeout does
// interrupt a running match. Measured at 0.06ms per call, against a scan that
// costs hundreds of times that.
const SCAN_SLOT = "__sensitiveCanaryScan";
const HARD_LIMIT_SLACK_MS = 2_000;

// `limitMs` bounds this call so it cannot overshoot what the invocation has
// left. Without it a single call could run the full hard limit past a deadline
// that was already spent.
function runInterruptibly<T>(work: () => T, limitMs: number): T {
  const slots = globalThis as unknown as Record<string, unknown>;
  slots[SCAN_SLOT] = work;
  try {
    return vm.runInThisContext(`globalThis.${SCAN_SLOT}()`, {
      timeout: Math.max(1, Math.floor(limitMs)),
      displayErrors: false,
    }) as T;
  } catch (error) {
    if (error instanceof Error && error.message.includes("timed out"))
      throw new ScanBudgetExceeded("a single rule", limitMs);
    throw error;
  } finally {
    delete slots[SCAN_SLOT];
  }
}

export function scan(
  text: string,
  categories: ReadonlySet<Category> = ALL_CATEGORIES,
): LocatedFinding[] {
  const remaining = remainingBudget();
  if (remaining <= 0)
    throw new ScanBudgetExceeded("this call's total", activeScanBudgetMs);
  return runInterruptibly(
    () => scanUninterrupted(text, categories, remaining),
    remaining + HARD_LIMIT_SLACK_MS,
  );
}

// One rule's matches over the text: pure over (rule, text) with no budget
// state, so the whole-text and windowed drivers share it. A poisoned rule
// trips only itself here. Each driver decides what a trip means.
function scanRule(rule: Rule, text: string): LocatedFinding[] {
  const findings: LocatedFinding[] = [];
  for (const match of text.matchAll(rule.regex)) {
    const secretValue =
      rule.secretGroup != null ? match[rule.secretGroup] : match[0];

    if (!secretValue) continue;
    // Both the captured value and the whole match: a rule with a
    // `secretGroup` captures only part of what it matched, and the
    // connection-string rule stops at the `@`, so the host — the one thing
    // that separates `user:password@localhost` from `user:password@` in front
    // of real infrastructure — is outside the capture.
    const matchStart = match.index ?? 0;
    const matchEnd = matchStart + match[0].length;
    const following = text.slice(matchEnd, matchEnd + 64);
    // The shape test applies only where the rule captured a free-form value.
    // A rule that matches a fixed prefix has already said what the thing is —
    // a Slack webhook is a URL and a secret, and asking whether it looks like
    // a URL is asking the wrong question.
    const capturesAValue = rule.secretGroup != null;
    if (
      rule.category === "secret" &&
      (isPlaceholder(secretValue, following) ||
        (capturesAValue &&
          (isNotSecretShaped(secretValue) ||
            isPlaceholder(match[0], following) ||
            isNotSecretShaped(match[0]) ||
            keyDescribesRatherThanHolds(match[0]))))
    )
      continue;
    if (
      rule.entropyThreshold != null &&
      entropy(secretValue) < rule.entropyThreshold
    )
      continue;
    if (rule.validate != null && !rule.validate(secretValue)) continue;

    const hasContext =
      !rule.contextWords || rule.contextWords.length === 0
        ? true
        : hasNearbyContextWord(
            text,
            matchStart,
            matchEnd,
            rule.contextWords,
            rule.contextWindow ?? effectiveContextWindow,
          );

    // Rules that require context (e.g. bare postal codes) are dropped when
    // no context label is nearby, to avoid flagging every 5-digit number.
    if (rule.requireContext && !hasContext) continue;

    // And the other way: a word nearby that says this is not what the rule is
    // for. `git clone git@github.com:…` and `ssh deploy@host` are addresses by
    // shape, and the command in front of them is what says they are not
    // anyone's mail.
    if (
      rule.excludeContext &&
      rule.excludeContext.length > 0 &&
      hasNearbyContextWord(
        text,
        matchStart,
        matchEnd,
        rule.excludeContext,
        rule.contextWindow ?? effectiveContextWindow,
      )
    ) {
      continue;
    }

    // Use the d-flag indices for the exact source location. Never use indexOf on the value.
    const indices = (match as unknown as { indices?: Array<[number, number] | undefined> }).indices;
    let start = matchStart;
    let end = matchEnd;
    if (rule.secretGroup != null) {
      const groupSpan = indices?.[rule.secretGroup];
      if (!groupSpan) continue;
      start = groupSpan[0];
      end = groupSpan[1];
    } else {
      const whole = indices?.[0];
      if (whole) {
        start = whole[0];
        end = whole[1];
      }
    }
    if (text.slice(start, end) !== secretValue) continue;
    findings.push({
      ruleId: rule.id,
      description: rule.description,
      category: rule.category,
      matchRedacted: redact(secretValue),
      secretValue,
      score: hasContext ? 1.0 : 0.4,
      start,
      end,
    });
  }
  return findings;
}

function scanUninterrupted(
  text: string,
  categories: ReadonlySet<Category>,
  budgetMs: number,
): LocatedFinding[] {
  const findings: LocatedFinding[] = [];
  const startedAt = Date.now();

  for (const rule of activeRules()) {
    if (!categories.has(rule.category)) continue;
    const elapsed = Date.now() - startedAt;
    // Thrown rather than returned: a partial result is indistinguishable from a
    // clean one, and the hooks stop the call on an error they cannot explain.
    if (elapsed > budgetMs) throw new ScanBudgetExceeded(rule.id, elapsed);
    findings.push(...scanRule(rule, text));
  }

  return findings;
}

export interface WindowTrip {
  start: number;
  end: number;
}

// Bounded scanning: one budget for the whole text lets adversarial input
// (e.g. 100KB of dot-chains) exhaust it and fail the entire message open.
// Windows partition the budget so a poisoned region trips alone. The caller
// substitutes an explicit marker for tripped ranges (fail-closed, bounded).
export const SCAN_WINDOW_CHARS = 65_536;
export const SCAN_WINDOW_OVERLAP = 8_192;

export function mergeRanges(ranges: WindowTrip[]): WindowTrip[] {
  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  const merged: WindowTrip[] = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (last && range.start <= last.end) {
      last.end = Math.max(last.end, range.end);
    } else {
      merged.push({ ...range });
    }
  }
  return merged;
}

// Poison that repeats stops being probed: after this many consecutive
// trips the rest is omitted unseen. Bounds total attempts when V8 timeouts
// fire late. Legitimate slow runs rarely trip twice in a row, let alone five
// times, and single-slice texts never reach the cutoff.
const MAX_CONSECUTIVE_TRIPS = 5;
// Per-rule V8 caps stay small on purpose: timeouts overshoot several-fold,
// so a small cap bounds the damage. The floor keeps legitimate slow rules
// (email-scale, ~200ms on hostile shapes) passing with margin. Without it,
// small shares would false-trip on realistic inputs like minified JS, which
// is worse than slow poison handling (poison is rare, minified JS is not).
const MIN_RULE_BUDGET_MS = 500;

// ── Window cache ────────────────────────────────────────────
// A window's findings are pure over (slice text, category filter, rule set).
// The envelope is not part of that key: a slice that completed before the
// envelope died is replayed on the next request instead of re-scanned. Without
// this, a payload too large to finish in one envelope re-pays the same prefix
// every request and trips at the same offset forever.
//
// Keys are SHA-256 digests of the slice text plus the category filter. A slice
// is up to SCAN_WINDOW_CHARS. The digest lets exportWindowCache persist
// results without a second copy of the text, and without any value at all.
interface CachedWindow {
  size: number;
  findings: LocatedFinding[];
}

const WINDOW_CACHE = new Map<string, CachedWindow>();
const WINDOW_CACHE_MAX_BYTES = 16_000_000;
let windowCacheBytes = 0;
let windowCacheSerial = 0;

// Ranges, never values: exportWindowCache must not write a secret to disk.
// Values are sliced out of the text again on lookup.
interface WindowRangeRecord {
  ruleId: string;
  category: Category;
  start: number;
  end: number;
  score: number;
}

const IMPORTED_WINDOWS = new Map<string, { size: number; findings: WindowRangeRecord[] }>();
const IMPORTED_WINDOWS_MAX = 20_000;

// Bump when detection semantics change without changing rule identity,
// pattern, flags, or gating (a validator fix, for instance). Stale findings
// must never hide a new detection.
export const WINDOW_CACHE_VERSION = 1;
let rulesFingerprint: string | null = null;

function categoryKey(categories: ReadonlySet<Category>): string {
  return [...categories].sort().join(",");
}

function windowDigest(text: string, categories: ReadonlySet<Category>): string {
  return createHash("sha256")
    .update(categoryKey(categories))
    .update("\u0000")
    .update(text)
    .digest("hex");
}

// Everything a window result depends on besides its text. Runtime inventory
// rules are part of activeRules(), so a hostname or username change moves it.
export function activeRulesFingerprint(): string {
  if (rulesFingerprint !== null) return rulesFingerprint;
  const parts = [`v${WINDOW_CACHE_VERSION}`];
  for (const rule of activeRules()) {
    parts.push([
      rule.id,
      rule.category,
      rule.regex.source,
      rule.regex.flags,
      String(rule.secretGroup ?? ""),
      String(rule.entropyThreshold ?? ""),
      rule.requireContext ? "1" : "0",
      (rule.contextWords ?? []).join("\u0001"),
      (rule.excludeContext ?? []).join("\u0001"),
      rule.validate ? "1" : "0",
    ].join("\u0002"));
  }
  rulesFingerprint = createHash("sha256").update(parts.join("\u0003")).digest("hex");
  return rulesFingerprint;
}

function invalidateWindowCache(): void {
  WINDOW_CACHE.clear();
  IMPORTED_WINDOWS.clear();
  windowCacheBytes = 0;
  rulesFingerprint = null;
  windowCacheSerial++;
}

export function clearWindowCache(): void {
  invalidateWindowCache();
}

// Monotonic counter for "did anything new complete since the last save".
export function windowCacheRevision(): number {
  return windowCacheSerial;
}

function windowCacheCost(entry: CachedWindow): number {
  let cost = entry.size * 2;
  for (const finding of entry.findings) cost += finding.secretValue.length * 2;
  return cost;
}

function windowCacheStore(digest: string, size: number, findings: LocatedFinding[]): void {
  const previous = WINDOW_CACHE.get(digest);
  if (previous) {
    WINDOW_CACHE.delete(digest);
    windowCacheBytes -= windowCacheCost(previous);
  }
  const entry: CachedWindow = { size, findings };
  const cost = windowCacheCost(entry);
  if (cost > WINDOW_CACHE_MAX_BYTES) return;
  while (windowCacheBytes + cost > WINDOW_CACHE_MAX_BYTES) {
    const oldest = WINDOW_CACHE.keys().next().value;
    if (oldest === undefined) break;
    const evicted = WINDOW_CACHE.get(oldest);
    WINDOW_CACHE.delete(oldest);
    if (evicted) windowCacheBytes -= windowCacheCost(evicted);
  }
  WINDOW_CACHE.set(digest, entry);
  windowCacheBytes += cost;
  windowCacheSerial++;
}

function reconstructFinding(record: WindowRangeRecord, text: string): LocatedFinding {
  const secretValue = text.slice(record.start, record.end);
  const rule = activeRules().find((candidate) => candidate.id === record.ruleId);
  return {
    ruleId: record.ruleId,
    description: rule?.description ?? record.ruleId,
    category: record.category,
    matchRedacted: redact(secretValue),
    secretValue,
    score: record.score,
    start: record.start,
    end: record.end,
  };
}

// Completed slice findings, or null when this exact slice was never finished.
function windowCacheGet(text: string, categories: ReadonlySet<Category>): LocatedFinding[] | null {
  const digest = windowDigest(text, categories);
  const hit = WINDOW_CACHE.get(digest);
  if (hit) return hit.findings;
  const imported = IMPORTED_WINDOWS.get(digest);
  if (!imported || imported.size !== text.length) return null;
  const findings = imported.findings.map((record) => reconstructFinding(record, text));
  // Promote: later requests skip reconstruction, and the next export includes
  // these windows.
  windowCacheStore(digest, text.length, findings);
  return findings;
}

export interface WindowCacheSnapshot {
  version: number;
  fingerprint: string;
  entries: Array<{ digest: string; size: number; findings: WindowRangeRecord[] }>;
}

// Value-free view for persistence: rule ids, categories, offsets, scores.
// Never secretValue or matchRedacted.
export function exportWindowCache(): WindowCacheSnapshot {
  const entries: WindowCacheSnapshot["entries"] = [];
  const seen = new Set<string>();
  for (const [digest, entry] of WINDOW_CACHE) {
    seen.add(digest);
    entries.push({
      digest,
      size: entry.size,
      findings: entry.findings.map((finding) => ({
        ruleId: finding.ruleId,
        category: finding.category,
        start: finding.start,
        end: finding.end,
        score: finding.score ?? 0.4,
      })),
    });
  }
  for (const [digest, entry] of IMPORTED_WINDOWS) {
    if (seen.has(digest)) continue;
    entries.push({ digest, size: entry.size, findings: entry.findings });
  }
  return { version: WINDOW_CACHE_VERSION, fingerprint: activeRulesFingerprint(), entries };
}

function isWindowRangeRecord(value: unknown): value is WindowRangeRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.ruleId === "string" &&
    (record.category === "secret" || record.category === "pii") &&
    Number.isInteger(record.start) &&
    (record.start as number) >= 0 &&
    Number.isInteger(record.end) &&
    (record.end as number) >= (record.start as number) &&
    typeof record.score === "number" &&
    Number.isFinite(record.score)
  );
}

// Loads a snapshot written by a previous process. Returns the number of
// windows accepted. A snapshot whose version or fingerprint differs is
// ignored: stale findings must not hide a new detection.
export function importWindowCache(snapshot: unknown): number {
  if (typeof snapshot !== "object" || snapshot === null) return 0;
  const { version, fingerprint, entries } = snapshot as Partial<WindowCacheSnapshot>;
  if (version !== WINDOW_CACHE_VERSION) return 0;
  if (fingerprint !== activeRulesFingerprint()) return 0;
  if (!Array.isArray(entries)) return 0;
  let accepted = 0;
  for (const entry of entries) {
    if (accepted >= IMPORTED_WINDOWS_MAX) break;
    if (typeof entry !== "object" || entry === null) continue;
    const { digest, size, findings } = entry as Record<string, unknown>;
    if (typeof digest !== "string" || digest.length !== 64) continue;
    if (!Number.isInteger(size) || (size as number) < 0) continue;
    if (!Array.isArray(findings)) continue;
    if (!findings.every((f) => isWindowRangeRecord(f) && f.end <= (size as number))) continue;
    IMPORTED_WINDOWS.set(digest, {
      size: size as number,
      findings: findings as WindowRangeRecord[],
    });
    accepted++;
  }
  return accepted;
}

export function scanWindows(
  text: string,
  categories: ReadonlySet<Category> = ALL_CATEGORIES,
): { findings: LocatedFinding[]; trips: WindowTrip[] } {
  const findings: LocatedFinding[] = [];
  const trips: WindowTrip[] = [];
  if (text.length === 0) return { findings, trips };
  const step = SCAN_WINDOW_CHARS - SCAN_WINDOW_OVERLAP;
  const slices: WindowTrip[] = [];
  for (let start = 0; start < text.length; start += step) {
    const end = Math.min(start + SCAN_WINDOW_CHARS, text.length);
    slices.push({ start, end });
    if (end === text.length) break;
  }
  // Envelope measured locally so spending accumulates: each slice shares
  // what is LEFT, never a fresh full budget. The V8 cap scales with the
  // share (a flat +2000ms slack would dominate small shares and defeat
  // the envelope for many-slice inputs).
  const startedAt = Date.now();
  const totalBudget = remainingBudget();
  let consecutiveTrips = 0;
  for (let i = 0; i < slices.length; i++) {
    const slice = slices[i];
    const sliceText = text.slice(slice.start, slice.end);
    // Cache first: a window that completed before is free, and an envelope
    // another string already spent must not turn a known-clean slice into an
    // omission.
    const cached = windowCacheGet(sliceText, categories);
    if (cached !== null) {
      for (const finding of cached) {
        findings.push({ ...finding, start: finding.start + slice.start, end: finding.end + slice.start });
      }
      consecutiveTrips = 0;
      continue;
    }
    const remaining = totalBudget - (Date.now() - startedAt);
    // Fail closed once the envelope is spent or poison repeats: everything
    // from here on becomes one omitted span instead of passing through.
    if (remaining <= 0 || consecutiveTrips >= MAX_CONSECUTIVE_TRIPS) {
      trips.push({ start: slice.start, end: text.length });
      break;
    }
    const sliceBudget = remaining / (slices.length - i);
    // Per-rule isolation: a poisoned rule trips alone and the slice keeps
    // every other rule's findings (a tripped slice previously discarded
    // findings its completed rules had already earned).
    const rules = activeRules();
    const ruleShare = sliceBudget / Math.max(rules.length, 1);
    const ruleCap = Math.max(MIN_RULE_BUDGET_MS, ruleShare * 2);
    let sliceTripped = false;
    const sliceFindings: LocatedFinding[] = [];
    const flushSlice = () => {
      for (const finding of sliceFindings) {
        findings.push({ ...finding, start: finding.start + slice.start, end: finding.end + slice.start });
      }
    };
    for (const rule of rules) {
      if (!categories.has(rule.category)) continue;
      const ruleRemaining = totalBudget - (Date.now() - startedAt);
      if (ruleRemaining <= 0) {
        flushSlice();
        trips.push({ start: slice.start, end: text.length });
        return { findings, trips: mergeRanges(trips) };
      }
      try {
        // The comfort floor never overrides the remaining envelope. V8 can
        // overshoot, so also check between rules, not only between windows.
        const located = runInterruptibly(() => scanRule(rule, sliceText), Math.min(ruleCap, ruleRemaining));
        for (const f of located) sliceFindings.push(f);
      } catch (error) {
        if (error instanceof ScanBudgetExceeded) {
          // A timeout allocated the entire remaining envelope. Millisecond
          // rounding can leave a fraction on the wall clock. Do not start
          // another rule with that apparent remainder.
          if (ruleRemaining <= ruleCap) {
            flushSlice();
            trips.push({ start: slice.start, end: text.length });
            return { findings, trips: mergeRanges(trips) };
          }
          sliceTripped = true;
          continue;
        }
        throw error;
      }
    }
    // Include the final rule: a single-window scan has no next iteration in
    // which to notice an overshoot. Unfinished coverage must stay explicit.
    if (totalBudget - (Date.now() - startedAt) <= 0) {
      flushSlice();
      trips.push({ start: slice.start, end: text.length });
      return { findings, trips: mergeRanges(trips) };
    }
    flushSlice();
    if (sliceTripped) {
      // Not cached. A rule that timed out under this envelope may complete
      // under a fuller one. A second bounded V8 timeout is cheaper than a
      // frozen omission.
      trips.push({ ...slice });
      consecutiveTrips++;
    } else {
      consecutiveTrips = 0;
      windowCacheStore(windowDigest(sliceText, categories), sliceText.length, sliceFindings);
    }
  }
  // Overlapping windows report the same occurrence twice. Collapse by
  // exact location so the renderer sees each occurrence once.
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.ruleId}\u0000${f.category}\u0000${f.start}\u0000${f.end}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { findings: deduped, trips: mergeRanges(trips) };
}
