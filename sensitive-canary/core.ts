// sensitive-canary engine: detection, redaction, stand-ins, and tool guards,
// with no agent attached. Two front ends share it:
//   - Pi's extension (config/pi/extensions/sensitive-canary), which hooks
//     each point of Pi's event bus.
//   - canary-proxy (../canary-proxy), which redacts provider request
//     bodies for any agent whose base URL points at it.
//
// lib/{rules,inspector}.ts are vendored from upstream coo-quack/sensitive-canary
// 9111ed20841d1ffefd86092dcb8b52ba082d973a (MIT, see lib/LICENSE). Local code
// adds provider and entropy rules, allow-tag policy, stand-ins, and cookie
// handling. See each file for refresh instructions.
//
// Secret replacements are stable, random, format-preserving strings. PII
// replacements are stable stand-ins from reserved namespaces (see
// lib/aliases.ts) that keep roles and relationships; `aliases: "tokens"`
// restores `__CANARY_HOST_1__`. This scanner is a defense in depth, not a
// confidentiality boundary.

import { randomBytes } from "node:crypto";
import { readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { type Finding, type LocatedFinding, mergeRanges, scanWindows, SCAN_WINDOW_OVERLAP, assertScanBudget, clearWindowCache, exportWindowCache, importWindowCache, windowCacheRevision, aliasStyle, aliasKeyScope, ruleAliasLabel, ruleGeneralization, inventoryStandInValue, isPromptOnlyRule, GENERALIZE_PATH } from "./lib/rules.ts";
import { AliasBook, aliasKeyPath, isAliasValue, loadAliasKey, SESSION_KEY_SUFFIX } from "./lib/aliases.ts";
import { planRedaction } from "./lib/redaction-spans.ts";
import { redactEncoded } from "./lib/encoded.ts";
import { reportRedaction } from "./lib/redaction-audit.ts";
import { assignmentEdits, inspectDocument } from "./lib/structured-text.ts";
import { applyAllowTags, dedupeFindings, type Message, resolveTagPriority, userTypedText } from "./lib/inspector.ts";
import { commandSendsCookies, redactCookieHeaders, redactCookieValue } from "./lib/cookies.ts";
import { isImagePayload } from "./lib/image-payload.ts";
import { isSecretFile } from "./lib/secret-files.ts";

// Larger strings skip regex scanning and are synthesized in full.
export const MAX_SCAN_BYTES = 2_000_000;

interface TextChunk {
  type: "text";
  text: string;
}

interface ThinkingChunk {
  type: "thinking";
  thinking: string;
}

// Bounded memo so the context handler does not re-scan the whole transcript on
// every API call. Keyed by exact text.
const SCAN_CACHE = new Map<string, { findings: LocatedFinding[]; trips: Array<{ start: number; end: number }> }>();
// Budget the memo by bytes, not entries: 512 × 2 MB keys is a gigabyte of RAM.
const SCAN_CACHE_MAX_BYTES = 32_000_000;
let scanCacheBytes = 0;

function cachedScan(text: string): { findings: LocatedFinding[]; trips: Array<{ start: number; end: number }> } {
  const hit = SCAN_CACHE.get(text);
  if (hit) return hit;
  const found = scanWindows(text);
  // A trip belongs to the hook envelope, not the text: caching it would make
  // one exhausted payload scan poison every later scan of the same string. A
  // tool call's arguments JSON is replayed inside the next provider payload,
  // so a tripped replay would later block the benign repeat call as a secret.
  if (found.trips.length > 0) return found;
  const cost = text.length * 2; // UTF-16 code units × 2 bytes
  if (cost <= SCAN_CACHE_MAX_BYTES) {
    while (scanCacheBytes + cost > SCAN_CACHE_MAX_BYTES) {
      const oldest = SCAN_CACHE.keys().next().value;
      if (oldest === undefined) break;
      SCAN_CACHE.delete(oldest);
      scanCacheBytes -= oldest.length * 2;
    }
    SCAN_CACHE.set(text, found);
    scanCacheBytes += cost;
  }
  return found;
}

const SYNTHETIC_VALUES = new Map<string, string>();
const SYNTHETIC_OUTPUTS = new Set<string>();
const SYNTHETIC_VALUES_MAX_BYTES = 8_000_000;
let syntheticValuesBytes = 0;
const TOKEN_COUNTERS = new Map<string, number>();

function storeSynthetic(value: string, synthetic: string): void {
  const cost = (value.length + synthetic.length) * 2;
  if (cost > SYNTHETIC_VALUES_MAX_BYTES) return;
  while (
    syntheticValuesBytes + cost > SYNTHETIC_VALUES_MAX_BYTES &&
    SYNTHETIC_VALUES.size > 0
  ) {
    const oldest = SYNTHETIC_VALUES.keys().next().value;
    if (oldest === undefined) break;
    const oldValue = SYNTHETIC_VALUES.get(oldest);
    SYNTHETIC_VALUES.delete(oldest);
    if (oldValue !== undefined) SYNTHETIC_OUTPUTS.delete(oldValue);
    syntheticValuesBytes -= (oldest.length + (oldValue?.length ?? 0)) * 2;
  }
  SYNTHETIC_VALUES.set(value, synthetic);
  SYNTHETIC_OUTPUTS.add(synthetic);
  syntheticValuesBytes += cost;
}

// PII placeholders are obviously fake (`__CANARY_HOST_1__`), never
// realistic: realistic fakes get mistaken for real paths and identifiers.
// The tag leaks only the value type, and numbering is stable per process
// so repeated values keep their identity. Secrets keep realistic
// shape-preserving synthesis.
function tokenTagFor(ruleId: string): string {
  if (ruleId === "unchanged-secret") return "SECRET";
  if (/ip/i.test(ruleId)) return "IP";
  if (/host/i.test(ruleId)) return "HOST";
  if (/user|login|owner/i.test(ruleId)) return "USER";
  if (/email/i.test(ruleId)) return "EMAIL";
  return "PII";
}

function syntheticToken(ruleId: string, value: string): string {
  const cached = SYNTHETIC_VALUES.get(value);
  if (cached !== undefined) return cached;
  const tag = tokenTagFor(ruleId);
  const n = (TOKEN_COUNTERS.get(tag) ?? 0) + 1;
  TOKEN_COUNTERS.set(tag, n);
  const synthetic = `__CANARY_${tag}_${n}__`;
  storeSynthetic(value, synthetic);
  return synthetic;
}

// Stable within this process so repeated values keep their identity and the
// model can still follow references. Character classes and separators survive,
// preserving JSON, URLs, IP-shaped values, and quoted configuration syntax.
export function syntheticValue(value: string): string {
  const cached = SYNTHETIC_VALUES.get(value);
  if (cached !== undefined) return cached;

  const chars = Array.from(value);
  const entropy = randomBytes(Math.max(chars.length, 1));
  const synthetic = chars
    .map((char, index) => {
      const byte = entropy[index] ?? 0;
      if (/\p{N}/u.test(char)) return String(byte % 10);
      if (/\p{Lu}/u.test(char)) {
        return String.fromCharCode(65 + (byte % 26));
      }
      if (/\p{L}/u.test(char)) {
        return String.fromCharCode(97 + (byte % 26));
      }
      return char;
    })
    .join("");
  // Punctuation-only credentials (or random short-value collisions) must not
  // pass through unchanged merely to preserve their shape.
  if (synthetic === value) return syntheticToken("unchanged-secret", value);
  storeSynthetic(value, synthetic);
  return synthetic;
}

// One book per process. The key loads lazily so importing the module (bench,
// tests) never touches the key file until a PII value needs a stand-in.
let aliasBook: AliasBook | undefined;
export function aliases(): AliasBook {
  // Before any session starts (bench, tests): shared key if configured,
  // otherwise one that lives only in this process.
  aliasBook ??= new AliasBook(aliasKeyScope() === "shared" ? loadAliasKey() : randomBytes(32));
  return aliasBook;
}

// The canary proxy is one long-lived process serving every session, so it
// installs a book on its persistent key instead of the per-session one.
export function setAliasBook(book: AliasBook): void {
  aliasBook = book;
}

// PII replacement. Stand-ins keep role, shape, and relationships and stay
// stable across sessions; `aliases: "tokens"` restores the numbered
// __CANARY_*__ placeholders.
function piiReplacement(ruleId: string, rawValue: string): string {
  const value = inventoryStandInValue(ruleId, rawValue);
  const general = ruleGeneralization(ruleId);
  if (general !== undefined) return `⟦${general}⟧`;
  if (aliasStyle() === "tokens") return syntheticToken(ruleId, value);
  return aliases().standIn(ruleId, value, ruleAliasLabel(ruleId));
}

export function isSyntheticValue(value: string): boolean {
  return SYNTHETIC_OUTPUTS.has(value) || aliasBook?.isStandIn(value) === true || isAliasValue(value);
}
// Provider payload fields carrying authenticated ciphertext must remain byte-for-byte
// unchanged. Redacting one character invalidates Codex reasoning and compaction
// records, so verification fails before the provider can answer.
const OPAQUE_PROVIDER_FIELDS: Record<string, true> = {
  encrypted_content: true,
  encryptedContent: true,
};
// Responses wire enums are never free text. When the shared scan budget is
// exhausted, fail-closed omission rewrites e.g. include[0] into
// "[sensitive-canary: omitted ...]", and the provider rejects the call
// (400 include[0]: unknown variant). Pass these control keys through so a
// starved budget cannot corrupt the call. Content fields (input text,
// instructions, tool arguments, data/url, etc.) remain scanned.
// Chat Completions compat adapters send the same class of enum as
// reasoning_effort (422 unknown variant).
const PROTOCOL_PASSTHROUGH_FIELDS: Record<string, true> = {
  include: true,
  reasoning: true,
  effort: true,
  summary: true,
  service_tier: true,
  serviceTier: true,
  reasoning_effort: true,
  reasoningEffort: true,
  tool_choice: true,
  toolChoice: true,
  type: true,
  role: true,
};

export function clearCaches(): void {
  SCAN_CACHE.clear();
  scanCacheBytes = 0;
  SYNTHETIC_VALUES.clear();
  SYNTHETIC_OUTPUTS.clear();
  syntheticValuesBytes = 0;
  TOKEN_COUNTERS.clear();
  clearWindowCache();
  lastScanCacheRevision = -1;
  aliasBook?.clear();
  SWAPPED.clear();
}

// Distinct values found while collectValues runs, for canary-proxy's badge
// counts. In memory for one call only; the values never leave it.
let valueSink: Set<string> | undefined;

export function collectValues<T>(work: () => T): { result: T; values: number } {
  const previous = valueSink;
  const sink = new Set<string>();
  valueSink = sink;
  try {
    return { result: work(), values: sink.size };
  } finally {
    valueSink = previous;
  }
}

// Overlapping findings (one address matched as an email and as user@host)
// are one value: their merged span's text is what gets counted.
function collectSpans(text: string, findings: Array<{ start: number; end: number }>): void {
  if (!valueSink) return;
  for (const range of mergeRanges(findings.map(({ start, end }) => ({ start, end })))) valueSink.add(text.slice(range.start, range.end));
}

// Completed scan windows next to the session, value-free by construction (see
// exportWindowCache). A resumed session reuses the windows a previous process
// finished instead of re-paying them on every request.
let lastScanCacheRevision = -1;

export function loadScanCache(sessionFile: string | undefined): void {
  if (!sessionFile) return;
  try {
    importWindowCache(JSON.parse(readFileSync(`${sessionFile}.canary-scan-cache.json`, "utf-8")));
  } catch {
    // Absent or unreadable: the next scan is cold, nothing to report.
  }
}

export function flushScanCache(sessionFile: string | undefined): void {
  if (!sessionFile) return;
  const revision = windowCacheRevision();
  if (revision === lastScanCacheRevision) return;
  const snapshot = exportWindowCache();
  if (snapshot.entries.length === 0) return;
  try {
    writeFileSync(`${sessionFile}.canary-scan-cache.json`, `${JSON.stringify(snapshot)}\n`, { mode: 0o600 });
    lastScanCacheRevision = revision;
  } catch {
    // A cache loss must not break the agent.
  }
}

// Set while user-typed text is scanned (context ingress, persisting a user
// message). Prompt-scoped generalize rules apply only then. The scans are
// synchronous, so a plain flag cannot leak into another scan.
let scanningUserText = false;

export function asUserText<T>(scan: () => T): T {
  const outer = scanningUserText;
  scanningUserText = true;
  try {
    return scan();
  } finally {
    scanningUserText = outer;
  }
}

export function redactText(text: string, allowTags: Set<string> = new Set()): { text: string; hits: number } {
  const sourceLength = text.length;
  type Edit = {start:number;end:number;replacementLength:number};
  // Each pass records edits in the coordinates of its own input; ranges map
  // back through the passes in reverse.
  const encodedEdits: Edit[] = [];
  const cookieEdits: Edit[] = [];
  const project = (edits: Edit[], at:number, end:boolean) => {
    let delta=0;
    for(const edit of edits) {
      const left=edit.start+delta, right=left+edit.replacementLength;
      if(at < left || (at === left && !end)) break;
      if(at < right || (at === right && end)) return end ? edit.end : edit.start;
      delta += edit.replacementLength-(edit.end-edit.start);
    }
    return at-delta;
  };
  const toOriginal = (range: {start:number;end:number}) => {
    const passes = [cookieEdits, encodedEdits];
    return {
      start: passes.reduce((at, edits) => project(edits, at, false), range.start),
      end: passes.reduce((at, edits) => project(edits, at, true), range.end),
    };
  };
  let encodedHits = 0;
  if (!allowTags.has("all")) {
    const encoded = redactEncoded(text, (decoded) => scanWindows(decoded).findings.filter((f) => !isSyntheticValue(f.secretValue) && (scanningUserText || !isPromptOnlyRule(f.ruleId))), (category) => allowTags.has(category), (start,end,replacementLength)=>encodedEdits.push({start,end,replacementLength}));
    text = encoded.text;
    encodedHits = encoded.hits;
  }
  let cookieHits = 0;
  if (!allowTags.has("secret")) {
    const cookieResult = redactCookieHeaders(text, syntheticValue, isSyntheticValue, (start,end,replacementLength)=>cookieEdits.push({start,end,replacementLength}));
    text = cookieResult.text;
    cookieHits = cookieResult.hits;
  }
  const { findings: raw, trips } = cachedScan(text);
  const allowed = allowTags.has("all") ? [] : [...raw, ...swappedFindings(text)].filter((f) => !isSyntheticValue(f.secretValue));
  // Structured document edits join the same renderer. Filter them by the
  // same allow-tags before planning so an allowed category cannot exempt an
  // overlapping forbidden secret.
  const omitted = () => {
    reportRedaction({ sourceLength, detections: [], replacements: [], omissions: [{start:0,end:sourceLength}], coordinateSystem: "original" });
    return { text: `[sensitive-canary: omitted ${text.length} chars (scan budget exceeded or incomplete document inspection)]`, hits: encodedHits + cookieHits + 1 };
  };
  const document = inspectDocument(text);
  if (document.status === "incomplete") return omitted();
  let extra: LocatedFinding[];
  try {
    extra = allowTags.has("all") ? [] : [...document.findings, ...(document.status === "json" ? [] : assignmentEdits(text))]
      .filter((f) => !isSyntheticValue(f.secretValue) && !isSyntheticValue(f.secretValue.startsWith('"') ? JSON.parse(f.secretValue) : f.secretValue));
  } catch { return omitted(); }
  const boilerplate = boilerplateSpans(text);
  const insideBoilerplate = (finding: { start: number; end: number }): boolean =>
    boilerplate.some((span) => finding.start >= span.start && finding.end <= span.end);
  const findings = (applyAllowTags([...allowed, ...extra], allowTags) as LocatedFinding[])
    .filter((finding) => !insideBoilerplate(finding))
    .filter((finding) => scanningUserText || !isPromptOnlyRule(finding.ruleId));
  const uniqueFindings = dedupeFindings(findings);
  collectSpans(text, findings);
  const expandedTrips = mergeRanges(
    trips.map((trip) => ({
      start: Math.max(0, trip.start - SCAN_WINDOW_OVERLAP),
      end: Math.min(text.length, trip.end + SCAN_WINDOW_OVERLAP),
    })),
  );
  const planned = planRedaction({
    text,
    findings,
    trips: expandedTrips,
    scalars: document.scalars,
    checkBudget: assertScanBudget,
    replacementFor: (finding) =>
      (finding as LocatedFinding & { jsonKind?: string }).jsonKind || finding.ruleId.startsWith("structured-")
        ? structuredReplacement(finding)
        : finding.category === "pii"
          ? piiReplacement(finding.ruleId, finding.secretValue)
          : syntheticValue(finding.secretValue),
  });
  if (document.status === "json") {
    try { JSON.parse(planned.text); assertScanBudget(); } catch { return omitted(); }
  }
  const passEdits = [...encodedEdits.map(({start,end})=>({start,end})), ...cookieEdits.map((edit)=>toOriginal({start:edit.start,end:edit.end}))];
  reportRedaction({ sourceLength, detections: [...passEdits, ...findings.map(toOriginal)], replacements: [...passEdits, ...planned.edits.filter(e=>!e.replacement.startsWith("[sensitive-canary: omitted")).map(toOriginal)], omissions: planned.edits.filter(e=>e.replacement.startsWith("[sensitive-canary: omitted")).map(toOriginal), coordinateSystem: "original" });
  return { text: planned.text, hits: encodedHits + cookieHits + uniqueFindings.length + trips.length + (planned.text !== text && uniqueFindings.length === 0 && trips.length === 0 ? 1 : 0) };
}

function structuredReplacement(finding: LocatedFinding): string {
  const kind = (finding as { jsonKind?: string }).jsonKind;
  const value = kind === "json-string" ? JSON.parse(finding.secretValue) as string : finding.secretValue;
  const synthetic =
    finding.category === "pii"
      ? piiReplacement(finding.ruleId, value)
      : syntheticValue(value);
  if (kind === "json-string") return JSON.stringify(synthetic);
  if (kind === "json-number") return JSON.stringify(synthetic);
  return synthetic;
}

function redactCookieField(
  value: string,
  key: string | undefined,
  allowTags: Set<string>,
): { value: string; hits: number } | undefined {
  if (allowTags.has("secret")) return;
  const header = key?.toLowerCase();
  if (header !== "cookie" && header !== "set-cookie") return;
  const cookieResult = redactCookieValue(
    value,
    header === "set-cookie",
    syntheticValue,
    isSyntheticValue,
  );
  const scanned = redactText(cookieResult.text, allowTags);
  return { value: scanned.text, hits: cookieResult.hits + scanned.hits };
}

// Provider-issued chain references must never be rewritten: replaying a
// redacted reasoning id or previous_response_id fails closed at the
// provider (400 invalid reasoning item id). The values are opaque routing
// tokens, not content, so only the exact reference keys pass — never the
// surrounding text. Reasoning-item ids are scoped to their item type so a
// customer `id` field elsewhere in the payload still scans normally.
const CHAIN_REFERENCE_PARENT_TYPES: Record<string, true> = {
  reasoning: true,
  compaction: true,
  function_call: true,
  function_call_output: true,
  // Completions-API call items (assistant tool_calls entries, kimi custom
  // calls) route by the same rules as Responses function calls.
  function: true,
  custom: true,
};

function isChainReference(key: string | undefined, parent: Record<string, unknown> | undefined, location: readonly (string | number)[], providerPayload: boolean): boolean {
  const at = (...parts: Array<string | null>): boolean => location.length === parts.length &&
    parts.every((part, i) => part === null ? typeof location[i] === "number" : location[i] === part);
  // JSON-Schema `required` entries are string array elements, so they arrive
  // without a key. They must name real properties or the provider 400s.
  // Protect them only inside tool-definition / structured-output schemas.
  if (providerPayload && location.length >= 2 && location[location.length - 2] === "required" &&
      (location[0] === "tools" || location[0] === "response_format" || location[0] === "text")) {
    return true;
  }
  if (!parent || !key) return false;
  // Persisted root details can be a provider object without a type tag.
  // Never extend this exception to arbitrary nested records.
  if (!providerPayload) return at("id") && ("encrypted_content" in parent || "encryptedContent" in parent);
  if (key === "previous_response_id") return at(key);
  // Tool-definition / structured-output names and the top-level model are
  // wire identifiers with provider-side constraints. A starved budget must
  // not rewrite them (400 invalid name / missing model).
  if (key === "model" && at(key)) return true;
  if (key === "name" && (at("tools", null, key) || at("tools", null, "function", key) ||
      at("response_format", "json_schema", key) || at("text", "format", key))) return true;
  if (at("input", null, key)) {
    if (key === "id") return typeof parent.type === "string" && CHAIN_REFERENCE_PARENT_TYPES[parent.type] === true;
    if (key === "call_id") return parent.type === "function_call" || parent.type === "function_call_output";
    if (key === "name") return parent.type === "function_call";
  }
  if (key === "tool_call_id") return at("messages", null, key) && parent.role === "tool";
  if (key === "id" && at("messages", null, "tool_calls", null, key)) {
    return parent.type === "function" || parent.type === "custom";
  }
  return key === "name" && (at("messages", null, "tool_calls", null, "function", key) ||
    at("messages", null, "tool_calls", null, "custom", key));
}

export function redactValue(
  value: unknown,
  allowTags: Set<string>,
  key?: string,
  parent?: Record<string, unknown>,
  location: readonly (string | number)[] = [],
  providerPayload = false,
): { value: unknown; hits: number } {
  // Opaque ciphertext must survive everywhere it travels: provider replay
  // and compaction both fail closed on a rewritten blob, so it passes
  // through at any depth. Protocol control enums only need that protection
  // inside the provider payload itself. Persisted details share no wire
  // contract with the provider, so a user-controlled `type`/`role`/`include`
  // key there must scan like any other field. (Within the payload these keys
  // are core-set enums. Narrowing them further by location would risk 400s
  // on future protocol shapes for no measurable gain.)
  if (key !== undefined && OPAQUE_PROVIDER_FIELDS[key] === true) {
    return { value, hits: 0 };
  }
  if (providerPayload && key !== undefined && PROTOCOL_PASSTHROUGH_FIELDS[key] === true) {
    return { value, hits: 0 };
  }
  if (typeof value === "string" && isChainReference(key, parent, location, providerPayload)) {
    return { value, hits: 0 };
  }
  if (typeof value === "string") {
    if (isImagePayload(value, key, parent)) return { value, hits: 0 };
    if (value.length > MAX_SCAN_BYTES) {
      return { value: syntheticValue(value), hits: 1 };
    }
    const cookieResult = redactCookieField(value, key, allowTags);
    if (cookieResult) return cookieResult;
    const { text, hits } = redactText(value, allowTags);
    return { value: text, hits };
  }
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return { value, hits: 0 };
  if (Array.isArray(value)) {
    let hits = 0;
    const out = value.map((item, index) => {
      const result = redactValue(item, allowTags, undefined, undefined, [...location, index], providerPayload);
      hits += result.hits;
      return result.value;
    });
    return { value: out, hits };
  }
  if (typeof value === "object" && value !== null) {
    let hits = 0;
    const out = Object.fromEntries(
      Object.entries(value).map(([childKey, item]) => {
        const result = redactValue(item, allowTags, childKey, value as Record<string, unknown>, [...location, childKey], providerPayload);
        hits += result.hits;
        return [childKey, result.value];
      }),
    );
    return { value: out, hits };
  }
  return { value, hits: 0 };
}

// Secret-path files may contain low-entropy passwords that pattern matching
// cannot detect. Their values are always synthesized while keys remain useful.

// Shell tokens, keeping quoted spans (and the spaces inside them) whole.
function shellWords(command: string): string[] {
  return command.match(/(?:"[^"\n]*"|'[^'\n]*'|[^\s|;&<>"'])+/g) ?? [];
}

// NAME=value assignments anywhere in the command (f=.env; cat $f). Names the
// command does not set fall back to the process environment, so $KUBECONFIG
// and friends resolve to the file they point at.
function shellAssignments(words: string[]): Map<string, string> {
  const vars = new Map<string, string>();
  for (const word of words) {
    const match = /^([A-Za-z_]\w*)=(.*)$/s.exec(word);
    if (match) vars.set(match[1] ?? "", (match[2] ?? "").replace(/^(["'])(.*)\1$/s, "$2"));
  }
  return vars;
}

function substituteVariables(word: string, vars: Map<string, string>): string {
  return word.replace(/\$\{?([A-Za-z_]\w*)\}?/g, (whole, name: string) => vars.get(name) ?? process.env[name] ?? whole);
}

// ANSI-C quoting ($'\x2eenv') spells characters as escapes.
function decodeAnsiC(word: string): string {
  return word.replace(/\$'((?:\\.|[^'\\])*)'/g, (_whole, body: string) =>
    body.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|[0-7]{1,3}|.)/g, (_escape, code: string) => {
      if (/^x/i.test(code) || /^u/.test(code)) return String.fromCharCode(Number.parseInt(code.slice(1), 16));
      if (/^[0-7]/.test(code)) return String.fromCharCode(Number.parseInt(code, 8));
      return ({ n: "\n", t: "\t", r: "\r" } as Record<string, string>)[code] ?? code;
    }),
  );
}

// Brace lists (.e{n,}v, {a,.env}) expand before the command sees a name.
// Bounded: a pathological token stops growing rather than stalling the hook.
const MAX_BRACE_WORDS = 64;
function expandBraces(word: string): string[] {
  const open = word.search(/\{[^{}]*,[^{}]*\}/);
  if (open < 0) return [word];
  const close = word.indexOf("}", open);
  const results: string[] = [];
  for (const option of word.slice(open + 1, close).split(",")) {
    for (const expanded of expandBraces(`${word.slice(0, open)}${option}${word.slice(close + 1)}`)) {
      if (results.length >= MAX_BRACE_WORDS) return results;
      results.push(expanded);
    }
  }
  return results;
}

// Spellings of one shell word that could name a file. Quoting can split a
// name without changing it (.e""nv, .e\nv), and interpreter one-liners name
// files inside string literals (python3 -c "open('.env')").
function wordPathSpellings(word: string): string[] {
  const spellings = [
    word.replace(/^["'`()$@]+|["'`()]+$/g, ""),
    word.replace(/["'\\]/g, "").replace(/^[`()$@]+|[`()]+$/g, ""),
  ];
  for (const literal of word.matchAll(/(["'])([^"'\s]+)\1/g)) spellings.push(literal[2] ?? "");
  return spellings;
}

function globRegExp(pattern: string): RegExp {
  let source = "";
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i] ?? "";
    if (char === "*") source += "[^/]*";
    else if (char === "?") source += "[^/]";
    else if (char === "[") {
      const close = pattern.indexOf("]", i + 1);
      if (close < 0) { source += "\\["; continue; }
      source += `[${pattern.slice(i + 1, close).replace(/^!/, "^").replace(/\\/g, "\\\\")}]`;
      i = close;
    } else source += char.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return new RegExp(`^${source}$`);
}

// An unquoted glob (cat .en?, cat *.key) names no file until bash expands it,
// so expand it the way bash would: against the directory, skipping dotfiles
// unless the pattern itself starts with a dot. Globbed directories are out of
// scope (a literal basename behind them is still checked as written).
function globMatches(word: string, cwd: string): string[] {
  if (/["'\\]/.test(word) || !/[*?[]/.test(word)) return [];
  const slash = word.lastIndexOf("/");
  const dir = slash < 0 ? "" : word.slice(0, slash + 1);
  const base = word.slice(slash + 1);
  if (!base || /[*?[]/.test(dir)) return [];
  let names: string[];
  let matcher: RegExp;
  try {
    names = readdirSync(path.resolve(cwd, expandHomePrefix(dir || ".")));
    matcher = globRegExp(base);
  } catch {
    return []; // Missing directory, or a bracket range bash would reject ([z-a]).
  }
  return names
    .filter((name) => (!name.startsWith(".") || base.startsWith(".")) && matcher.test(name))
    .map((name) => `${dir}${name}`);
}

// Every path a bash command could name after the shell expands it: variables,
// ANSI-C quoting, brace lists, quote removal, string literals, and globs.
// Arbitrary computation (base64, $(...) output, eval of built strings) stays
// out of scope: this is a lexical guard, not a sandbox.
export function commandPathCandidates(command: string, cwd: string): string[] {
  const words = shellWords(command);
  const vars = shellAssignments(words);
  const candidates: string[] = [];
  for (const word of words) {
    const value = /^[A-Za-z_]\w*=/.test(word) ? word.slice(word.indexOf("=") + 1) : word;
    for (const expanded of expandBraces(decodeAnsiC(substituteVariables(value, vars)))) {
      candidates.push(...wordPathSpellings(expanded), ...globMatches(expanded, cwd));
    }
  }
  return candidates;
}

function commandReadsSecretFile(command: string, cwd: string): boolean {
  return commandPathCandidates(command, cwd).some((candidate) => isSecretPath(candidate, cwd));
}

// The local canary inventory holds real PII used as match patterns. The model
// must never read it back: exfiltrated inventory values would dodge the very
// rules built from them. Covers the default location, $SENSITIVE_CANARY_CONFIG,
// and ~/$HOME spellings. The shipped inert template stays readable.
function expandHomePrefix(filePath: string): string {
  const home = process.env.HOME ?? "";
  if (filePath.startsWith("~/")) return `${home}${filePath.slice(1)}`;
  if (home && filePath.startsWith("$HOME/")) return `${home}${filePath.slice(5)}`;
  if (home && filePath.startsWith("${HOME}/")) return `${home}${filePath.slice(7)}`;
  return filePath;
}

export function canonicalPath(filePath: string, cwd: string): string {
  const expanded = path.resolve(cwd, expandHomePrefix(filePath.replace(/^@/, "")));
  try { return realpathSync(expanded); } catch { return expanded; }
}

// A link to a secret file reads the secret under its own name, so the link's
// target decides too. Relative paths resolve against the agent's cwd.
export function isSecretPath(filePath: string, cwd: string): boolean {
  return isSecretFile(filePath) || isSecretFile(canonicalPath(filePath, cwd));
}

function isCanaryInventory(filePath: string, cwd: string): boolean {
  if (!filePath) return false;
  const override = process.env.SENSITIVE_CANARY_CONFIG;
  if (/^\$(?:SENSITIVE_CANARY_CONFIG|\{SENSITIVE_CANARY_CONFIG\})$/.test(filePath)) {
    if (!override) return false;
    filePath = override;
  }
  const expanded = canonicalPath(filePath.split(/[?:]/)[0] ?? filePath, cwd);
  const defaultPath = path.join(process.env.HOME ?? "", ".config", "sensitive-canary", "config.json");
  if (expanded.endsWith("/.config/sensitive-canary/config.json") || expanded === canonicalPath(defaultPath, cwd)) return true;
  // The generalize list: which topics you consider sensitive.
  if (expanded.endsWith("/sensitive-canary/generalize.json") || expanded === canonicalPath(GENERALIZE_PATH, cwd)) return true;
  // The stand-in key: with it, stand-ins could be matched back to guesses.
  if (expanded.endsWith("/sensitive-canary/alias-key") || expanded.endsWith("/sensitive-canary/proxy-alias-key") || expanded.endsWith(SESSION_KEY_SUFFIX) || expanded === canonicalPath(aliasKeyPath(), cwd)) return true;
  return !!override && expanded === canonicalPath(override, cwd);
}

function commandReadsCanaryInventory(command: string, cwd: string): boolean {
  return commandPathCandidates(command, cwd).some((candidate) => isCanaryInventory(candidate, cwd));
}

// Candidate path inputs across Pi's file-touching tools.
export function candidatePaths(input: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ["path", "file_path", "filePath", "file"]) {
    const value = input[key];
    if (typeof value === "string" && value) {
      out.push(value);
    }
  }
  return out;
}

export const SYNTHESIS_NOTICE =
  "[sensitive-canary] Synthesized placeholders above are not real data — use only as labels. Never pass to tools, use as paths/commands/identifiers, or reverse.";

const SYNTHESIS_NOTICE_SUFFIX =
  " Sensitive numeric document fields may be rendered as strings; document schema types are not preserved.";
// No per-message notice: redacted output carries no guidance text.
// Failure-time guidance lives in the system reminder (once per session)
// and the tool_call block errors. Ablation (8 fresh muse-spark sessions,
// 0 misuse events either way) showed the proactive notice adds nothing
// measurable here. It cost ~65 tokens per redacted message.
// Shared by Pi (appended to its system prompt) and canary-proxy (added to
// every redacted request), so every agent is told the same thing. It tells the
// model stand-ins are usable in local tools: an earlier "never pass a
// placeholder to a tool" wording, written before swap-back, made models
// refuse to even report a value they had seen.
export const SYNTHESIS_SYSTEM_REMINDER =
  "SENSITIVE-CANARY: Personal, infrastructure and secret values in this conversation may be replaced before you see them. Personal and infrastructure values become stable stand-ins: names under the .example TLD, label-hex words (user-3c9d0e, person-…, host-…), n-hex name parts (n3c9d0e), 240.0.0.0/5 and 2001:db8:: addresses, 02: MACs. Secrets become synthetic placeholders; ⟦…⟧ marks generalized wording. Stand-ins keep roles and relationships (same domain, same subnet, same person) and stay consistent within a session, but may differ between sessions. When asked for such a value, give the stand-in you saw and say it is redacted; do not refuse. Local tool calls (shell, file read/write/edit/search) may reuse stand-ins: they are mapped back to the real values before the tool runs; a stand-in that cannot be mapped reaches the tool unchanged, so the call fails. Stand-ins are not mapped back for web tools or anything that leaves the machine. Output of tool calls that read secret files (.env, private keys, credentials) is withheld, as are secret-file lines in search results. Do not try to reverse or guess real values. Suggest the user re-run with [allow-pii] only when they need the real value shown to them.";

// Canary's own boilerplate must never be redacted: a user inventory word
// colliding with it (e.g. a case-insensitive acronym matching ordinary
// prose in the notice) would otherwise rewrite the notice, the system
// reminder, and every message carrying them — corrupting guidance and
// inflating warnings. Findings wholly inside these fixed strings are dropped
// at the single choke point all interception paths share. Trip markers still
// fire there: fail-closed omission stays honest even inside boilerplate.
const BOILERPLATE_MARKERS = [SYNTHESIS_NOTICE, SYNTHESIS_NOTICE_SUFFIX, SYNTHESIS_SYSTEM_REMINDER];

// Generalized wording is final: a term inside ⟦…⟧ is never generalized
// again, or every rescan would nest another pair of brackets.
const GENERALIZED = /⟦[^⟦⟧\n]{1,80}⟧/g;

function boilerplateSpans(text: string): Array<{ start: number; end: number }> {
  const spans: Array<{ start: number; end: number }> = [];
  for (const match of text.matchAll(GENERALIZED)) spans.push({ start: match.index, end: match.index + match[0].length });
  for (const marker of BOILERPLATE_MARKERS) {
    let from = 0;
    while (true) {
      const at = text.indexOf(marker, from);
      if (at < 0) break;
      spans.push({ start: at, end: at + marker.length });
      from = at + 1;
    }
  }
  return spans;
}



export function latestAllowTags(messages: Message[]): Set<string> {
  const latestUser = [...messages].reverse().find((message) => message.role === "user");
  return resolveTagPriority(latestUser ? userTypedText(latestUser) : "").effectiveAllow;
}

// Real values swapped into tool calls this session, by the rule id that
// re-detects them. Output that echoes one is aliased again even when no
// scanning rule would have caught it (a host composed from known parts).
const SWAPPED = new Map<string, string>();
const SWAPPED_MAX = 2_000;

export function rememberSwapped(value: string, ruleId: string): void {
  if (value.length < 3 || SWAPPED.has(value)) return;
  if (SWAPPED.size >= SWAPPED_MAX) SWAPPED.delete(SWAPPED.keys().next().value!);
  SWAPPED.set(value, ruleId);
}

function swappedFindings(text: string): LocatedFinding[] {
  if (SWAPPED.size === 0) return [];
  const lower = text.toLowerCase();
  const out: LocatedFinding[] = [];
  for (const [value, ruleId] of SWAPPED) {
    const needle = value.toLowerCase();
    for (let at = lower.indexOf(needle); at >= 0; at = lower.indexOf(needle, at + needle.length)) {
      // Whole tokens only: a swapped "acme" must not rewrite "acmeville".
      const before = text[at - 1] ?? "";
      const after = text[at + needle.length] ?? "";
      if (/[\p{L}\p{N}_]/u.test(before) || /[\p{L}\p{N}_]/u.test(after)) continue;
      const secretValue = text.slice(at, at + needle.length);
      out.push({ ruleId, description: "Value swapped into a tool call", category: "pii", matchRedacted: "[swapped]", secretValue, start: at, end: at + needle.length });
    }
  }
  return out;
}

export function blocksSecretAccess(toolName: string, command: string, targets: string[], allowTags: Set<string>, cwd: string): boolean {
  if (allowTags.has("secret")) return false;
  return (
    (toolName === "bash" && (commandReadsSecretFile(command, cwd) || commandSendsCookies(command))) ||
    targets.some((target) => isSecretPath(target, cwd))
  );
}

// Inventory reads are PII-gated rather than secret-gated: the file holds
// match patterns, and [allow-pii]/[allow-all] is the matching bypass.
export function blocksInventoryAccess(toolName: string, command: string, targets: string[], allowTags: Set<string>, cwd: string): boolean {
  if (allowTags.has("pii") || allowTags.has("all")) return false;
  return (
    (toolName === "bash" && commandReadsCanaryInventory(command, cwd)) ||
    targets.some((target) => isCanaryInventory(target, cwd))
  );
}
