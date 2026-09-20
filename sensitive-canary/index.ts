// sensitive-canary for Pi.
//
// Upstream (coo-quack/sensitive-canary) ships Claude Code hooks: standalone
// processes that read a JSON envelope on stdin and signal a block through the
// exit code. Pi's extension API is an in-process event bus instead, so the
// executables do not transfer. The *detection engine* does, and that is the
// part worth having -- upstream rules (plus local additions) derived from
// gitleaks/TruffleHog, entropy filtering, and Luhn validation.
// lib/{rules,inspector}.ts are vendored from upstream
// 9111ed20841d1ffefd86092dcb8b52ba082d973a (MIT, see lib/LICENSE).
// Local code adds provider and entropy rules, Pi allow-tag policy, and cookie
// handling. See each file for refresh instructions.
//
// The port is deliberately not one-to-one. Pi exposes tool_result and the
// final provider payload, so detected values can be replaced before they enter
// the transcript or leave the process. Secret replacements are stable, random,
// format-preserving strings. PII replacements are obviously-fake numbered
// tokens (`__CANARY_HOST_1__`) so the model never mistakes them for real
// paths or identifiers. Only the value type leaks.
//
// Five interception points:
//   tool_call               -- block secret-file access, cookie transfer, and
//                              secret-shaped tool arguments.
//   context                 -- synthesize user-authored sensitive values.
//   before_provider_request -- scan the final wire payload, including system
//                              prompts and provider-specific fields.
//   tool_result             -- synthesize tool output and secret-file values.
//   message_end             -- persist the redacted view, never the original,
//                              so compaction (which bypasses the event bus and
//                              reads stored entries) can only re-send what the
//                              provider already saw.
//
// The latest user prompt can bypass one category or all checks with an
// explicit allow tag. Older, quoted, and runtime-generated tags do not apply.
// This scanner remains a defense in depth, not a confidentiality boundary.
//
// Redaction is on by default and can be toggled for local models: bare /canary
// flips it, or /canary on|off|status flips it explicitly (command only, no shortcut).
// or the --no-canary CLI flag at startup. The toggle persists per session via an appendEntry record and is
// announced on the `sensitive-canary:mode` event so the footer can show
// CANARY ON/OFF. While off, every interception point passes through raw.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { randomBytes } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { type Finding, type LocatedFinding, mergeRanges, scanWindows, SCAN_WINDOW_OVERLAP, withScanBudget, assertScanBudget, ScanBudgetExceeded, setRuntimeInventory, clearWindowCache, exportWindowCache, importWindowCache, windowCacheRevision } from "./lib/rules.ts";
import { planRedaction } from "./lib/redaction-spans.ts";
import { reportRedaction } from "./lib/redaction-audit.ts";
import { assignmentEdits, inspectDocument } from "./lib/structured-text.ts";
import {
  applyAllowTags,
  dedupeFindings,
  type Message,
  randomBird,
  resolveTagPriority,
  userTypedText,
} from "./lib/inspector.ts";
import { toolResultDigest } from "./lib/certification.ts";
import {
  commandSendsCookies,
  redactCookieHeaders,
  redactCookieValue,
} from "./lib/cookies.ts";
import { isImagePayload } from "./lib/image-payload.ts";
import { isDotenvFile, isSecretFile } from "./lib/secret-files.ts";
import { collectRuntimeIdentity, identityFromGit, identityFromOs } from "./lib/runtime-inventory.ts";

// Larger strings skip regex scanning and are synthesized in full.
const MAX_SCAN_BYTES = 2_000_000;

// Persisted toggle record (cf. readonly-mode's STATE_ENTRY pattern).
const STATE_ENTRY = "sensitive-canary";
type CanaryState = { enabled?: boolean };

const FILE_READ_COMMANDS: Record<string, true> = {
  cat: true,
  head: true,
  tail: true,
  less: true,
  more: true,
  bat: true,
  nl: true,
};

interface TextChunk {
  type: "text";
  text: string;
}

function isTextChunk(value: unknown): value is TextChunk {
  if (typeof value !== "object" || value === null) return false;
  if (!("type" in value) || value.type !== "text") return false;
  return "text" in value && typeof value.text === "string";
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
function syntheticValue(value: string): string {
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

function isSyntheticValue(value: string): boolean {
  return SYNTHETIC_OUTPUTS.has(value);
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

function clearCaches(): void {
  SCAN_CACHE.clear();
  scanCacheBytes = 0;
  SYNTHETIC_VALUES.clear();
  SYNTHETIC_OUTPUTS.clear();
  syntheticValuesBytes = 0;
  TOKEN_COUNTERS.clear();
  clearWindowCache();
  lastScanCacheRevision = -1;
}

// Value-free audit ledger: rule IDs and counts only, never values. Every
// finding that survives allow-tag filtering passes through redactText, so
// this one hook records context, provider-payload, tool-result, and
// persistence redactions with the same per-stage semantics as the warnings.
const LEDGER = new Map<string, { category: string; count: number }>();

function recordLedger(findings: Finding[]): void {
  for (const finding of findings) {
    const entry = LEDGER.get(finding.ruleId) ?? { category: finding.category, count: 0 };
    entry.count++;
    LEDGER.set(finding.ruleId, entry);
  }
}

function flushLedger(sessionFile: string | undefined): void {
  if (LEDGER.size === 0) return;
  const byRule: Record<string, { category: string; count: number }> = {};
  let totalHits = 0;
  for (const [id, entry] of LEDGER) {
    byRule[id] = { ...entry };
    totalHits += entry.count;
  }
  LEDGER.clear();
  if (!sessionFile) return;
  try {
    writeFileSync(`${sessionFile}.canary-ledger.json`, `${JSON.stringify({ updatedAt: new Date().toISOString(), totalHits, byRule })}\n`, { mode: 0o600 });
  } catch {
    // Audit must never break the agent.
  }
}

// Completed scan windows next to the session, value-free by construction (see
// exportWindowCache). A resumed session reuses the windows a previous process
// finished instead of re-paying them on every request.
let lastScanCacheRevision = -1;

function loadScanCache(sessionFile: string | undefined): void {
  if (!sessionFile) return;
  try {
    importWindowCache(JSON.parse(readFileSync(`${sessionFile}.canary-scan-cache.json`, "utf-8")));
  } catch {
    // Absent or unreadable: the next scan is cold, nothing to report.
  }
}

function flushScanCache(sessionFile: string | undefined): void {
  if (!sessionFile) return;
  const revision = windowCacheRevision();
  if (revision === lastScanCacheRevision) return;
  const snapshot = exportWindowCache();
  if (snapshot.entries.length === 0) return;
  try {
    writeFileSync(`${sessionFile}.canary-scan-cache.json`, `${JSON.stringify(snapshot)}\n`, { mode: 0o600 });
    lastScanCacheRevision = revision;
  } catch {
    // Cache loss is not worth breaking the agent over.
  }
}

// Tripped scan windows become explicit markers, never silent passthrough.
// Ranges expand by the window overlap first so a value straddling the edge
// is swallowed whole instead of leaking its outside fragment.
function applyTripMarkers(text: string, trips: Array<{ start: number; end: number }>): string {
  const merged = mergeRanges(
    trips.map((trip) => ({
      start: Math.max(0, trip.start - SCAN_WINDOW_OVERLAP),
      end: Math.min(text.length, trip.end + SCAN_WINDOW_OVERLAP),
    })),
  );
  let out = text;
  for (let i = merged.length - 1; i >= 0; i--) {
    const span = merged[i];
    out = `${out.slice(0, span.start)}[sensitive-canary: omitted ${span.end - span.start} chars (scan budget exceeded)]${out.slice(span.end)}`;
  }
  return out;
}

function redactText(text: string, allowTags: Set<string> = new Set()): { text: string; hits: number } {
  const sourceLength = text.length;
  const cookieEdits: Array<{start:number;end:number;replacementLength:number}> = [];
  const toOriginal = (range: {start:number;end:number}) => {
    const project = (at:number, end:boolean) => {
      let delta=0;
      for(const edit of cookieEdits) {
        const left=edit.start+delta, right=left+edit.replacementLength;
        if(at < left || (at === left && !end)) break;
        if(at < right || (at === right && end)) return end ? edit.end : edit.start;
        delta += edit.replacementLength-(edit.end-edit.start);
      }
      return at-delta;
    };
    return {start:project(range.start,false),end:project(range.end,true)};
  };
  let cookieHits = 0;
  if (!allowTags.has("secret")) {
    const cookieResult = redactCookieHeaders(text, syntheticValue, isSyntheticValue, (start,end,replacementLength)=>cookieEdits.push({start,end,replacementLength}));
    text = cookieResult.text;
    cookieHits = cookieResult.hits;
  }
  const { findings: raw, trips } = cachedScan(text);
  const allowed = allowTags.has("all") ? [] : raw.filter((f) => !isSyntheticValue(f.secretValue));
  // Structured document edits join the same renderer. Filter them by the
  // same allow-tags before planning so an allowed category cannot exempt an
  // overlapping forbidden secret.
  const omitted = () => {
    reportRedaction({ sourceLength, detections: [], replacements: [], omissions: [{start:0,end:sourceLength}], coordinateSystem: "original" });
    return { text: `[sensitive-canary: omitted ${text.length} chars (scan budget exceeded or incomplete document inspection)]`, hits: cookieHits + 1 };
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
    .filter((finding) => !insideBoilerplate(finding));
  const uniqueFindings = dedupeFindings(findings);
  recordLedger(uniqueFindings);
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
          ? syntheticToken(finding.ruleId, finding.secretValue)
          : syntheticValue(finding.secretValue),
  });
  if (document.status === "json") {
    try { JSON.parse(planned.text); assertScanBudget(); } catch { return omitted(); }
  }
  reportRedaction({ sourceLength, detections: [...cookieEdits.map(({start,end})=>({start,end})), ...findings.map(toOriginal)], replacements: [...cookieEdits.map(({start,end})=>({start,end})), ...planned.edits.filter(e=>!e.replacement.startsWith("[sensitive-canary: omitted")).map(toOriginal)], omissions: planned.edits.filter(e=>e.replacement.startsWith("[sensitive-canary: omitted")).map(toOriginal), coordinateSystem: "original" });
  return { text: planned.text, hits: cookieHits + uniqueFindings.length + trips.length + (planned.text !== text && uniqueFindings.length === 0 && trips.length === 0 ? 1 : 0) };
}

function structuredReplacement(finding: LocatedFinding): string {
  const kind = (finding as { jsonKind?: string }).jsonKind;
  const value = kind === "json-string" ? JSON.parse(finding.secretValue) as string : finding.secretValue;
  const synthetic =
    finding.category === "pii"
      ? syntheticToken(finding.ruleId, value)
      : syntheticValue(value);
  if (kind === "json-string") return JSON.stringify(synthetic);
  if (kind === "json-number") return JSON.stringify(synthetic);
  return synthetic;
}

// Applies redactText to every text chunk. Shared by the ingress (context)
// and egress (tool_result) handlers.
function redactChunks(content: readonly unknown[], allowTags: Set<string> = new Set()): {
  content: unknown[];
  hits: number;
} {
  let hits = 0;
  const out = content.map((chunk) => {
    if (!isTextChunk(chunk)) return chunk;
    if (chunk.text.length > MAX_SCAN_BYTES) {
      hits++;
      return { ...chunk, text: syntheticValue(chunk.text) };
    }
    const { text, hits: n } = redactText(chunk.text, allowTags);
    if (n === 0) return chunk;
    hits += n;
    return { ...chunk, text };
  });
  return { content: out, hits };
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

function redactValue(
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

function extractFilePathsFromCommand(command: string): string[] {
  const paths: string[] = [];
  for (const segment of command.split(/\s*[|;&]+\s*/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2) continue;
    if (FILE_READ_COMMANDS[path.basename(tokens[0] ?? "")] !== true) continue;

    let skipNext = false;
    for (let i = 1; i < tokens.length; i++) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      const token = tokens[i];
      if (!token || token.startsWith("-")) continue;
      if (token === ">" || token === ">>" || token === "<") {
        skipNext = true;
        continue;
      }
      paths.push(token.replace(/^["']+|["']+$/g, ""));
    }
  }
  return [...new Set(paths)];
}

function commandReadsSecretFile(command: string): boolean {
  return command
    .split(/[\s|;&<>]+/)
    .some((token) =>
      isSecretFile(token.replace(/^["'`()$@]+|["'`()]+$/g, "")),
    );
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

function canonicalPath(filePath: string, cwd: string): string {
  const expanded = path.resolve(cwd, expandHomePrefix(filePath.replace(/^@/, "")));
  try { return realpathSync(expanded); } catch { return expanded; }
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
  return !!override && expanded === canonicalPath(override, cwd);
}

function commandReadsCanaryInventory(command: string, cwd: string): boolean {
  // Retain quoted spaces and variable sigils. This recognizes direct path
  // spellings, not arbitrary shell expansion or dynamically computed paths.
  const tokens = command.match(/(?:"[^"\n]*"|'[^'\n]*'|[^\s|;&<>"'])+/g) ?? [];
  return tokens.some((token) => isCanaryInventory(token.replace(/["'`]/g, "").replace(/^[()]+|[()]+$/g, ""), cwd));
}

// Candidate path inputs across Pi's file-touching tools.
function candidatePaths(input: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ["path", "file_path", "filePath", "file"]) {
    const value = input[key];
    if (typeof value === "string" && value) {
      out.push(value);
    }
  }
  return out;
}

const FILE_PATH_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls", "search_files"]);

function hasNonRelativePath(toolName: string, targets: string[]): boolean {
  if (!FILE_PATH_TOOLS.has(toolName)) return false;
  return targets.some((target) => {
    const value = target.replace(/^@/, "");
    return path.isAbsolute(value) || path.win32.isAbsolute(value) ||
      /^~|^\$(?:HOME|\{HOME\})(?:[\\/]|$)/.test(value);
  });
}

function synthesizeEnvChunks(content: readonly unknown[]): {
  content: unknown[];
  hits: number;
} {
  let hits = 0;
  const out = content.map((chunk) => {
    if (!isTextChunk(chunk)) return chunk;
    if (chunk.text.length > MAX_SCAN_BYTES) {
      hits++;
      return { ...chunk, text: syntheticValue(chunk.text) };
    }
    const text = chunk.text
      .split("\n")
      .map((line) => {
        const equals = line.indexOf("=");
        if (equals < 0 || line.slice(equals + 1).trim().length === 0) {
          return line;
        }
        hits++;
        return `${line.slice(0, equals + 1)}${syntheticValue(line.slice(equals + 1))}`;
      })
      .join("\n");
    return { ...chunk, text };
  });
  return { content: out, hits };
}

function synthesizeWholeChunks(content: readonly unknown[]): {
  content: unknown[];
  hits: number;
} {
  let hits = 0;
  const out = content.map((chunk) => {
    if (!isTextChunk(chunk)) return chunk;
    hits++;
    return { ...chunk, text: syntheticValue(chunk.text) };
  });
  return { content: out, hits };
}

const SYNTHESIS_NOTICE =
  "[sensitive-canary] Synthesized placeholders above are not real data — use only as labels. Never pass to tools, use as paths/commands/identifiers, or reverse.";

const SYNTHESIS_NOTICE_SUFFIX =
  " Sensitive numeric document fields may be rendered as strings; document schema types are not preserved.";
// No per-message notice: redacted output carries no guidance text.
// Failure-time guidance lives in the system reminder (once per session)
// and the tool_call block errors. Ablation (8 fresh muse-spark sessions,
// 0 misuse events either way) showed the proactive notice adds nothing
// measurable here. It cost ~65 tokens per redacted message.
const SYNTHESIS_SYSTEM_REMINDER =
  "SENSITIVE-CANARY: Sensitive values can be synthetic placeholders. These placeholders are not real credentials, identities, contact details, or production data. Preserve only their structure and relationships. Never pass a placeholder to a tool or attempt to reverse it. Never cd into, read, or execute a path containing a placeholder: resolve the dynamic segment at runtime ($HOME, $(id -un), positional selection) instead of reusing redacted text. If one blocks the task, stop and ask the user to re-run with [allow-pii].";

// Canary's own boilerplate must never be redacted: a user inventory word
// colliding with it (e.g. a case-insensitive acronym matching ordinary
// prose in the notice) would otherwise rewrite the notice, the system
// reminder, and every message carrying them — corrupting guidance and
// inflating warnings. Findings wholly inside these fixed strings are dropped
// at the single choke point all interception paths share. Trip markers still
// fire there: fail-closed omission stays honest even inside boilerplate.
const BOILERPLATE_MARKERS = [SYNTHESIS_NOTICE, SYNTHESIS_NOTICE_SUFFIX, SYNTHESIS_SYSTEM_REMINDER];

function boilerplateSpans(text: string): Array<{ start: number; end: number }> {
  const spans: Array<{ start: number; end: number }> = [];
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



function latestAllowTags(messages: Message[]): Set<string> {
  const latestUser = [...messages].reverse().find((message) => message.role === "user");
  return resolveTagPriority(latestUser ? userTypedText(latestUser) : "").effectiveAllow;
}

function allowGrantLabel(tags: Set<string>): string {
  if (tags.has("all")) return "all sensitive-canary checks (PII and secrets)";
  const parts: string[] = [];
  if (tags.has("secret")) parts.push("secrets");
  if (tags.has("pii")) parts.push("PII");
  return parts.join(" and ") || "sensitive values";
}

type AllowGrantCtx = {
  hasUI?: boolean;
  mode?: string;
  signal?: AbortSignal;
  ui?: {
    select?: (prompt: string, choices: string[], opts?: { signal?: AbortSignal }) => Promise<string>;
  };
};

async function resolveAllowGrant(
  tags: Set<string>,
  ctx: AllowGrantCtx | undefined,
  prior: boolean | undefined,
): Promise<{ tags: Set<string>; grant: boolean | undefined }> {
  if (tags.size === 0) return { tags, grant: prior };
  if (prior === true) return { tags, grant: true };
  if (prior === false) return { tags: new Set(), grant: false };
  const interactive = Boolean(
    ctx?.hasUI && ctx.ui?.select && ctx.mode && ["tui", "rpc"].includes(ctx.mode),
  );
  if (!interactive) return { tags, grant: true };
  try {
    const choice = await ctx!.ui!.select!(
      `sensitive-canary: this prompt asks to allow ${allowGrantLabel(tags)} this turn. Permit?`,
      ["Yes", "No"],
      { signal: ctx?.signal },
    );
    const grant = choice === "Yes";
    return { tags: grant ? tags : new Set(), grant };
  } catch {
    return { tags: new Set(), grant: false };
  }
}

// Placeholders are fake by design, so executing them always fails confusingly
// (no such path, user, or host). Fail fast with recovery guidance instead.
// The tag maps back to the allow-tag category, exactly like tokenTagFor.
const PLACEHOLDER_RE = /__CANARY_([A-Z]+)_\d+__/g;

function placeholderViolations(input: unknown, allowTags: Set<string>): string | undefined {
  if (allowTags.has("all")) return;
  let serialized: string;
  try {
    serialized = JSON.stringify(input ?? {});
  } catch {
    return;
  }
  for (const match of serialized.matchAll(PLACEHOLDER_RE)) {
    const category = match[1] === "SECRET" ? "secret" : "pii";
    if (!allowTags.has(category)) return match[0];
  }
  return;
}

function blocksSecretAccess(toolName: string, command: string, targets: string[], allowTags: Set<string>): boolean {
  if (allowTags.has("secret")) return false;
  return (
    (toolName === "bash" && (commandReadsSecretFile(command) || commandSendsCookies(command))) ||
    targets.some(isSecretFile)
  );
}

// Secrets only: host/user/email in commands are normal (ssh, git, $HOME).
// Block, do not redact-and-run. Scan-budget trips fail closed.
function toolInputHasSecret(input: unknown, allowTags: Set<string>): boolean {
  if (allowTags.has("secret") || allowTags.has("all")) return false;
  let serialized: string;
  try {
    serialized = JSON.stringify(input ?? {});
  } catch {
    return true;
  }
  try {
    const { findings, trips } = cachedScan(serialized);
    return trips.length > 0 || findings.some((finding) => finding.category === "secret");
  } catch (error) {
    if (error instanceof ScanBudgetExceeded) return true;
    throw error;
  }
}

// Inventory reads are PII-gated rather than secret-gated: the file holds
// match patterns, and [allow-pii]/[allow-all] is the matching bypass.
function blocksInventoryAccess(toolName: string, command: string, targets: string[], allowTags: Set<string>, cwd: string): boolean {
  if (allowTags.has("pii") || allowTags.has("all")) return false;
  return (
    (toolName === "bash" && commandReadsCanaryInventory(command, cwd)) ||
    targets.some((target) => isCanaryInventory(target, cwd))
  );
}

function sanitizeToolContent(
  content: readonly unknown[],
  fileKind: "none" | "dotenv" | "secret-file",
  allowTags: Set<string>,
): { content: unknown[]; hits: number } {
  if (allowTags.has("all")) return { content: [...content], hits: 0 };
  if (allowTags.has("secret")) return redactChunks(content, allowTags);
  if (fileKind === "dotenv") return synthesizeEnvChunks(content);
  if (fileKind === "secret-file") return synthesizeWholeChunks(content);
  return redactChunks(content, allowTags);
}

export default function sensitiveCanary(pi: ExtensionAPI): void {
  let pendingWarningCount = 0;
  let allowTags = new Set<string>();
  let allowGrant: boolean | undefined;
  let canaryEnabled = true;

  function applyCanary(next: boolean, ctx?: { ui?: { notify?: (message: string, level?: string) => void } }): void {
    canaryEnabled = next;
    pi.appendEntry(STATE_ENTRY, { enabled: next });
    pi.events.emit("sensitive-canary:mode", { enabled: next });
    ctx?.ui?.notify?.(
      next
        ? "Sensitive-canary enabled: values are synthesized before they reach the model"
        : "Sensitive-canary disabled: raw values reach the model (for local models)",
      "info",
    );
  }

  pi.registerFlag("no-canary", {
    description: "Start with sensitive-canary redaction disabled (for local models)",
    type: "boolean",
    default: false,
  });

  pi.registerCommand("canary", {
    description: "Enable, disable, or inspect sensitive-canary redaction",
    handler: async (args, ctx) => {
      switch (args.trim().toLowerCase()) {
        case "on": applyCanary(true, ctx); break;
        case "off": applyCanary(false, ctx); break;
        case "": applyCanary(!canaryEnabled, ctx); break;
        case "status": ctx.ui.notify(`Sensitive-canary ${canaryEnabled ? "enabled" : "disabled"}`, "info"); break;
        default: ctx.ui.notify("Usage: /canary [on|off|status] (bare /canary toggles)", "info"); return;
      }
    },
  });

  pi.events.on("sensitive-canary:sanitize-stored-text", (event: { text: string; certified: boolean }) => withScanBudget(() => {
    if (typeof event.text !== "string") return;
    if (!canaryEnabled) {
      event.certified = true;
      return;
    }
    event.text = event.text.length > MAX_SCAN_BYTES
      ? syntheticValue(event.text)
      : redactText(event.text).text;
    event.certified = true;
  }));

  function recordWarning(hits: number): void {
    pendingWarningCount += hits;
  }

  function flushWarning(ctx: { ui?: { notify?: (message: string, level: "warning") => void } }): void {
    if (pendingWarningCount === 0) return;
    ctx.ui?.notify?.(
      `${randomBird()} sensitive-canary: synthesized ${pendingWarningCount} value(s) during this response`,
      "warning",
    );
    pendingWarningCount = 0;
  }

  pi.on("agent_start", () => {
    pendingWarningCount = 0;
    allowTags = new Set<string>();
    allowGrant = undefined;
    LEDGER.clear();
  });

  pi.on("session_start", async (_event, ctx) => {
    const state = ctx.sessionManager
      .getBranch()
      .filter((entry) => entry.type === "custom" && entry.customType === STATE_ENTRY)
      .at(-1) as { data?: CanaryState } | undefined;
    // --no-canary forces off at startup. Otherwise restore the persisted
    // toggle, defaulting to on. No toast on load: the footer tag shows it.
    const next = pi.getFlag("no-canary") === true
      ? false
      : (typeof state?.data?.enabled === "boolean" ? state.data.enabled : true);
    canaryEnabled = next;
    pi.appendEntry(STATE_ENTRY, { enabled: next });
    pi.events.emit("sensitive-canary:mode", { enabled: next });
    setRuntimeInventory(collectRuntimeIdentity({ ...identityFromOs(), ...identityFromGit() }));
    clearCaches();
    loadScanCache(ctx.sessionManager.getSessionFile());
  });

  pi.on("agent_end", (_event, ctx) => {
    flushWarning(ctx);
    // PI_SESSION_FILE exists only in shell-tool children (or may be inherited
    // from a parent agent). Resolve the active session at flush time instead.
    flushLedger(ctx.sessionManager.getSessionFile());
    flushScanCache(ctx.sessionManager.getSessionFile());
  });

  pi.on("before_agent_start", (event) => {
    if (!canaryEnabled) return;
    if (event.systemPrompt.includes(SYNTHESIS_SYSTEM_REMINDER)) return;
    return {
      systemPrompt: `${event.systemPrompt}\n\n${SYNTHESIS_SYSTEM_REMINDER}`,
    };
  });

  // ── pre-exec: block direct sensitive-file reads ───────────────────────────
  pi.on("tool_call", (event, ctx) => {
    if (!canaryEnabled) return;
    const input = (event.input ?? {}) as Record<string, unknown>;
    const command = String(input.command ?? "");
    const targets = candidatePaths(input);
    if (blocksSecretAccess(event.toolName, command, targets, allowTags)) {
      return {
        block: true,
        reason: "sensitive-canary: refusing direct secret access or transmission. Add [allow-secrets] or [allow-all] to the current user prompt to bypass this check.",
      };
    }
    if (blocksInventoryAccess(event.toolName, command, targets, allowTags, ctx?.cwd ?? process.cwd())) {
      return {
        block: true,
        reason: "sensitive-canary: refusing to read the local PII inventory — its values would dodge the rules built from them. Add [allow-pii] or [allow-all] to the current user prompt to bypass this check.",
      };
    }
    const placeholder = placeholderViolations(event.input, allowTags);
    if (placeholder !== undefined) {
      return {
        block: true,
        reason: `sensitive-canary: ${placeholder} is a synthetic placeholder, not a real path or identifier — the call cannot succeed with it. Resolve the real value at runtime ($HOME, $(id -un), positional selection) instead of reusing redacted text. Add [allow-pii] or [allow-all] to the current user prompt to bypass this check.`,
      };
    }
    if (withScanBudget(() => toolInputHasSecret(event.input, allowTags))) {
      return {
        block: true,
        reason: "sensitive-canary: refusing to send a secret in a tool call. Add [allow-secrets] or [allow-all] to the current user prompt to bypass this check.",
      };
    }
    if (hasNonRelativePath(event.toolName, targets)) {
      return {
        block: true,
        reason: "sensitive-canary: file-tool paths must be relative while canary is on. Retry with a path relative to the current working directory. For external paths, resolve them at runtime in Bash, or explicitly use /canary off.",
      };
    }
  });

  // ── ingress: user-authored text, before it reaches the provider ───────────
  // Stay synchronous unless a TUI confirm is required: bench and most unit
  // tests call context without await.
  pi.on("context", (event, ctx) => {
    if (!canaryEnabled) return;
    const all = event.messages as readonly unknown[] as Message[];
    const requested = latestAllowTags(all);
    const interactive = Boolean(
      requested.size > 0 &&
      allowGrant === undefined &&
      ctx?.hasUI && ctx.ui?.select && ctx.mode && ["tui", "rpc"].includes(ctx.mode),
    );
    const redact = () => {
      if (allowTags.has("all")) return;
      return withScanBudget(() => {
    let total = 0;
    const messages = all.map((message) => {
      if (message.role !== "user") return message;
      if (
        (typeof message.content === "string" &&
          message.content.includes(SYNTHESIS_NOTICE)) ||
        (Array.isArray(message.content) &&
          message.content.some(
            (chunk) => isTextChunk(chunk) && chunk.text.includes(SYNTHESIS_NOTICE),
          ))
      ) {
        return message;
      }
      if (typeof message.content === "string") {
        if (message.content.length > MAX_SCAN_BYTES) {
          total++;
          return {
            ...message,
            content: syntheticValue(message.content),
          };
        }
        const { text, hits } = redactText(message.content, allowTags);
        if (hits === 0) return message;
        total += hits;
        return {
          ...message,
          content: text,
        };
      }
      if (!Array.isArray(message.content)) return message;
      const { content, hits } = redactChunks(message.content, allowTags);
      if (hits === 0) return message;
      total += hits;
      return { ...message, content };
    });

    if (total === 0) return;
    recordWarning(total);
    return { messages };
      });
    };
    if (interactive) {
      return (async () => {
        const resolved = await resolveAllowGrant(requested, ctx, allowGrant);
        allowGrant = resolved.grant;
        allowTags = resolved.tags;
        return redact();
      })();
    }
    if (allowGrant === false) allowTags = new Set();
    else allowTags = requested;
    if (requested.size > 0 && allowGrant === undefined) allowGrant = true;
    return redact();
  });

  // ── final egress: scan the exact provider payload ─────────────────────────
  pi.on("before_provider_request", (event, ctx) => withScanBudget(() => {
    if (!canaryEnabled) return;
    if (allowTags.has("all")) return;
    const { value, hits } = redactValue(event.payload, allowTags, undefined, undefined, [], true);
    if (hits === 0) return;

    recordWarning(hits);
    return value;
  }));

  // ── egress: synthesize sensitive values before they enter the transcript ─
  pi.on("tool_result", (event, ctx) => withScanBudget(() => {
    if (!canaryEnabled) return;
    const input = event.input ?? {};
    const command = String(input.command ?? "");
    const targets =
      event.toolName === "bash"
        ? extractFilePathsFromCommand(command)
        : candidatePaths(input);
    const fileKind = targets.some(isDotenvFile)
      ? "dotenv"
      : targets.some(isSecretFile)
        ? "secret-file"
        : "none";
    const result = sanitizeToolContent(event.content, fileKind, allowTags);
    const { content, hits } = result;
    const finalContent = hits === 0 ? event.content : content;
    pi.events.emit("sensitive-canary:tool-result-sanitized", {
      toolCallId: event.toolCallId,
      digest: toolResultDigest(finalContent),
    });
    if (hits === 0) return;

    recordWarning(hits);
    return { content: finalContent };
  }));
  // ── persistence: store the redacted view, never the original ────────────
  // The context/tool_result handlers patch provider-bound copies. Session
  // entries keep the originals, and compaction re-sends those originals
  // without touching the extension bus. Redacting here (same role back, so
  // the runner syncs state and storage) closes that leak: whatever the
  // provider saw is all compaction can re-send. Allow-tags behave exactly
  // as on the wire, so approved values keep working across turns.
  // Tool-call argument chunks are left alone: execution already ran on them.
  pi.on("message_end", (event) => withScanBudget(() => {
    if (!canaryEnabled) return;
    const message = event.message as { role?: string; content?: unknown; details?: unknown };
    if (!message || typeof message !== "object") return;
    const tags =
      message.role === "user"
        ? latestAllowTags([{ role: "user", content: message.content } as Message])
        : allowTags;
    if (tags.has("all")) return;
    let content = message.content;
    let details = message.details;
    let hits = 0;
    if (message.role === "user" || message.role === "assistant") {
      if (typeof content === "string") {
        if (content.length > MAX_SCAN_BYTES) {
          content = syntheticValue(content);
          hits++;
        } else if (!content.includes(SYNTHESIS_NOTICE)) {
          const redacted = redactText(content, tags);
          if (redacted.hits > 0) {
            content = redacted.text;
            hits += redacted.hits;
          }
        }
      } else if (Array.isArray(content)) {
        const redacted = redactChunks(content, tags);
        if (redacted.hits > 0) {
          content = redacted.content;
          hits += redacted.hits;
        }
      }
    }
    if (details !== undefined) {
      const redacted = redactValue(details, tags);
      if (redacted.hits > 0) {
        details = redacted.value;
        hits += redacted.hits;
      }
    }
    if (hits === 0) return;
    recordWarning(hits);
    return { message: { ...message, content, details } };
  }));
  pi.on("session_shutdown", () => {
    allowTags.clear();
    allowGrant = undefined;
    setRuntimeInventory([]);
    clearCaches();
  });
}
