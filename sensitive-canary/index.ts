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
// format-preserving strings. PII replacements are stable stand-ins from
// reserved namespaces (host-3c9d0e, prod-db.n4a5b6c.internal.example,
// 241.18.5.7; see lib/aliases.ts) that keep roles and relationships. Tool
// calls that reuse a stand-in are blocked, so none is mistaken for a real
// path or identifier. `aliases: "tokens"` restores `__CANARY_HOST_1__`.
//
// Interception points:
//   tool_call               -- block secret-file access, cookie transfer, and
//                              secret-shaped tool arguments.
//   context                 -- synthesize user-authored sensitive values.
//   before_provider_request -- scan the final wire payload, including system
//                              prompts and provider-specific fields.
//   tool_result             -- synthesize tool output and secret-file values.
//   message_end             -- persist the redacted view, never the original.
//   session_before_compact  -- redact the summarization copy.
//   session_before_tree     -- redact the branch-summary copy. Compaction and
//                              branch summaries call the provider without
//                              before_provider_request and serialize stored
//                              thinking, tool-call arguments, user bash
//                              output, and extension messages. These events
//                              stop that path from re-sending a raw value.
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
import { readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { type Finding, type LocatedFinding, mergeRanges, scanWindows, SCAN_WINDOW_OVERLAP, withScanBudget, assertScanBudget, ScanBudgetExceeded, setRuntimeInventory, clearWindowCache, exportWindowCache, importWindowCache, windowCacheRevision, aliasStyle, aliasKeyScope, ruleAliasLabel, aliasLabels, inventoryLiterals, ruleGeneralization, isPromptOnlyRule, GENERALIZE_PATH } from "./lib/rules.ts";
import { assignInPlace, planSwapBack } from "./lib/swap-back.ts";
import { AliasBook, aliasKeyPath, aliasSpans, isAliasValue, loadAliasKey, registerAliasLabels, SESSION_KEY_SUFFIX, sessionAliasKey } from "./lib/aliases.ts";
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
import { collectRuntimeIdentity, identityFromGit, identityFromGitRemotes, identityFromOs, identityFromSsh } from "./lib/runtime-inventory.ts";

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

interface ThinkingChunk {
  type: "thinking";
  thinking: string;
}

function isThinkingChunk(value: unknown): value is ThinkingChunk {
  if (typeof value !== "object" || value === null) return false;
  if (!("type" in value) || value.type !== "thinking") return false;
  return "thinking" in value && typeof value.thinking === "string";
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

// One book per process. The key loads lazily so importing the module (bench,
// tests) never touches the key file until a PII value needs a stand-in.
let aliasBook: AliasBook | undefined;
function aliases(): AliasBook {
  // Before any session starts (bench, tests): shared key if configured,
  // otherwise one that lives only in this process.
  aliasBook ??= new AliasBook(aliasKeyScope() === "shared" ? loadAliasKey() : randomBytes(32));
  return aliasBook;
}

// PII replacement. Stand-ins keep role, shape, and relationships and stay
// stable across sessions; `aliases: "tokens"` restores the numbered
// __CANARY_*__ placeholders.
function piiReplacement(ruleId: string, value: string): string {
  const general = ruleGeneralization(ruleId);
  if (general !== undefined) return `⟦${general}⟧`;
  if (aliasStyle() === "tokens") return syntheticToken(ruleId, value);
  return aliases().standIn(ruleId, value, ruleAliasLabel(ruleId));
}

function isSyntheticValue(value: string): boolean {
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

function clearCaches(): void {
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
    // A cache loss must not break the agent.
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

// Set while user-typed text is scanned (context ingress, persisting a user
// message). Prompt-scoped generalize rules apply only then. The scans are
// synchronous, so a plain flag cannot leak into another scan.
let scanningUserText = false;

function asUserText<T>(scan: () => T): T {
  const outer = scanningUserText;
  scanningUserText = true;
  try {
    return scan();
  } finally {
    scanningUserText = outer;
  }
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
  const allowed = allowTags.has("all") ? [] : [...raw, ...swappedFindings(text)].filter((f) => !isSyntheticValue(f.secretValue));
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
    .filter((finding) => !insideBoilerplate(finding))
    .filter((finding) => scanningUserText || !isPromptOnlyRule(finding.ruleId));
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
          ? piiReplacement(finding.ruleId, finding.secretValue)
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
      ? piiReplacement(finding.ruleId, value)
      : syntheticValue(value);
  if (kind === "json-string") return JSON.stringify(synthetic);
  if (kind === "json-number") return JSON.stringify(synthetic);
  return synthetic;
}

// Applies redactText to every text and thinking chunk. The ingress (context),
// egress (tool_result), and persistence/summarization handlers share it. The
// function leaves tool-call chunks alone unless redactToolArgs is set. Tools
// execute their arguments after message_end, so the caller decides when a
// rewrite cannot break a pending call.
function redactChunks(
  content: readonly unknown[],
  allowTags: Set<string> = new Set(),
  redactToolArgs = false,
): {
  content: unknown[];
  hits: number;
} {
  let hits = 0;
  const out = content.map((chunk) => {
    if (isTextChunk(chunk)) {
      if (chunk.text.length > MAX_SCAN_BYTES) {
        hits++;
        return { ...chunk, text: syntheticValue(chunk.text) };
      }
      const { text, hits: n } = redactText(chunk.text, allowTags);
      if (n === 0) return chunk;
      hits += n;
      return { ...chunk, text };
    }
    if (isThinkingChunk(chunk)) {
      if (chunk.thinking.length > MAX_SCAN_BYTES) {
        hits++;
        return { ...chunk, thinking: syntheticValue(chunk.thinking) };
      }
      const { text, hits: n } = redactText(chunk.thinking, allowTags);
      if (n === 0) return chunk;
      hits += n;
      return { ...chunk, thinking: text };
    }
    if (redactToolArgs && typeof chunk === "object" && chunk !== null &&
        (chunk as { type?: unknown }).type === "toolCall") {
      const args = (chunk as { arguments?: unknown }).arguments;
      if (args === undefined) return chunk;
      const redacted = redactValue(args, allowTags);
      if (redacted.hits === 0) return chunk;
      hits += redacted.hits;
      return { ...(chunk as Record<string, unknown>), arguments: redacted.value };
    }
    return chunk;
  });
  return { content: out, hits };
}

// Returns a redacted copy of a message. The message_end handler and the
// summarization hooks use it, and the caller chooses whether tool-call
// arguments are in scope. Nothing here mutates the input.
function redactStoredMessage(
  message: Record<string, unknown>,
  allowTags: Set<string>,
  redactToolArgs: boolean,
): { message: Record<string, unknown>; hits: number } {
  let hits = 0;
  let out = message;
  const replaceField = (field: string, value: unknown): void => {
    if (typeof value !== "string" || value.length === 0) return;
    if (value.length > MAX_SCAN_BYTES) {
      out = { ...out, [field]: syntheticValue(value) };
      hits++;
      return;
    }
    if (field === "content" && value.includes(SYNTHESIS_NOTICE)) return;
    const redacted = redactText(value, allowTags);
    if (redacted.hits === 0) return;
    out = { ...out, [field]: redacted.text };
    hits += redacted.hits;
  };
  if (message.role === "user" || message.role === "assistant" || message.role === "custom") {
    if (typeof message.content === "string") {
      replaceField("content", message.content);
    } else if (Array.isArray(message.content)) {
      const redacted = redactChunks(message.content, allowTags, redactToolArgs);
      if (redacted.hits > 0) {
        out = { ...out, content: redacted.content };
        hits += redacted.hits;
      }
    }
  } else if (message.role === "toolResult") {
    if (Array.isArray(message.content)) {
      const redacted = redactChunks(message.content, allowTags, false);
      if (redacted.hits > 0) {
        out = { ...out, content: redacted.content };
        hits += redacted.hits;
      }
    }
  } else if (message.role === "bashExecution") {
    replaceField("command", message.command);
    replaceField("output", message.output);
  } else if (message.role === "branchSummary" || message.role === "compactionSummary") {
    replaceField("summary", message.summary);
  }
  if (message.details !== undefined) {
    const redacted = redactValue(message.details, allowTags);
    if (redacted.hits > 0) {
      out = { ...out, details: redacted.value };
      hits += redacted.hits;
    }
  }
  return { message: out, hits };
}

// Redacts the preparation arrays in place. The core reads
// preparation.messagesToSummarize / turnPrefixMessages after the event.
// Replacing them here changes only the summarization copy. It never changes
// the transcript or the messages that tools already executed against.
function redactCompactionPreparation(preparation: Record<string, unknown>, allowTags: Set<string>): number {
  let hits = 0;
  for (const key of ["messagesToSummarize", "turnPrefixMessages"] as const) {
    const list = preparation[key];
    if (!Array.isArray(list)) continue;
    preparation[key] = list.map((message) => {
      if (!message || typeof message !== "object") return message;
      const redacted = redactStoredMessage(message as Record<string, unknown>, allowTags, true);
      hits += redacted.hits;
      return redacted.message;
    });
  }
  if (typeof preparation.previousSummary === "string") {
    const redacted = redactText(preparation.previousSummary, allowTags);
    if (redacted.hits > 0) {
      preparation.previousSummary = redacted.text;
      hits += redacted.hits;
    }
  }
  // The core extracts the file lists before this event and appends them to the
  // summary. Without this step, a path that was just redacted inside a tool
  // call would travel to the provider through the file list.
  const fileOps = preparation.fileOps as
    | { read?: unknown; written?: unknown; edited?: unknown }
    | undefined;
  if (fileOps && typeof fileOps === "object") {
    for (const key of ["read", "written", "edited"] as const) {
      const paths = fileOps[key];
      if (!(paths instanceof Set)) continue;
      const redactedPaths = new Set<string>();
      for (const path of paths) {
        const redacted = redactText(String(path), allowTags);
        hits += redacted.hits;
        redactedPaths.add(redacted.text);
      }
      fileOps[key] = redactedPaths;
    }
  }
  return hits;
}

// Branch summaries read session entries, not messages. The core keeps the
// array reference it collected, so the handler replaces entries in place.
// Each original entry must stay untouched for the transcript and the TUI.
function redactStoredEntry(entry: Record<string, unknown>, allowTags: Set<string>): { entry: Record<string, unknown>; hits: number } {
  if (entry.type === "message" && entry.message && typeof entry.message === "object") {
    const redacted = redactStoredMessage(entry.message as Record<string, unknown>, allowTags, true);
    if (redacted.hits === 0) return { entry, hits: 0 };
    return { entry: { ...entry, message: redacted.message }, hits: redacted.hits };
  }
  if (entry.type === "custom_message") {
    const redacted = redactStoredMessage(
      { role: "custom", content: entry.content, details: entry.details },
      allowTags,
      true,
    );
    if (redacted.hits === 0) return { entry, hits: 0 };
    return {
      entry: { ...entry, content: redacted.message.content, details: redacted.message.details },
      hits: redacted.hits,
    };
  }
  if (entry.type === "branch_summary" || entry.type === "compaction") {
    if (typeof entry.summary !== "string") return { entry, hits: 0 };
    const redacted = redactText(entry.summary, allowTags);
    if (redacted.hits === 0) return { entry, hits: 0 };
    return { entry: { ...entry, summary: redacted.text }, hits: redacted.hits };
  }
  return { entry, hits: 0 };
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
function commandPathCandidates(command: string, cwd: string): string[] {
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
  return commandPathCandidates(command, cwd).some(isSecretFile);
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
  // The generalize list: which topics you consider sensitive.
  if (expanded.endsWith("/sensitive-canary/generalize.json") || expanded === canonicalPath(GENERALIZE_PATH, cwd)) return true;
  // The stand-in key: with it, stand-ins could be matched back to guesses.
  if (expanded.endsWith("/sensitive-canary/alias-key") || expanded.endsWith(SESSION_KEY_SUFFIX) || expanded === canonicalPath(aliasKeyPath(), cwd)) return true;
  return !!override && expanded === canonicalPath(override, cwd);
}

function commandReadsCanaryInventory(command: string, cwd: string): boolean {
  return commandPathCandidates(command, cwd).some((candidate) => isCanaryInventory(candidate, cwd));
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

// Home-directory paths carry the username, which the canary redacts, so the
// model would be typing a path it can only half see. Absolute paths elsewhere
// (/etc, /nix/store) are fine unless they themselves contain a sensitive
// value. Windows drive and UNC paths stay blocked. Scan-budget trips block.
function blocksPrivatePath(toolName: string, targets: string[], cwd: string): boolean {
  if (!FILE_PATH_TOOLS.has(toolName)) return false;
  const home = process.env.HOME ? canonicalPath(process.env.HOME, cwd) : "";
  return targets.some((target) => {
    const value = target.replace(/^@/, "");
    if (/^~|^\$(?:HOME|\{HOME\})(?:[\\/]|$)/.test(value)) return true;
    if (path.win32.isAbsolute(value) && !path.isAbsolute(value)) return true;
    if (value.startsWith("\\\\")) return true;
    if (!path.isAbsolute(value)) return false;
    const resolved = canonicalPath(value, cwd);
    if (home && home !== "/" && (resolved === home || resolved.startsWith(`${home}/`))) return true;
    if (home && home !== "/" && (value === process.env.HOME || value.startsWith(`${process.env.HOME}/`))) return true;
    try {
      const { findings, trips } = cachedScan(value);
      return trips.length > 0 || findings.length > 0;
    } catch (error) {
      if (error instanceof ScanBudgetExceeded) return true;
      throw error;
    }
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
  "SENSITIVE-CANARY: Sensitive values can be synthetic placeholders. These placeholders are not real credentials, identities, contact details, or production data. Personal and infrastructure values become stable stand-ins: names under the .example TLD, label-hex words (user-3c9d0e, person-…, host-…), n-hex name parts, 240.0.0.0/5 and 2001:db8:: addresses, 02: MACs. Stand-ins keep roles and relationships (same domain, same subnet, same person) within this session; a new session uses new stand-ins. Preserve only their structure and relationships. Never pass a placeholder to a tool or attempt to reverse it. Never cd into, read, or execute a path containing a placeholder: resolve the dynamic segment at runtime ($HOME, $(id -un), positional selection) instead of reusing redacted text. If one blocks the task, stop and ask the user to re-run with [allow-pii].";

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
  // Generalized wording stands for several possible originals, so it can
  // never be swapped back: written into a file or command it would replace
  // the real text.
  if (!allowTags.has("pii")) {
    const general = serialized.match(GENERALIZED)?.[0];
    if (general !== undefined) return general;
  }
  // Stand-ins are swapped back to real values instead (see tool_call). With
  // the older numbered tokens nothing is swapped, so a stand-in left over
  // from a stand-ins session would reach the wrong host: block it.
  if (allowTags.has("pii") || aliasStyle() === "stand-ins") return;
  return aliasSpans(serialized)[0];
}

// Real values swapped into tool calls this session, by the rule id that
// re-detects them. Output that echoes one is aliased again even when no
// scanning rule would have caught it (a host composed from known parts).
const SWAPPED = new Map<string, string>();
const SWAPPED_MAX = 2_000;

function rememberSwapped(value: string, ruleId: string): void {
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

function blocksSecretAccess(toolName: string, command: string, targets: string[], allowTags: Set<string>, cwd: string): boolean {
  if (allowTags.has("secret")) return false;
  return (
    (toolName === "bash" && (commandReadsSecretFile(command, cwd) || commandSendsCookies(command))) ||
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

  pi.on("session_start", async (event, ctx) => {
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
    setRuntimeInventory(collectRuntimeIdentity({
      ...identityFromOs(),
      ...identityFromGit(),
      // SSH config and git remotes name infrastructure; opt out with
      // SENSITIVE_CANARY_INFRA_INVENTORY=off.
      ...(process.env.SENSITIVE_CANARY_INFRA_INVENTORY === "off"
        ? {}
        : { ...identityFromSsh(), ...identityFromGitRemotes(ctx?.cwd ?? process.cwd()) }),
    }));
    registerAliasLabels(aliasLabels());
    // One key per session unless aliasKey is "shared" (see lib/aliases.ts).
    const started = event as { reason?: string; previousSessionFile?: string } | undefined;
    aliasBook = new AliasBook(aliasKeyScope() === "shared"
      ? loadAliasKey()
      : sessionAliasKey(ctx.sessionManager.getSessionFile?.(), started?.reason === "fork" ? started.previousSessionFile : undefined));
    // Mint inventory stand-ins up front, so stand-ins from earlier sessions
    // swap back before their value has appeared in this one.
    if (aliasStyle() === "stand-ins") {
      for (const entry of inventoryLiterals()) aliases().standIn(entry.ruleId, entry.literal, entry.label);
    }
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
    if (blocksSecretAccess(event.toolName, command, targets, allowTags, ctx?.cwd ?? process.cwd())) {
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
        reason: placeholder.startsWith("⟦")
          ? `sensitive-canary: ${placeholder} is generalized wording, not the original text, and cannot be written back or used in a command. Leave that text out of the call, or add [allow-pii] to the current user prompt to bypass this check.`
          : `sensitive-canary: ${placeholder} is a synthetic placeholder, not a real path or identifier — the call cannot succeed with it. Resolve the real value at runtime ($HOME, $(id -un), positional selection) instead of reusing redacted text. Add [allow-pii] or [allow-all] to the current user prompt to bypass this check.`,
      };
    }
    if (withScanBudget(() => toolInputHasSecret(event.input, allowTags))) {
      return {
        block: true,
        reason: "sensitive-canary: refusing to send a secret in a tool call. Add [allow-secrets] or [allow-all] to the current user prompt to bypass this check.",
      };
    }
    if (withScanBudget(() => blocksPrivatePath(event.toolName, targets, ctx?.cwd ?? process.cwd()))) {
      return {
        block: true,
        reason: "sensitive-canary: file-tool paths inside the home directory, or containing an identifying name, must be relative while canary is on. Retry with a path relative to the current working directory. For home paths, resolve them at runtime in Bash ($HOME), or explicitly use /canary off.",
      };
    }
    // Swap-back runs last, on arguments every check above has passed. Pi
    // executes the tool with this same object, so mutating it in place is
    // how the real values reach the tool (documented extension behavior).
    // The transcript keeps the model's original, stand-in arguments.
    if (aliasStyle() !== "stand-ins") return;
    const swap = planSwapBack(event.toolName, event.input, aliases(), allowTags.has("pii") || allowTags.has("all"));
    if (swap.unresolved.length > 0) {
      return {
        block: true,
        reason: `sensitive-canary: ${swap.unresolved[0]} is a stand-in this session cannot map back to a real value (it may come from another machine or a re-rolled key). Resolve the real value at runtime ($HOME, $(id -un), positional selection), or ask the user.`,
      };
    }
    if (swap.egress.length > 0) {
      return {
        block: true,
        reason: `sensitive-canary: ${swap.egress[0]} stands in for a real value, and this call would send it off the machine (a web tool, or a network command whose destination is not one of your own hosts). Use the stand-in only as the host you connect to, or add [allow-pii] to the current user prompt to bypass this check.`,
      };
    }
    if (swap.resolved.length === 0) return;
    // Real paths can land on a guarded file (a stand-in home directory).
    const swappedInput = swap.input as Record<string, unknown>;
    const swappedCommand = String(swappedInput.command ?? "");
    const swappedTargets = candidatePaths(swappedInput);
    if (blocksSecretAccess(event.toolName, swappedCommand, swappedTargets, allowTags, ctx?.cwd ?? process.cwd()) ||
        blocksInventoryAccess(event.toolName, swappedCommand, swappedTargets, allowTags, ctx?.cwd ?? process.cwd())) {
      return {
        block: true,
        reason: "sensitive-canary: refusing direct secret or inventory access. Add [allow-secrets], [allow-pii], or [allow-all] to the current user prompt to bypass this check.",
      };
    }
    for (const resolved of swap.resolved) rememberSwapped(resolved.value, resolved.ruleId);
    assignInPlace(event.input, swap.input);
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
    const messages = all.map((message) => asUserText(() => {
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
    }));

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
  // without touching the extension bus. This handler redacts the message in
  // place, and the runner syncs state and storage, so the stored view is the
  // view the provider saw. Allow-tags behave exactly as on the wire, so
  // approved values keep working across turns. Tool-call arguments are only
  // rewritten when the message cannot execute them. The summarization hooks
  // cover the rest.
  pi.on("message_end", (event) => withScanBudget(() => {
    if (!canaryEnabled) return;
    const message = event.message as Record<string, unknown> | undefined;
    if (!message || typeof message !== "object") return;
    const tags =
      message.role === "user"
        ? latestAllowTags([{ role: "user", content: message.content } as Message])
        : allowTags;
    if (tags.has("all")) return;
    // Tool calls execute after message_end. Rewriting their arguments here
    // would feed placeholders to the tool runner. An error, an abort, or a
    // token-cap stop cannot execute them, so those are safe to rewrite.
    const stopReason = message.stopReason;
    const mayExecuteTools =
      message.role === "assistant" &&
      stopReason !== "error" && stopReason !== "aborted" && stopReason !== "length";
    const redact = () => redactStoredMessage(message, tags, !mayExecuteTools);
    const redacted = message.role === "user" ? asUserText(redact) : redact();
    if (redacted.hits === 0) return;
    recordWarning(redacted.hits);
    return { message: redacted.message };
  }));
  // ── summarization: compaction and branch summaries bypass the wire hook ──
  // completeSummarization calls the agent stream function directly, so
  // before_provider_request never runs for it. The preparation holds stored
  // messages (thinking, tool-call arguments, bash output, extension content)
  // that compaction serializes verbatim. Redact the copy it will use.
  pi.on("session_before_compact", (event) => withScanBudget(() => {
    if (!canaryEnabled || allowTags.has("all")) return;
    const preparation = (event as { preparation?: Record<string, unknown> }).preparation;
    if (!preparation || typeof preparation !== "object") return;
    const hits = redactCompactionPreparation(preparation, allowTags);
    if (hits > 0) recordWarning(hits);
  }));
  pi.on("session_before_tree", (event) => withScanBudget(() => {
    if (!canaryEnabled || allowTags.has("all")) return;
    const entries = (event as { preparation?: { entriesToSummarize?: unknown[] } }).preparation
      ?.entriesToSummarize;
    if (!Array.isArray(entries)) return;
    let hits = 0;
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index];
      if (!entry || typeof entry !== "object") continue;
      const redacted = redactStoredEntry(entry as Record<string, unknown>, allowTags);
      hits += redacted.hits;
      if (redacted.entry !== entry) entries[index] = redacted.entry;
    }
    if (hits > 0) recordWarning(hits);
  }));
  pi.on("session_shutdown", () => {
    allowTags.clear();
    allowGrant = undefined;
    setRuntimeInventory([]);
    clearCaches();
  });
}
