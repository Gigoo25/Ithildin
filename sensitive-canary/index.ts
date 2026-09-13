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
// paths or identifiers; only the value type leaks.
//
// Five interception points:
//   tool_call               -- block direct `.env` access and cookie transfer.
//   context                 -- synthesize user-authored sensitive values.
//   before_provider_request -- scan the final wire payload, including system
//                              prompts and provider-specific fields.
//   tool_result             -- synthesize tool output and all `.env` values.
//   message_end             -- persist the redacted view, never the original,
//                              so compaction (which bypasses the event bus and
//                              reads stored entries) can only re-send what the
//                              provider already saw.
//
// The latest user prompt can bypass one category or all checks with an
// explicit allow tag. Older, quoted, and runtime-generated tags do not apply.
// This scanner remains a defense in depth, not a confidentiality boundary.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { type Finding, scan } from "./lib/rules.ts";
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

// Larger strings skip regex scanning and are synthesized in full.
const MAX_SCAN_BYTES = 2_000_000;

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
const SCAN_CACHE = new Map<string, Finding[]>();
// Budget the memo by bytes, not entries: 512 × 2 MB keys is a gigabyte of RAM.
const SCAN_CACHE_MAX_BYTES = 32_000_000;
let scanCacheBytes = 0;

function cachedScan(text: string): Finding[] {
  const hit = SCAN_CACHE.get(text);
  if (hit) return hit;
  const found = scan(text);
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

function clearCaches(): void {
  SCAN_CACHE.clear();
  scanCacheBytes = 0;
  SYNTHETIC_VALUES.clear();
  SYNTHETIC_OUTPUTS.clear();
  syntheticValuesBytes = 0;
  TOKEN_COUNTERS.clear();
}

function redactText(text: string, allowTags: Set<string> = new Set()): { text: string; hits: number } {
  let cookieHits = 0;
  if (!allowTags.has("secret")) {
    const cookieResult = redactCookieHeaders(text, syntheticValue, isSyntheticValue);
    text = cookieResult.text;
    cookieHits = cookieResult.hits;
  }
  const findings = applyAllowTags(
    dedupeFindings(cachedScan(text)).filter(
      (finding) => !isSyntheticValue(finding.secretValue),
    ),
    allowTags,
  );
  for (const finding of findings) {
    const replacement =
      finding.category === "pii"
        ? syntheticToken(finding.ruleId, finding.secretValue)
        : syntheticValue(finding.secretValue);
    text = text.replaceAll(finding.secretValue, replacement);
  }
  return { text, hits: cookieHits + findings.length };
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

function redactValue(
  value: unknown,
  allowTags: Set<string>,
  key?: string,
  parent?: Record<string, unknown>,
): { value: unknown; hits: number } {
  if (key !== undefined && OPAQUE_PROVIDER_FIELDS[key] === true) {
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
    const out = value.map((item) => {
      const result = redactValue(item, allowTags);
      hits += result.hits;
      return result.value;
    });
    return { value: out, hits };
  }
  if (typeof value === "object" && value !== null) {
    let hits = 0;
    const out = Object.fromEntries(
      Object.entries(value).map(([childKey, item]) => {
        const result = redactValue(item, allowTags, childKey, value as Record<string, unknown>);
        hits += result.hits;
        return [childKey, result.value];
      }),
    );
    return { value: out, hits };
  }
  return { value, hits: 0 };
}

// `.env` and `.env.* may contain low-entropy passwords that pattern matching
// cannot detect. Their values are always synthesized while keys remain useful.
function isEnvFile(filePath: string): boolean {
  if (!filePath) return false;
  return filePath.split(/[?:]/).some((candidate) => {
    const base = path.basename(candidate);
    return base === ".env" || (base.startsWith(".env.") && base !== ".env.example");
  });
}

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

function commandReadsEnv(command: string): boolean {
  return command
    .split(/[\s|;&<>]+/)
    .some((token) =>
      isEnvFile(token.replace(/^["'`()$]+|["'`()]+$/g, "")),
    );
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

const SYNTHESIS_NOTICE =
  "[sensitive-canary] Some sensitive values in this context were replaced with synthetic placeholders. Treat them as non-real data; preserve their structure only. Do not use placeholders as file paths, command arguments, URLs, or identifiers.";

const SYNTHESIS_SYSTEM_REMINDER =
  "SENSITIVE-CANARY: Sensitive values can be synthetic placeholders. These placeholders are not real credentials, identities, contact details, or production data. Preserve only their structure and relationships. Never pass a placeholder to a tool or attempt to reverse it. If one blocks the task, stop and ask the user to re-run with [allow-pii].";

function withSynthesisNotice(content: readonly unknown[]): unknown[] {
  if (
    content.some(
      (chunk) => isTextChunk(chunk) && chunk.text.includes(SYNTHESIS_NOTICE),
    )
  ) {
    return [...content];
  }
  return [...content, { type: "text", text: `\n\n${SYNTHESIS_NOTICE}` }];
}

function latestAllowTags(messages: Message[]): Set<string> {
  const latestUser = [...messages].reverse().find((message) => message.role === "user");
  return resolveTagPriority(latestUser ? userTypedText(latestUser) : "").effectiveAllow;
}

function blocksSecretAccess(toolName: string, command: string, targets: string[], allowTags: Set<string>): boolean {
  if (allowTags.has("secret")) return false;
  return (
    (toolName === "bash" && (commandReadsEnv(command) || commandSendsCookies(command))) ||
    targets.some(isEnvFile)
  );
}

function sanitizeToolContent(
  content: readonly unknown[],
  envOutput: boolean,
  allowTags: Set<string>,
): { content: unknown[]; hits: number } {
  if (allowTags.has("all")) return { content: [...content], hits: 0 };
  if (envOutput && !allowTags.has("secret")) return synthesizeEnvChunks(content);
  return redactChunks(content, allowTags);
}

export default function sensitiveCanary(pi: ExtensionAPI): void {
  let pendingWarningCount = 0;
  let allowTags = new Set<string>();

  pi.events.on("sensitive-canary:sanitize-stored-text", (event: { text: string; certified: boolean }) => {
    if (typeof event.text !== "string") return;
    event.text = event.text.length > MAX_SCAN_BYTES
      ? syntheticValue(event.text)
      : redactText(event.text).text;
    event.certified = true;
  });

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
  });

  pi.on("agent_end", (_event, ctx) => {
    flushWarning(ctx);
  });

  pi.on("before_agent_start", (event) => {
    if (event.systemPrompt.includes(SYNTHESIS_SYSTEM_REMINDER)) return;
    return {
      systemPrompt: `${event.systemPrompt}\n\n${SYNTHESIS_SYSTEM_REMINDER}`,
    };
  });

  // ── pre-exec: block direct sensitive-file reads ───────────────────────────
  pi.on("tool_call", (event) => {
    const input = (event.input ?? {}) as Record<string, unknown>;
    const command = String(input.command ?? "");
    const targets = candidatePaths(input);
    if (blocksSecretAccess(event.toolName, command, targets, allowTags)) {
      return {
        block: true,
        reason: "sensitive-canary: refusing direct secret access or transmission. Add [allow-secrets] or [allow-all] to the current user prompt to bypass this check.",
      };
    }
  });

  // ── ingress: user-authored text, before it reaches the provider ───────────
  pi.on("context", async (event, ctx) => {
    const all = event.messages as readonly unknown[] as Message[];
    allowTags = latestAllowTags(all);
    if (allowTags.has("all")) return;
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
            content: `${syntheticValue(message.content)}\n\n${SYNTHESIS_NOTICE}`,
          };
        }
        const { text, hits } = redactText(message.content, allowTags);
        if (hits === 0) return message;
        total += hits;
        return {
          ...message,
          content: `${text}\n\n${SYNTHESIS_NOTICE}`,
        };
      }
      if (!Array.isArray(message.content)) return message;
      const { content, hits } = redactChunks(message.content, allowTags);
      if (hits === 0) return message;
      total += hits;
      return { ...message, content: withSynthesisNotice(content) };
    });

    if (total === 0) return;
    recordWarning(total);
    return { messages };
  });

  // ── final egress: scan the exact provider payload ─────────────────────────
  pi.on("before_provider_request", async (event, ctx) => {
    if (allowTags.has("all")) return;
    const { value, hits } = redactValue(event.payload, allowTags);
    if (hits === 0) return;

    recordWarning(hits);
    return value;
  });

  // ── egress: synthesize sensitive values before they enter the transcript ─
  pi.on("tool_result", async (event, ctx) => {
    const input = event.input ?? {};
    const command = String(input.command ?? "");
    const targets =
      event.toolName === "bash"
        ? extractFilePathsFromCommand(command)
        : candidatePaths(input);
    const result = sanitizeToolContent(event.content, targets.some(isEnvFile), allowTags);
    const { content, hits } = result;
    const finalContent = hits === 0 ? event.content : withSynthesisNotice(content);
    pi.events.emit("sensitive-canary:tool-result-sanitized", {
      toolCallId: event.toolCallId,
      digest: toolResultDigest(finalContent),
    });
    if (hits === 0) return;

    recordWarning(hits);
    return { content: finalContent };
  });
  // ── persistence: store the redacted view, never the original ────────────
  // The context/tool_result handlers patch provider-bound copies; session
  // entries keep the originals, and compaction re-sends those originals
  // without touching the extension bus. Redacting here (same role back, so
  // the runner syncs state and storage) closes that leak: whatever the
  // provider saw is all compaction can re-send. Allow-tags behave exactly
  // as on the wire, so approved values keep working across turns.
  // Tool-call argument chunks are left alone: execution already ran on them.
  pi.on("message_end", async (event) => {
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
          content = `${syntheticValue(content)}\n\n${SYNTHESIS_NOTICE}`;
          hits++;
        } else if (!content.includes(SYNTHESIS_NOTICE)) {
          const redacted = redactText(content, tags);
          if (redacted.hits > 0) {
            content = `${redacted.text}\n\n${SYNTHESIS_NOTICE}`;
            hits += redacted.hits;
          }
        }
      } else if (Array.isArray(content)) {
        const redacted = redactChunks(content, tags);
        if (redacted.hits > 0) {
          content = withSynthesisNotice(redacted.content);
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
  });
  pi.on("session_shutdown", () => {
    allowTags.clear();
    clearCaches();
  });
}
