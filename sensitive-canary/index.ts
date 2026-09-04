// sensitive-canary for Pi.
//
// Upstream (coo-quack/sensitive-canary) ships Claude Code hooks: standalone
// processes that read a JSON envelope on stdin and signal a block through the
// exit code. Pi's extension API is an in-process event bus instead, so the
// executables do not transfer. The *detection engine* does, and that is the
// part worth having -- 31 upstream rules (plus local additions) derived from
// gitleaks/TruffleHog, entropy filtering, Luhn validation. lib/{rules,inspector}.ts are vendored from
// upstream 9111ed20841d1ffefd86092dcb8b52ba082d973a (MIT, see lib/LICENSE),
// with local additions: rules.ts carries LOCAL_SECRET_RULES (extra providers
// plus an entropy rule anchored to secret-ish key names) and scan() passes
// validate() the extracted secretValue; inspector.ts has the unused
// resolveTagPriority removed. Refresh by re-copying upstream into
// SECRET_RULES / re-applying the deletions — see the notes in each file.
//
// The port is deliberately not one-to-one. Pi exposes tool_result and the
// final provider payload, so detected values can be replaced before they enter
// the transcript or leave the process. Replacements are stable, random,
// format-preserving strings; the model keeps usable structure without seeing
// original values.
//
// Three interception points:
//   context                 -- synthesize user-authored sensitive values.
//   before_provider_request -- scan the final wire payload, including system
//                              prompts and provider-specific fields.
//   tool_result             -- synthesize tool output and all `.env` values.
//
// Detection is deliberately non-bypassable. A regex scanner is defense in
// depth, not a confidentiality boundary: proprietary design can still look
// like ordinary prose and requires an approved provider or local model.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { type Finding, scan } from "./lib/rules.ts";
import { dedupeFindings, type Message, randomBird } from "./lib/inspector.ts";
import { toolResultDigest } from "./lib/certification.ts";

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
  const cost = (value.length + synthetic.length) * 2;
  if (cost <= SYNTHETIC_VALUES_MAX_BYTES) {
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
}

function redactText(text: string): { text: string; hits: number } {
  const findings = dedupeFindings(cachedScan(text)).filter(
    (finding) => !isSyntheticValue(finding.secretValue),
  );
  for (const finding of findings) {
    text = text.replaceAll(
      finding.secretValue,
      syntheticValue(finding.secretValue),
    );
  }
  return { text, hits: findings.length };
}

// Applies redactText to every text chunk. Shared by the ingress (context)
// and egress (tool_result) handlers.
function redactChunks(content: readonly unknown[]): {
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
    const { text, hits: n } = redactText(chunk.text);
    if (n === 0) return chunk;
    hits += n;
    return { ...chunk, text };
  });
  return { content: out, hits };
}

function redactValue(
  value: unknown,
  key?: string,
): { value: unknown; hits: number } {
  if (key !== undefined && OPAQUE_PROVIDER_FIELDS[key] === true) {
    return { value, hits: 0 };
  }
  if (typeof value === "string") {
    if (value.length > MAX_SCAN_BYTES) {
      return { value: syntheticValue(value), hits: 1 };
    }
    const { text, hits } = redactText(value);
    return { value: text, hits };
  }
  if (Array.isArray(value)) {
    let hits = 0;
    const out = value.map((item) => {
      const result = redactValue(item);
      hits += result.hits;
      return result.value;
    });
    return { value: out, hits };
  }
  if (typeof value === "object" && value !== null) {
    let hits = 0;
    const out = Object.fromEntries(
      Object.entries(value).map(([childKey, item]) => {
        const result = redactValue(item, childKey);
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

function resultNamesEnvFile(content: readonly unknown[]): boolean {
  return content.some(
    (chunk) =>
      isTextChunk(chunk) &&
      chunk.text.split("\n").some((line) => {
        const location = /^(.+):\d+(?:-\d+)?$/.exec(line.trim());
        return location !== null && isEnvFile(location[1] ?? "");
      }),
  );
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
  "[sensitive-canary] Some sensitive values in this context were replaced with synthetic placeholders. Treat them as non-real data; preserve their structure only.";

function withSynthesisNotice(content: readonly unknown[]): unknown[] {
  return [...content, { type: "text", text: `\n\n${SYNTHESIS_NOTICE}` }];
}

export default function sensitiveCanary(pi: ExtensionAPI): void {
  let pendingWarningCount = 0;

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
  });

  pi.on("agent_end", (_event, ctx) => {
    flushWarning(ctx);
  });

  // ── pre-exec: block direct sensitive-file reads ───────────────────────────
  pi.on("tool_call", (event) => {
    const input = (event.input ?? {}) as Record<string, unknown>;
    const command = String(input.command ?? "");
    const targets = candidatePaths(input);
    if (
      (event.toolName === "bash" && commandReadsEnv(command)) ||
      targets.some(isEnvFile)
    ) {
      return {
        block: true,
        reason: "sensitive-canary: refusing to read .env files",
      };
    }
  });

  // ── ingress: user-authored text, before it reaches the provider ───────────
  pi.on("context", async (event, ctx) => {
    const all = event.messages as readonly unknown[] as Message[];
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
        const { text, hits } = redactText(message.content);
        if (hits === 0) return message;
        total += hits;
        return {
          ...message,
          content: `${text}\n\n${SYNTHESIS_NOTICE}`,
        };
      }
      if (!Array.isArray(message.content)) return message;
      const { content, hits } = redactChunks(message.content);
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
    const { value, hits } = redactValue(event.payload);
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
    const envOutput = targets.some(isEnvFile);
    const result = envOutput
      ? synthesizeEnvChunks(event.content)
      : redactChunks(event.content);
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
  pi.on("session_shutdown", () => {
    clearCaches();
  });
}
