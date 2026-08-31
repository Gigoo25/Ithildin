// sensitive-canary for omp.
//
// Upstream (coo-quack/sensitive-canary) ships Claude Code hooks: standalone
// processes that read a JSON envelope on stdin and signal a block through the
// exit code. omp's extension API is an in-process event bus instead, so the
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
// The port is deliberately not one-to-one. omp exposes tool_result and the
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

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { type Finding, scan } from "./lib/rules.ts";
import { dedupeFindings, type Message, randomBird } from "./lib/inspector.ts";

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
  if (value.length <= MAX_SCAN_BYTES) SYNTHETIC_VALUES.set(value, synthetic);
  return synthetic;
}

function redactText(text: string): { text: string; hits: number } {
  const findings = dedupeFindings(cachedScan(text));
  if (findings.length === 0) return { text, hits: 0 };
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

function redactValue(value: unknown): { value: unknown; hits: number } {
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
      Object.entries(value).map(([key, item]) => {
        const result = redactValue(item);
        hits += result.hits;
        return [key, result.value];
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
  const base = path.basename(filePath);
  return base === ".env" || base.startsWith(".env.");
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

// Candidate path inputs across omp's file-touching tools. `read` uses `path`,
// but selectors ride along on it (`file.ts:20-40`), so the suffix is trimmed
// before the filename test.
function candidatePaths(input: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const key of ["path", "file_path", "filePath", "file"]) {
    const value = input[key];
    if (typeof value === "string" && value) {
      out.push(value.replace(/:[0-9raw,+-].*$/, ""));
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

export default function sensitiveCanary(pi: ExtensionAPI): void {
  // ── ingress: user-authored text, before it reaches the provider ───────────
  pi.on("context", async (event, ctx) => {
    const all = event.messages as readonly unknown[] as Message[];
    let total = 0;
    const messages = all.map((message) => {
      if (message.role !== "user") return message;
      if (typeof message.content === "string") {
        if (message.content.length > MAX_SCAN_BYTES) {
          total++;
          return { ...message, content: syntheticValue(message.content) };
        }
        const { text, hits } = redactText(message.content);
        if (hits === 0) return message;
        total += hits;
        return { ...message, content: text };
      }
      if (!Array.isArray(message.content)) return message;
      const { content, hits } = redactChunks(message.content);
      if (hits === 0) return message;
      total += hits;
      return { ...message, content };
    });

    if (total === 0) return;
    ctx.ui?.notify?.(
      `${randomBird()} sensitive-canary: synthesized ${total} value(s) from your prompt`,
      "warning",
    );
    return { messages };
  });

  // ── final egress: scan the exact provider payload ─────────────────────────
  pi.on("before_provider_request", async (event, ctx) => {
    const { value, hits } = redactValue(event.payload);
    if (hits === 0) return;

    ctx.ui?.notify?.(
      `${randomBird()} sensitive-canary: synthesized ${hits} value(s) from provider payload`,
      "warning",
    );
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
    const result = targets.some(isEnvFile)
      ? synthesizeEnvChunks(event.content)
      : redactChunks(event.content);
    const { content, hits } = result;
    if (hits === 0) return;

    ctx.ui?.notify?.(
      `${randomBird()} sensitive-canary: synthesized ${hits} value(s) from ${event.toolName} output`,
      "warning",
    );
    return { content };
  });
}
