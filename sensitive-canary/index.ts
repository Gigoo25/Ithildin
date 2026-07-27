// sensitive-canary for omp.
//
// Upstream (coo-quack/sensitive-canary) ships Claude Code hooks: standalone
// processes that read a JSON envelope on stdin and signal a block through the
// exit code. omp's extension API is an in-process event bus instead, so the
// executables do not transfer. The *detection engine* does, and that is the
// part worth having -- 31 rules derived from gitleaks/TruffleHog, entropy
// filtering, Luhn validation. lib/{rules,inspector}.ts are vendored verbatim
// from upstream 9111ed20841d1ffefd86092dcb8b52ba082d973a (MIT, see lib/LICENSE);
// refresh by re-copying those two files, they import nothing of their own.
//
// The port is deliberately not one-to-one, because omp can do something Claude
// Code cannot. Upstream's PreToolUse sees a tool's *inputs* and may only allow
// or deny, so it guards `Read(.env)` by filename and greps a bash command
// string for paths. It is blind to what a command actually prints --
// `ssh host 'cat settings.json'` sails through and the key lands in the
// transcript. omp exposes tool_result, which rewrites output after execution,
// so this port scans egress too and redacts in place.
//
// Three interception points, and the reason for each:
//   tool_call   -- refuse .env by name, and files whose contents scan dirty,
//                  before the read happens (upstream parity).
//   tool_result -- scan every tool's output and redact. The load-bearing one.
//   context     -- scan user-authored text before each API call. omp has no
//                  cancel-the-prompt event, so this redacts rather than blocks;
//                  the notify() keeps it from being silent.
//
// Allow tags ([allow-secret] / [allow-pii] / [allow-all]) behave as upstream
// documents. Upstream recovers them by tailing the session transcript from a
// short-lived subprocess; here the context event already carries the message
// list, so tags are parsed there and cached for the tool events that follow.

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import fs from "node:fs";
import path from "node:path";
import { type Finding, scan } from "./lib/rules.ts";
import {
  applyAllowTags,
  dedupeFindings,
  findingsToLines,
  type Message,
  parseAllowTags,
  randomBird,
} from "./lib/inspector.ts";

// Files/outputs above this size stream past unscanned. 31 regexes over a
// multi-megabyte buffer is not worth the stall on every read.
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

const ALLOW_HINTS: readonly string[] = [
  "To allow, the user must add a tag to their next prompt:",
  "  [allow-secret]  — allow secrets",
  "  [allow-pii]     — allow PII",
  "  [allow-all]     — bypass all checks",
];

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
// every API call. Keyed by exact text; redaction is idempotent, so reusing a
// hit is always safe.
const SCAN_CACHE = new Map<string, Finding[]>();
const SCAN_CACHE_MAX = 512;

function cachedScan(text: string): Finding[] {
  const hit = SCAN_CACHE.get(text);
  if (hit) return hit;
  const found = scan(text);
  if (SCAN_CACHE.size >= SCAN_CACHE_MAX) {
    const oldest = SCAN_CACHE.keys().next().value;
    if (oldest !== undefined) SCAN_CACHE.delete(oldest);
  }
  SCAN_CACHE.set(text, found);
  return found;
}

// Allow tags from the most recent user turn, refreshed by the context handler.
let allowTags = new Set<string>();

// Shared block envelope: every refusal the LLM sees has the same shape, so the
// three call sites below stay in lockstep.
function blocked(
  source: string,
  detail: readonly string[],
): { block: true; reason: string } {
  return {
    block: true,
    reason: [
      `${randomBird()} sensitive-canary: blocked — ${source}`,
      "",
      ...detail,
      "",
      ...ALLOW_HINTS,
    ].join("\n"),
  };
}

// Rewrites secret values to `[REDACTED <description>]` in every text chunk.
// Shared by the ingress (context) and egress (tool_result) handlers.
function redactChunks(content: readonly unknown[]): {
  content: unknown[];
  hits: number;
} {
  let hits = 0;
  const out = content.map((chunk) => {
    if (!isTextChunk(chunk) || chunk.text.length > MAX_SCAN_BYTES) return chunk;
    const findings = dedupeFindings(
      applyAllowTags(cachedScan(chunk.text), allowTags),
    );
    if (findings.length === 0) return chunk;

    let text = chunk.text;
    for (const finding of findings) {
      hits++;
      text = text.replaceAll(
        finding.secretValue,
        `[REDACTED ${finding.description}]`,
      );
    }
    return { ...chunk, text };
  });
  return { content: out, hits };
}

// upstream parity: `.env` and `.env.*` are refused by name whatever they hold.
// A file merely ending in `.env` (production.env) is left to content scanning.
function isBlockedEnvFile(filePath: string): boolean {
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
      paths.push(token);
    }
  }
  return [...new Set(paths)];
}

// `echo $STRIPE_KEY` never names a secret in the command text; the value only
// appears once the shell expands it. Upstream resolves referenced names against
// the hook's own environment and scans those values, so this does the same.
function extractEnvVarNames(command: string): string[] {
  const names = new Set<string>();
  const pattern = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
  for (const match of command.matchAll(pattern)) {
    const name = match[1] ?? match[2];
    if (name) names.add(name);
  }
  return [...names];
}

function scanFileAt(filePath: string): Finding[] {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size > MAX_SCAN_BYTES) return [];
    return cachedScan(fs.readFileSync(filePath, "utf8"));
  } catch {
    // Unreadable or missing: not this hook's problem, let the tool report it.
    return [];
  }
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

export default function sensitiveCanary(pi: ExtensionAPI): void {
  // ── ingress: user-authored text, before it reaches the provider ───────────
  pi.on("context", async (event, ctx) => {
    allowTags = parseAllowTags(event.messages as readonly unknown[] as Message[]);
    if (allowTags.has("all")) return;

    let total = 0;
    const messages = event.messages.map((message) => {
      if (message.role !== "user" || !Array.isArray(message.content)) {
        return message;
      }
      const { content, hits } = redactChunks(message.content);
      if (hits === 0) return message;
      total += hits;
      return { ...message, content };
    });

    if (total === 0) return;
    ctx.ui?.notify?.(
      `${randomBird()} sensitive-canary: redacted ${total} value(s) from your prompt`,
      "warning",
    );
    return { messages };
  });

  // ── pre-execution: refuse the read outright (upstream parity) ─────────────
  pi.on("tool_call", async (event) => {
    if (allowTags.has("all")) return;
    const input: Record<string, unknown> = event.input ?? {};
    const isBash = event.toolName.toLowerCase() === "bash";
    const command = String(input.command ?? "");

    const targets = isBash
      ? extractFilePathsFromCommand(command)
      : candidatePaths(input);

    for (const target of targets) {
      if (isBlockedEnvFile(target)) {
        return blocked(target, [
          ".env and .env.* contain secrets and must not be read into the conversation.",
        ]);
      }
      const findings = dedupeFindings(
        applyAllowTags(scanFileAt(target), allowTags),
      );
      if (findings.length > 0) {
        return blocked(target, findingsToLines(findings));
      }
    }

    if (!isBash) return;
    const expanded: Finding[] = [];
    for (const name of extractEnvVarNames(command)) {
      const value = process.env[name];
      if (value) expanded.push(...cachedScan(value));
    }
    const findings = dedupeFindings(applyAllowTags(expanded, allowTags));
    if (findings.length > 0) {
      return blocked("expanded environment variable", findingsToLines(findings));
    }
  });

  // ── egress: what the tool actually printed. No upstream equivalent. ───────
  pi.on("tool_result", async (event, ctx) => {
    if (event.isError || allowTags.has("all")) return;

    const { content, hits } = redactChunks(event.content);
    if (hits === 0) return;

    ctx.ui?.notify?.(
      `${randomBird()} sensitive-canary: redacted ${hits} value(s) from ${event.toolName} output`,
      "warning",
    );
    return { content };
  });
}
