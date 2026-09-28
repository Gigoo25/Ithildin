// Canary engine as the proxy uses it: redact a provider request body, and
// swap stand-ins in the model's tool calls back to real values.
//
// The engine is packages/sensitive-canary (core.ts + lib/), and this proxy is
// the only place it runs: every agent (Claude, Pi, local models) points its
// provider base URL here. The proxy is a single long-lived process for every agent and session, so its stand-ins come from
// one persistent key (proxy-alias-key): a restart keeps them stable, and so
// keeps the provider's prompt cache warm.
//
// Every request carries the whole conversation, and redacting it re-mints
// every stand-in the model can name, so the book never needs to be saved.

import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { aliases, asUserText, blocksInventoryAccess, blocksSecretAccess, candidatePaths, flushScanCache, isSecretPath, latestAllowTags, loadScanCache, redactValue, rememberSwapped, setAliasBook } from "../engine/core.ts";
import { AliasBook, aliasKeyPath, loadAliasKey, registerAliasLabels } from "../engine/lib/aliases.ts";
import type { Message } from "../engine/lib/inspector.ts";
import { aliasLabels, aliasStyle, inventoryLiterals, setRuntimeInventory, withScanBudget } from "../engine/lib/rules.ts";
import { collectRuntimeIdentity, identityFromGit, identityFromOs, identityFromSsh } from "../engine/lib/runtime-inventory.ts";
import { planSwapBack } from "../engine/lib/swap-back.ts";

export type Format = "anthropic" | "chat" | "responses";

// Scan results survive a restart (which every rules change triggers): cold,
// one long conversation costs seconds; loaded, tens of milliseconds. The file
// holds rule ranges keyed by text hashes, never values, and is dropped when
// the rules change.
let scanCacheBase: string | undefined;

export function saveScanCache(): void {
  flushScanCache(scanCacheBase);
}

export function initEngine(keyFile = process.env.SENSITIVE_CANARY_PROXY_KEY_FILE ?? path.join(path.dirname(aliasKeyPath()), "proxy-alias-key")): void {
  setRuntimeInventory(collectRuntimeIdentity({
    ...identityFromOs(),
    ...identityFromGit(),
    // Git remotes are per project, and the proxy has no project.
    ...(process.env.SENSITIVE_CANARY_INFRA_INVENTORY === "off" ? {} : identityFromSsh()),
  }));
  registerAliasLabels(aliasLabels());
  setAliasBook(new AliasBook(loadAliasKey(keyFile)));
  scanCacheBase = path.join(path.dirname(keyFile), "proxy");
  loadScanCache(scanCacheBase);
  if (aliasStyle() === "stand-ins") {
    for (const entry of inventoryLiterals()) aliases().standIn(entry.ruleId, entry.literal, entry.label);
  }
}

// ── allow tags ──────────────────────────────────────────────────────────────
// The latest thing the user typed decides. Tool-result turns (Anthropic user
// messages holding only tool_result blocks) are not typed, so they are
// skipped.

function textBlocks(content: unknown): Array<{ type: "text"; text: string }> {
  if (typeof content === "string") return [{ type: "text", text: content }];
  if (!Array.isArray(content)) return [];
  return content.flatMap((block) => {
    if (typeof block === "string") return [{ type: "text" as const, text: block }];
    if (!block || typeof block !== "object") return [];
    const { type, text } = block as { type?: unknown; text?: unknown };
    return (type === "text" || type === "input_text") && typeof text === "string" ? [{ type: "text" as const, text }] : [];
  });
}

export function requestAllowTags(format: Format, body: Record<string, unknown>): Set<string> {
  const list = format === "responses"
    ? (typeof body.input === "string" ? [{ role: "user", content: body.input }] : body.input)
    : body.messages;
  if (!Array.isArray(list)) return new Set();
  const users: Message[] = [];
  for (const item of list) {
    if (!item || typeof item !== "object" || (item as { role?: unknown }).role !== "user") continue;
    const blocks = textBlocks((item as { content?: unknown }).content);
    if (blocks.length > 0) users.push({ role: "user", content: blocks });
  }
  return latestAllowTags(users);
}

// ── request redaction ───────────────────────────────────────────────────────

// Anthropic block fields that are wire identifiers or signed model output.
// Thinking is signed: one changed character fails the whole request. It is the
// provider's own output, so nothing in it is news to the provider.
const ANTHROPIC_OPAQUE_BLOCKS = new Set(["thinking", "redacted_thinking"]);
const ANTHROPIC_ID_KEYS = new Set(["id", "tool_use_id", "name", "signature", "cache_control"]);

function redactAnthropicBlock(block: unknown, tags: Set<string>, location: Array<string | number>): { value: unknown; hits: number } {
  if (!block || typeof block !== "object" || Array.isArray(block)) return redactValue(block, tags, undefined, undefined, location, true);
  const record = block as Record<string, unknown>;
  if (typeof record.type === "string" && ANTHROPIC_OPAQUE_BLOCKS.has(record.type)) return { value: block, hits: 0 };
  let hits = 0;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (ANTHROPIC_ID_KEYS.has(key) && (typeof value === "string" || key === "cache_control")) {
      out[key] = value;
      continue;
    }
    const result = redactValue(value, tags, key, record, [...location, key], true);
    hits += result.hits;
    out[key] = result.value;
  }
  return { value: out, hits };
}

// Typed user text gets prompt-scoped generalize rules too; tool output, files
// and model text do not, so files using those words stay readable. Anthropic
// user turns also carry tool_result blocks, which are not typed.
function typed<T>(user: boolean, scan: () => T): T {
  return user ? asUserText(scan) : scan();
}

function redactAnthropic(body: Record<string, unknown>, tags: Set<string>): { value: Record<string, unknown>; hits: number } {
  const { messages, ...rest } = body;
  const top = redactValue(rest, tags, undefined, undefined, [], true);
  let hits = top.hits;
  const out = top.value as Record<string, unknown>;
  if (Array.isArray(messages)) {
    out.messages = messages.map((message, i) => {
      if (!message || typeof message !== "object") return message;
      const { content, ...fields } = message as Record<string, unknown>;
      const next: Record<string, unknown> = { ...fields };
      const user = fields.role === "user";
      if (typeof content === "string") {
        const result = typed(user, () => redactValue(content, tags, "content", message as Record<string, unknown>, ["messages", i, "content"], true));
        hits += result.hits;
        next.content = result.value;
      } else if (Array.isArray(content)) {
        next.content = content.map((block, j) => {
          const text = user && (block as { type?: unknown } | null)?.type === "text";
          const result = typed(text, () => redactAnthropicBlock(block, tags, ["messages", i, "content", j]));
          hits += result.hits;
          return result.value;
        });
      } else if (content !== undefined) {
        next.content = content;
      }
      return next;
    });
  } else if (messages !== undefined) {
    out.messages = messages;
  }
  return { value: out, hits };
}

// Chat messages and Responses input items: the same walk as the rest of the
// body, with user items scanned as typed text.
function redactOpenAi(format: Format, body: Record<string, unknown>, tags: Set<string>): { value: Record<string, unknown>; hits: number } {
  const key = format === "responses" ? "input" : "messages";
  const { [key]: list, ...rest } = body;
  const top = redactValue(rest, tags, undefined, undefined, [], true);
  let hits = top.hits;
  const out = top.value as Record<string, unknown>;
  if (Array.isArray(list)) {
    out[key] = list.map((item, i) => {
      const user = !!item && typeof item === "object" && (item as { role?: unknown }).role === "user";
      const result = typed(user, () => redactValue(item, tags, undefined, undefined, [key, i], true));
      hits += result.hits;
      return result.value;
    });
  } else {
    const result = typed(true, () => redactValue(list, tags, key, body, [key], true));
    hits += result.hits;
    if (list !== undefined) out[key] = result.value;
  }
  return { value: out, hits };
}

export function redactRequest(format: Format, body: Record<string, unknown>): { body: Record<string, unknown>; hits: number; tags: Set<string> } {
  const tags = requestAllowTags(format, body);
  const stripped = stripAllowTags(format, body);
  if (tags.has("all")) return { body: stripped, hits: 0, tags };
  const result = redactBody(format, stripped, tags);
  return { body: result.body, hits: result.hits, tags };
}

// One scan envelope per request. Split out so tests can set the allow tags.
export function redactBody(format: Format, body: Record<string, unknown>, tags: Set<string>): { body: Record<string, unknown>; hits: number } {
  return withScanBudget(() => {
    const withheld = withholdSecretReads(format, body, tags);
    const result = format === "anthropic" ? redactAnthropic(withheld.body, tags) : redactOpenAi(format, withheld.body, tags);
    return { body: result.value, hits: result.hits + withheld.hits };
  });
}

// ── secret reads ────────────────────────────────────────────────────────────
// The tool runs on this machine; only what it returned travels. A result whose
// call read a secret file (.env, private keys, credentials) or the canary's
// own inventory is replaced whole: values in those files often have no shape
// the rules could find. The call itself stays, so the model knows what it ran.
// Results are matched to calls by id, which every format carries. Checked on
// the harness's real arguments, before redaction rewrites them.

export const WITHHELD_NOTICE = "Output withheld: this call read a protected file (.env, private keys, credentials), so its contents are not shown. Work with such files through commands that do not print their values, or ask the user to include [allow-secrets] in their prompt.";

// The agent's working directory, from its system prompt (Claude: "Primary
// working directory:", Pi: "Current working directory:"). The latest mention
// wins: Claude reports a changed cwd in later user turns. Relative tool paths
// resolve against it, so links to secret files are followed from the right
// place. Falls back to $HOME.
const CWD_LINE = /(?:Primary|Current) working directory: ([^\n]+)/g;

export function requestCwd(format: Format, body: Record<string, unknown>): string {
  const texts: string[] = [];
  const add = (content: unknown) => { for (const block of textBlocks(content)) texts.push(block.text); };
  add(format === "anthropic" ? body.system : format === "responses" ? body.instructions : undefined);
  const list = format === "responses" ? body.input : body.messages;
  if (Array.isArray(list)) {
    for (const item of list) {
      const role = (item as { role?: unknown } | null)?.role;
      if (role === "user" || role === "system" || role === "developer") add((item as { content?: unknown }).content);
    }
  }
  let cwd: string | undefined;
  for (const text of texts) for (const match of text.matchAll(CWD_LINE)) cwd = match[1]!.trim();
  try {
    if (cwd && path.isAbsolute(cwd) && statSync(cwd).isDirectory()) return cwd;
  } catch {
    // A stale or foreign cwd: fall through.
  }
  return process.env.HOME ?? process.cwd();
}

function readsSecret(name: string, input: unknown, tags: Set<string>, cwd: string): boolean {
  if (!input || typeof input !== "object" || Array.isArray(input)) return false;
  const record = input as Record<string, unknown>;
  const tool = BASH_TOOLS.has(name) ? "bash" : name;
  const command = String(record.command ?? "");
  const targets = candidatePaths(record);
  return blocksSecretAccess(tool, command, targets, tags, cwd) || blocksInventoryAccess(tool, command, targets, tags, cwd);
}

function parseArgs(json: unknown): unknown {
  if (typeof json !== "string") return json;
  try {
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

function withholdSecretReads(format: Format, body: Record<string, unknown>, tags: Set<string>): { body: Record<string, unknown>; hits: number } {
  const list = format === "responses" ? body.input : body.messages;
  if (!Array.isArray(list)) return { body, hits: 0 };
  const cwd = requestCwd(format, body);
  const listed = secretListing(cwd);
  const secret = new Set<string>();
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    if (format === "anthropic" && Array.isArray(record.content)) {
      for (const block of record.content as Array<Record<string, unknown>>) {
        if (block?.type === "tool_use" && readsSecret(String(block.name), block.input, tags, cwd)) secret.add(String(block.id));
      }
    } else if (format === "chat" && Array.isArray(record.tool_calls)) {
      for (const call of record.tool_calls as Array<{ id?: unknown; function?: { name?: unknown; arguments?: unknown } }>) {
        if (readsSecret(String(call?.function?.name), parseArgs(call?.function?.arguments), tags, cwd)) secret.add(String(call.id));
      }
    } else if (format === "responses" && (record.type === "function_call" || record.type === "custom_tool_call")) {
      if (readsSecret(String(record.name), parseArgs(record.arguments ?? record.input), tags, cwd)) secret.add(String(record.call_id));
    }
  }
  let hits = 0;
  // A result is withheld whole, or has its secret-file search lines withheld.
  const result = (id: unknown, content: unknown): unknown => {
    if (secret.has(String(id))) {
      hits++;
      return WITHHELD_NOTICE;
    }
    const lines = withholdSecretLines(content, listed);
    hits += lines.hits;
    return lines.content;
  };
  const replaced = list.map((item) => {
    if (!item || typeof item !== "object") return item;
    const record = item as Record<string, unknown>;
    if (format === "anthropic" && Array.isArray(record.content)) {
      const before = hits;
      const content = (record.content as Array<Record<string, unknown>>).map((block) =>
        block?.type === "tool_result" ? { ...block, content: result(block.tool_use_id, block.content) } : block);
      return hits > before ? { ...record, content } : item;
    }
    if (format === "chat" && record.role === "tool") {
      const before = hits;
      const content = result(record.tool_call_id, record.content);
      return hits > before ? { ...record, content } : item;
    }
    if (format === "responses" && (record.type === "function_call_output" || record.type === "custom_tool_call_output")) {
      const before = hits;
      const output = result(record.call_id, record.output);
      return hits > before ? { ...record, output } : item;
    }
    return item;
  });
  return hits === 0 ? { body, hits } : { body: { ...body, [format === "responses" ? "input" : "messages"]: replaced }, hits };
}

// Search output names a file on each line (grep -rn, rg: "path:12:text",
// context "path-12-text") or once above its rows (search_files, rg --heading:
// "path:" then "12:text"). A search over a directory reads secret files the
// call never named, so their lines are withheld one by one. Other output
// shapes are not recognized.
export const WITHHELD_LINE = "[protected-file line withheld]";
const GROUP_HEADER = /^(\S[^:]*):$/;
// search_files rows: "  12: text", "  12- context", "  12:5 text" (column);
// rg --heading: "12:text".
const GROUP_ROW = /^(\s*\d+(?::\d+)?[:-]?(?=\s)|\s*\d+[:-])/;
const FLAT_CONTEXT = /^(\S.*?)-\d+-/;

// Whether a listed path is a secret file, following links. A name with spaces
// counts only when it exists: "Loaded .env: 3 vars" is prose, not a path.
// Memoized per request: every line of every result is a candidate.
function secretListing(cwd: string): (listed: string) => boolean {
  const seen = new Map<string, boolean>();
  return (listed) => {
    let secret = seen.get(listed);
    if (secret === undefined) {
      secret = (!/\s/.test(listed) || existsSync(path.resolve(cwd, listed))) && isSecretPath(listed, cwd);
      seen.set(listed, secret);
    }
    return secret;
  };
}

function withholdLines(text: string, secret: (listed: string) => boolean): { text: string; hits: number } {
  if (!text.includes(":") && !text.includes("-")) return { text, hits: 0 };
  let hits = 0;
  let group = false;
  const lines = text.split("\n").map((line) => {
    // A header that is not a secret file may still be a flat line ending
    // in ":" (".env-3-KEY:"), so it falls through to the flat checks.
    const header = GROUP_HEADER.exec(line);
    if (header && secret(header[1]!)) {
      group = true;
      return line;
    }
    const row = GROUP_ROW.exec(line);
    if (row) {
      if (!group) return line;
      hits++;
      return `${row[1]} ${WITHHELD_LINE}`;
    }
    group = false;
    // Match lines put ":" after the path, context lines "-12-"; context text
    // can hold a ":" too, so both heads are checked.
    const colon = line.indexOf(":");
    const head = [colon > 0 ? line.slice(0, colon) : undefined, FLAT_CONTEXT.exec(line)?.[1]]
      .find((candidate) => candidate !== undefined && secret(candidate));
    if (!head) return line;
    hits++;
    return `${head}: ${WITHHELD_LINE}`;
  });
  return hits === 0 ? { text, hits } : { text: lines.join("\n"), hits };
}

// Tool result content: a string, or text parts (Anthropic text blocks, chat
// text parts, Responses input_text).
function withholdSecretLines(content: unknown, secret: (listed: string) => boolean): { content: unknown; hits: number } {
  if (typeof content === "string") {
    const out = withholdLines(content, secret);
    return { content: out.text, hits: out.hits };
  }
  if (!Array.isArray(content)) return { content, hits: 0 };
  let hits = 0;
  const parts = content.map((part) => {
    if (!part || typeof part !== "object" || typeof (part as { text?: unknown }).text !== "string") return part;
    const out = withholdLines((part as { text: string }).text, secret);
    hits += out.hits;
    return out.hits === 0 ? part : { ...part, text: out.text };
  });
  return hits === 0 ? { content, hits } : { content: parts, hits };
}

// ── provider blindness ──────────────────────────────────────────────────────
// The provider must not learn that values are swapped. The proxy adds nothing
// that mentions redaction, and the allow tags the user types are removed from
// the typed text it forwards; they still set this request's policy here. Tool
// output keeps them: rewriting it would corrupt what a command printed.

// Same tag set the engine parses (resolveTagPriority).
const ALLOW_TAG = /\[(?:allow|mask)-(?:all|secrets?|pii)\][ \t]?/gi;

function stripTagText(content: unknown): unknown {
  if (typeof content === "string") return content.replace(ALLOW_TAG, "");
  if (!Array.isArray(content)) return content;
  return content.map((block) => {
    if (!block || typeof block !== "object") return block;
    const { type, text } = block as { type?: unknown; text?: unknown };
    return (type === "text" || type === "input_text") && typeof text === "string" ? { ...block, text: text.replace(ALLOW_TAG, "") } : block;
  });
}

export function stripAllowTags(format: Format, body: Record<string, unknown>): Record<string, unknown> {
  if (format === "responses" && typeof body.input === "string") return { ...body, input: stripTagText(body.input) };
  const key = format === "responses" ? "input" : "messages";
  const list = body[key];
  if (!Array.isArray(list)) return body;
  return {
    ...body,
    [key]: list.map((item) => {
      if (!item || typeof item !== "object" || (item as { role?: unknown }).role !== "user") return item;
      const record = item as { content?: unknown };
      return { ...record, content: stripTagText(record.content) };
    }),
  };
}

// ── swap-back ───────────────────────────────────────────────────────────────
// Only tools that run on this machine get real values. Anything else (web
// tools, MCP servers, subagent prompts) keeps the stand-ins: a real value
// must not leave the machine through a tool the proxy cannot see into.

const BASH_TOOLS = new Set(["bash", "Bash"]);
const LOCAL_TOOLS = new Set([
  "read", "write", "edit", "grep", "find", "ls", "search_files",
  "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS", "NotebookEdit",
]);

// planSwapBack's tool vocabulary: "bash" gets the network-destination check,
// "web_fetch" treats every position as egress.
function swapToolName(name: string): string {
  if (BASH_TOOLS.has(name)) return "bash";
  if (LOCAL_TOOLS.has(name)) return name;
  return "web_fetch";
}

export function swapToolArguments(toolName: string, args: unknown, tags: Set<string>): { args: unknown; swapped: number } {
  if (aliasStyle() !== "stand-ins") return { args, swapped: 0 };
  const swap = planSwapBack(swapToolName(toolName), args, aliases(), tags.has("pii") || tags.has("all"));
  // Swap per span. A stand-in the book cannot resolve (often a stand-in-shaped
  // literal in source or docs), or one bound off the machine, stays a stand-in
  // in swap.input: that span fails on a name that does not exist rather than
  // leaking the value, while resolved spans beside it still get real values.
  if (swap.resolved.length === 0) return { args, swapped: 0 };
  for (const resolved of swap.resolved) rememberSwapped(resolved.value, resolved.ruleId);
  return { args: swap.input, swapped: swap.resolved.length };
}

// Reply text the model wrote. It goes to the harness on this machine, not a
// tool, so every stand-in the book knows is swapped and none counts as egress.
// The next request redacts it again: rememberSwapped makes the real value
// re-detectable, and the persistent key gives it the same stand-in, so the
// provider sees the bytes it wrote and the prompt cache holds.
export function swapText(text: string, tags: Set<string>): { text: string; swapped: number } {
  if (aliasStyle() !== "stand-ins" || text === "") return { text, swapped: 0 };
  const swap = planSwapBack("read", text, aliases(), tags.has("pii") || tags.has("all"));
  if (swap.resolved.length === 0) return { text, swapped: 0 };
  for (const resolved of swap.resolved) rememberSwapped(resolved.value, resolved.ruleId);
  return { text: swap.input as string, swapped: swap.resolved.length };
}

// Arguments as a JSON string (OpenAI shapes, Anthropic streaming).
export function swapToolJson(toolName: string, json: string, tags: Set<string>): { json: string; swapped: number } {
  let args: unknown;
  try {
    args = json.trim() === "" ? {} : JSON.parse(json);
  } catch {
    return { json, swapped: 0 };
  }
  const result = swapToolArguments(toolName, args, tags);
  return result.swapped === 0 ? { json, swapped: 0 } : { json: JSON.stringify(result.args), swapped: result.swapped };
}

