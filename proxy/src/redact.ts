// The engine as the proxy uses it: redact a provider request body, and
// swap stand-ins in the model's tool calls back to real values.
//
// The engine is ../engine (core.ts + lib/), and this proxy is the only place
// it runs: every agent (Claude, Pi, local models) points its provider base
// URL here. The proxy is a single long-lived process for every agent and
// session, so its stand-ins come from one persistent key (proxy-alias-key):
// a restart keeps them stable, and so keeps the provider's prompt cache warm.
//
// Every request carries the whole conversation, and redacting it re-mints
// every stand-in the model can name, so the book never needs to be saved.

import { createHmac } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import {
  aliases,
  asUserText,
  collectValues,
  blocksInventoryAccess,
  blocksSecretAccess,
  candidatePaths,
  flushScanCache,
  isSecretPath,
  latestAllowTags,
  loadScanCache,
  redactValue,
  rememberSwapped,
  setAliasBook,
} from "../engine/core.ts";
import {
  AliasBook,
  aliasKeyPath,
  aliasMatches,
  aliasSpans,
  loadAliasKey,
  registerAliasLabels,
} from "../engine/lib/aliases.ts";
import { assert } from "../engine/lib/assert.ts";
import { type Message, userTypedText } from "../engine/lib/inspector.ts";
import { setting } from "../engine/lib/names.ts";
import {
  aliasLabels,
  aliasStyle,
  inventoryLiterals,
  setRuntimeInventory,
  withScanBudget,
} from "../engine/lib/rules.ts";
import {
  collectRuntimeIdentity,
  identityFromGit,
  identityFromNetworkFiles,
  identityFromOs,
  identityFromRepos,
  identityFromSsh,
  identityFromTailscale,
  identityFromWifi,
} from "../engine/lib/runtime-inventory.ts";
import type { InventoryEntry } from "../engine/lib/rules.ts";
import { planSwapBack } from "../engine/lib/swap-back.ts";
import { protectedBlocked, protectedChange } from "./protect.ts";
import { BASH_TOOLS, LOCAL_TOOLS, shellCommand, WRITE_TOOLS } from "./tools.ts";
import { argsKey, initReplay, recordOriginal, replayOriginal, saveReplay } from "./replay.ts";

export type Format = "anthropic" | "chat" | "responses";

// Scan results survive a restart (which every rules change triggers): cold,
// one long conversation costs seconds; loaded, tens of milliseconds. The file
// holds rule ranges keyed by text hashes, never values, and is dropped when
// the rules change.
let scanCacheBase: string | undefined;

export function saveScanCache(): void {
  flushScanCache(scanCacheBase);
  saveReplay();
  aliases().saveCounters();
}

// This machine's identity, as runtime inventory. The proxy serves every
// project, so git remotes come from every repository under the roots
// ($ITHILDIN_REPO_ROOTS, colon-separated; default: home).
function collectIdentity(): InventoryEntry[] {
  const infra = setting("INFRA_INVENTORY") !== "off";
  const roots = setting("REPO_ROOTS")?.split(":").filter(Boolean);
  return collectRuntimeIdentity({
    ...identityFromOs(),
    ...identityFromGit(),
    ...(infra
      ? {
          ...identityFromSsh(),
          ...identityFromRepos(roots),
          ...identityFromWifi(),
          ...identityFromNetworkFiles(),
          ...identityFromTailscale(),
        }
      : {}),
  });
}

// Every value ever collected, keyed by literal. A value only ever joins:
// one that stops being collected (Wi-Fi out of range, a peer offline) is
// still in earlier turns, and every request resends the whole conversation.
// Bounded like every rule source: each entry is a regex on every scan.
const knownIdentity = new Map<string, InventoryEntry>();
export const IDENTITY_ENTRIES_MAX = 1000;

// Merges fresh entries into the known ones and returns whether any joined.
// A new literal whose id is taken gets the next free number on that id,
// which keeps the id's kind (host, ip, ssid) for its stand-in.
export function mergeIdentity(
  known: Map<string, InventoryEntry>,
  fresh: InventoryEntry[],
): boolean {
  const ids = new Set([...known.values()].map((entry) => entry.id));
  assert(ids.size === known.size, "known identity ids are unique");
  let joined = false;
  for (const entry of fresh) {
    const key = entry.caseSensitive === false ? entry.literal.toLowerCase() : entry.literal;
    if (known.has(key)) continue;
    if (known.size >= IDENTITY_ENTRIES_MAX) {
      process.stderr.write(
        `ithildin: identity inventory full at ${IDENTITY_ENTRIES_MAX}; ` +
          "newer values are not covered\n",
      );
      break;
    }
    let id = entry.id;
    const stem = id.replace(/-\d+$/, "");
    // At most ids.size numbers are taken, so ids.size + 2 is always free.
    for (let n = 2; ids.has(id) && n <= ids.size + 2; n++) id = `${stem}-${n}`;
    assert(!ids.has(id), "a renumbered identity id is free");
    ids.add(id);
    known.set(key, { ...entry, id });
    joined = true;
  }
  assert(known.size <= IDENTITY_ENTRIES_MAX, "known identity within its bound");
  return joined;
}

// Collects again (a new network, a new clone) and installs the rules when
// anything joined. Unchanged, the rules and every scan cache stay as they are.
export function refreshIdentity(collect: () => InventoryEntry[] = collectIdentity): boolean {
  if (!mergeIdentity(knownIdentity, collect())) return false;
  setRuntimeInventory([...knownIdentity.values()]);
  registerAliasLabels(aliasLabels());
  if (aliasStyle() === "stand-ins") {
    for (const entry of inventoryLiterals())
      aliases().standIn(entry.ruleId, entry.literal, entry.label);
  }
  return true;
}

export function initEngine(
  keyFile = setting("PROXY_KEY_FILE") ?? path.join(path.dirname(aliasKeyPath()), "proxy-alias-key"),
): void {
  mergeIdentity(knownIdentity, collectIdentity());
  setRuntimeInventory([...knownIdentity.values()]);
  registerAliasLabels(aliasLabels());
  const aliasKey = loadAliasKey(keyFile);
  const book = new AliasBook(aliasKey);
  setAliasBook(book);
  scanCacheBase = path.join(path.dirname(keyFile), "proxy");
  book.loadCounters(`${scanCacheBase}-standins.json`);
  initReplay(
    createHmac("sha256", aliasKey).update("replay").digest(),
    `${scanCacheBase}-replay.json`,
  );
  loadScanCache(scanCacheBase);
  if (aliasStyle() === "stand-ins") {
    for (const entry of inventoryLiterals())
      aliases().standIn(entry.ruleId, entry.literal, entry.label);
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
    return (type === "text" || type === "input_text") && typeof text === "string"
      ? [{ type: "text" as const, text }]
      : [];
  });
}

const PROTECTED_TAG = /\[allow-protected\]/i;

// User text the user did not type: summaries and transcripts the agent
// writes, which can quote tags (a tool's notice saying which to type). Claude
// Code's and Pi's summaries (COMPACTION_SUMMARY_PREFIX, BRANCH_SUMMARY_PREFIX);
// opencode's summary request, whose one user message holds the whole history
// (buildPrompt, or a plugin prompt and "The following is the conversation
// history:"); opencode v2's checkpoint and shell turns (to-llm-message.ts);
// Pi's summary requests (generateSummary, generateTurnPrefixSummary,
// generateBranchSummary), and Claude Code's compact instruction, sent after
// the whole conversation.
const AGENT_WRITTEN = new RegExp(
  "^\\s*(?:This session is being continued from a previous conversation\\b" +
    "|The conversation history before this point was compacted into the following summary:" +
    "|The following is a summary of a branch that this conversation came back from:" +
    "|Here is the conversation so far:\\s*<conversation>" +
    "|<conversation>\\n|# Conversation\\n" +
    "|CRITICAL: Respond with TEXT ONLY\\. Do NOT call any tools\\." +
    "|<conversation-checkpoint>" +
    "|Shell command: )" +
    "|\\n\\nThe following is the conversation history:\\n\\n",
);

// The text blocks of a user turn that may hold what the user typed.
function promptBlocks(content: unknown): Array<{ type: "text"; text: string }> {
  return textBlocks(content).filter((block) => !AGENT_WRITTEN.test(block.text));
}

// The tags each session's latest prompt carried, for its requests that hold
// none: a summary request, whose one user turn the agent wrote, would
// otherwise mask what the user allowed. Oldest sessions go first.
const SESSION_TAGS_MAX = 256;
const sessionTags = new Map<string, Set<string>>();

function rememberTags(session: string, tags: Set<string>) {
  sessionTags.delete(session);
  sessionTags.set(session, new Set(tags));
  if (sessionTags.size > SESSION_TAGS_MAX) sessionTags.delete(sessionTags.keys().next().value!);
}

export function requestAllowTags(
  format: Format,
  body: Record<string, unknown>,
  session?: string,
): Set<string> {
  const list =
    format === "responses"
      ? typeof body.input === "string"
        ? [{ role: "user", content: body.input }]
        : body.input
      : body.messages;
  if (!Array.isArray(list)) return new Set(session ? sessionTags.get(session) : undefined);
  const users: Message[] = [];
  let typed = "";
  for (const item of list) {
    if (!item || typeof item !== "object" || (item as { role?: unknown }).role !== "user") continue;
    const content = (item as { content?: unknown }).content;
    const blocks = promptBlocks(content);
    if (blocks.length === 0) continue;
    // Anthropic tool results come back as user turns, often with harness text
    // beside them. Taken as the latest prompt, they cancelled the typed tag
    // at the first tool call, so [allow-secrets] never reached a read. Such
    // a turn decides only when it carries a tag of its own.
    const results =
      Array.isArray(content) &&
      content.some((block) => (block as { type?: unknown } | null)?.type === "tool_result");
    if (results && latestAllowTags([{ role: "user", content: blocks }]).size === 0) continue;
    // Typed text only: a system reminder quoting CLAUDE.md, or a pasted
    // fence, that mentions [allow-protected] is not the user asking for it.
    if (!results) typed = userTypedText({ role: "user", content: blocks });
    users.push({ role: "user", content: blocks });
  }
  if (users.length === 0) return new Set(session ? sessionTags.get(session) : undefined);
  const tags = latestAllowTags(users);
  // Proxy-only, like [allow-images]: the latest typed prompt decides, not a
  // tool-result turn, whatever tags that carries.
  if (PROTECTED_TAG.test(typed)) tags.add("protected");
  if (session) rememberTags(session, tags);
  return tags;
}

// Typed user prompts in a request, for the badges' per-turn count. Turns
// holding tool results are not prompts, even with harness text beside them.
export function typedPromptCount(format: Format, body: Record<string, unknown>): number {
  const list = format === "responses" ? body.input : body.messages;
  if (!Array.isArray(list)) return typeof list === "string" ? 1 : 0;
  return list.filter((item) => {
    if (!item || typeof item !== "object" || (item as { role?: unknown }).role !== "user")
      return false;
    const content = (item as { content?: unknown }).content;
    if (
      Array.isArray(content) &&
      content.some((block) => (block as { type?: unknown } | null)?.type === "tool_result")
    )
      return false;
    return promptBlocks(content).length > 0;
  }).length;
}

// ── request redaction ───────────────────────────────────────────────────────

// Anthropic block fields that are wire identifiers or signed model output.
// Thinking is signed: one changed character fails the whole request. It is the
// provider's own output, so nothing in it is news to the provider.
const ANTHROPIC_OPAQUE_BLOCKS = new Set(["thinking", "redacted_thinking"]);
const ANTHROPIC_ID_KEYS = new Set(["id", "tool_use_id", "name", "signature", "cache_control"]);

function redactAnthropicBlock(
  block: unknown,
  tags: Set<string>,
  location: Array<string | number>,
): { value: unknown; hits: number } {
  if (!block || typeof block !== "object" || Array.isArray(block))
    return redactValue(block, tags, undefined, undefined, location, true);
  const record = block as Record<string, unknown>;
  if (typeof record.type === "string" && ANTHROPIC_OPAQUE_BLOCKS.has(record.type))
    return { value: block, hits: 0 };
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

function redactAnthropic(
  body: Record<string, unknown>,
  tags: Set<string>,
): { value: Record<string, unknown>; hits: number } {
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
      const replayed =
        !user && typeof content === "string" ? replayOriginal("text", content) : undefined;
      if (replayed !== undefined) {
        next.content = replayed;
      } else if (typeof content === "string") {
        const result = typed(user, () =>
          redactValue(
            content,
            tags,
            "content",
            message as Record<string, unknown>,
            ["messages", i, "content"],
            true,
          ),
        );
        hits += result.hits;
        next.content = result.value;
      } else if (Array.isArray(content)) {
        next.content = content.map((block, j) => {
          const replayed = user ? undefined : replayAnthropicBlock(block);
          if (replayed !== undefined) return replayed;
          const text = user && (block as { type?: unknown } | null)?.type === "text";
          const result = typed(text, () =>
            redactAnthropicBlock(block, tags, ["messages", i, "content", j]),
          );
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

// The model's own turns, as the provider sent them (replay.ts). Undefined
// when the harness's copy is not a recorded one.
function replayAnthropicBlock(block: unknown): unknown {
  if (!block || typeof block !== "object") return undefined;
  const record = block as Record<string, unknown>;
  if (record.type === "text" && typeof record.text === "string") {
    const text = replayOriginal("text", record.text);
    return text === undefined ? undefined : { ...record, text };
  }
  if (record.type === "tool_use") {
    const harness = argsKey(record.input);
    const original = harness === undefined ? undefined : replayOriginal("args", harness);
    return original === undefined ? undefined : { ...record, input: JSON.parse(original) };
  }
  return undefined;
}

// A Chat assistant message or a Responses function call with every
// replayable part put back and every other part redacted. Undefined when
// nothing replays, so the item takes the ordinary walk.
function replayOpenAiItem(
  item: Record<string, unknown>,
  tags: Set<string>,
  location: Array<string | number>,
): { value: unknown; hits: number } | undefined {
  let replays = 0;
  let hits = 0;
  const redact = (
    value: unknown,
    at: Array<string | number>,
    key?: string,
    parent?: Record<string, unknown>,
  ) => {
    const result = redactValue(value, tags, key, parent, at, true);
    hits += result.hits;
    return result.value;
  };
  const replay = (kind: "text" | "args", value: unknown): string | undefined => {
    const harness =
      kind === "text" ? (typeof value === "string" ? value : undefined) : argsKey(value);
    const original = harness === undefined ? undefined : replayOriginal(kind, harness);
    if (original !== undefined) replays++;
    return original;
  };
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(item)) {
    const at = [...location, key];
    if (key === "content" && typeof value === "string") {
      out[key] = replay("text", value) ?? redact(value, at, key, item);
    } else if (key === "content" && Array.isArray(value)) {
      out[key] = value.map((part, i) => {
        const record = part as { type?: unknown; text?: unknown } | null;
        const original =
          record?.type === "text" || record?.type === "output_text"
            ? replay("text", record.text)
            : undefined;
        return original === undefined ? redact(part, [...at, i]) : { ...record, text: original };
      });
    } else if (key === "tool_calls" && Array.isArray(value)) {
      out[key] = value.map((call, i) => {
        const { function: fn, ...fields } = (call ?? {}) as { function?: { arguments?: unknown } };
        const original =
          typeof fn?.arguments === "string" ? replay("args", fn.arguments) : undefined;
        if (original === undefined) return redact(call, [...at, i]);
        return {
          ...(redact(fields, [...at, i]) as Record<string, unknown>),
          function: { ...fn, arguments: original },
        };
      });
    } else if (key === "arguments" && typeof value === "string") {
      out[key] = replay("args", value) ?? redact(value, at, key, item);
    } else if (
      ["type", "role", "id", "call_id", "name"].includes(key) &&
      typeof value === "string"
    ) {
      out[key] = value;
    } else {
      out[key] = redact(value, at, key, item);
    }
  }
  return replays === 0 ? undefined : { value: out, hits };
}

// Chat messages and Responses input items: the same walk as the rest of the
// body, with user items scanned as typed text.
function redactOpenAi(
  format: Format,
  body: Record<string, unknown>,
  tags: Set<string>,
): { value: Record<string, unknown>; hits: number } {
  const key = format === "responses" ? "input" : "messages";
  const { [key]: list, ...rest } = body;
  const top = redactValue(rest, tags, undefined, undefined, [], true);
  let hits = top.hits;
  const out = top.value as Record<string, unknown>;
  if (Array.isArray(list)) {
    out[key] = list.map((item, i) => {
      const record = item as Record<string, unknown> | null;
      if (
        record &&
        typeof record === "object" &&
        (record.role === "assistant" || record.type === "function_call")
      ) {
        const replayed = replayOpenAiItem(record, tags, [key, i]);
        if (replayed) {
          hits += replayed.hits;
          return replayed.value;
        }
      }
      const user =
        !!item && typeof item === "object" && (item as { role?: unknown }).role === "user";
      const result = typed(user, () =>
        redactValue(item, tags, undefined, undefined, [key, i], true),
      );
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

// What one request's redaction did, by kind, for the status badges: distinct
// values masked (stand-ins and generalized words), tool results withheld as
// protected-file reads, search lines withheld from protected files, and
// inline images withheld. hits counts findings instead, per text scanned.
export interface Counts {
  masked: number;
  files: number;
  lines: number;
  images: number;
}

export function redactRequest(
  format: Format,
  body: Record<string, unknown>,
  session?: string,
): { body: Record<string, unknown>; hits: number; counts: Counts; tags: Set<string> } {
  const tags = requestAllowTags(format, body, session);
  requestDirs.set(tags, requestCwd(format, body));
  rememberLiterals(format, body);
  // A new stand-in must not equal a word the conversation already holds:
  // swap-back would turn that word into the real value.
  let corpus: string | undefined;
  aliases().setCorpus(() => (corpus ??= JSON.stringify(body)));
  try {
    return redactWithCorpus(format, body, tags);
  } finally {
    aliases().setCorpus(undefined);
  }
}

function redactWithCorpus(
  format: Format,
  body: Record<string, unknown>,
  tags: Set<string>,
): { body: Record<string, unknown>; hits: number; counts: Counts; tags: Set<string> } {
  // Each prompt's own tag decides its images, read before tags are stripped;
  // the notice goes in after, so its own tag mention survives.
  const images = withholdImages(format, stripAllowTags(format, body), body);
  if (tags.has("all"))
    return {
      body: explainBlocked(format, images.body),
      hits: images.hits,
      counts: { masked: 0, files: 0, lines: 0, images: images.hits },
      tags,
    };
  const stripped = images.body;
  const result = redactBody(format, stripped, tags);
  return {
    body: explainBlocked(format, result.body),
    hits: result.hits + images.hits,
    counts: { ...result.counts, images: images.hits },
    tags,
  };
}

// ── invented stand-ins ──────────────────────────────────────────────────────
// A model that does not know what stand-ins are can take them for corruption.
// A local model rewrote a Jira report five times to "repair" its ticket
// stand-ins, then wrote a made-up stand-in as the whole file: nothing to swap
// back, so 13 bytes of stand-in replaced the report on disk.
//
// A file write or edit naming a stand-in the book cannot resolve, one that
// never appeared in real input either (a stand-in-shaped literal in a file or
// test is fine), does not run: its arguments are dropped, so the tool fails
// validation, and every later request shows that failure as standInBlocked.
// The notice says nothing about redaction (provider blindness, below).

// Stand-in-shaped text seen in real input: system prompts, typed prompts and
// tool results. The model's own turns do not count: they hold what it made up.
const seenLiterals = new Set<string>();
// Blocked call id -> the notice its result is replaced with. Kept, not
// consumed: every later request carries the same failed result and must read
// the same. Protected changes (protect.ts) are blocked the same way.
const blockedCalls = new Map<string, string>();
const MAX_REMEMBERED = 50_000;

function rememberLiterals(format: Format, body: Record<string, unknown>): void {
  const list = format === "responses" ? body.input : body.messages;
  const real = [
    format === "anthropic" ? body.system : format === "responses" ? body.instructions : undefined,
  ];
  if (Array.isArray(list)) {
    for (const item of list) {
      if (!item || typeof item !== "object") continue;
      const record = item as Record<string, unknown>;
      if (
        record.role === "assistant" ||
        record.type === "function_call" ||
        record.type === "custom_tool_call" ||
        record.type === "reasoning"
      )
        continue;
      real.push(record);
    }
  } else {
    real.push(list);
  }
  if (seenLiterals.size > MAX_REMEMBERED) seenLiterals.clear();
  for (const value of real) {
    if (value === undefined) continue;
    for (const match of aliasMatches(typeof value === "string" ? value : JSON.stringify(value)))
      seenLiterals.add(match.text);
  }
}

export function standInBlocked(tokens: string[]): string {
  return (
    `Not run: ${tokens.join(", ")} ${tokens.length === 1 ? "does" : "do"} not appear anywhere in ` +
    `this conversation, so nothing was written. Use values exactly as they appear in files and ` +
    `tool output; do not make up identifiers.`
  );
}

export function egressBlocked(tokens: string[]): string {
  return (
    `Not run: this command would send ${tokens.join(", ")} to a host that is not one of the ` +
    `user's own machines. Ask the user before sending these values off the machine; ` +
    `they can include [allow-pii] in their prompt to permit it.`
  );
}

function explainBlocked(format: Format, body: Record<string, unknown>): Record<string, unknown> {
  const key = format === "responses" ? "input" : "messages";
  const list = body[key];
  if (!Array.isArray(list)) return body;
  if (blockedCalls.size === 0) return body;
  let hits = 0;
  const notice = (id: unknown): string | undefined => {
    const text = blockedCalls.get(String(id));
    if (text) hits++;
    return text;
  };
  const replaced = list.map((item) => {
    if (!item || typeof item !== "object") return item;
    const record = item as Record<string, unknown>;
    if (format === "anthropic" && Array.isArray(record.content)) {
      return {
        ...record,
        content: (record.content as Array<Record<string, unknown>>).map((block) => {
          const text = block?.type === "tool_result" ? notice(block.tool_use_id) : undefined;
          return text === undefined ? block : { ...block, content: text, is_error: true };
        }),
      };
    }
    if (format === "chat" && record.role === "tool") {
      const text = notice(record.tool_call_id);
      return text === undefined ? item : { ...record, content: text };
    }
    if (
      format === "responses" &&
      (record.type === "function_call_output" || record.type === "custom_tool_call_output")
    ) {
      const text = notice(record.call_id);
      return text === undefined ? item : { ...record, output: text };
    }
    return item;
  });
  return hits === 0 ? body : { ...body, [key]: replaced };
}

// Query parameter values, scanned like body strings. API query strings are
// flags (?beta=true), so this rarely finds anything, but a URL is sent too.
export function redactQuery(
  search: string,
  tags: Set<string>,
): { search: string; hits: number; values: number } {
  if (search === "" || search === "?" || tags.has("all")) return { search, hits: 0, values: 0 };
  const params = new URLSearchParams(search);
  let hits = 0;
  const { values } = collectValues(() =>
    withScanBudget(() => {
      for (const [name, value] of [...params]) {
        const result = redactValue(value, tags, name, undefined, ["query", name], true);
        if (result.hits === 0) continue;
        hits += result.hits;
        params.set(name, String(result.value));
      }
    }),
  );
  return hits === 0 ? { search, hits, values } : { search: `?${params}`, hits, values };
}

// Request headers the agent sends to its own provider: the user's credentials
// for it (masked, the provider refuses the call) and protocol fields.
const PASSED_HEADERS = new Set([
  "authorization",
  "x-api-key",
  "api-key",
  "x-goog-api-key",
  "cookie",
  "content-type",
  "accept",
  "anthropic-version",
  "anthropic-beta",
]);

// Header values, scanned like query values: a user agent, an X-* header a
// harness or plugin adds. Changed in place.
export function redactHeaders(
  headers: Headers,
  tags: Set<string>,
): { hits: number; values: number } {
  if (tags.has("all")) return { hits: 0, values: 0 };
  let hits = 0;
  const { values } = collectValues(() =>
    withScanBudget(() => {
      for (const [name, value] of [...headers]) {
        if (PASSED_HEADERS.has(name)) continue;
        const result = redactValue(value, tags, name, undefined, ["headers", name], true);
        if (result.hits === 0) continue;
        hits += result.hits;
        headers.set(name, String(result.value));
      }
    }),
  );
  return { hits, values };
}

// One scan envelope per request. Split out so tests can set the allow tags.
export function redactBody(
  format: Format,
  body: Record<string, unknown>,
  tags: Set<string>,
): { body: Record<string, unknown>; hits: number; counts: Counts } {
  return withScanBudget(() => {
    const withheld = withholdSecretReads(format, body, tags);
    const { result, values } = collectValues(() =>
      format === "anthropic"
        ? redactAnthropic(withheld.body, tags)
        : redactOpenAi(format, withheld.body, tags),
    );
    const counts = {
      masked: values,
      files: withheld.files,
      lines: withheld.hits - withheld.files,
      images: 0,
    };
    return { body: result.value, hits: result.hits + withheld.hits, counts };
  });
}

// ── secret reads ────────────────────────────────────────────────────────────
// The tool runs on this machine; only what it returned travels. A result whose
// call read a secret file (.env, private keys, credentials) or Ithildin's
// own inventory is replaced whole: values in those files often have no shape
// the rules could find. The call itself stays, so the model knows what it ran.
// Results are matched to calls by id, which every format carries. Checked on
// the harness's real arguments, before redaction rewrites them.

export const WITHHELD_NOTICE =
  "Output withheld: this call read a protected file (.env, private keys, credentials), so its " +
  "contents are not shown. Work with such files through commands that do not print their values, " +
  "or ask the user to include [allow-secrets] in their prompt.";
// Ithildin's own config and inventory hold personal values, so [allow-pii]
// opens them, not [allow-secrets]. One notice for both sent the user around
// in circles typing a tag that could never work.
export const INVENTORY_NOTICE =
  "Output withheld: this call read a file of personal values, so its contents are not shown. Ask " +
  "the user to include [allow-pii] in their prompt if you need to see it.";

// The agent's working directory, from its system prompt (Claude: "Primary
// working directory:", Pi: "Current working directory:"). The latest mention
// wins: Claude reports a changed cwd in later user turns. Relative tool paths
// resolve against it, so links to secret files are followed from the right
// place. Falls back to $HOME. Tool results are never read, and the line must
// start a line, as the agents write it, so quoted prose does not move it.
const CWD_LINE = /^[ \t]*(?:- )?(?:Primary|Current) working directory: ([^\n]+)/gm;

export function requestCwd(format: Format, body: Record<string, unknown>): string {
  const texts: string[] = [];
  const add = (content: unknown) => {
    for (const block of textBlocks(content)) texts.push(block.text);
  };
  add(
    format === "anthropic" ? body.system : format === "responses" ? body.instructions : undefined,
  );
  const list = format === "responses" ? body.input : body.messages;
  if (Array.isArray(list)) {
    for (const item of list) {
      const role = (item as { role?: unknown } | null)?.role;
      if (role === "user" || role === "system" || role === "developer")
        add((item as { content?: unknown }).content);
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

// The notice for a call that read something protected, or undefined.
function readsSecret(
  name: string,
  input: unknown,
  tags: Set<string>,
  cwd: string,
): string | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) return;
  const record = input as Record<string, unknown>;
  // A shell-shaped call reads like one whatever its name (tools.ts).
  const shell = shellCommand(record);
  const tool = shell !== undefined || BASH_TOOLS.has(name) ? "bash" : name;
  const command = shell ?? "";
  const targets = candidatePaths(record);
  if (blocksSecretAccess(tool, command, targets, tags, cwd)) return WITHHELD_NOTICE;
  if (blocksInventoryAccess(tool, command, targets, tags, cwd)) return INVENTORY_NOTICE;
  return undefined;
}

function parseArgs(json: unknown): unknown {
  if (typeof json !== "string") return json;
  try {
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

// Notices for the tool calls in a conversation that read something
// protected, by call id.
function secretCalls(
  format: Format,
  list: unknown[],
  tags: Set<string>,
  cwd: string,
): Map<string, string> {
  const secret = new Map<string, string>();
  const withhold = (id: unknown, notice: string | undefined) => {
    if (notice) secret.set(String(id), notice);
  };
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    if (format === "anthropic" && Array.isArray(record.content)) {
      for (const block of record.content as Array<Record<string, unknown>>) {
        if (block?.type === "tool_use")
          withhold(block.id, readsSecret(String(block.name), block.input, tags, cwd));
      }
    } else if (format === "chat" && Array.isArray(record.tool_calls)) {
      for (const call of record.tool_calls as Array<{
        id?: unknown;
        function?: { name?: unknown; arguments?: unknown };
      }>) {
        withhold(
          call.id,
          readsSecret(
            String(call?.function?.name),
            parseArgs(call?.function?.arguments),
            tags,
            cwd,
          ),
        );
      }
    } else if (
      format === "responses" &&
      (record.type === "function_call" || record.type === "custom_tool_call")
    ) {
      withhold(
        record.call_id,
        readsSecret(String(record.name), parseArgs(record.arguments ?? record.input), tags, cwd),
      );
    }
  }
  return secret;
}

// The conversation with every tool result passed through `result`, which
// counts what it changed in `counter.hits`. Unchanged items stay as they were.
function mapToolResults(
  format: Format,
  list: unknown[],
  counter: { hits: number },
  result: (id: unknown, content: unknown) => unknown,
): unknown[] {
  return list.map((item) => {
    if (!item || typeof item !== "object") return item;
    const record = item as Record<string, unknown>;
    const before = counter.hits;
    if (format === "anthropic" && Array.isArray(record.content)) {
      const content = (record.content as Array<Record<string, unknown>>).map((block) =>
        block?.type === "tool_result"
          ? { ...block, content: result(block.tool_use_id, block.content) }
          : block,
      );
      return counter.hits > before ? { ...record, content } : item;
    }
    if (format === "chat" && record.role === "tool") {
      const content = result(record.tool_call_id, record.content);
      return counter.hits > before ? { ...record, content } : item;
    }
    if (
      format === "responses" &&
      (record.type === "function_call_output" || record.type === "custom_tool_call_output")
    ) {
      const output = result(record.call_id, record.output);
      return counter.hits > before ? { ...record, output } : item;
    }
    return item;
  });
}

// hits counts withheld results and withheld lines together; files, the
// results alone.
function withholdSecretReads(
  format: Format,
  body: Record<string, unknown>,
  tags: Set<string>,
): { body: Record<string, unknown>; hits: number; files: number } {
  const list = format === "responses" ? body.input : body.messages;
  if (!Array.isArray(list)) return { body, hits: 0, files: 0 };
  const cwd = requestCwd(format, body);
  const listed = secretListing(cwd);
  const secret = secretCalls(format, list, tags, cwd);
  const counter = { hits: 0, files: 0 };
  // A result is withheld whole, or has its secret-file search lines withheld.
  const result = (id: unknown, content: unknown): unknown => {
    const notice = secret.get(String(id));
    if (notice) {
      counter.hits++;
      counter.files++;
      return notice;
    }
    const lines = withholdSecretLines(content, listed);
    counter.hits += lines.hits;
    return lines.content;
  };
  const replaced = mapToolResults(format, list, counter, result);
  const { hits, files } = counter;
  return hits === 0
    ? { body, hits, files }
    : { body: { ...body, [format === "responses" ? "input" : "messages"]: replaced }, hits, files };
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
      secret =
        (!/\s/.test(listed) || existsSync(path.resolve(cwd, listed))) && isSecretPath(listed, cwd);
      seen.set(listed, secret);
    }
    return secret;
  };
}

function withholdLines(
  text: string,
  secret: (listed: string) => boolean,
): { text: string; hits: number } {
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
    const head = [colon > 0 ? line.slice(0, colon) : undefined, FLAT_CONTEXT.exec(line)?.[1]].find(
      (candidate) => candidate !== undefined && secret(candidate),
    );
    if (!head) return line;
    hits++;
    return `${head}: ${WITHHELD_LINE}`;
  });
  return hits === 0 ? { text, hits } : { text: lines.join("\n"), hits };
}

// Tool result content: a string, or text parts (Anthropic text blocks, chat
// text parts, Responses input_text).
function withholdSecretLines(
  content: unknown,
  secret: (listed: string) => boolean,
): { content: unknown; hits: number } {
  if (typeof content === "string") {
    const out = withholdLines(content, secret);
    return { content: out.text, hits: out.hits };
  }
  if (!Array.isArray(content)) return { content, hits: 0 };
  let hits = 0;
  const parts = content.map((part) => {
    if (!part || typeof part !== "object" || typeof (part as { text?: unknown }).text !== "string")
      return part;
    const out = withholdLines((part as { text: string }).text, secret);
    hits += out.hits;
    return out.hits === 0 ? part : { ...part, text: out.text };
  });
  return hits === 0 ? { content, hits } : { content: parts, hits };
}

// ── images ──────────────────────────────────────────────────────────────────
// Images, PDFs and audio are opaque to the rules: a screenshot of a terminal
// or a scanned letter would reach the provider whole. Inline ones are
// replaced with a notice unless the prompt that brought them in carries
// [allow-images] (or [allow-all]): the user's own message for a pasted image,
// the latest typed prompt before it for one a tool read. Deciding per prompt,
// not per request, keeps earlier turns byte-stable, and so the prompt cache.
// Images by URL or uploaded file id are already the provider's to fetch.

export const IMAGE_NOTICE =
  "Image withheld: images and documents cannot be checked for sensitive values, so this one is " +
  "not shown. Ask the user to include [allow-images] in their prompt if you need to see it.";
const IMAGE_TAG = /\[allow-(?:images?|all)\]/i;

function isInlineData(value: unknown): boolean {
  return typeof value === "string" && value.startsWith("data:");
}

// Anthropic image/document with a base64 source or a data: URL; chat
// image_url, file and input_audio parts; Responses input_image and input_file.
// engine/lib/image-payload.ts lets the same bytes through unscanned once allowed.
function isOpaqueBlock(block: Record<string, unknown>): boolean {
  const source = block.source as { type?: unknown; url?: unknown } | undefined;
  switch (block.type) {
    case "image":
    case "document":
      return source?.type === "base64" || isInlineData(source?.url);
    case "image_url":
      return isInlineData((block.image_url as { url?: unknown } | undefined)?.url);
    case "input_image":
      return isInlineData(block.image_url);
    case "file":
      return typeof (block.file as { file_data?: unknown } | undefined)?.file_data === "string";
    case "input_file":
      return typeof block.file_data === "string";
    case "input_audio":
      return true;
    default:
      return false;
  }
}

function withheldImage(format: Format): Record<string, unknown> {
  return { type: format === "responses" ? "input_text" : "text", text: IMAGE_NOTICE };
}

function replaceImages(value: unknown, format: Format, count: { hits: number }): unknown {
  if (Array.isArray(value)) {
    let changed = false;
    const out = value.map((item) => {
      const next = replaceImages(item, format, count);
      if (next !== item) changed = true;
      return next;
    });
    return changed ? out : value;
  }
  if (!value || typeof value !== "object") return value;
  const record = value as Record<string, unknown>;
  if (isOpaqueBlock(record)) {
    count.hits++;
    return withheldImage(format);
  }
  let changed = false;
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(record)) {
    out[key] = replaceImages(child, format, count);
    if (out[key] !== child) changed = true;
  }
  return changed ? out : value;
}

// Tags are read from `tagged` (the body as the client sent it), images
// replaced in `body` (the same body with its tags stripped).
export function withholdImages(
  format: Format,
  body: Record<string, unknown>,
  tagged = body,
): { body: Record<string, unknown>; hits: number } {
  const key = format === "responses" ? "input" : "messages";
  const list = body[key];
  const original = tagged[key];
  if (!Array.isArray(list) || !Array.isArray(original)) return { body, hits: 0 };
  const count = { hits: 0 };
  let allowed = false;
  const out = list.map((item, i) => {
    if (!item || typeof item !== "object") return item;
    const record = (original[i] ?? item) as { role?: unknown; content?: unknown };
    // A tool-result turn is not a prompt, even with harness text beside it.
    const results =
      Array.isArray(record.content) &&
      record.content.some((block) => (block as { type?: unknown } | null)?.type === "tool_result");
    if (record.role === "user" && !results) {
      const typed = promptBlocks(record.content);
      if (typed.length > 0) allowed = typed.some((block) => IMAGE_TAG.test(block.text));
    }
    return allowed ? item : replaceImages(item, format, count);
  });
  return count.hits === 0 ? { body, hits: 0 } : { body: { ...body, [key]: out }, hits: count.hits };
}

// ── provider blindness ──────────────────────────────────────────────────────
// The provider must not learn that values are swapped. The proxy adds nothing
// that mentions redaction, and the allow tags the user types are removed from
// the typed text it forwards; they still set this request's policy here. Tool
// output keeps them: rewriting it would corrupt what a command printed.

// Same tag set the engine parses (resolveTagPriority), plus [allow-images]
// and [allow-protected].
const ALLOW_TAG = /\[(?:(?:allow|mask)-(?:all|secrets?|pii)|allow-(?:images?|protected))\][ \t]?/gi;

function stripTagText(content: unknown): unknown {
  if (typeof content === "string") return content.replace(ALLOW_TAG, "");
  if (!Array.isArray(content)) return content;
  return content.map((block) => {
    if (!block || typeof block !== "object") return block;
    const { type, text } = block as { type?: unknown; text?: unknown };
    return (type === "text" || type === "input_text") && typeof text === "string"
      ? { ...block, text: text.replace(ALLOW_TAG, "") }
      : block;
  });
}

export function stripAllowTags(
  format: Format,
  body: Record<string, unknown>,
): Record<string, unknown> {
  if (format === "responses" && typeof body.input === "string")
    return { ...body, input: stripTagText(body.input) };
  const key = format === "responses" ? "input" : "messages";
  const list = body[key];
  if (!Array.isArray(list)) return body;
  return {
    ...body,
    [key]: list.map((item) => {
      if (!item || typeof item !== "object" || (item as { role?: unknown }).role !== "user")
        return item;
      const record = item as { content?: unknown };
      return { ...record, content: stripTagText(record.content) };
    }),
  };
}

// ── swap-back ───────────────────────────────────────────────────────────────
// Only tools that run on this machine get real values. Anything else (web
// tools, MCP servers, subagent prompts) keeps the stand-ins: a real value
// must not leave the machine through a tool the proxy cannot see into.

// planSwapBack's tool vocabulary: "bash" gets the network-destination check,
// "web_fetch" treats every position as egress.
function swapToolName(name: string): string {
  if (BASH_TOOLS.has(name)) return "bash";
  if (LOCAL_TOOLS.has(name)) return name;
  return "web_fetch";
}

type Swapped = { args: unknown; swapped: number; blocked?: boolean };

function block(callId: string | undefined, notice: string): Swapped {
  if (callId) {
    if (blockedCalls.size > MAX_REMEMBERED) blockedCalls.clear();
    blockedCalls.set(callId, notice);
  }
  return { args: {}, swapped: 0, blocked: true };
}

// The request's cwd, for protected paths named relative to it. Keyed by the
// request's tag set, the one thing every reply rewriter is handed.
const requestDirs = new WeakMap<Set<string>, string>();

// Checked on the arguments as written and as swapped: a path may hold a
// stand-in (a home directory) that only its real value resolves.
export function swapToolArguments(
  toolName: string,
  args: unknown,
  tags: Set<string>,
  callId?: string,
): Swapped {
  const result = swapArguments(toolName, args, tags, callId);
  if (result.blocked || tags.has("protected")) return result;
  const cwd = requestDirs.get(tags) ?? process.env.HOME ?? process.cwd();
  const kind =
    protectedChange(toolName, args, cwd) ??
    (result.swapped > 0 ? protectedChange(toolName, result.args, cwd) : undefined);
  return kind ? block(callId, protectedBlocked(kind)) : result;
}

function swapArguments(
  toolName: string,
  args: unknown,
  tags: Set<string>,
  callId?: string,
): Swapped {
  if (aliasStyle() !== "stand-ins") return { args, swapped: 0 };
  const swap = planSwapBack(
    swapToolName(toolName),
    args,
    aliases(),
    tags.has("pii") || tags.has("all"),
  );
  // Old hash-like shapes: stand-ins now look real, so a model that writes a
  // label and six hex digits copied them from an older transcript or made
  // them up.
  const invented = WRITE_TOOLS.has(toolName)
    ? [...new Set(aliasSpans(JSON.stringify(args ?? {})))].filter(
        (token) => !seenLiterals.has(token) && !aliases().isStandIn(token),
      )
    : [];
  if (invented.length > 0) return block(callId, standInBlocked(invented));
  // A shell command sending a stand-in somewhere other than the user's own
  // hosts: swapped, the real value leaves; unswapped, the call does the
  // wrong thing. Web and MCP tools keep their stand-ins (they are meant to).
  if (swap.egress.length > 0 && swapToolName(toolName) === "bash")
    return block(callId, egressBlocked([...new Set(swap.egress)]));
  // Swap per span. A stand-in the book cannot resolve (often a stand-in-shaped
  // literal in source or docs), or one bound off the machine, stays a stand-in
  // in swap.input: that span fails on a name that does not exist rather than
  // leaking the value, while resolved spans beside it still get real values.
  const harness = argsKey(swap.resolved.length === 0 ? args : swap.input);
  const original = argsKey(args);
  if (harness !== undefined && original !== undefined) recordOriginal("args", harness, original);
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

// A whole reply block: swapped, and recorded so the next request gives the
// model back exactly what it wrote (replay.ts).
export function swapWholeText(text: string, tags: Set<string>): { text: string; swapped: number } {
  const result = swapText(text, tags);
  if (text !== "") recordOriginal("text", result.text, text);
  return result;
}

// A freeform call's raw input (Responses custom tools: Codex apply_patch).
export function swapToolInput(
  toolName: string,
  input: string,
  tags: Set<string>,
  callId?: string,
): { input: string; swapped: number } {
  const result = swapToolArguments(toolName, input, tags, callId);
  if (result.blocked) return { input: "", swapped: 0 };
  return { input: result.args as string, swapped: result.swapped };
}

// Arguments as a JSON string (OpenAI shapes, Anthropic streaming).
export function swapToolJson(
  toolName: string,
  json: string,
  tags: Set<string>,
  callId?: string,
): { json: string; swapped: number; blocked?: boolean } {
  let args: unknown;
  try {
    args = json.trim() === "" ? {} : JSON.parse(json);
  } catch {
    return { json, swapped: 0 };
  }
  const result = swapToolArguments(toolName, args, tags, callId);
  if (result.blocked) return { json: "{}", swapped: 0, blocked: true };
  return result.swapped === 0
    ? { json, swapped: 0 }
    : { json: JSON.stringify(result.args), swapped: result.swapped };
}
