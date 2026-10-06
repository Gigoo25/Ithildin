// Context shaping: the copy of a request that goes to the provider has its old
// tool results masked before it leaves. Every request re-sends the whole
// conversation, so a 5k `cat` from twenty turns ago costs 5k on every turn
// after it. Measured on Pi's 12-task eval, results older than ten turns were
// 65% of all re-sent tool-result tokens.
//
// Two properties this has to keep, or the provider's prompt cache breaks on
// every request instead of on none:
//
//   Pure. The same request shapes to the same bytes, every time. Nothing here
//   reads the clock, a counter, or any proxy state; the cutoff is a function
//   of the message list alone. That is why it takes no arguments beyond the
//   body: the per-session turn counter in server.ts is for the badge, and
//   using it here would make every forwarded prefix depend on traffic the
//   conversation never saw.
//   Stepped. The stub names nothing relative to now, and the cutoff only moves
//   every MASK_STEP_TURNS turns, so the masked prefix stays byte-identical
//   between requests.
//
// This runs on the request that has already been redacted and already been
// recorded for the dashboard: the conversation the dashboard keeps is the one
// that arrived, and only the forwarded copy is masked. Redaction first also
// means a stub can never quote something the engine was holding back.
//
// Not a second redaction layer. Masking only ever removes text the engine
// already cleared, and it fails open: a request that cannot be shaped is
// forwarded exactly as redaction left it.

import { compact } from "./compact.ts";
import type { Format } from "./redact.ts";

// Ported from Pi's output-shaping extension (mask.ts), which could only shape
// Pi's own message objects. The traversal is rewritten per wire format; the
// thresholds and the stub wording are the measured ones.
export const MASK_KEEP_TURNS = 10;
export const MASK_STEP_TURNS = 10;
export const MASK_MIN_CHARS = 1_000;
export const MASK_THRESHOLD_TOKENS = 30_000;

// ITHILDIN_SHAPE=off (or raw) shapes nothing, on any route.
export function shapingOn(env: Record<string, string | undefined> = process.env): boolean {
  const value = env.ITHILDIN_SHAPE?.trim().toLowerCase();
  return value !== "off" && value !== "raw" && value !== "false" && value !== "0";
}

export interface Shaped {
  body: Record<string, unknown>;
  // Results replaced by a stub, and results only compacted.
  masked: number;
  compacted: number;
  savedChars: number;
}

type Record_ = Record<string, unknown>;

function conversation(format: Format, body: Record<string, unknown>): unknown[] | undefined {
  const list = format === "responses" ? body.input : body.messages;
  return Array.isArray(list) ? list : undefined;
}

function record(item: unknown): Record_ | undefined {
  return item && typeof item === "object" && !Array.isArray(item) ? (item as Record_) : undefined;
}

// The turns a cutoff counts: an assistant message, or its Responses spelling.
function isAssistant(format: Format, item: unknown): boolean {
  const entry = record(item);
  if (!entry) return false;
  return format === "responses"
    ? entry.type === "message" && entry.role === "assistant"
    : entry.role === "assistant";
}

// What a tool result holds: a string, or Anthropic's array of typed blocks.
function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => {
      const entry = record(block);
      return entry && typeof entry.text === "string" ? entry.text : "";
    })
    .join("\n");
}

// Only text is ours to drop. An image, or anything else typed, is left alone.
function textOnly(content: unknown): boolean {
  if (typeof content === "string") return true;
  if (!Array.isArray(content)) return false;
  return content.every((block) => record(block)?.type === "text");
}

function estimateTokens(list: unknown[], format: Format): number {
  let chars = 0;
  for (const item of list) {
    const entry = record(item);
    if (!entry) continue;
    chars += textOf(entry.content).length;
    chars += JSON.stringify(toolCalls(format, item)).length;
  }
  return Math.ceil(chars / 4);
}

// The calls a conversation made, keyed by the id their results answer. What
// the stub names, so a masked result is still identifiable.
function toolCalls(
  format: Format,
  item: unknown,
): Array<{ id?: unknown; name: string; input: unknown }> {
  const entry = record(item);
  if (!entry) return [];
  if (format === "anthropic" && Array.isArray(entry.content))
    return (entry.content as unknown[])
      .map((block) => record(block))
      .filter((block) => block?.type === "tool_use")
      .map((block) => ({
        id: block!.id,
        name: String(block!.name ?? "tool"),
        input: block!.input,
      }));
  if (format === "chat" && Array.isArray(entry.tool_calls))
    return (entry.tool_calls as unknown[])
      .map((call) => record(call))
      .filter(Boolean)
      .map((call) => ({
        id: call!.id,
        name: String(record(call!.function)?.name ?? "tool"),
        input: parseArgs(record(call!.function)?.arguments),
      }));
  if (
    format === "responses" &&
    (entry.type === "function_call" || entry.type === "custom_tool_call")
  )
    return [
      { id: entry.call_id, name: String(entry.name ?? "tool"), input: parseArgs(entry.arguments) },
    ];
  return [];
}

// A chat or Responses call carries its arguments as one JSON string, and a
// broken one must not stop the walk: an unparsed call is named `tool`.
function parseArgs(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

// What the stub names: the command, path, or pattern the call used.
function describe(name: string, args: unknown): string {
  const fields = record(args);
  const value =
    fields?.command ??
    fields?.path ??
    fields?.pattern ??
    fields?.url ??
    fields?.query ??
    fields?.file_path;
  if (typeof value !== "string" || !value) return name;
  const single = value.replace(/\s+/g, " ").trim();
  return `${name} \`${single.length > 80 ? `${single.slice(0, 80)}…` : single}\``;
}

// The stub. It names nothing relative to now, so the same old result masks to
// the same bytes on every request, which is what keeps the cached prefix.
function stubFor(name: string, args: unknown, size: number, lines: number): string {
  return (
    `[masked to save context: ${describe(name, args)} returned ${lines} lines (${size} chars) ` +
    "earlier in this session. Re-run the call if you need that output again.]"
  );
}

// How many assistant turns back are still whole. Zero means shape nothing: a
// short conversation has nothing to gain, and touching bytes would only spend
// cache for nothing. The steps keep the masked prefix stable between turns.
function cutoffFor(list: unknown[], format: Format): number {
  const turns = list.filter((item) => isAssistant(format, item)).length;
  if (turns <= MASK_KEEP_TURNS || estimateTokens(list, format) < MASK_THRESHOLD_TOKENS) return 0;
  return Math.floor((turns - MASK_KEEP_TURNS) / MASK_STEP_TURNS) * MASK_STEP_TURNS;
}
interface Call {
  name: string;
  input: unknown;
}

interface Replacement {
  entry: unknown;
  saved: number;
  stubbed: boolean;
}

// One tool result, shaped: a stub when it is old and big, the compacting
// passes otherwise, or undefined to leave it exactly as it arrived. Nothing
// but text is ever touched.
function shaped(
  content: unknown,
  id: unknown,
  calls: Map<string, Call>,
  old: boolean,
): { text: string; saved: number } | undefined {
  if (!textOnly(content)) return;
  const text = textOf(content);
  if (!text) return;
  if (old && text.length >= MASK_MIN_CHARS) {
    const call = id === undefined ? undefined : calls.get(String(id));
    const stub = stubFor(call?.name ?? "tool", call?.input, text.length, text.split("\n").length);
    return { text: stub, saved: text.length - stub.length };
  }
  const compacted = compact(text);
  return compacted === undefined
    ? undefined
    : { text: compacted, saved: text.length - compacted.length };
}

function shapeAnthropic(
  item: unknown,
  calls: Map<string, Call>,
  old: boolean,
): Replacement | undefined {
  const entry = record(item);
  if (!entry || !Array.isArray(entry.content)) return;
  let saved = 0;
  let hit = 0;
  let anyStub = false;
  const content = (entry.content as unknown[]).map((block) => {
    const typed = record(block);
    if (typed?.type !== "tool_result") return block;
    const next = shaped(typed.content, typed.tool_use_id, calls, old);
    if (!next) return block;
    hit++;
    if (old && next.text.startsWith("[masked")) anyStub = true;
    saved += next.saved;
    return { ...typed, content: next.text };
  });
  // Anthropic carries several results in one user turn, so a hit is counted per
  // block; the turn counts as stubbed only if a block was replaced by a stub.
  return hit === 0 ? undefined : { entry: { ...entry, content }, saved, stubbed: old && anyStub };
}

function shapeChat(item: unknown, calls: Map<string, Call>, old: boolean): Replacement | undefined {
  const entry = record(item);
  if (!entry || entry.role !== "tool") return;
  const next = shaped(entry.content, entry.tool_call_id, calls, old);
  return next === undefined
    ? undefined
    : { entry: { ...entry, content: next.text }, saved: next.saved, stubbed: old };
}

function shapeResponses(
  item: unknown,
  calls: Map<string, Call>,
  old: boolean,
): Replacement | undefined {
  const entry = record(item);
  if (!entry || (entry.type !== "function_call_output" && entry.type !== "custom_tool_call_output"))
    return;
  const next = shaped(entry.output, entry.call_id, calls, old);
  return next === undefined
    ? undefined
    : { entry: { ...entry, output: next.text }, saved: next.saved, stubbed: old };
}

// The request with its old tool results masked, or undefined when there was
// nothing to mask. Pure: the same body gives the same result, byte for byte.
export function shapeRequest(format: Format, body: Record<string, unknown>): Shaped | undefined {
  const list = conversation(format, body);
  if (!list) return;
  const cutoff = cutoffFor(list, format);
  const calls = new Map<string, Call>();
  let turn = 0;
  let masked = 0;
  let savedChars = 0;
  let compacted = 0;
  const out = list.map((item) => {
    // Every item can carry calls: an Anthropic or chat call sits in an
    // assistant turn, a Responses call is its own top-level item. Recording
    // them all is what lets a stub name the command that produced the result.
    for (const call of toolCalls(format, item))
      if (call.id !== undefined) calls.set(String(call.id), { name: call.name, input: call.input });
    if (isAssistant(format, item)) {
      turn++;
      return item;
    }
    // A tool result answers the call above it, so it belongs to the turn the
    // counter reached when that call was seen. `cutoff` counts whole turns of
    // history, and the result lands one turn after its call, so the boundary
    // is cutoff + 1: getting this wrong stubs everything, because every
    // result then looks one turn older than it is.
    const replaced = shapeEntry(format, item, calls, turn <= cutoff + 1);
    if (!replaced) return item;
    if (replaced.stubbed) masked++;
    else compacted++;
    savedChars += replaced.saved;
    return replaced.entry;
  });
  // Either count is a change: a request with only compaction is still shaped.
  if (masked + compacted === 0) return;
  return { body: { ...body, [keyOf(format)]: out }, masked, compacted, savedChars };
}

function keyOf(format: Format): "messages" | "input" {
  return format === "responses" ? "input" : "messages";
}

function shapeEntry(
  format: Format,
  item: unknown,
  calls: Map<string, Call>,
  old: boolean,
): Replacement | undefined {
  if (format === "anthropic") return shapeAnthropic(item, calls, old);
  if (format === "chat") return shapeChat(item, calls, old);
  return shapeResponses(item, calls, old);
}
