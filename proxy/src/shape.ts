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
  // Results and call inputs replaced by a stub, results only compacted, and
  // results that repeat an output still whole above them.
  masked: number;
  compacted: number;
  deduped: number;
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
function stubFor(name: string, args: unknown, size: number, lines: number, images: number): string {
  const pictures = images === 0 ? "" : ` and ${images} image${images === 1 ? "" : "s"}`;
  return (
    `[masked to save context: ${describe(name, args)} returned ${lines} lines (${size} chars)` +
    `${pictures} earlier in this session. Re-run the call if you need that output again.]`
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

// What one walk over the conversation knows so far: the calls it has seen, and
// the outputs still whole, by text, with the call that made each one.
interface Walk {
  calls: Map<string, Call>;
  outputs: Map<string, string>;
}

type Kind = "masked" | "compacted" | "deduped";
type Counts = Record<Kind, number>;

interface Change {
  text: string;
  saved: number;
  kind: Kind;
}

interface Replacement {
  entry: unknown;
  saved: number;
  counts: Counts;
}

// An image costs a provider about 1.5k tokens whatever its bytes, so a masked
// one counts as that much text and the saved figure stays in one unit.
const IMAGE_CHARS = 6_000;

// A repeat shorter than this is not worth the note that replaces it.
export const DEDUPE_MIN_CHARS = 500;

// What a tool result holds when it is only text and images, the only kinds
// that are ours to drop; undefined for anything else typed.
function partsOf(content: unknown): { text: string; images: number } | undefined {
  if (typeof content === "string") return { text: content, images: 0 };
  if (!Array.isArray(content)) return;
  const texts: string[] = [];
  let images = 0;
  for (const block of content) {
    const entry = record(block);
    const type = entry?.type;
    const text = entry?.text;
    if (TEXT_TYPES.has(String(type)) && typeof text === "string") texts.push(text);
    else if (type === "image" || type === "input_image") images++;
    else return;
  }
  return { text: texts.join("\n"), images };
}

const TEXT_TYPES = new Set(["text", "input_text", "output_text"]);

// The note a repeated output becomes. The first copy is still whole above it
// in this request: when that one is masked, the repeat stops being one and is
// sent whole again, which a cutoff step pays for at an earlier point anyway.
function sameAs(first: string, size: number, lines: number): string {
  return (
    `[same output as ${first} earlier in this session: ${lines} lines (${size} chars), ` +
    "byte for byte. It is still in the conversation above.]"
  );
}

// One tool result, shaped: a stub when it is old and big, a note when it
// repeats an output still whole above it, the compacting passes otherwise, or
// undefined to leave it exactly as it arrived.
function shaped(content: unknown, id: unknown, walk: Walk, old: boolean): Change | undefined {
  const parts = partsOf(content);
  if (!parts) return;
  const { text, images } = parts;
  const call = id === undefined ? undefined : walk.calls.get(String(id));
  const name = call?.name ?? "tool";
  const lines = text.split("\n").length;
  if (old && (text.length >= MASK_MIN_CHARS || images > 0)) {
    const stub = stubFor(name, call?.input, text.length, lines, images);
    return { text: stub, saved: text.length + images * IMAGE_CHARS - stub.length, kind: "masked" };
  }
  // A recent image is the model's to look at.
  if (images > 0 || !text) return;
  if (text.length >= DEDUPE_MIN_CHARS) {
    const first = walk.outputs.get(text);
    if (first !== undefined) {
      const note = sameAs(first, text.length, lines);
      return { text: note, saved: text.length - note.length, kind: "deduped" };
    }
    walk.outputs.set(text, describe(name, call?.input));
  }
  const compacted = compact(text);
  return compacted === undefined
    ? undefined
    : { text: compacted, saved: text.length - compacted.length, kind: "compacted" };
}

function counted(kind: Kind): Counts {
  return { masked: 0, compacted: 0, deduped: 0, [kind]: 1 };
}

function shapeAnthropic(item: unknown, walk: Walk, old: boolean): Replacement | undefined {
  const entry = record(item);
  if (!entry || !Array.isArray(entry.content)) return;
  let saved = 0;
  const counts: Counts = { masked: 0, compacted: 0, deduped: 0 };
  // Anthropic carries several results in one user turn, so each block counts.
  const content = (entry.content as unknown[]).map((block) => {
    const typed = record(block);
    if (typed?.type !== "tool_result") return block;
    const next = shaped(typed.content, typed.tool_use_id, walk, old);
    if (!next) return block;
    counts[next.kind]++;
    saved += next.saved;
    return { ...typed, content: next.text };
  });
  return counts.masked + counts.compacted + counts.deduped === 0
    ? undefined
    : { entry: { ...entry, content }, saved, counts };
}

function shapeChat(item: unknown, walk: Walk, old: boolean): Replacement | undefined {
  const entry = record(item);
  if (!entry || entry.role !== "tool") return;
  const next = shaped(entry.content, entry.tool_call_id, walk, old);
  return next === undefined
    ? undefined
    : { entry: { ...entry, content: next.text }, saved: next.saved, counts: counted(next.kind) };
}

function shapeResponses(item: unknown, walk: Walk, old: boolean): Replacement | undefined {
  const entry = record(item);
  if (!entry || (entry.type !== "function_call_output" && entry.type !== "custom_tool_call_output"))
    return;
  const next = shaped(entry.output, entry.call_id, walk, old);
  return next === undefined
    ? undefined
    : { entry: { ...entry, output: next.text }, saved: next.saved, counts: counted(next.kind) };
}

// The request with its old tool results masked, or undefined when there was
// nothing to mask. Pure: the same body gives the same result, byte for byte.
export function shapeRequest(format: Format, body: Record<string, unknown>): Shaped | undefined {
  const list = conversation(format, body);
  if (!list) return;
  const cutoff = cutoffFor(list, format);
  const walk: Walk = { calls: new Map(), outputs: new Map() };
  const totals: Counts = { masked: 0, compacted: 0, deduped: 0 };
  let turn = 0;
  let savedChars = 0;
  const out = list.map((item) => {
    // Every item can carry calls: an Anthropic or chat call sits in an
    // assistant turn, a Responses call is its own top-level item. Recording
    // them all is what lets a stub name the command that produced the result.
    for (const call of toolCalls(format, item))
      if (call.id !== undefined)
        walk.calls.set(String(call.id), { name: call.name, input: call.input });
    if (isAssistant(format, item)) turn++;
    // A result answers the call above it, so it shares that call's turn: the
    // first `cutoff` turns are old, calls and results alike. A cutoff of zero
    // is a conversation too short to shape, so nothing in it is old, not even
    // its first turn.
    const old = cutoff > 0 && turn <= cutoff;
    const replaced = shapeEntry(format, item, walk, old);
    if (!replaced) return item;
    for (const kind of Object.keys(totals) as Kind[]) totals[kind] += replaced.counts[kind];
    savedChars += replaced.saved;
    return replaced.entry;
  });
  // Any count is a change: a request with only compaction is still shaped.
  if (totals.masked + totals.compacted + totals.deduped === 0) return;
  return { body: { ...body, [keyOf(format)]: out }, ...totals, savedChars };
}

function keyOf(format: Format): "messages" | "input" {
  return format === "responses" ? "input" : "messages";
}

function shapeEntry(
  format: Format,
  item: unknown,
  walk: Walk,
  old: boolean,
): Replacement | undefined {
  if (old) {
    const call = shapeCall(format, item);
    if (call) return call;
  }
  if (format === "anthropic") return shapeAnthropic(item, walk, old);
  if (format === "chat") return shapeChat(item, walk, old);
  return shapeResponses(item, walk, old);
}

// ── old calls ───────────────────────────────────────────────────────────────
//
// A call's input is re-sent every turn too, and the big ones are the model's
// own writes: a whole file in a Write, both sides of an Edit, a patch. Past the
// cutoff a long string in an input becomes a note. The wording says the call
// ran with the full text and that a new one needs it, because a model that
// reads its own history as having written placeholders will write them.

export const INPUT_MIN_CHARS = MASK_MIN_CHARS;
// Deep enough for an edit list inside an input, no deeper.
const INPUT_DEPTH_MAX = 4;

function inputNote(size: number): string {
  return (
    `[${size} chars of this earlier call's input removed from the history to save context. ` +
    "The call ran with the full text; a new call needs its full text written out.]"
  );
}

// The value with every long string in it replaced, or undefined when none was.
function maskedValue(value: unknown, depth = 0): { value: unknown; saved: number } | undefined {
  if (typeof value === "string") {
    if (value.length < INPUT_MIN_CHARS) return;
    const note = inputNote(value.length);
    return { value: note, saved: value.length - note.length };
  }
  if (!value || typeof value !== "object" || depth >= INPUT_DEPTH_MAX) return;
  const out: Record<string, unknown> | unknown[] = Array.isArray(value)
    ? [...value]
    : { ...(value as Record_) };
  let saved = 0;
  for (const key of Object.keys(out)) {
    const next = maskedValue((out as Record_)[key], depth + 1);
    if (!next) continue;
    (out as Record_)[key] = next.value;
    saved += next.saved;
  }
  return saved > 0 ? { value: out, saved } : undefined;
}

// Arguments carried as one JSON string: masked inside, and written back the
// way JSON.stringify writes them. A string that does not parse is left whole.
function maskedArguments(text: unknown): { value: string; saved: number } | undefined {
  if (typeof text !== "string" || text.length < INPUT_MIN_CHARS) return;
  const parsed = parseArgs(text);
  const next = parsed === undefined ? undefined : maskedValue(parsed);
  if (!next) return;
  const value = JSON.stringify(next.value);
  return value.length < text.length ? { value, saved: text.length - value.length } : undefined;
}

function shapeCall(format: Format, item: unknown): Replacement | undefined {
  const entry = record(item);
  if (!entry) return;
  if (format === "anthropic") return shapeBlocks(entry);
  if (format === "chat") return shapeChatCalls(entry);
  const field = entry.type === "function_call" ? "arguments" : "input";
  if (entry.type !== "function_call" && entry.type !== "custom_tool_call") return;
  const next = field === "arguments" ? maskedArguments(entry.arguments) : maskedValue(entry.input);
  return (
    next && {
      entry: { ...entry, [field]: next.value },
      saved: next.saved,
      counts: counted("masked"),
    }
  );
}

function shapeBlocks(entry: Record_): Replacement | undefined {
  if (entry.role !== "assistant" || !Array.isArray(entry.content)) return;
  let saved = 0;
  let masked = 0;
  const content = (entry.content as unknown[]).map((block) => {
    const typed = record(block);
    const next = typed?.type === "tool_use" ? maskedValue(typed.input) : undefined;
    if (!next) return block;
    saved += next.saved;
    masked++;
    return { ...typed, input: next.value };
  });
  return masked === 0
    ? undefined
    : { entry: { ...entry, content }, saved, counts: { masked, compacted: 0, deduped: 0 } };
}

function shapeChatCalls(entry: Record_): Replacement | undefined {
  if (entry.role !== "assistant" || !Array.isArray(entry.tool_calls)) return;
  let saved = 0;
  let masked = 0;
  const calls = (entry.tool_calls as unknown[]).map((call) => {
    const typed = record(call);
    const fn = record(typed?.function);
    const next = fn ? maskedArguments(fn.arguments) : undefined;
    if (!next) return call;
    saved += next.saved;
    masked++;
    return { ...typed, function: { ...fn, arguments: next.value } };
  });
  return masked === 0
    ? undefined
    : {
        entry: { ...entry, tool_calls: calls },
        saved,
        counts: { masked, compacted: 0, deduped: 0 },
      };
}
