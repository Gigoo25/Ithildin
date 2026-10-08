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
//   in steps of MASK_STEP_TURNS turns, so the masked prefix stays
//   byte-identical between requests.
//   Paid for. A step costs a cache write. On OpenAI that is everything after
//   the first result it masks; Anthropic looks back only about 20 blocks from
//   a cache marker, and agents move their marker to the newest message, so
//   there it is the whole conversation. The cutoff only takes a step when
//   what it masks, read back over the turns still to come, costs more than
//   that rewrite. A conversation is guessed to run on as long again as it has
//   so far, and at least MASK_HORIZON_TURNS more. Each step is decided on the
//   conversation as it stood when the step came due, a prefix of this one, so
//   the answer is the same on every later request and the cutoff never moves
//   back.
//
// This runs on the request that has already been redacted and already been
// recorded for the dashboard: the conversation the dashboard keeps is the one
// that arrived, and only the forwarded copy is masked. Redaction first also
// means a stub can never quote something the engine was holding back.
//
// Not a second redaction layer. Masking only ever removes text the engine
// already cleared, and it fails open: a request that cannot be shaped is
// forwarded exactly as redaction left it.

import { setting } from "../engine/lib/names.ts";
import { compact } from "./compact.ts";
import { crushJson } from "./crush.ts";
import { markBoundaries } from "./mark.ts";
import type { Format } from "./redact.ts";

// Ported from Pi's output-shaping extension (mask.ts), which could only shape
// Pi's own message objects. The traversal is rewritten per wire format; the
// thresholds and the stub wording are the measured ones.
export const MASK_KEEP_TURNS = 10;
export const MASK_STEP_TURNS = 10;
// A stub is about 150 characters, so a result is worth one from about 400.
export const MASK_MIN_CHARS = 400;
export const MASK_THRESHOLD_TOKENS = 30_000;
// Prices relative to uncached input. Anthropic charges 1.25x for a cache
// write, 2x when it is asked to keep it an hour; OpenAI's caching writes at the
// plain price. Both read back at about a tenth.
export const MASK_HORIZON_TURNS = 20;
const CACHE_READ = 0.1;
const CACHE_WRITE = { short: 1.25, hour: 2, openai: 1 };

// ITHILDIN_SHAPE=off (or raw) shapes nothing, on any route.
export function shapingOn(env: Record<string, string | undefined> = process.env): boolean {
  const value = setting("SHAPE", env)?.trim().toLowerCase();
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
  // The turns old before this request and after it, when they differ: a step,
  // read from the body alone, so the journal can name it after a restart.
  step?: { from: number; to: number };
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
function stubFor(
  name: string,
  args: unknown,
  size: number,
  lines: number,
  images: number,
  back: string,
): string {
  const pictures = images === 0 ? "" : ` and ${images} image${images === 1 ? "" : "s"}`;
  return (
    `[masked to save context: ${describe(name, args)} returned ${lines} lines (${size} chars)` +
    `${pictures} earlier in this session. ${back}]`
  );
}

// How a note says to get the output back: the retrieve tool when the agent has
// it, which also keeps the output for it, and the call itself otherwise.
function wayBack(text: string, retrieval: Retrieval | undefined): string {
  if (!retrieval || !text) return "Re-run the call if you need that output again.";
  const id = retrieval.keep(text);
  return `Call ${retrieval.tool} with id "${id}" if you need that output again.`;
}

// How many assistant turns back are still whole. Zero means shape nothing: a
// short conversation has nothing to gain, and touching bytes would only spend
// cache for nothing. The steps keep the masked prefix stable between turns.
// The furthest whole step a conversation of this many turns could mask to.
function dueAt(turns: number, tokens: number): number {
  if (turns <= MASK_KEEP_TURNS || tokens < MASK_THRESHOLD_TOKENS) return 0;
  return Math.floor((turns - MASK_KEEP_TURNS) / MASK_STEP_TURNS) * MASK_STEP_TURNS;
}

// What a cache write costs, and whether it rewrites the whole conversation.
// The markers at the cutoff (mark.ts) often let a step read back the turns
// before it, but not always: on live traffic some steps found the entry the
// step before wrote and some did not, with the same bytes. So a step is priced
// as the whole rewrite it may be, and a read is a saving the gate does not
// count on.
interface Price {
  write: number;
  whole: boolean;
}

function writePrice(format: Format, body: Record_): Price {
  if (format !== "anthropic") return { write: CACHE_WRITE.openai, whole: false };
  // Claude Code marks its system prompt; a marker on any block says the same.
  const marked = JSON.stringify([body.system, body.tools]).includes('"ttl":"1h"');
  return { write: marked ? CACHE_WRITE.hour : CACHE_WRITE.short, whole: true };
}

// What each item is: the turn it belongs to, its size, and how much masking it
// would save over shaping it as recent. Run with walks of their own, so this
// says nothing about the real pass.
interface Sized {
  turn: number;
  tokens: number;
  gain: number;
}

function sizes(format: Format, list: unknown[], retrieval: Retrieval | undefined): Sized[] {
  const asOld: Walk = { calls: new Map(), outputs: new Map(), retrieval };
  const asNew: Walk = { calls: new Map(), outputs: new Map(), retrieval };
  let turn = 0;
  return list.map((item) => {
    for (const walk of [asOld, asNew]) remember(format, item, walk);
    if (isAssistant(format, item)) turn++;
    const old = shapeEntry(format, item, asOld, true)?.saved ?? 0;
    const recent = shapeEntry(format, item, asNew, false)?.saved ?? 0;
    // Every byte, results included: this is what a rewrite sends again.
    const tokens = Math.ceil(JSON.stringify(item ?? null).length / 4);
    return { turn, tokens, gain: Math.max(0, Math.ceil((old - recent) / 4)) };
  });
}

// Whether masking turns (from, to] pays for rewriting what follows the first
// item it changes, in the conversation that ended at item `end`, `turns` in.
interface Step {
  end: number;
  turns: number;
  from: number;
  to: number;
}

function pays(items: Sized[], step: Step, price: Price): boolean {
  const { end, from, to } = step;
  let gain = 0;
  let suffix = 0;
  let changed = false;
  for (let i = 0; i < end; i++) {
    const item = items[i]!;
    const inStep = item.turn > from && item.turn <= to;
    if (inStep && item.gain > 0) changed = true;
    if (changed || price.whole) suffix += Math.max(0, item.tokens - (inStep ? item.gain : 0));
    if (inStep) gain += item.gain;
  }
  const write = price.write;
  // A step that changes no bytes is free to take.
  const horizon = Math.max(MASK_HORIZON_TURNS, step.turns);
  return !changed || gain * CACHE_READ * horizon >= suffix * (write - CACHE_READ);
}

// The cutoff, and the cutoff as the request before this one had it: the one
// decided just before the newest assistant turn, where that request ended.
function cutoffFor(
  format: Format,
  body: Record_,
  list: unknown[],
  walk: Walk,
): { cutoff: number; previous: number } {
  const items = sizes(format, list, walk.retrieval);
  const write = writePrice(format, body);
  let cutoff = 0;
  let previous = 0;
  let turns = 0;
  let tokens = 0;
  // Every point a request could have ended: just before each assistant turn,
  // and the end of the list.
  for (let end = 0; end <= items.length; end++) {
    const item = items[end];
    if (item === undefined || isAssistant(format, list[end])) {
      const due = dueAt(turns, tokens);
      if (due > cutoff && pays(items, { end, turns, from: cutoff, to: due }, write)) cutoff = due;
      if (item !== undefined) previous = cutoff;
    }
    if (item === undefined) break;
    tokens += item.tokens;
    if (isAssistant(format, list[end])) turns++;
  }
  return { cutoff, previous };
}

function remember(format: Format, item: unknown, walk: Walk): void {
  // Every item can carry calls: an Anthropic or chat call sits in an
  // assistant turn, a Responses call is its own top-level item. Recording
  // them all is what lets a stub name the command that produced the result.
  for (const call of toolCalls(format, item))
    if (call.id !== undefined)
      walk.calls.set(String(call.id), { name: call.name, input: call.input });
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
  retrieval: Retrieval | undefined;
}

// The agent's retrieve tool (retrieve.ts), when the request offers it: its
// name as the agent calls it, and where a shortened output is kept, returning
// the id that reads it back. The id is a digest of the text, so a note naming
// it is as pure as one that does not.
export interface Retrieval {
  tool: string;
  keep(text: string): string;
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
    const back = wayBack(text, walk.retrieval);
    const stub = stubFor(name, call?.input, text.length, lines, images, back);
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
  const compacted = crushed(text, walk.retrieval) ?? compact(text);
  return compacted === undefined
    ? undefined
    : { text: compacted, saved: text.length - compacted.length, kind: "compacted" };
}

const CRUSH_MIN_CHARS = 1_000;

// A JSON output with its long arrays cut to the items that differ (crush.ts).
// Lossy, so only with a way to read the whole output back.
function crushed(text: string, retrieval: Retrieval | undefined): string | undefined {
  if (!retrieval || text.length < CRUSH_MIN_CHARS) return;
  const result = crushJson(text);
  if (!result) return;
  const id = retrieval.keep(text);
  return (
    `${result.text}\n[${result.omitted} similar array items omitted to save context. ` +
    `Call ${retrieval.tool} with id "${id}" for the whole output.]`
  );
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
export function shapeRequest(
  format: Format,
  body: Record<string, unknown>,
  retrieval?: Retrieval,
): Shaped | undefined {
  const list = conversation(format, body);
  if (!list) return;
  const walk: Walk = { calls: new Map(), outputs: new Map(), retrieval };
  const { cutoff, previous } = cutoffFor(format, body, list, walk);
  const kept = latestNotes(format, list, cutoff);
  const totals: Counts = { masked: 0, compacted: 0, deduped: 0 };
  let turn = 0;
  let savedChars = 0;
  // The last item of the turns the previous request had masked, and of those
  // this one masks: the same but on a step.
  let boundary = -1;
  let current = -1;
  const out = list.map((item, at) => {
    remember(format, item, walk);
    if (isAssistant(format, item)) turn++;
    if (turn <= previous) boundary = at;
    if (turn <= cutoff) current = at;
    // A result answers the call above it, so it shares that call's turn: the
    // first `cutoff` turns are old, calls and results alike. A cutoff of zero
    // is a conversation too short to shape, so nothing in it is old, not even
    // its first turn.
    const old = cutoff > 0 && turn <= cutoff;
    const replaced = withNotes(item, old ? dropNotes(item, at, kept) : undefined, (entry) =>
      shapeEntry(format, entry, walk, old),
    );
    if (!replaced) return item;
    for (const kind of Object.keys(totals) as Kind[]) totals[kind] += replaced.counts[kind];
    savedChars += replaced.saved;
    return replaced.entry;
  });
  // Any count is a change: a request with only compaction is still shaped.
  if (totals.masked + totals.compacted + totals.deduped === 0) return;
  const ats = [previous > 0 ? boundary : -1, cutoff > 0 ? current : -1].filter((at) => at >= 0);
  const shaped = { ...body, [keyOf(format)]: out };
  const marked = format === "anthropic" ? markBoundaries(shaped, out, ats) : shaped;
  const step = cutoff > previous ? { step: { from: previous, to: cutoff } } : {};
  return { body: marked, ...totals, savedChars, ...step };
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

// The note is about 170 characters; from 400 a long shell command is worth
// one too, and old commands were a seventh of what was left after shaping.
export const INPUT_MIN_CHARS = 400;
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

// An old assistant turn's thinking is dropped whole: it is signed, so it cannot
// be cut, and the API takes a past turn without it (its own clear_thinking
// context edit does the same). Only the latest turn of a tool loop must keep
// its thinking, and an old turn is never that. A turn that is nothing but
// thinking keeps it, since an empty turn is refused.
const THINKING = new Set(["thinking", "redacted_thinking"]);

function shapeBlocks(entry: Record_): Replacement | undefined {
  if (entry.role !== "assistant" || !Array.isArray(entry.content)) return;
  const blocks = entry.content as unknown[];
  const isThinking = (block: unknown) => THINKING.has(String(record(block)?.type));
  const drop = blocks.some((block) => !isThinking(block));
  let saved = 0;
  let masked = 0;
  const content = blocks.flatMap((block) => {
    const typed = record(block);
    if (drop && isThinking(block)) {
      saved += JSON.stringify(block).length;
      masked++;
      return [];
    }
    const next = typed?.type === "tool_use" ? maskedValue(typed.input) : undefined;
    if (!next) return [block];
    saved += next.saved;
    masked++;
    return [{ ...typed, input: next.value }];
  });
  return masked === 0
    ? undefined
    : { entry: { ...entry, content }, saved, counts: { masked, compacted: 0, deduped: 0 } };
}

// A chat turn's reasoning, by the field each provider sends it back in:
// DeepSeek and opencode Go's reasoning_content, OpenRouter's reasoning and
// reasoning_details. Unlike Anthropic's thinking nothing checks it, and it is
// billed as input on every turn that re-sends it (a fifth of the prompt tokens
// on an opencode Go session), so an old turn's is dropped the same way.
const REASONING = ["reasoning_content", "reasoning", "reasoning_details"];

// Whether a chat turn says or calls something: one that does not keeps its
// reasoning, since an empty turn is refused.
function hasOutput(entry: Record_): boolean {
  const { content, tool_calls: calls } = entry;
  if (Array.isArray(calls) && calls.length > 0) return true;
  return (typeof content === "string" || Array.isArray(content)) && content.length > 0;
}

function shapeChatCalls(entry: Record_): Replacement | undefined {
  if (entry.role !== "assistant") return;
  let saved = 0;
  let masked = 0;
  const out: Record_ = { ...entry };
  if (Array.isArray(entry.tool_calls))
    out.tool_calls = (entry.tool_calls as unknown[]).map((call) => {
      const typed = record(call);
      const fn = record(typed?.function);
      const next = fn ? maskedArguments(fn.arguments) : undefined;
      if (!next) return call;
      saved += next.saved;
      masked++;
      return { ...typed, function: { ...fn, arguments: next.value } };
    });
  if (hasOutput(entry))
    for (const field of REASONING) {
      const value = entry[field];
      if (value === undefined || value === null || value === "") continue;
      saved += JSON.stringify(value).length;
      masked++;
      delete out[field];
    }
  return masked === 0
    ? undefined
    : { entry: out, saved, counts: { masked, compacted: 0, deduped: 0 } };
}

// ── superseded harness notes ────────────────────────────────────────────────
//
// A harness puts notes of its own in user turns, each a text block that is one
// tag: a reminder of the instructions or the skills on offer, the tokens left,
// a background task's news. Each is re-sent on every turn after it, and a newer
// one of the same kind says the same or supersedes it. In the old part of the
// conversation, a note with a newer one of its kind in the same step (the
// MASK_STEP_TURNS turns a cutoff moves by) is dropped, and the newest of each
// kind in a step stays, so an instruction given once is never lost.
//
// Within one step, not across the whole old part: a step must change nothing
// before the previous cutoff, or the marker there (mark.ts) cannot be read
// back. Across the old part, a newer note stepping in dropped an older one
// anywhere above it, down to the first message, and the step rewrote the whole
// conversation (CACHING.md). A step's notes depend only on that step, so once
// it is old its bytes never change again.

// The step a turn's items fall in: turns 0 to 10 are old at a cutoff of 10,
// 11 to 20 at 20, and so on.
function stepOf(turn: number): number {
  return turn === 0 ? 0 : Math.ceil(turn / MASK_STEP_TURNS) - 1;
}

const NOTE = /^\s*<([a-z][\w-]*)>([\s\S]*)<\/\1>\s*$/;

// A note's kind: its tag and first line, numbers aside, so the tokens-left
// count from turn 3 and turn 30 are one kind.
function noteKind(block: unknown): string | undefined {
  const typed = record(block);
  if (typed?.type !== "text" || typeof typed.text !== "string") return;
  const match = NOTE.exec(typed.text);
  if (!match) return;
  const first = match[2]!.trim().split("\n")[0]!;
  return `${match[1]}:${first.replace(/\d+/g, "#").slice(0, 120)}`;
}

function userBlocks(item: unknown): unknown[] | undefined {
  const entry = record(item);
  return entry?.role === "user" && Array.isArray(entry.content) ? entry.content : undefined;
}

// Where the newest note of each kind sits in each step of the old part, as
// "item:block".
// Anthropic only: it is where harnesses put notes as blocks of their own.
function latestNotes(format: Format, list: unknown[], cutoff: number): Set<string> | undefined {
  if (format !== "anthropic" || cutoff === 0) return;
  const latest = new Map<string, string>();
  let turn = 0;
  list.forEach((item, at) => {
    if (isAssistant(format, item)) turn++;
    if (turn > cutoff) return;
    userBlocks(item)?.forEach((block, index) => {
      const kind = noteKind(block);
      if (kind) latest.set(`${stepOf(turn)}\0${kind}`, `${at}:${index}`);
    });
  });
  return new Set(latest.values());
}

// The item without its superseded notes, or undefined when it had none. A turn
// keeps one block at least, since an empty one is refused.
function dropNotes(item: unknown, at: number, kept: Set<string> | undefined) {
  const blocks = userBlocks(item);
  if (!kept || !blocks) return;
  let saved = 0;
  let dropped = 0;
  const content = blocks.filter((block, index) => {
    if (noteKind(block) === undefined || kept.has(`${at}:${index}`)) return true;
    if (dropped === blocks.length - 1) return true;
    saved += JSON.stringify(block).length;
    dropped++;
    return false;
  });
  return dropped === 0 ? undefined : { entry: { ...(item as Record_), content }, saved, dropped };
}

// The rest of shaping run on what dropping notes left, with both counted.
function withNotes(
  item: unknown,
  notes: ReturnType<typeof dropNotes>,
  rest: (item: unknown) => Replacement | undefined,
): Replacement | undefined {
  const next = rest(notes ? notes.entry : item);
  if (!notes) return next;
  const counts = next?.counts ?? { masked: 0, compacted: 0, deduped: 0 };
  return {
    entry: next?.entry ?? notes.entry,
    saved: notes.saved + (next?.saved ?? 0),
    counts: { ...counts, masked: counts.masked + notes.dropped },
  };
}
