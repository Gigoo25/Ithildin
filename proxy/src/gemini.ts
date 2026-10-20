// Gemini's own API (generateContent, streamGenerateContent), as opencode Go
// serves its Gemini models. A request holds
// `contents`, turns of `parts`: text, inlineData, functionCall and
// functionResponse, and the model's thought parts with their signatures.
//
// The rest of the proxy reads a conversation in the Anthropic shape, so a
// Gemini request is read through a view of it in that shape, one item per
// turn: allow tags, the working directory, secret reads, labels and strays
// come out the same as for any other agent. Only what is written goes into
// Gemini's own shape (redact.ts).

import { createHash } from "node:crypto";

type Fields = Record<string, unknown>;

function record(value: unknown): Fields | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Fields)
    : undefined;
}

function partsOf(turn: unknown): unknown[] {
  const parts = record(turn)?.parts;
  return Array.isArray(parts) ? parts : [];
}

// ── call ids ────────────────────────────────────────────────────────────────
// Results are matched to calls by id, and a blocked call is explained by its
// id in every later request (redact.ts). Gemini clients mostly send no id: the
// AI SDK sends a call back as its name and arguments, and the result as its
// name. A call without one is named by the conversation it belongs to (a
// digest of its first turn), its tool and how many calls to that tool came
// before it; its result, by the same count of results. The model answers each
// turn's calls in order, so the two counts agree, and a call the reply
// carries gets the id the next request will give it.

function conversationKey(contents: unknown[]): string {
  const first = JSON.stringify(contents[0] ?? null);
  return createHash("sha256").update(first).digest("hex").slice(0, 12);
}

function derivedId(key: string, name: string, count: Map<string, number>): string {
  const n = count.get(name) ?? 0;
  count.set(name, n + 1);
  return `gemini:${key}:${name}#${n}`;
}

// The id of each functionCall and functionResponse in a conversation, by the
// call or response object itself.
export function geminiCallIds(contents: unknown[]): WeakMap<object, string> {
  const key = conversationKey(contents);
  const calls = new Map<string, number>();
  const results = new Map<string, number>();
  const ids = new WeakMap<object, string>();
  for (const part of contents.flatMap(partsOf)) {
    const call = record(record(part)?.functionCall);
    const result = record(record(part)?.functionResponse);
    for (const [entry, count] of [
      [call, calls],
      [result, results],
    ] as const) {
      if (!entry) continue;
      const name = String(entry.name);
      const id = typeof entry.id === "string" ? entry.id : derivedId(key, name, count);
      ids.set(entry, id);
    }
  }
  return ids;
}

// What the reply to a request needs to name its calls: the conversation and
// how many calls to each tool it already holds. Keyed by the request's tag
// set, the one thing every reply rewriter is handed (redact.ts).
const replyCalls = new WeakMap<Set<string>, { key: string; count: Map<string, number> }>();

export function noteGeminiCalls(tags: Set<string>, contents: unknown[]): void {
  const count = new Map<string, number>();
  for (const part of contents.flatMap(partsOf)) {
    const call = record(record(part)?.functionCall);
    if (call) count.set(String(call.name), (count.get(String(call.name)) ?? 0) + 1);
  }
  replyCalls.set(tags, { key: conversationKey(contents), count });
}

// The id the next request will give a call in this reply.
export function nextGeminiCallId(tags: Set<string>, call: Fields): string | undefined {
  if (typeof call.id === "string") return call.id;
  const known = replyCalls.get(tags);
  return known && derivedId(known.key, String(call.name), known.count);
}

// ── the view ────────────────────────────────────────────────────────────────

// What a result says, for the readers that take a result's text: the AI SDK
// puts it under response.content, Gemini's own examples under
// response.output or response.result.
export function resultContent(response: unknown): unknown {
  const fields = record(response);
  if (!fields) return response;
  for (const key of ["content", "output", "result"])
    if (fields[key] !== undefined) return fields[key];
  return JSON.stringify(response);
}

function blockOf(part: unknown, ids: WeakMap<object, string>): Fields {
  const fields = record(part) ?? {};
  const call = record(fields.functionCall);
  if (call)
    return { type: "tool_use", id: ids.get(call), name: String(call.name), input: call.args };
  const result = record(fields.functionResponse);
  if (result)
    return {
      type: "tool_result",
      tool_use_id: ids.get(result),
      content: resultContent(result.response),
    };
  if (typeof fields.text === "string")
    return fields.thought === true
      ? { type: "thinking", thinking: fields.text }
      : { type: "text", text: fields.text };
  return { type: "other" };
}

// The request as an Anthropic one: system from systemInstruction, a message
// per turn of contents (in the same order, so a turn's index is the same in
// both), and the declared functions as tools.
export function geminiView(body: Fields): Fields {
  const contents = Array.isArray(body.contents) ? body.contents : [];
  const ids = geminiCallIds(contents);
  const messages = contents.map((turn) => ({
    role: record(turn)?.role === "model" ? "assistant" : "user",
    content: partsOf(turn).map((part) => blockOf(part, ids)),
  }));
  const system = partsOf(body.systemInstruction).map((part) => blockOf(part, ids));
  const tools = (Array.isArray(body.tools) ? body.tools : []).flatMap((tool) => {
    const declared = record(tool)?.functionDeclarations;
    return (Array.isArray(declared) ? declared : []).map((fn) => {
      const fields = record(fn) ?? {};
      return { name: fields.name, input_schema: fields.parameters ?? fields.parametersJsonSchema };
    });
  });
  return { system, messages, tools };
}

// ── results ─────────────────────────────────────────────────────────────────

// The conversation with each result's content passed through `map`, which
// returns undefined to leave it as it was. Unchanged turns stay as they were.
export function mapGeminiResults(
  contents: unknown[],
  map: (id: string | undefined, content: unknown) => unknown,
): unknown[] {
  const ids = geminiCallIds(contents);
  return contents.map((turn) => {
    let changed = false;
    const parts = partsOf(turn).map((part) => {
      const result = record(record(part)?.functionResponse);
      if (!result) return part;
      const out = map(ids.get(result), resultContent(result.response));
      if (out === undefined) return part;
      changed = true;
      return {
        ...record(part),
        functionResponse: { ...result, response: withContent(result, out) },
      };
    });
    return changed ? { ...record(turn), parts } : turn;
  });
}

// A result's response with its content replaced, under the key it was read
// from; a response read whole becomes { content }.
function withContent(result: Fields, content: unknown): Fields {
  const response = record(result.response);
  const key = ["content", "output", "result"].find((name) => response?.[name] !== undefined);
  return key ? { ...response, [key]: content } : { name: result.name, content };
}
