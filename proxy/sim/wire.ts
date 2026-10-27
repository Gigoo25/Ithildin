// A model turn as each API streams it, and the stream as the harness reads it
// back. The bytes are cut at random points, inside an event, a stand-in or a
// UTF-8 character, because the proxy rewrites the stream as it passes and the
// cuts are where that goes wrong.
//
// Reading the stream back also checks it agrees with itself: a Responses
// stream says each text three times (deltas, the done event, the completed
// response), and a harness may read any of them.

import type { Format } from "../src/redact.ts";
import type { ModelCall, Turn } from "./model.ts";
import type { Usage } from "./cache.ts";
import { Random } from "./random.ts";

type Fields = Record<string, unknown>;
type Event = { event?: string; data: unknown };

// A string in one to four pieces.
function pieces(random: Random, text: string): string[] {
  if (text.length < 2) return [text];
  // Sometimes every one to three characters, as the APIs often stream, so a
  // cut lands inside a stand-in, an escape or a character.
  if (random.chance(0.25)) {
    const out: string[] = [];
    for (let at = 0; at < text.length;) {
      const size = random.int(1, 3);
      out.push(text.slice(at, at + size));
      at += size;
    }
    return out;
  }
  const cuts = [
    ...new Set(Array.from({ length: random.int(0, 3) }, () => random.int(1, text.length - 1))),
  ];
  cuts.sort((a, b) => a - b);
  return [0, ...cuts].map((at, i) => text.slice(at, cuts[i] ?? text.length));
}

function anthropicEvents(turn: Turn, usage: Usage, random: Random): Event[] {
  const out: Event[] = [];
  const add = (data: Fields) => out.push({ event: String(data.type), data });
  add({
    type: "message_start",
    message: {
      id: "msg_sim",
      type: "message",
      role: "assistant",
      content: [],
      usage: {
        input_tokens: usage.uncached,
        cache_read_input_tokens: usage.read,
        cache_creation_input_tokens: usage.write,
        output_tokens: 1,
      },
    },
  });
  let index = 0;
  const block = (start: Fields, deltas: Fields[]) => {
    add({ type: "content_block_start", index, content_block: start });
    for (const delta of deltas) add({ type: "content_block_delta", index, delta });
    add({ type: "content_block_stop", index });
    index++;
  };
  block({ type: "thinking", thinking: "", signature: "" }, [
    ...pieces(random, turn.thinking).map((thinking) => ({ type: "thinking_delta", thinking })),
    { type: "signature_delta", signature: `sig-${turn.thinking.length}` },
  ]);
  if (turn.text)
    block(
      { type: "text", text: "" },
      pieces(random, turn.text).map((text) => ({ type: "text_delta", text })),
    );
  for (const call of turn.calls)
    block(
      { type: "tool_use", id: call.id, name: call.name, input: {} },
      pieces(random, JSON.stringify(call.input)).map((json) => ({
        type: "input_json_delta",
        partial_json: json,
      })),
    );
  const stop = turn.calls.length > 0 ? "tool_use" : "end_turn";
  add({ type: "message_delta", delta: { stop_reason: stop }, usage: { output_tokens: 50 } });
  add({ type: "message_stop" });
  return out;
}

function responsesItems(turn: Turn): Fields[] {
  const items: Fields[] = [
    {
      type: "reasoning",
      id: "rs_sim",
      summary: [{ type: "summary_text", text: turn.thinking }],
      encrypted_content: Buffer.from(turn.thinking).toString("base64"),
    },
  ];
  if (turn.text)
    items.push({
      type: "message",
      id: "msg_sim",
      role: "assistant",
      content: [{ type: "output_text", text: turn.text }],
    });
  turn.calls.forEach((call, i) =>
    items.push({
      type: "function_call",
      id: `fc_sim_${i}`,
      call_id: call.id,
      name: call.name,
      arguments: JSON.stringify(call.input),
    }),
  );
  return items;
}

function responsesEvents(turn: Turn, usage: Usage, random: Random): Event[] {
  const out: Event[] = [];
  const add = (data: Fields) => out.push({ event: String(data.type), data });
  add({ type: "response.created", response: { id: "resp_sim" } });
  const items = responsesItems(turn);
  items.forEach((item, output_index) => {
    const empty: Fields = { ...item, ...(item.type === "function_call" ? { arguments: "" } : {}) };
    if (item.type === "message") empty.content = [];
    add({ type: "response.output_item.added", output_index, item: empty });
    if (item.type === "message") {
      for (const delta of pieces(random, turn.text))
        add({ type: "response.output_text.delta", item_id: item.id, content_index: 0, delta });
      add({
        type: "response.output_text.done",
        item_id: item.id,
        content_index: 0,
        text: turn.text,
      });
    }
    if (item.type === "function_call") {
      for (const delta of pieces(random, String(item.arguments)))
        add({ type: "response.function_call_arguments.delta", item_id: item.id, delta });
      add({
        type: "response.function_call_arguments.done",
        item_id: item.id,
        arguments: item.arguments,
      });
    }
    add({ type: "response.output_item.done", output_index, item });
  });
  add({
    type: "response.completed",
    response: {
      id: "resp_sim",
      output: items,
      usage: {
        input_tokens: usage.read + usage.uncached,
        input_tokens_details: { cached_tokens: usage.read },
        output_tokens: 50,
      },
    },
  });
  return out;
}

function chatEvents(turn: Turn, usage: Usage, random: Random): Event[] {
  const out: Event[] = [];
  const chunk = (delta: Fields, finish: string | null = null) =>
    out.push({
      data: {
        id: "chat_sim",
        object: "chat.completion.chunk",
        choices: [{ index: 0, delta, finish_reason: finish }],
      },
    });
  chunk({ role: "assistant", content: "" });
  for (const reasoning of pieces(random, turn.thinking)) chunk({ reasoning_content: reasoning });
  if (turn.text) for (const content of pieces(random, turn.text)) chunk({ content });
  turn.calls.forEach((call, index) => {
    chunk({
      tool_calls: [
        { index, id: call.id, type: "function", function: { name: call.name, arguments: "" } },
      ],
    });
    for (const args of pieces(random, JSON.stringify(call.input)))
      chunk({ tool_calls: [{ index, function: { arguments: args } }] });
  });
  chunk({}, turn.calls.length > 0 ? "tool_calls" : "stop");
  out.push({
    data: {
      id: "chat_sim",
      choices: [],
      usage: {
        prompt_tokens: usage.read + usage.uncached,
        completion_tokens: 50,
        prompt_tokens_details: { cached_tokens: usage.read },
      },
    },
  });
  out.push({ data: "[DONE]" });
  return out;
}

// The turn as an SSE response, its bytes cut at random points.
export function streamed(format: Format, turn: Turn, usage: Usage, random: Random): Response {
  const events =
    format === "anthropic"
      ? anthropicEvents(turn, usage, random)
      : format === "responses"
        ? responsesEvents(turn, usage, random)
        : chatEvents(turn, usage, random);
  const text = events
    .map((e) => {
      const data = typeof e.data === "string" ? e.data : JSON.stringify(e.data);
      return `${e.event ? `event: ${e.event}\n` : ""}data: ${data}\n\n`;
    })
    .join("");
  const bytes = new TextEncoder().encode(text);
  const cuts = pieces(random, "x".repeat(bytes.length)).map((piece) => piece.length);
  let at = 0;
  const chunks = cuts.map((size) => bytes.slice(at, (at += size)));
  return new Response(
    new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    }),
    { headers: { "content-type": "text/event-stream" } },
  );
}

export function parseEvents(text: string): Fields[] {
  return text.split("\n\n").flatMap((block) => {
    const data = block
      .split("\n")
      .filter((line) => line.startsWith("data: "))
      .map((line) => line.slice(6))
      .join("\n");
    if (!data || data === "[DONE]") return [];
    return [JSON.parse(data) as Fields];
  });
}

export interface Read {
  turn: Turn;
  problems: string[];
}

function parseInput(text: string, problems: string[]): Record<string, unknown> {
  try {
    return JSON.parse(text || "{}") as Record<string, unknown>;
  } catch {
    problems.push(`a call's arguments do not parse: ${text.slice(0, 80)}`);
    return {};
  }
}

function readAnthropic(events: Fields[], problems: string[]): Turn {
  const blocks = new Map<number, Fields & { json?: string }>();
  for (const e of events) {
    const index = Number(e.index);
    if (e.type === "content_block_start")
      blocks.set(index, { ...(e.content_block as Fields), json: "" });
    if (e.type !== "content_block_delta") continue;
    const block = blocks.get(index)!;
    const delta = e.delta as Fields;
    if (delta.type === "text_delta") block.text = String(block.text ?? "") + String(delta.text);
    if (delta.type === "thinking_delta")
      block.thinking = String(block.thinking ?? "") + String(delta.thinking);
    if (delta.type === "input_json_delta") block.json += String(delta.partial_json);
  }
  const turn: Turn = { thinking: "", text: "", calls: [] };
  for (const block of blocks.values()) {
    if (block.type === "thinking") turn.thinking += String(block.thinking ?? "");
    if (block.type === "text") turn.text += String(block.text ?? "");
    if (block.type === "tool_use")
      turn.calls.push({
        id: String(block.id),
        name: String(block.name),
        input: parseInput(block.json ?? "", problems),
      });
  }
  return turn;
}

function readResponses(events: Fields[], problems: string[]): Turn {
  const deltas = new Map<string, string>();
  const turn: Turn = { thinking: "", text: "", calls: [] };
  let completed: unknown;
  for (const e of events) {
    const id = String(e.item_id);
    if (
      e.type === "response.output_text.delta" ||
      e.type === "response.function_call_arguments.delta"
    )
      deltas.set(id, (deltas.get(id) ?? "") + String(e.delta));
    if (e.type === "response.output_text.done" && e.text !== deltas.get(id))
      problems.push(
        `text deltas say ${JSON.stringify(deltas.get(id))}, done says ${JSON.stringify(e.text)}`,
      );
    if (e.type === "response.function_call_arguments.done" && e.arguments !== deltas.get(id))
      problems.push(`argument deltas and done disagree for ${id}`);
    if (e.type === "response.completed") completed = (e.response as Fields).output;
    if (e.type !== "response.output_item.done") continue;
    const item = e.item as Fields;
    if (item.type === "reasoning")
      turn.thinking = ((item.summary as Fields[]) ?? []).map((s) => String(s.text)).join("");
    if (item.type === "message")
      turn.text += ((item.content as Fields[]) ?? []).map((c) => String(c.text)).join("");
    if (item.type === "function_call")
      turn.calls.push({
        id: String(item.call_id),
        name: String(item.name),
        input: parseInput(String(item.arguments), problems),
      });
  }
  const done = events.filter((e) => e.type === "response.output_item.done").map((e) => e.item);
  if (JSON.stringify(completed) !== JSON.stringify(done))
    problems.push("response.completed and the items it finished disagree");
  return turn;
}

function readChat(events: Fields[], problems: string[]): Turn {
  const turn: Turn = { thinking: "", text: "", calls: [] };
  const calls: Array<{ id: string; name: string; args: string }> = [];
  for (const e of events) {
    const delta = ((e.choices as Fields[] | undefined)?.[0]?.delta ?? {}) as Fields;
    if (typeof delta.content === "string") turn.text += delta.content;
    if (typeof delta.reasoning_content === "string") turn.thinking += delta.reasoning_content;
    for (const call of (delta.tool_calls as Fields[] | undefined) ?? []) {
      const at = Number(call.index);
      const fn = (call.function ?? {}) as Fields;
      calls[at] ??= { id: "", name: "", args: "" };
      if (call.id) calls[at]!.id = String(call.id);
      if (fn.name) calls[at]!.name = String(fn.name);
      if (typeof fn.arguments === "string") calls[at]!.args += fn.arguments;
    }
  }
  turn.calls = calls.map((c): ModelCall => ({
    id: c.id,
    name: c.name,
    input: parseInput(c.args, problems),
  }));
  return turn;
}

// What the harness made of the proxy's response, and anything inconsistent
// in it.
export function readTurn(format: Format, text: string): Read {
  const problems: string[] = [];
  let events: Fields[];
  try {
    events = parseEvents(text);
  } catch (error) {
    return {
      turn: { thinking: "", text: "", calls: [] },
      problems: [`stream does not parse: ${String(error)}`],
    };
  }
  const turn =
    format === "anthropic"
      ? readAnthropic(events, problems)
      : format === "responses"
        ? readResponses(events, problems)
        : readChat(events, problems);
  return { turn, problems };
}
