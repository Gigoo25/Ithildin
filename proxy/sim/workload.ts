// Conversations to replay through shaping: made up from a seed, in the shapes
// the agents send, or cut from a real request body.
//
// A conversation is generated once, as events, and written out per wire
// format, so the same session reaches shaping as Claude Code, Codex and
// opencode would send it. Each seed turns a random set of features on (swarm
// testing): a run where no session has images exercises different paths than
// one where every session does, and a bug that needs two features together
// turns up in the seeds that happen to pick both.

import { Random } from "./random.ts";
import type { Format } from "../src/redact.ts";

type Fields = Record<string, unknown>;

export interface Features {
  notes: boolean;
  midTurn: boolean;
  repeats: boolean;
  json: boolean;
  images: boolean;
  bigInputs: boolean;
  thinking: boolean;
  // How often a round ends the loop and the user types the next prompt.
  answers: number;
}

export function featuresFor(random: Random): Features {
  return {
    notes: random.chance(0.5),
    midTurn: random.chance(0.5),
    repeats: random.chance(0.5),
    json: random.chance(0.5),
    images: random.chance(0.3),
    bigInputs: random.chance(0.5),
    thinking: random.chance(0.7),
    answers: random.pick([0.02, 0.1, 0.25]),
  };
}

interface Output {
  text: string;
  image: boolean;
}

interface Call {
  id: string;
  name: string;
  input: Fields;
  output: Output;
}

type Event =
  | { kind: "prompt"; text: string; notes: string[] }
  | { kind: "round"; thinking: string; calls: Call[]; notes: string[]; typed?: string }
  | { kind: "answer"; thinking: string; text: string };

const NOTES = [
  "<system-reminder>\nThe task tools haven't been used recently.\n</system-reminder>",
  "<total_tokens>14986380 tokens left</total_tokens>",
  "<system-reminder>\nNote: src/server.ts was modified by the user.\n</system-reminder>",
];

function note(random: Random): string {
  return random.pick(NOTES).replace("14986380", String(random.int(1e6, 2e7)));
}

function output(random: Random, features: Features, seen: string[]): Output {
  if (features.repeats && seen.length > 0 && random.chance(0.15))
    return { text: random.pick(seen), image: false };
  if (features.images && random.chance(0.05)) return { text: "", image: true };
  if (features.json && random.chance(0.1)) {
    const rows = Array.from({ length: random.int(40, 160) }, (_, i) => ({
      id: i,
      name: random.text(20),
      ok: random.chance(0.9),
    }));
    return { text: JSON.stringify(rows, null, 2), image: false };
  }
  const size = random.pick([random.int(80, 400), random.int(400, 4000), random.int(4000, 24000)]);
  return { text: random.text(size), image: false };
}

function call(random: Random, features: Features, id: string, seen: string[]): Call {
  const out = output(random, features, seen);
  if (out.text.length >= 500) seen.push(out.text);
  if (features.bigInputs && random.chance(0.15))
    return {
      id,
      name: "Write",
      input: { file_path: "src/x.ts", content: random.text(random.int(500, 5000)) },
      output: { text: "File written.", image: false },
    };
  const name = random.pick(["Bash", "Read", "Grep"]);
  const input = name === "Bash" ? { command: random.text(40) } : { file_path: random.text(20) };
  return { id, name, input, output: out };
}

// A session of about `rounds` model rounds, as events.
export function events(seed: number, rounds: number): { features: Features; events: Event[] } {
  const random = new Random(seed);
  const features = featuresFor(random);
  const seen: string[] = [];
  const list: Event[] = [{ kind: "prompt", text: random.text(200), notes: [note(random)] }];
  let ids = 0;
  for (let round = 0; round < rounds; round++) {
    if (random.chance(features.answers)) {
      list.push({ kind: "answer", thinking: random.text(300), text: random.text(400) });
      const notes = features.notes && random.chance(0.5) ? [note(random)] : [];
      list.push({ kind: "prompt", text: random.text(random.int(20, 600)), notes });
      continue;
    }
    const calls = Array.from({ length: random.chance(0.2) ? 2 : 1 }, () =>
      call(random, features, `call_${seed}_${ids++}`, seen),
    );
    const notes = features.notes && random.chance(0.3) ? [note(random)] : [];
    const typed = features.midTurn && random.chance(0.03) ? random.text(80) : undefined;
    list.push({
      kind: "round",
      thinking: random.text(random.int(100, 1500)),
      calls,
      notes,
      ...(typed === undefined ? {} : { typed }),
    });
  }
  return { features, events: list };
}

const IMAGE = { type: "base64", media_type: "image/png", data: "iVBORw0KGgo".repeat(200) };

function anthropicResult(call: Call): Fields {
  const content = call.output.image
    ? [{ type: "image", source: IMAGE }]
    : [{ type: "text", text: call.output.text }];
  return { type: "tool_result", tool_use_id: call.id, content };
}

function anthropicMessages(list: Event[], thinking: boolean): Fields[] {
  const think = (text: string) =>
    thinking ? [{ type: "thinking", thinking: text, signature: `sig${text.length}` }] : [];
  const text = (value: string) => ({ type: "text", text: value });
  return list.flatMap((event): Fields[] => {
    if (event.kind === "prompt")
      return [{ role: "user", content: [...event.notes.map(text), text(event.text)] }];
    if (event.kind === "answer")
      return [{ role: "assistant", content: [...think(event.thinking), text(event.text)] }];
    const uses = event.calls.map((c) => ({
      type: "tool_use",
      id: c.id,
      name: c.name,
      input: c.input,
    }));
    const results = [...event.calls.map(anthropicResult), ...event.notes.map(text)];
    if (event.typed !== undefined) results.push(text(event.typed));
    return [
      { role: "assistant", content: [...think(event.thinking), ...uses] },
      { role: "user", content: results },
    ];
  });
}

function responsesInput(list: Event[]): Fields[] {
  const user = (texts: string[]) => ({
    type: "message",
    role: "user",
    content: texts.map((text) => ({ type: "input_text", text })),
  });
  const reasoning = (text: string) => ({
    type: "reasoning",
    summary: [{ type: "summary_text", text: text.slice(0, 80) }],
    encrypted_content: Buffer.from(text).toString("base64"),
  });
  return list.flatMap((event): Fields[] => {
    if (event.kind === "prompt") return [user([...event.notes, event.text])];
    if (event.kind === "answer")
      return [
        reasoning(event.thinking),
        {
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: event.text }],
        },
      ];
    const out: Fields[] = [reasoning(event.thinking)];
    for (const c of event.calls)
      out.push({
        type: "function_call",
        call_id: c.id,
        name: c.name,
        arguments: JSON.stringify(c.input),
      });
    for (const c of event.calls)
      out.push({ type: "function_call_output", call_id: c.id, output: c.output.text || "[image]" });
    if (event.typed !== undefined) out.push(user([event.typed]));
    return out;
  });
}

function chatMessages(list: Event[]): Fields[] {
  const out: Fields[] = [{ role: "system", content: "You are opencode." }];
  for (const event of list) {
    if (event.kind === "prompt") out.push({ role: "user", content: event.text });
    else if (event.kind === "answer")
      out.push({ role: "assistant", content: event.text, reasoning_content: event.thinking });
    else {
      const calls = event.calls.map((c) => ({
        id: c.id,
        type: "function",
        function: { name: c.name, arguments: JSON.stringify(c.input) },
      }));
      out.push({
        role: "assistant",
        content: "",
        reasoning_content: event.thinking,
        tool_calls: calls,
      });
      for (const c of event.calls)
        out.push({ role: "tool", tool_call_id: c.id, content: c.output.text || "[image]" });
      if (event.typed !== undefined) out.push({ role: "user", content: event.typed });
    }
  }
  return out;
}

// opencode's Gemini models, through the AI SDK: a turn's thought comes back as
// a thought part with its signature, a call as its name and arguments with no
// id, and its result under the same name, each result a part of one user turn.
function geminiContents(list: Event[], thinking: boolean): Fields[] {
  const think = (text: string) =>
    thinking
      ? [
          {
            text,
            thought: true,
            thoughtSignature: Buffer.from(`sig${text.length}`).toString("base64"),
          },
        ]
      : [];
  const user = (texts: string[]) => ({ role: "user", parts: texts.map((text) => ({ text })) });
  return list.flatMap((event): Fields[] => {
    if (event.kind === "prompt") return [user([...event.notes, event.text])];
    if (event.kind === "answer")
      return [{ role: "model", parts: [...think(event.thinking), { text: event.text }] }];
    const calls = event.calls.map((c) => ({ functionCall: { name: c.name, args: c.input } }));
    const results = event.calls.map((c) => ({
      functionResponse: {
        name: c.name,
        response: { name: c.name, content: c.output.text || "[image]" },
      },
    }));
    const out: Fields[] = [
      { role: "model", parts: [...think(event.thinking), ...calls] },
      { role: "user", parts: results },
    ];
    if (event.typed !== undefined) out.push(user([event.typed]));
    return out;
  });
}

const TOOLS = ["Bash", "Read", "Grep", "Write"].map((name) => ({
  name,
  description: `The ${name} tool.`,
  input_schema: { type: "object" },
}));

// The whole session as its last request would carry it.
export function generated(format: Format, seed: number, rounds: number): Fields {
  const { features, events: list } = events(seed, rounds);
  if (format === "responses")
    return {
      model: "gpt-6-luna",
      instructions: "You are Codex.",
      tools: TOOLS,
      input: responsesInput(list),
    };
  if (format === "chat")
    return { model: "deepseek-v4", tools: TOOLS, messages: chatMessages(list) };
  if (format === "gemini")
    return {
      systemInstruction: { parts: [{ text: "You are opencode." }] },
      tools: [
        {
          functionDeclarations: TOOLS.map(({ name, description }) => ({
            name,
            description,
            parameters: { type: "object" },
          })),
        },
      ],
      contents: geminiContents(list, features.thinking),
    };
  return {
    model: "claude-opus-5-5",
    system: [
      { type: "text", text: "x-anthropic-billing-header: cc_version=2.1" },
      {
        type: "text",
        text: "You are Claude Code.",
        cache_control: { type: "ephemeral", ttl: "1h" },
      },
    ],
    tools: TOOLS,
    thinking: features.thinking ? { type: "adaptive" } : undefined,
    messages: anthropicMessages(list, features.thinking),
  };
}

// Where each format keeps its conversation, and its system prompt.
export function listKey(format: Format): "input" | "contents" | "messages" {
  return format === "responses" ? "input" : format === "gemini" ? "contents" : "messages";
}

export function systemOf(format: Format, body: Fields): unknown {
  return format === "responses"
    ? body.instructions
    : format === "gemini"
      ? body.systemInstruction
      : body.system;
}

export function listOf(format: Format, body: Fields): unknown[] {
  const list = body[listKey(format)];
  return Array.isArray(list) ? list : [];
}

export function withList(format: Format, body: Fields, list: unknown[]): Fields {
  return { ...body, [listKey(format)]: list };
}

function modelItem(item: unknown): boolean {
  const entry = item as Fields | undefined;
  if (entry?.role === "assistant" || entry?.role === "model") return true;
  return typeof entry?.type === "string" && /^reasoning$|_call$/.test(entry.type);
}

// Moves the agent's marker to the newest message, as Claude Code does: off
// every earlier message, onto the last block of the last one.
function markNewest(list: unknown[]): unknown[] {
  return list.map((item, at) => {
    const entry = item as Fields;
    if (!Array.isArray(entry.content)) return item;
    const blocks = (entry.content as Fields[]).map(({ cache_control: _, ...block }) => block);
    if (at === list.length - 1) {
      const last = blocks.findLastIndex((block) => block.type !== "thinking");
      if (last >= 0)
        blocks[last] = { ...blocks[last], cache_control: { type: "ephemeral", ttl: "1h" } };
    }
    return { ...entry, content: blocks };
  });
}

// The requests the agent sent on the way to `body`, oldest first: the list as
// it stood before each model turn, and the whole list when it ends on a user
// turn.
export function requestsOf(format: Format, body: Fields): Fields[] {
  const list = listOf(format, body);
  const out: Fields[] = [];
  for (let at = 1; at <= list.length; at++) {
    const ends = at === list.length || (modelItem(list[at]) && !modelItem(list[at - 1]));
    if (!ends || modelItem(list[at - 1])) continue;
    const slice = list.slice(0, at);
    out.push(withList(format, body, format === "anthropic" ? markNewest(slice) : slice));
  }
  return out;
}
