// Session titles for the dashboard, read from the agents' own traffic. Claude
// Code and opencode each ask a model to name a session, in a request of its
// own that carries the session's id; the reply is the title. Pi asks for none.
//
// The reply is read as it came from the provider, before swap-back, so a
// title holds stand-ins, never a real value. The user's own name for a
// session (Claude Code's /rename) wins over one a model made up.

import { parseSseBlock } from "./streams.ts";

// What a naming request asks for, by the start of its system prompt:
//   title  Claude Code's session title, as JSON {"title": ...}
//   name   Claude Code's /rename without a name, as JSON {"name": ...}
//   line   opencode's title agent, as plain text
export type TitleAsk = "title" | "name" | "line";

const ASKS: Array<[RegExp, TitleAsk]> = [
  [/^You are naming a coding session so the user can pick it out/, "title"],
  [/^Generate a short kebab-case name \(2-4 words\)/, "name"],
  [/^You are a title generator\. You output ONLY a thread title\./, "line"],
];

// Claude Code tells the model when the user names a session (/rename).
const RENAMED = /The user named this session "([^"\n]{1,200})"\./g;
const TITLE_MAX = 80;

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => {
      if (typeof block === "string") return block;
      const text = (block as { text?: unknown } | null)?.text;
      return typeof text === "string" ? text : "";
    })
    .join("\n");
}

// The system prompt, in each format: Anthropic's system, Responses'
// instructions, or a leading system or developer message.
function systemText(body: Record<string, unknown>): string {
  if (body.system !== undefined) return textOf(body.system);
  if (typeof body.instructions === "string") return body.instructions;
  const list = Array.isArray(body.messages) ? body.messages : body.input;
  const first = Array.isArray(list)
    ? (list[0] as { role?: unknown; content?: unknown } | undefined)
    : undefined;
  return first?.role === "system" || first?.role === "developer" ? textOf(first.content) : "";
}

export function titleAsk(body: unknown): TitleAsk | undefined {
  if (!body || typeof body !== "object") return undefined;
  const system = systemText(body as Record<string, unknown>).trimStart();
  return ASKS.find(([pattern]) => pattern.test(system))?.[1];
}

// The latest name the user gave the session, from the conversation.
export function renamedIn(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const record = body as { messages?: unknown; input?: unknown };
  const list = Array.isArray(record.messages) ? record.messages : record.input;
  if (!Array.isArray(list)) return undefined;
  let name: string | undefined;
  for (const item of list) {
    const message = item as { role?: unknown; content?: unknown } | null;
    if (message?.role !== "user") continue;
    for (const match of textOf(message.content).matchAll(RENAMED)) name = match[1];
  }
  return name === undefined ? undefined : clean(name);
}

// The model's words in a reply, streamed or whole, in each format.
export function replyText(raw: string): string {
  const trimmed = raw.trimStart();
  if (trimmed.startsWith("{")) {
    try {
      return wholeText(JSON.parse(trimmed));
    } catch {
      return "";
    }
  }
  let text = "";
  for (const block of raw.split(/\r?\n\r?\n/)) {
    const event = parseSseBlock(block);
    if (!event || event.data === "[DONE]") continue;
    try {
      text += deltaText(JSON.parse(event.data));
    } catch {
      continue;
    }
  }
  return text;
}

function wholeText(reply: Record<string, unknown>): string {
  if (Array.isArray(reply.content)) return textOf(reply.content);
  const choices = reply.choices as Array<{ message?: { content?: unknown } }> | undefined;
  if (Array.isArray(choices)) return textOf(choices[0]?.message?.content);
  if (typeof reply.output_text === "string") return reply.output_text;
  if (Array.isArray(reply.output))
    return reply.output.map((item) => textOf((item as { content?: unknown }).content)).join("");
  return "";
}

function deltaText(event: Record<string, unknown>): string {
  const delta = event.delta as { type?: unknown; text?: unknown; content?: unknown } | undefined;
  if (event.type === "content_block_delta" && delta?.type === "text_delta")
    return typeof delta.text === "string" ? delta.text : "";
  if (event.type === "response.output_text.delta")
    return typeof event.delta === "string" ? event.delta : "";
  const choices = event.choices as Array<{ delta?: { content?: unknown } }> | undefined;
  const content = Array.isArray(choices) ? choices[0]?.delta?.content : undefined;
  return typeof content === "string" ? content : "";
}

// The title in a reply, as each agent reads it: a field of the JSON, or the
// first line of text once any thinking is cut.
export function titleFrom(ask: TitleAsk, text: string): string | undefined {
  if (ask === "line") {
    const lines = text.replace(/<think>[\s\S]*?<\/think>/g, "").split("\n");
    return clean(lines.find((line) => line.trim() !== "") ?? "");
  }
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end < start) return undefined;
  try {
    const value = (JSON.parse(text.slice(start, end + 1)) as Record<string, unknown>)[ask];
    return typeof value === "string" ? clean(value) : undefined;
  } catch {
    return undefined;
  }
}

function clean(title: string): string | undefined {
  const line = title
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^["'`]+|["'`]+$/g, "")
    .trim();
  if (line === "") return undefined;
  const chars = [...line];
  return chars.length > TITLE_MAX ? chars.slice(0, TITLE_MAX - 1).join("") + "…" : line;
}
