// The thinking in a model's reply, for the dashboard to show while it streams.
// A request's body holds only the thinking of turns before it, and only when
// the client sends it back, so without this the newest turn's thinking is never
// seen. Read only: the rewriter passes thinking upstream of here untouched,
// since it is signed (streams.ts).
//
// What each format streams it as: Anthropic's thinking_delta, Responses'
// reasoning summary and reasoning text deltas, and the chat providers'
// reasoning_content or reasoning (DeepSeek, OpenRouter, opencode Go).

import type { Format } from "./redact.ts";

// Between two blocks or summary parts of one reply's thinking.
export const THINKING_BREAK = "\n\n";

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function anthropicEvent(data: Record<string, unknown>): string {
  if (data.type === "content_block_start")
    return record(data.content_block)?.type === "thinking" ? THINKING_BREAK : "";
  const delta = record(data.delta);
  return data.type === "content_block_delta" && delta?.type === "thinking_delta"
    ? text(delta.thinking)
    : "";
}

function chatEvent(data: Record<string, unknown>): string {
  const choices = Array.isArray(data.choices) ? data.choices : [];
  return choices
    .map((choice) => {
      const delta = record(record(choice)?.delta);
      return text(delta?.reasoning_content) || text(delta?.reasoning);
    })
    .join("");
}

const RESPONSES_DELTAS = new Set([
  "response.reasoning_summary_text.delta",
  "response.reasoning_text.delta",
]);

function responsesEvent(data: Record<string, unknown>): string {
  if (data.type === "response.reasoning_summary_part.added") return THINKING_BREAK;
  return RESPONSES_DELTAS.has(String(data.type)) ? text(data.delta) : "";
}

// The thinking one stream event carries, "" for none. Most events carry none,
// so one without the word is not parsed.
export function thinkingOfEvent(format: Format, data: string): string {
  if (!data.includes("thinking") && !data.includes("reasoning")) return "";
  let parsed: Record<string, unknown> | undefined;
  try {
    parsed = record(JSON.parse(data));
  } catch {
    return "";
  }
  if (!parsed) return "";
  if (format === "anthropic") return anthropicEvent(parsed);
  if (format === "chat") return chatEvent(parsed);
  return responsesEvent(parsed);
}

// The thinking in a whole (non-streamed) reply, "" for none.
export function thinkingOfBody(format: Format, body: Record<string, unknown>): string {
  const parts: string[] = [];
  if (format === "anthropic" && Array.isArray(body.content)) {
    for (const block of body.content)
      if (record(block)?.type === "thinking") parts.push(text(record(block)!.thinking));
  } else if (format === "chat" && Array.isArray(body.choices)) {
    for (const choice of body.choices) {
      const message = record(record(choice)?.message);
      parts.push(text(message?.reasoning_content) || text(message?.reasoning));
    }
  } else if (format === "responses" && Array.isArray(body.output)) {
    for (const item of body.output) {
      if (record(item)?.type !== "reasoning") continue;
      const { summary, content } = record(item)!;
      for (const part of [summary, content].flatMap((list) => (Array.isArray(list) ? list : [])))
        parts.push(text(record(part)?.text));
    }
  }
  return parts.filter((part) => part !== "").join(THINKING_BREAK);
}
