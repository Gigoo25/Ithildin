// Response rewriting: stand-ins in tool-call arguments and reply text get
// their real values back, so tools act on real values and the user reads
// them. The provider never sees them: the next request redacts them again.
//
// Arguments stream as JSON fragments, and a stand-in can straddle two of
// them, so each tool call's fragments are held until the call is complete,
// then released as one fragment with the swapped JSON. Reply text is held
// only to the last whitespace (stand-ins contain none), so it still streams.
// Thinking and reasoning pass untouched: thinking is signed.
//
// One rewriter per format, each fed parsed SSE events and returning the
// events to send on. Non-streaming bodies get the same swap in one pass.

import {
  type Format,
  swapText,
  swapToolArguments,
  swapToolInput,
  swapToolJson,
  swapWholeText,
} from "./redact.ts";
import { aliases } from "../engine/core.ts";
import { recordOriginal } from "./replay.ts";

export interface SseEvent {
  event?: string | undefined;
  data: string;
  // Kept for a client that resumes a stream (Last-Event-ID).
  id?: string | undefined;
  retry?: string | undefined;
}

export function parseSseBlock(block: string): SseEvent | undefined {
  let event: string | undefined;
  let id: string | undefined;
  let retry: string | undefined;
  const data: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    else if (line.startsWith("id:")) id = line.slice(3).replace(/^ /, "");
    else if (line.startsWith("retry:")) retry = line.slice(6).trim();
  }
  if (event === undefined && data.length === 0 && id === undefined && retry === undefined)
    return undefined;
  return {
    event,
    data: data.join("\n"),
    ...(id === undefined ? {} : { id }),
    ...(retry === undefined ? {} : { retry }),
  };
}

export function formatSse(event: SseEvent): string {
  const lines = event.event === undefined ? [] : [`event: ${event.event}`];
  if (event.id !== undefined) lines.push(`id: ${event.id}`);
  if (event.retry !== undefined) lines.push(`retry: ${event.retry}`);
  // An id- or retry-only block carries no data line: one would dispatch an
  // empty event.
  const bare = event.data === "" && event.event === undefined && lines.length > 0;
  if (!bare) for (const line of event.data.split("\n")) lines.push(`data: ${line}`);
  return `${lines.join("\n")}\n\n`;
}

export interface Rewriter {
  push(event: SseEvent): SseEvent[];
  // A stream cut short: held text and unfinished calls, swapped and guarded
  // like the rest, so nothing the provider sent is dropped.
  flush(): SseEvent[];
  swapped: number;
}

function json(event: SseEvent): Record<string, unknown> | undefined {
  try {
    const value = JSON.parse(event.data);
    return value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

// Streamed reply text, released up to the last whitespace. A run with no
// whitespace is released past a tail as long as the longest stand-in.
const HOLD_LIMIT = 512;
const HOLD_TAIL = 160;

class TextHold {
  private held = "";
  // The whole block as the provider sent it and as released, for replay.ts.
  private raw = "";
  private out = "";
  constructor(
    private readonly tags: Set<string>,
    private readonly count: (swapped: number) => void,
  ) {}

  push(chunk: string): string {
    this.held += chunk;
    this.raw += chunk;
    const space = Math.max(
      this.held.lastIndexOf(" "),
      this.held.lastIndexOf("\n"),
      this.held.lastIndexOf("\t"),
    );
    const cut =
      space >= 0
        ? space + 1
        : this.held.length > HOLD_LIMIT
          ? this.held.length - Math.max(HOLD_TAIL, aliases().longestStandIn())
          : 0;
    return this.release(cut);
  }

  flush(): string {
    const rest = this.release(this.held.length);
    if (this.raw !== "") recordOriginal("text", this.out, this.raw);
    return rest;
  }

  private release(cut: number): string {
    if (cut <= 0) return "";
    const out = swapText(this.held.slice(0, cut), this.tags);
    this.held = this.held.slice(cut);
    this.count(out.swapped);
    this.out += out.text;
    return out.text;
  }
}

// ── Anthropic Messages ──────────────────────────────────────────────────────

class AnthropicRewriter implements Rewriter {
  swapped = 0;
  private readonly calls = new Map<
    number,
    { name: string; id?: string | undefined; json: string }
  >();
  private readonly texts = new Map<number, TextHold>();
  constructor(private readonly tags: Set<string>) {}

  push(event: SseEvent): SseEvent[] {
    const data = json(event);
    if (!data) return [event];
    const index = typeof data.index === "number" ? data.index : -1;
    if (data.type === "content_block_start") {
      const block = data.content_block as { type?: string; name?: string; id?: string } | undefined;
      if (block?.type === "tool_use")
        this.calls.set(index, { name: String(block.name ?? ""), id: block.id, json: "" });
      if (block?.type === "text")
        this.texts.set(
          index,
          new TextHold(this.tags, (n) => {
            this.swapped += n;
          }),
        );
      return [event];
    }
    const text = this.texts.get(index);
    if (text) return this.pushText(index, text, event, data);
    const call = this.calls.get(index);
    if (!call) return [event];
    if (data.type === "content_block_delta") {
      const delta = data.delta as { type?: string; partial_json?: unknown } | undefined;
      if (delta?.type === "input_json_delta" && typeof delta.partial_json === "string") {
        call.json += delta.partial_json;
        return [];
      }
      return [event];
    }
    if (data.type === "content_block_stop") {
      this.calls.delete(index);
      const result = swapToolJson(call.name, call.json, this.tags, call.id);
      this.swapped += result.swapped;
      if (result.json === "") return [event];
      const delta: SseEvent = {
        event: "content_block_delta",
        data: JSON.stringify({
          type: "content_block_delta",
          index,
          delta: { type: "input_json_delta", partial_json: result.json },
        }),
      };
      return [delta, event];
    }
    return [event];
  }

  flush(): SseEvent[] {
    const indexes = [...this.texts.keys(), ...this.calls.keys()].sort((a, b) => a - b);
    const out = indexes.flatMap((index) => {
      const text = this.texts.get(index)?.flush();
      const call = this.calls.get(index);
      const result = call && swapToolJson(call.name, call.json, this.tags, call.id);
      this.swapped += result?.swapped ?? 0;
      const delta = text
        ? { type: "text_delta", text }
        : result?.json
          ? { type: "input_json_delta", partial_json: result.json }
          : undefined;
      if (!delta) return [];
      const data = JSON.stringify({ type: "content_block_delta", index, delta });
      return [{ event: "content_block_delta", data }];
    });
    this.texts.clear();
    this.calls.clear();
    return out;
  }

  private pushText(
    index: number,
    text: TextHold,
    event: SseEvent,
    data: Record<string, unknown>,
  ): SseEvent[] {
    if (data.type === "content_block_delta") {
      const delta = data.delta as { type?: string; text?: unknown } | undefined;
      if (delta?.type !== "text_delta" || typeof delta.text !== "string") return [event];
      delta.text = text.push(delta.text);
      return delta.text === "" ? [] : [{ ...event, data: JSON.stringify(data) }];
    }
    if (data.type === "content_block_stop") {
      this.texts.delete(index);
      const rest = text.flush();
      if (rest === "") return [event];
      return [
        {
          event: "content_block_delta",
          data: JSON.stringify({
            type: "content_block_delta",
            index,
            delta: { type: "text_delta", text: rest },
          }),
        },
        event,
      ];
    }
    return [event];
  }
}

// ── OpenAI Chat Completions ─────────────────────────────────────────────────

type ChatToolCall = {
  index?: number;
  id?: string;
  function?: { name?: string; arguments?: string };
};
type ChatChoice = {
  index?: number;
  delta?: { content?: unknown; tool_calls?: ChatToolCall[] };
  finish_reason?: unknown;
};

class ChatRewriter implements Rewriter {
  swapped = 0;
  // choice index -> tool index -> call
  private readonly calls = new Map<
    number,
    Map<number, { name: string; id?: string; args: string }>
  >();
  private readonly texts = new Map<number, TextHold>();
  private base: Record<string, unknown> = {};
  constructor(private readonly tags: Set<string>) {}

  private flushCalls(choice: number): SseEvent[] {
    const calls = this.calls.get(choice);
    this.calls.delete(choice);
    if (!calls) return [];
    const toolCalls = [...calls].map(([index, call]) => {
      const result = swapToolJson(call.name, call.args, this.tags, call.id);
      this.swapped += result.swapped;
      return { index, function: { arguments: result.json } };
    });
    return [
      {
        data: JSON.stringify({
          ...this.base,
          choices: [{ index: choice, delta: { tool_calls: toolCalls }, finish_reason: null }],
        }),
      },
    ];
  }

  // Held text and tool calls go out ahead of the end of the stream.
  flush(): SseEvent[] {
    const rest = [...this.texts].flatMap(([index, text]) => {
      const content = text.flush();
      return content === ""
        ? []
        : [
            {
              data: JSON.stringify({
                ...this.base,
                choices: [{ index, delta: { content }, finish_reason: null }],
              }),
            },
          ];
    });
    this.texts.clear();
    return [...rest, ...[...this.calls.keys()].flatMap((choice) => this.flushCalls(choice))];
  }

  // Argument fragments are held until the call finishes; the event goes on
  // with them emptied.
  private holdCalls(index: number, toolCalls: ChatToolCall[]): void {
    for (const call of toolCalls) {
      const calls = this.calls.get(index) ?? new Map();
      this.calls.set(index, calls);
      const slot = calls.get(call.index ?? 0) ?? { name: "", args: "" };
      calls.set(call.index ?? 0, slot);
      if (call.function?.name) slot.name = call.function.name;
      if (call.id) slot.id = call.id;
      if (typeof call.function?.arguments === "string") {
        slot.args += call.function.arguments;
        call.function.arguments = "";
      }
    }
  }

  private swapContent(index: number, choice: ChatChoice): void {
    let text = this.texts.get(index);
    if (!text) {
      text = new TextHold(this.tags, (n) => {
        this.swapped += n;
      });
      this.texts.set(index, text);
    }
    let content = typeof choice.delta?.content === "string" ? text.push(choice.delta.content) : "";
    if (choice.finish_reason != null) {
      content += text.flush();
      this.texts.delete(index);
    }
    choice.delta = { ...choice.delta, content };
  }

  push(event: SseEvent): SseEvent[] {
    if (event.data.trim() === "[DONE]") return [...this.flush(), event];
    const data = json(event);
    if (!data || !Array.isArray(data.choices)) return [event];
    this.base = { id: data.id, object: data.object, created: data.created, model: data.model };
    const finishing: Array<{ index: number; reason: unknown }> = [];
    for (const choice of data.choices as ChatChoice[]) {
      const index = choice.index ?? 0;
      this.holdCalls(index, choice.delta?.tool_calls ?? []);
      if (
        typeof choice.delta?.content === "string" ||
        (choice.finish_reason != null && this.texts.has(index))
      )
        this.swapContent(index, choice);
      if (choice.finish_reason != null && this.calls.has(index)) {
        finishing.push({ index, reason: choice.finish_reason });
        choice.finish_reason = null;
      }
    }
    const out: SseEvent[] = [{ ...event, data: JSON.stringify(data) }];
    for (const { index, reason } of finishing) {
      out.push(...this.flushCalls(index));
      out.push({
        data: JSON.stringify({
          ...this.base,
          choices: [{ index, delta: {}, finish_reason: reason }],
        }),
      });
    }
    return out;
  }
}

// ── OpenAI Responses (incl. Codex) ──────────────────────────────────────────

type ResponseItem = {
  type?: string;
  id?: string;
  call_id?: string;
  name?: string | undefined;
  arguments?: string;
  // custom_tool_call: freeform input.
  input?: string;
  content?: Array<{ type?: string; text?: unknown }>;
};

// Items whose tool input is swapped and guarded.
const CALL_ITEMS = new Set(["function_call", "custom_tool_call", "message"]);

class ResponsesRewriter implements Rewriter {
  swapped = 0;
  private readonly names = new Map<string, string>();
  // Custom (freeform) calls by item id, to their names.
  private readonly customs = new Map<string, string>();
  private readonly callIds = new Map<string, string>();
  private readonly done = new Map<string, string>();
  private readonly texts = new Map<string, TextHold>();
  // Where each held text sits, for its last delta if the stream is cut short.
  private readonly textAt = new Map<string, Record<string, unknown>>();
  // Arguments and freeform input streamed so far, by item id, until done.
  private readonly pending = new Map<string, string>();
  constructor(private readonly tags: Set<string>) {}

  flush(): SseEvent[] {
    const event = (type: string, fields: Record<string, unknown>): SseEvent => ({
      event: type,
      data: JSON.stringify({ type, ...fields }),
    });
    const texts = [...this.texts].flatMap(([key, text]) => {
      const delta = text.flush();
      return delta === ""
        ? []
        : [event("response.output_text.delta", { ...this.textAt.get(key), delta })];
    });
    const calls = [...this.pending].map(([itemId, raw]) => {
      const custom = this.customs.has(itemId);
      const item: ResponseItem = custom
        ? { type: "custom_tool_call", id: itemId, name: this.customs.get(itemId), input: raw }
        : { type: "function_call", id: itemId, name: this.names.get(itemId), arguments: raw };
      this.swapItem(item);
      return custom
        ? event("response.custom_tool_call_input.delta", { item_id: itemId, delta: item.input })
        : event("response.function_call_arguments.delta", {
            item_id: itemId,
            delta: item.arguments,
          });
    });
    this.texts.clear();
    this.pending.clear();
    return [...texts, ...calls];
  }

  // Final text in done and completed events. Its swaps were counted as the
  // deltas streamed, so they are not counted again.
  private swapMessage(item: ResponseItem): void {
    if (item.type !== "message" || !Array.isArray(item.content)) return;
    for (const part of item.content) {
      if (part?.type === "output_text" && typeof part.text === "string")
        part.text = swapText(part.text, this.tags).text;
    }
  }

  private swapItem(item: ResponseItem): void {
    this.swapMessage(item);
    if (item.id !== undefined) this.pending.delete(item.id);
    if (item.type === "custom_tool_call" && typeof item.input === "string") {
      this.swapCustom(item as ResponseItem & { input: string });
      return;
    }
    if (item.type !== "function_call" || typeof item.arguments !== "string") return;
    const known = item.id === undefined ? undefined : this.done.get(item.id);
    if (known !== undefined) {
      item.arguments = known;
      return;
    }
    const result = swapToolJson(
      item.name ?? "",
      item.arguments,
      this.tags,
      item.call_id ?? (item.id === undefined ? undefined : this.callIds.get(item.id)),
    );
    this.swapped += result.swapped;
    item.arguments = result.json;
    if (item.id !== undefined) this.done.set(item.id, result.json);
  }

  private swapCustom(item: ResponseItem & { input: string }): void {
    const known = item.id === undefined ? undefined : this.done.get(item.id);
    if (known !== undefined) {
      item.input = known;
      return;
    }
    const result = swapToolInput(
      item.name ?? "",
      item.input,
      this.tags,
      item.call_id ?? (item.id === undefined ? undefined : this.callIds.get(item.id)),
    );
    this.swapped += result.swapped;
    item.input = result.input;
    if (item.id !== undefined) this.done.set(item.id, result.input);
  }

  // The held freeform input, swapped, goes out as one delta ahead of done.
  private customDone(event: SseEvent, data: Record<string, unknown>, itemId: string): SseEvent[] {
    this.pending.delete(itemId);
    const item: ResponseItem & { input: string } = {
      type: "custom_tool_call",
      id: itemId,
      name: this.customs.get(itemId),
      input: String(data.input),
    };
    this.swapCustom(item);
    data.input = item.input;
    const delta = {
      type: "response.custom_tool_call_input.delta",
      item_id: itemId,
      output_index: data.output_index,
      sequence_number: data.sequence_number,
      delta: item.input,
    };
    return [
      { event: "response.custom_tool_call_input.delta", data: JSON.stringify(delta) },
      { ...event, data: JSON.stringify(data) },
    ];
  }

  // Held text goes out as one last delta ahead of the done event.
  private textDone(
    event: SseEvent,
    data: Record<string, unknown>,
    textKey: string,
    itemId: string | undefined,
  ): SseEvent[] {
    const rest = this.texts.get(textKey)?.flush() ?? "";
    this.texts.delete(textKey);
    this.textAt.delete(textKey);
    if (typeof data.text === "string") data.text = swapText(data.text, this.tags).text;
    const done = { ...event, data: JSON.stringify(data) };
    if (rest === "") return [done];
    const delta = {
      type: "response.output_text.delta",
      item_id: itemId,
      output_index: data.output_index,
      content_index: data.content_index,
      sequence_number: data.sequence_number,
      delta: rest,
    };
    return [{ event: "response.output_text.delta", data: JSON.stringify(delta) }, done];
  }

  // The held call's swapped arguments go out as one delta ahead of done.
  private argumentsDone(
    event: SseEvent,
    data: Record<string, unknown>,
    itemId: string,
    args: string,
  ): SseEvent[] {
    this.pending.delete(itemId);
    const item: ResponseItem = {
      type: "function_call",
      id: itemId,
      name: this.names.get(itemId),
      arguments: args,
    };
    this.swapItem(item);
    data.arguments = item.arguments;
    const delta = {
      type: "response.function_call_arguments.delta",
      item_id: itemId,
      output_index: data.output_index,
      sequence_number: data.sequence_number,
      delta: item.arguments,
    };
    return [
      { event: "response.function_call_arguments.delta", data: JSON.stringify(delta) },
      { ...event, data: JSON.stringify(data) },
    ];
  }

  // Reply text, held until a stand-in in it cannot be split.
  private textDelta(
    event: SseEvent,
    data: Record<string, unknown>,
    textKey: string,
    delta: string,
  ): SseEvent[] {
    let text = this.texts.get(textKey);
    if (!text) {
      text = new TextHold(this.tags, (n) => {
        this.swapped += n;
      });
      this.texts.set(textKey, text);
      const at = {
        item_id: data.item_id,
        output_index: data.output_index,
        content_index: data.content_index,
      };
      this.textAt.set(textKey, at);
    }
    data.delta = text.push(delta);
    return data.delta === "" ? [] : [{ ...event, data: JSON.stringify(data) }];
  }

  // A call's name and id, from the item that opens it.
  private added(item: ResponseItem | undefined): void {
    if (!item?.id) return;
    if (item.type === "custom_tool_call") this.customs.set(item.id, item.name ?? "");
    else if (item.type === "function_call") this.names.set(item.id, item.name ?? "");
    else return;
    if (item.call_id) this.callIds.set(item.id, item.call_id);
  }

  push(event: SseEvent): SseEvent[] {
    const data = json(event);
    if (!data) return [event];
    const type = data.type;
    if (type === "response.output_item.added") {
      this.added(data.item as ResponseItem | undefined);
      return [event];
    }
    const itemId = typeof data.item_id === "string" ? data.item_id : undefined;
    const textKey = `${itemId}:${String(data.content_index ?? 0)}`;
    if (type === "response.output_text.delta" && typeof data.delta === "string")
      return this.textDelta(event, data, textKey, data.delta);
    if (type === "response.output_text.done") return this.textDone(event, data, textKey, itemId);
    if (type === "response.content_part.done") {
      const part = data.part as { type?: string; text?: unknown } | undefined;
      if (part?.type !== "output_text" || typeof part.text !== "string") return [event];
      part.text = swapText(part.text, this.tags).text;
      return [{ ...event, data: JSON.stringify(data) }];
    }
    if (
      (type === "response.function_call_arguments.delta" && itemId && this.names.has(itemId)) ||
      (type === "response.custom_tool_call_input.delta" && itemId && this.customs.has(itemId))
    ) {
      if (typeof data.delta === "string")
        this.pending.set(itemId, (this.pending.get(itemId) ?? "") + data.delta);
      return [];
    }
    if (
      type === "response.function_call_arguments.done" &&
      itemId &&
      this.names.has(itemId) &&
      typeof data.arguments === "string"
    )
      return this.argumentsDone(event, data, itemId, data.arguments);
    if (
      type === "response.custom_tool_call_input.done" &&
      itemId &&
      this.customs.has(itemId) &&
      typeof data.input === "string"
    )
      return this.customDone(event, data, itemId);
    if (type === "response.output_item.done") {
      const item = data.item as ResponseItem | undefined;
      if (!item || !CALL_ITEMS.has(item.type ?? "")) return [event];
      this.swapItem(item);
      return [{ ...event, data: JSON.stringify(data) }];
    }
    const response = data.response as { output?: ResponseItem[] } | undefined;
    if (
      Array.isArray(response?.output) &&
      response.output.some((item) => CALL_ITEMS.has(item?.type ?? ""))
    ) {
      for (const item of response.output) if (item) this.swapItem(item);
      return [{ ...event, data: JSON.stringify(data) }];
    }
    return [event];
  }
}

export function createRewriter(format: Format, tags: Set<string>): Rewriter {
  if (format === "anthropic") return new AnthropicRewriter(tags);
  if (format === "chat") return new ChatRewriter(tags);
  return new ResponsesRewriter(tags);
}

// ── non-streaming bodies ────────────────────────────────────────────────────

export function swapResponseBody(
  format: Format,
  body: Record<string, unknown>,
  tags: Set<string>,
): number {
  let swapped = 0;
  if (format === "anthropic" && Array.isArray(body.content)) {
    for (const block of body.content as Array<{
      type?: string;
      id?: string;
      name?: string;
      input?: unknown;
      text?: unknown;
    }>) {
      if (block?.type === "text" && typeof block.text === "string") {
        const result = swapWholeText(block.text, tags);
        block.text = result.text;
        swapped += result.swapped;
      }
      if (block?.type !== "tool_use") continue;
      const result = swapToolArguments(block.name ?? "", block.input, tags, block.id);
      block.input = result.args;
      swapped += result.swapped;
    }
  } else if (format === "chat" && Array.isArray(body.choices)) {
    for (const choice of body.choices as Array<{
      message?: { content?: unknown; tool_calls?: ChatToolCall[] };
    }>) {
      if (choice.message && typeof choice.message.content === "string") {
        const result = swapWholeText(choice.message.content, tags);
        choice.message.content = result.text;
        swapped += result.swapped;
      }
      for (const call of choice.message?.tool_calls ?? []) {
        if (typeof call.function?.arguments !== "string") continue;
        const result = swapToolJson(
          call.function.name ?? "",
          call.function.arguments,
          tags,
          call.id,
        );
        call.function.arguments = result.json;
        swapped += result.swapped;
      }
    }
  } else if (format === "responses" && Array.isArray(body.output)) {
    for (const item of body.output as ResponseItem[]) {
      if (item?.type === "message" && Array.isArray(item.content)) {
        for (const part of item.content) {
          if (part?.type !== "output_text" || typeof part.text !== "string") continue;
          const result = swapWholeText(part.text, tags);
          part.text = result.text;
          swapped += result.swapped;
        }
      }
      if (item?.type === "custom_tool_call" && typeof item.input === "string") {
        const result = swapToolInput(item.name ?? "", item.input, tags, item.call_id);
        item.input = result.input;
        swapped += result.swapped;
      }
      if (item?.type !== "function_call" || typeof item.arguments !== "string") continue;
      const result = swapToolJson(item.name ?? "", item.arguments, tags, item.call_id);
      item.arguments = result.json;
      swapped += result.swapped;
    }
  }
  return swapped;
}
