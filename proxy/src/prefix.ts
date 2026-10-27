// Where a conversation's prompt-cache prefix broke, and whose doing it was.
//
// A provider caches a request's prefix and bills the next request's matching
// part at a tenth of the price, so a turn that only appends costs little. A
// turn that changes anything earlier — a timestamp in the system prompt, a
// tool list that reorders, an edited old message — pays full price, plus the
// cache write, for everything after the change. That costs more than all of
// shaping saves, and nothing in a request says it happened.
//
// So every main request is reduced to one digest per part, in the order the
// provider caches them (model, tools, system, thinking settings, then each
// message), and compared with the previous request of the same conversation.
// The first part that differs is where the prefix broke. It is checked three
// times: on the request as the agent sent it, as redaction left it, and as it
// was forwarded. A break the agent's copy already had is the agent's; one that
// appears with redaction is redaction's (a value learned late, masked in text
// that went out in clear before); one only in the forwarded copy is shaping's
// (a cutoff step). Comparing redacted copies alone counted redaction's breaks
// as the agent's.
//
// Only digests are kept, never text, and only for the most recent
// conversations.

import { createHash } from "node:crypto";
import type { Format } from "./redact.ts";

export interface Break {
  // "system", "tools", "message 12": the first part that changed.
  at: string;
  cause: "agent" | "redaction" | "shaping";
}

const CONVERSATIONS_MAX = 256;
const HEAD_PARTS = ["model", "tools", "system", "thinking"];

type Fields = Record<string, unknown>;

// A part's digest. cache_control is left out: agents move the breakpoint to
// the newest message every turn, and the provider does not count the marker
// as content. Moving it also turns string content into one text block, to
// carry the marker, and back on the next turn; the provider reads the two
// the same, so a string digests as that block.
function digest(value: unknown, seen: WeakMap<object, string>): string {
  if (value && typeof value === "object") {
    const known = seen.get(value);
    if (known !== undefined) return known;
  }
  const text = JSON.stringify(value ?? null, (key, inner) => {
    if (key === "cache_control") return undefined;
    return key === "content" && typeof inner === "string" ? [{ type: "text", text: inner }] : inner;
  });
  const hash = createHash("sha1").update(text).digest("base64").slice(0, 16);
  if (value && typeof value === "object") seen.set(value, hash);
  return hash;
}

function messages(format: Format, body: Fields): unknown[] {
  const list =
    format === "responses" ? body.input : format === "gemini" ? body.contents : body.messages;
  return Array.isArray(list) ? list : [];
}

// The parts in the order the provider caches them.
function parts(format: Format, body: Fields, seen: WeakMap<object, string>): string[] {
  const system =
    format === "responses"
      ? body.instructions
      : format === "gemini"
        ? body.systemInstruction
        : body.system;
  // A Gemini request names its model in the path, and its thinking under
  // generationConfig.
  const thinking = (body.generationConfig as Fields | undefined)?.thinkingConfig;
  const head = [
    body.model,
    body.tools,
    system,
    body.thinking ?? body.reasoning ?? body.reasoning_effort ?? thinking,
  ];
  return [...head, ...messages(format, body)].map((part) => digest(part, seen));
}

function label(index: number): string {
  return HEAD_PARTS[index] ?? `message ${index - HEAD_PARTS.length + 1}`;
}

// The first part where `now` stops extending `before`, or undefined when it
// only appended. A shorter list that matched throughout broke where it ends:
// the agent dropped or compacted its history.
function firstChange(before: string[], now: string[]): number | undefined {
  for (let index = 0; index < before.length; index++)
    if (before[index] !== now[index]) return index;
  return undefined;
}

// What a conversation is keyed by: the session, the model, and its first
// message. A subagent shares its parent's session but not its first message,
// so it is a conversation of its own rather than a break in the parent's.
function keyOf(format: Format, session: string, body: Fields): string {
  const first = messages(format, body).find(
    (item) => (item as Fields | undefined)?.role !== "system",
  );
  return `${session}\0${String(body.model)}\0${digest(first, new WeakMap())}`;
}

// The conversation a request belongs to and its messages' digests, for cache
// diagnostics (diagnose.ts) to tell a session's threads apart.
export function threadOf(
  format: Format,
  session: string,
  body: Fields,
): { key: string; digests: string[] } {
  const seen = new WeakMap<object, string>();
  const digests = messages(format, body).map((item) => digest(item, seen));
  return { key: keyOf(format, session, body), digests };
}

export class PrefixWatch {
  private readonly last = new Map<string, { raw: string[]; arrived: string[]; sent: string[] }>();
  constructor() {}

  // The break in this request's prefix, if there was one. `raw` is the body
  // as the agent sent it, `arrived` as redaction left it, `sent` as
  // forwarded; each is the same object as the one before when nothing
  // changed it. A
  // Responses request that names a previous response carries only the new
  // items, so it has no prefix to compare.
  check(
    format: Format,
    session: string,
    { raw, arrived, sent }: { raw: Fields; arrived: Fields; sent: Fields },
  ): Break | undefined {
    if (format === "responses" && arrived.previous_response_id) return;
    const key = keyOf(format, session, arrived);
    const seen = new WeakMap<object, string>();
    const now = {
      raw: parts(format, raw, seen),
      arrived: parts(format, arrived, seen),
      sent: parts(format, sent, seen),
    };
    const before = this.last.get(key);
    this.last.delete(key);
    this.last.set(key, now);
    if (this.last.size > CONVERSATIONS_MAX) this.last.delete(this.last.keys().next().value!);
    if (!before) return;
    const sentAt = firstChange(before.sent, now.sent);
    if (sentAt === undefined) return;
    const by = (list: "raw" | "arrived") => {
      const at = firstChange(before[list], now[list]);
      return at !== undefined && at <= sentAt;
    };
    const cause = by("raw") ? "agent" : by("arrived") ? "redaction" : "shaping";
    return { at: label(sentAt), cause };
  }
}
