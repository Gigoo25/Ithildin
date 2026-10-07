// A cache marker at the shaping cutoff, on Anthropic.
//
// Anthropic looks for a cached prefix only about 20 blocks back from a
// cache_control marker, and agents mark their system prompt and the newest
// message. So when a cutoff step changes message 420 of 500, nothing before
// it is found again: the step rewrites the whole conversation, though only
// what follows the previous cutoff changed. Measured on Claude Code sessions,
// that unchanged prefix was 60-70% of every later step's write.
//
// So the forwarded copy carries one more marker, on the last message of the
// turns the previous request had already masked. Every request between two
// steps writes or reads the same entry there, and the step itself, which
// changes only what follows it, reads it back. It is placed by the cutoff as
// of the request before this one, a function of the message list like the
// cutoff itself: on the step it is still at the old boundary, the entry the
// step can read, and it moves to the new one on the request after.
//
// Anthropic allows four markers. Claude Code uses three, so this takes the
// last; a request that already has four is left as it came.

type Record_ = Record<string, unknown>;

export const MARKERS_MAX = 4;
// Blocks a marker may not sit on: Anthropic refuses one on thinking.
const UNMARKABLE = new Set(["thinking", "redacted_thinking"]);

// Each marker in the order the provider reads them, tools, then system, then
// the messages, with the message it is in (-1 before the first).
function markers(body: Record_): Array<{ at: number; ttl: unknown }> {
  const found: Array<{ at: number; ttl: unknown }> = [];
  const walk = (value: unknown, at: number): void => {
    if (Array.isArray(value)) for (const inner of value) walk(inner, at);
    else if (value && typeof value === "object") {
      const marker = (value as Record_).cache_control;
      if (marker && typeof marker === "object") found.push({ at, ttl: (marker as Record_).ttl });
      for (const [key, inner] of Object.entries(value))
        if (key !== "cache_control") walk(inner, at);
    }
  };
  walk([body.tools, body.system], -1);
  const messages = Array.isArray(body.messages) ? body.messages : [];
  messages.forEach((message, at) => walk(message, at));
  return found;
}

// Whether a request has a marker to spare for the cutoff.
export function markRoom(body: Record_): boolean {
  return markers(body).length < MARKERS_MAX;
}

// The marker to add before message `at`. A longer TTL may not follow a
// shorter one, so it keeps the TTL of the marker before it, or of the one
// after when there is none before.
function markerAt(body: Record_, at: number): Record_ {
  const all = markers(body);
  const before = all.filter((marker) => marker.at < at).at(-1);
  const ttl = (before ?? all.find((marker) => marker.at > at))?.ttl;
  return typeof ttl === "string" ? { type: "ephemeral", ttl } : { type: "ephemeral" };
}

// The message with a marker on its last block, or undefined when it has no
// block that can carry one or already carries one. A message whose content is
// a plain string is left alone: spelling it as a block for the marker, then
// back when the marker moves on, would change bytes the cache has already read.
function marked(message: unknown, marker: Record_): Record_ | undefined {
  if (!message || typeof message !== "object") return;
  const entry = message as Record_;
  const content = entry.content;
  if (!Array.isArray(content) || JSON.stringify(content).includes('"cache_control"')) return;
  const last = content.findLastIndex((block) => {
    const typed = block as Record_ | undefined;
    if (!typed || typeof typed !== "object" || UNMARKABLE.has(String(typed.type))) return false;
    return typed.type !== "text" || (typeof typed.text === "string" && typed.text !== "");
  });
  if (last < 0) return;
  const blocks = content.slice();
  blocks[last] = { ...(blocks[last] as Record_), cache_control: marker };
  return { ...entry, content: blocks };
}

// The messages with a marker on the last message at or before `at` that can
// carry one, placed against the markers the request arrived with; the list
// unchanged when there is no room or no such message.
export function markBoundary(body: Record_, messages: unknown[], at: number): unknown[] {
  if (at >= messages.length || !markRoom(body)) return messages;
  for (let i = at; i >= 0; i--) {
    const next = marked(messages[i], markerAt(body, i));
    if (!next) continue;
    const out = messages.slice();
    out[i] = next;
    return out;
  }
  return messages;
}
