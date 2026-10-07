// A cache marker at the shaping cutoff, on Anthropic.
//
// Anthropic looks for a cached prefix only about 20 blocks back from a
// cache_control marker, and agents mark their system prompt and the newest
// message. So when a cutoff step changes message 420 of 500, nothing before
// it is found again: the step rewrites the whole conversation, though only
// what follows the previous cutoff changed. Measured on Claude Code sessions,
// that unchanged prefix was 60-70% of every later step's write.
//
// So the forwarded copy carries a marker on the last message of the turns
// the previous request had already masked, where a step can read back what it
// does not change. An entry is written only where a request processes the
// prompt rather than reads it, and every request between two steps reads that
// prefix from the newest message's entry, so nothing there writes one. The
// step is the request that does: it rewrites what follows the old boundary, so
// it also carries a marker on the new one, and writes the entry the next step
// reads. Both are functions of the message list, like the cutoff itself.
//
// Anthropic allows four markers and Claude Code uses three, two of them on
// adjacent system blocks. A step needs two, so it takes the first system
// marker off: the second looks back far enough to find the same entry. A
// request without that room is marked only as far as it has room.

type Record_ = Record<string, unknown>;

export const MARKERS_MAX = 4;
// How far back from a marker Anthropic looks for an earlier entry, in blocks.
const LOOKBACK_BLOCKS = 20;
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

// The index of the last message at or before `at` that can carry a marker,
// or -1 when there is none.
function markable(messages: unknown[], at: number): number {
  for (let i = Math.min(at, messages.length - 1); i >= 0; i--)
    if (marked(messages[i], { type: "ephemeral" })) return i;
  return -1;
}

// The system blocks with their first marker taken off, when a later system
// block carries one too: that later marker looks back far enough to find the
// first one's entry, so the first only spends a marker. Undefined when there
// is no such pair.
function spared(system: unknown): unknown[] | undefined {
  if (!Array.isArray(system)) return;
  const at = system.flatMap((block, i) =>
    block && typeof block === "object" && "cache_control" in block ? [i] : [],
  );
  if (at.length < 2 || at[1]! - at[0]! > LOOKBACK_BLOCKS) return;
  const { cache_control: _dropped, ...rest } = system[at[0]!] as Record_;
  return system.map((block, i) => (i === at[0] ? rest : block));
}

// How many markers a request can add: the ones it has room for, and one more
// when it carries a system marker that another makes redundant.
export function markRoom(body: Record_): number {
  return MARKERS_MAX - markers(body).length + (spared(body.system) ? 1 : 0);
}

// The body with a marker on the last markable message at or before each of
// `ats`, placed against the markers the request arrived with, freeing a
// redundant system marker when it needs the room. A boundary that does not fit
// is left unmarked, and the body is unchanged when none does.
export function markBoundaries(body: Record_, messages: unknown[], ats: number[]): Record_ {
  const wanted = [...new Set(ats.map((at) => markable(messages, at)).filter((i) => i >= 0))];
  const free = MARKERS_MAX - markers(body).length;
  const system = wanted.length > free ? spared(body.system) : undefined;
  const room = free + (system ? 1 : 0);
  const out = messages.slice();
  for (const i of wanted.slice(0, room)) out[i] = marked(out[i], markerAt(body, i));
  return { ...body, ...(system && { system }), messages: out };
}
