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
// marker off: the second looks back far enough to find the same entry. Pi's
// Claude transport marks its last tool and last system block instead, which
// fills all four; the system marker a few blocks on stands for the tool one
// the same way. A request without that room is marked only as far as it has
// room.

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

// Where each marker sits, as the journal names it: t<i> on a tool, s<i> on a
// system block, m<i> in a message. The TTL is named only when it is not an
// hour, which is what every marker asks for when the cache behaves.
export function markerText(body: Record_): string {
  const named: string[] = [];
  const add = (list: unknown, prefix: string) => {
    if (!Array.isArray(list)) return;
    list.forEach((item, i) => {
      for (const { ttl } of markers({ messages: [item] }))
        named.push(
          `${prefix}${i}${ttl === "1h" ? "" : `:${typeof ttl === "string" ? ttl : "5m"}`}`,
        );
    });
  };
  add(body.tools, "t");
  add(body.system, "s");
  add(body.messages, "m");
  return named.join(",");
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

// The tools and system blocks with their first marker taken off, when a later
// system block carries one too: that later marker looks back far enough to
// find the first one's entry, so the first only spends a marker. The tools
// come before the system prompt, so a tool's marker can be the first.
// Undefined when there is no such pair.
function spared(body: Record_): Partial<Pick<Record_, "tools" | "system">> | undefined {
  if (!Array.isArray(body.system)) return;
  const tools = Array.isArray(body.tools) ? body.tools : [];
  const blocks = [...tools, ...body.system];
  const at = blocks.flatMap((block, i) =>
    block && typeof block === "object" && "cache_control" in block ? [i] : [],
  );
  const second = at.find((i) => i >= tools.length && i > at[0]!);
  if (second === undefined || second - at[0]! > LOOKBACK_BLOCKS) return;
  const { cache_control: _dropped, ...rest } = blocks[at[0]!] as Record_;
  const out = blocks.map((block, i) => (i === at[0] ? rest : block));
  if (at[0]! >= tools.length) return { system: out.slice(tools.length) };
  return { tools: out.slice(0, tools.length) };
}

// How many markers a request can add: the ones it has room for, and one more
// when it carries a system marker that another makes redundant.
export function markRoom(body: Record_): number {
  return MARKERS_MAX - markers(body).length + (spared(body) ? 1 : 0);
}

// A one-shot summary: no tools, and one user turn holding the whole history
// as text (Pi's generateSummary, generateBranchSummary and
// generateTurnPrefixSummary). Nothing reads its prompt again, yet the Claude
// Code transport marks it for an hour whatever Pi asks (cacheRetention
// "none"): a 221k compaction was billed as a 1h write, twice plain input.
const SUMMARY_PROMPT = /^\s*(?:<conversation>\n|# Conversation\n)/;

export function isStandaloneSummary(body: Record_): boolean {
  if (Array.isArray(body.tools) && body.tools.length > 0) return false;
  const messages = body.messages;
  // The transport may add user turns of its own (reminders), never a reply.
  if (!Array.isArray(messages) || messages.length === 0) return false;
  if (messages.some((message) => (message as Record_ | undefined)?.role !== "user")) return false;
  return messages.some((message) => {
    const content = (message as Record_).content;
    if (typeof content === "string") return SUMMARY_PROMPT.test(content);
    if (!Array.isArray(content)) return false;
    return content.some((block) => {
      const typed = block as Record_ | undefined;
      return (
        typed?.type === "text" && typeof typed.text === "string" && SUMMARY_PROMPT.test(typed.text)
      );
    });
  });
}

// The body with the markers in its messages taken off, or undefined when it
// has none. Tool and system markers stay: that prefix is shared with the
// session's other requests, so it can still be read back.
export function unmarkedMessages(body: Record_): Record_ | undefined {
  const messages = body.messages;
  if (!Array.isArray(messages) || !JSON.stringify(messages).includes('"cache_control"')) return;
  const strip = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(strip);
    if (!value || typeof value !== "object") return value;
    const out: Record_ = {};
    for (const [key, inner] of Object.entries(value))
      if (key !== "cache_control") out[key] = strip(inner);
    return out;
  };
  return { ...body, messages: messages.map(strip) };
}

// The body with a marker on the last markable message at or before each of
// `ats`, placed against the markers the request arrived with, freeing a
// redundant tool or system marker when it needs the room. A boundary that does not fit
// is left unmarked, and the body is unchanged when none does.
export function markBoundaries(body: Record_, messages: unknown[], ats: number[]): Record_ {
  const wanted = [...new Set(ats.map((at) => markable(messages, at)).filter((i) => i >= 0))];
  const free = MARKERS_MAX - markers(body).length;
  const freed = wanted.length > free ? spared(body) : undefined;
  const room = free + (freed ? 1 : 0);
  const out = messages.slice();
  for (const i of wanted.slice(0, room)) out[i] = marked(out[i], markerAt(body, i));
  return { ...body, ...freed, messages: out };
}
