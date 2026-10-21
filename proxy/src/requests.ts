// The last few requests as they were sent upstream, kept in memory for the
// dashboard's view of each session's conversation. This is the text after redaction, so it is
// the proxy's own proof of what left the machine: a real value that masking
// missed is in it, and the page shows it as it is. Nothing is written to disk,
// and a restart clears it. Off when ITHILDIN_KEEP_REQUESTS is 0.

import { createHash } from "node:crypto";
import { setting } from "../engine/lib/names.ts";
import type { Context } from "./events.ts";

export const KEEP_DEFAULT = 20;
export const KEEP_MAX = 200;
// Longest body kept whole, in characters (UTF-16 code units, what a string's
// length is). A longer one is cut so it still reads, and the view says so.
export const BODY_BYTES_MAX = 8 * 1024 * 1024;
// Sessions whose latest turn is kept past the limit above.
export const SESSIONS_MAX = 20;
// All kept text together, in characters (UTF-16, so about twice that in
// bytes). KEEP_MAX bodies at BODY_BYTES_MAX would be gigabytes; past this the
// oldest go first, whatever the count allows.
export const KEPT_CHARS_MAX = 128 * 1024 * 1024;
// Longest reply thinking kept for one request, in characters. A reply thinks
// far less than this; it bounds one that runs on.
export const THINKING_CHARS_MAX = 1024 * 1024;
const SESSION_CHARS = 8;

export interface SentSummary {
  id: number;
  time: number;
  route: string;
  endpoint: string;
  session?: string;
  sessionName?: string;
  // The handler's count of the request, as on its events (events.ts).
  turn?: number;
  // A turn of the conversation, not a side request (server.ts isMainRequest).
  main: boolean;
  // Characters in the body as sent, and whether the view holds all of them.
  size: number;
  cut: boolean;
}

// A value masked in a request, as the dashboard marks it in that request.
// The event feed holds only the newest few thousand of these across every
// session, which a long session's values alone outrun.
export interface MaskedValue {
  standIn: string;
  kind: string;
  rule: string;
  preview: string;
}
// Masked values kept per request: far past any real session's, and a bound
// on what a request made of nothing else can hold.
export const MASKED_PER_REQUEST_MAX = 100_000;

// The thinking of a request's reply as it arrives, and whether the reply is
// over: the page reads it again until it is.
export interface ReplyThinking {
  text: string;
  done: boolean;
}

// An earlier turn's thinking, from the reply the proxy kept for the request
// that turn answered: `at` is the turn's place in the later request's list.
export interface EarlierThinking {
  at: number;
  text: string;
}

// Where a request's conversation ends: how many entries, and a digest of the
// last. A later request whose entry at that place matches it carries this
// request's reply as the next turn.
interface Ends {
  count: number;
  last: string;
}

interface Sent extends SentSummary {
  text: string;
  masked: MaskedValue[];
  reply: ReplyThinking;
  // Worked out when first asked, null when the body has no conversation.
  ends?: Ends | null;
}

// A request's conversation: Messages and Chat `messages`, Responses `input`,
// Gemini `contents`. Undefined for a body that is not one.
function conversation(text: string): unknown[] | undefined {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!body || typeof body !== "object") return undefined;
  const { messages, input, contents } = body as Record<string, unknown>;
  const list = messages ?? input ?? contents;
  return Array.isArray(list) ? list : undefined;
}

// One entry of a conversation, as a digest. The agent moves its cache marker
// to the newest entry each request, so the marker is left out.
function entryDigest(entry: unknown): string {
  const text = JSON.stringify(entry, (key, value) => (key === "cache_control" ? undefined : value));
  return createHash("sha1")
    .update(text ?? "")
    .digest("base64");
}

const CLOSERS: Record<string, string> = { "{": "}", "[": "]" };
// What each closing bracket must have been opened by.
const OPENERS: Record<string, string> = { "}": "{", "]": "[" };

// Where the number or literal at `from` ends, or past the cut when it runs on.
function tokenEnd(head: string, from: number): number {
  let at = from;
  while (at < head.length && /[-+0-9a-zA-Z.]/.test(head[at]!)) at++;
  return at;
}

interface Candidate {
  // How much of the cut head to keep.
  at: number;
  // The brackets to close behind it, deepest first.
  close: string;
}

// Where the string opened by the quote at `from` ends in `text`, past the cut
// when the cut runs into it. A backslash escapes the character after it, and a
// quote inside the string does not close it.
function stringEnd(text: string, from: number): number {
  for (let at = from + 1; at < text.length; at++) {
    if (text[at] === "\\") at++;
    else if (text[at] === '"') return at + 1;
  }
  return text.length + 1;
}

// Every place the text so far could be cut so it still parses: after a bracket,
// before a comma that follows a whole value, and at the cut itself. A token is
// read from the whole body, so a value the cut lands at the end of is still
// known to be whole; one it lands inside is left out, since half a number
// parses as a different number. Null when the text is not JSON at all.
function candidates(head: string, text: string, limit: number): Candidate[] | null {
  const stack: string[] = [];
  const found: Candidate[] = [];
  const closers = () =>
    stack
      .slice()
      .reverse()
      .map((what) => CLOSERS[what]!)
      .join("");
  const cut = (at: number) => found.push({ at, close: closers() });
  // Whether the text since the last cut is a whole value, so that cutting
  // before the next comma leaves a value and not a dangling colon or bracket.
  let wholeValue = true;
  let midValue = false;
  // Where the string that is open began, or -1: a cut inside one keeps the text
  // it read, which is the whole of a long tool output, rather than dropping the
  // message the tool output is in.
  let stringFrom = -1;
  for (let at = 0; at < head.length; at++) {
    const char = head[at]!;
    if (char === '"') {
      const end = stringEnd(text, at);
      if (end > limit) {
        stringFrom = at;
        break;
      }
      at = end - 1;
      wholeValue = true;
    } else if (char === "{" || char === "[") {
      stack.push(char);
      cut(at + 1);
      // An array element may be cut right after its bracket, unlike a key.
      wholeValue = char === "[";
    } else if (char === "}" || char === "]") {
      const open = stack.pop();
      cut(at + 1);
      if (open !== OPENERS[char!]) return null;
      wholeValue = true;
    } else if (char === ",") {
      // Before the comma, and only where a value before it is whole: cutting
      // mid-value would leave the colon and the half-value behind.
      if (wholeValue) cut(at);
      wholeValue = false;
    } else if (char === ":") {
      // A colon ends a key; the value after it is what may be cut.
      wholeValue = false;
    } else if (/-|[0-9tfn]/.test(char)) {
      const end = tokenEnd(text, at);
      if (end > limit) {
        midValue = true;
        break;
      }
      at = end - 1;
      wholeValue = true;
    }
  }
  // The cut itself ends the text, so it is a candidate too, once the string it
  // may be inside is closed. A backslash at the cut would escape that closing
  // quote, so a cut there closes nothing and keeps the text before the string.
  if (stringFrom >= 0 && head[head.length - 1] !== "\\")
    found.push({ at: head.length, close: '"' + closers() });
  else if (stringFrom < 0 && !midValue && wholeValue) cut(head.length);
  return found;
}

// A body cut at `limit`, made whole again. The conversation view needs JSON it
// can parse, so the cut lands where the text so far is whole values and the
// brackets left open close behind it, and the partial tail goes. Text that is
// not an object or an array is cut plain, as before.
export function clampToJson(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const head = text.slice(0, limit);
  if (head[0] !== "{" && head[0] !== "[") return head;
  const found = candidates(head, text, limit);
  // The last candidate keeps the most of the body. The ones before it are the
  // way back when the cut ran into a number or a literal and left a dangling
  // colon, which no rule about brackets can see.
  for (let at = (found?.length ?? 0) - 1; found && at >= 0; at--) {
    const whole = head.slice(0, found[at]!.at) + found[at]!.close;
    try {
      JSON.parse(whole);
      return whole;
    } catch {
      continue;
    }
  }
  return head;
}

// How many requests to keep, from the settings: a whole number from 0 to
// KEEP_MAX, else the default.
export function keepFromSettings(value = setting("KEEP_REQUESTS")): number {
  if (value === undefined || !/^\d+$/.test(value)) return KEEP_DEFAULT;
  return Math.min(Number(value), KEEP_MAX);
}

export class SentRequests {
  private readonly kept: Sent[] = [];
  private readonly keep: number;
  private readonly charsMax: number;
  private chars = 0;
  private readonly now: () => number;
  private lastId = 0;

  // No parameter property: Node's type stripping (the node checks) rejects it.
  constructor(
    keep: number = keepFromSettings(),
    now: () => number = Date.now,
    charsMax: number = KEPT_CHARS_MAX,
  ) {
    this.keep = keep;
    this.now = now;
    this.charsMax = charsMax;
  }

  get enabled(): boolean {
    return this.keep > 0;
  }

  record(
    { route, endpoint, session, sessionName, turn }: Context,
    body: string,
    main = true,
    masked: MaskedValue[] = [],
  ): number | undefined {
    if (!this.enabled) return undefined;
    const cut = body.length > BODY_BYTES_MAX;
    const text = cut ? clampToJson(body, BODY_BYTES_MAX) : body;
    this.chars += text.length;
    this.kept.push({
      id: ++this.lastId,
      time: this.now(),
      route,
      endpoint,
      ...(session ? { session: session.slice(0, SESSION_CHARS) } : {}),
      ...(sessionName ? { sessionName } : {}),
      ...(turn ? { turn } : {}),
      main,
      size: body.length,
      cut,
      text,
      masked: masked.slice(0, MASKED_PER_REQUEST_MAX),
      reply: { text: "", done: false },
    });
    if (this.kept.length > this.keep) this.drop();
    while (this.chars > this.charsMax && this.kept.length > 1) this.drop();
    return this.lastId;
  }

  // More of a request's reply thinking. A break between two blocks is kept
  // only once there is thinking before it. Past THINKING_CHARS_MAX the rest
  // is dropped.
  think(id: number, more: string): void {
    const reply = this.find(id)?.reply;
    if (!reply || reply.done || more === "" || (reply.text === "" && more.trim() === "")) return;
    const room = THINKING_CHARS_MAX - reply.text.length;
    const kept = more.length > room ? more.slice(0, Math.max(room, 0)) : more;
    reply.text += kept;
    this.chars += kept.length;
  }

  // The reply is over, however it ended.
  ended(id: number): void {
    const reply = this.find(id)?.reply;
    if (reply) reply.done = true;
  }

  // A request's reply thinking so far.
  thinking(id: number): ReplyThinking | undefined {
    return this.find(id)?.reply;
  }

  // The thinking of the turns in a request's conversation that came from
  // replies kept here, which the agent often does not send back. Each is the
  // reply of the newest earlier request in the session whose conversation
  // ended right where that turn begins. Undefined for no such request.
  earlier(id: number): EarlierThinking[] | undefined {
    const sent = this.find(id);
    if (!sent) return undefined;
    const list = conversation(sent.text);
    if (!list) return [];
    const found = new Map<number, string>();
    for (const before of this.kept) {
      if (before.id >= id || before.session !== sent.session || before.reply.text === "") continue;
      const ends = this.endsOf(before);
      if (!ends || ends.count >= list.length) continue;
      if (entryDigest(list[ends.count - 1]) === ends.last) found.set(ends.count, before.reply.text);
    }
    return [...found].map(([at, text]) => ({ at, text })).sort((a, b) => a.at - b.at);
  }

  private endsOf(sent: Sent): Ends | null {
    if (sent.ends === undefined) {
      const list = conversation(sent.text);
      sent.ends = list?.length ? { count: list.length, last: entryDigest(list.at(-1)) } : null;
    }
    return sent.ends;
  }

  // Newest last, and the one asked for is almost always among the newest.
  private find(id: number): Sent | undefined {
    for (let i = this.kept.length - 1; i >= 0; i--)
      if (this.kept[i]!.id === id) return this.kept[i];
    return undefined;
  }

  // The oldest request, unless it is its session's latest turn: each session
  // keeps one to show, however busy the others are, up to SESSIONS_MAX.
  private drop(): void {
    const latest = new Set<Sent>();
    const seen = new Set<string>();
    for (let i = this.kept.length - 1; i >= 0; i--) {
      const sent = this.kept[i]!;
      if (!sent.main || !sent.session || seen.has(sent.session)) continue;
      seen.add(sent.session);
      if (seen.size <= SESSIONS_MAX) latest.add(sent);
    }
    const at = this.kept.findIndex((sent) => !latest.has(sent));
    const [gone] = this.kept.splice(at < 0 ? 0 : at, 1);
    this.chars -= gone!.text.length + gone!.reply.text.length;
  }

  // Newest first, without the text.
  list(): { enabled: boolean; keep: number; requests: SentSummary[] } {
    const requests = this.kept
      .map(({ text: _text, masked: _masked, reply: _reply, ...summary }) => summary)
      .reverse();
    return { enabled: this.enabled, keep: this.keep, requests };
  }

  // The values masked in one request, for the dashboard to mark.
  masked(id: number): MaskedValue[] | undefined {
    return this.kept.find((entry) => entry.id === id)?.masked;
  }

  // One request's text, laid out for reading when it is JSON. A cut body is
  // clamped so it still parses, so it reads the same way, less its last turn.
  text(id: number): string | undefined {
    const sent = this.kept.find((entry) => entry.id === id);
    if (!sent) return undefined;
    try {
      return JSON.stringify(JSON.parse(sent.text), null, 1);
    } catch {
      return sent.text;
    }
  }
}
