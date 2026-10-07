// The last few requests as they were sent upstream, kept in memory for the
// dashboard's view of each session's conversation. This is the text after redaction, so it is
// the proxy's own proof of what left the machine: a real value that masking
// missed is in it, and the page shows it as it is. Nothing is written to disk,
// and a restart clears it. Off when ITHILDIN_KEEP_REQUESTS is 0.

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

interface Sent extends SentSummary {
  text: string;
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
  ): void {
    if (!this.enabled) return;
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
    });
    if (this.kept.length > this.keep) this.drop();
    while (this.chars > this.charsMax && this.kept.length > 1) this.drop();
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
    this.chars -= gone!.text.length;
  }

  // Newest first, without the text.
  list(): { enabled: boolean; keep: number; requests: SentSummary[] } {
    const requests = this.kept.map(({ text: _text, ...summary }) => summary).reverse();
    return { enabled: this.enabled, keep: this.keep, requests };
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
