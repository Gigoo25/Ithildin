// What the proxy did, kept in memory for the local dashboard (dashboard.ts).
// Nothing here is written to disk or sent anywhere: a restart clears it.
//
// The real value behind a stand-in is cut down to a preview (first and last
// characters and the length) the moment it arrives, and only the preview is
// kept. A screenshot of the dashboard shows that a value was replaced, not
// what it was.
//
// An event is one thing that happened:
//
//   request   a request was scanned: how long, and how many new values it held
//   masked    a value was replaced for the first time (later requests carry
//             the same conversation again, so repeats count in the stats only)
//   swapped   a stand-in in a reply or a tool call got its real value back
//   blocked   a guard stopped a tool call
//   refused   the proxy refused a request or a reply
//   leaked    a string on the watch list was in an outgoing request (watch.ts);
//             each place it was found shows once, though the conversation
//             goes out again every turn

import { createHash } from "node:crypto";
import { aliasKind } from "../engine/lib/aliases.ts";
import { type ActivityEvent, REPLY_TEXT } from "../engine/lib/activity.ts";
import type { Break } from "./prefix.ts";
import type { Usage } from "./usage.ts";

export interface Context {
  route: string;
  // The path after the route, as the upstream gets it: already redacted.
  endpoint: string;
  session: string | undefined;
  // "claude 2": which session of which agent (sessions.ts).
  sessionName?: string;
  // The request this happened in, counted by the handler: what it masked, its
  // leaks, the swaps in its reply and its kept text share it.
  turn?: number;
}

export interface Entry {
  id: number;
  time: number;
  type: "request" | "masked" | "swapped" | "blocked" | "refused" | "leaked";
  route: string;
  endpoint?: string;
  // First characters of the session id, enough to tell conversations apart.
  session?: string;
  sessionName?: string;
  turn?: number;
  kind?: string;
  rule?: string;
  standIn?: string;
  preview?: string;
  // A masked value's message as sent, in pieces: its own stand-in marked
  // "this", the other stand-ins in the same request marked "other".
  parts?: Part[];
  // Reply text, or the name of the tool whose call was swapped.
  where?: string;
  // A request's scan time, or a refusal's status.
  ms?: number;
  status?: number;
  // What the proxy did about a leak: it sent the request or refused it.
  action?: "flag" | "block";
  count?: number;
  text?: string;
}

export interface Part {
  text: string;
  mark?: "this" | "other";
}

export interface Stats {
  startedAt: number;
  requests: number;
  routes: Record<string, number>;
  scanMsTotal: number;
  scanMsMax: number;
  // Replacements made, repeats included, and the distinct values behind them.
  replacements: number;
  distinct: number;
  kinds: Record<string, number>;
  swappedText: number;
  swappedCalls: number;
  // What context shaping took off the wire: results and inputs stubbed,
  // results compacted, repeats noted, and the characters all saved (shape.ts).
  shapedMasked: number;
  shapedCompacted: number;
  shapedDeduped: number;
  shapedSavedChars: number;
  // What the replies said they cost (usage.ts): tokens sent fresh, read from
  // the provider's prompt cache, written to it, and generated.
  usageReplies: number;
  usageInput: number;
  usageCacheRead: number;
  usageCacheWrite: number;
  usageOutput: number;
  // Requests whose cached prefix broke (prefix.ts), by whose doing, and the
  // latest one's place.
  cacheBreaksAgent: number;
  cacheBreaksShaping: number;
  lastBreak?: string;
  blocked: number;
  refused: number;
  // Distinct places a watched string was found in a request.
  leaked: number;
}

// One session's share of the stats, for the dashboard's head: what shaping
// took off its requests and what its replies said the cache did.
export interface Tally {
  shapedMasked: number;
  shapedCompacted: number;
  shapedDeduped: number;
  shapedSavedChars: number;
  usageInput: number;
  usageCacheRead: number;
  usageCacheWrite: number;
  usageOutput: number;
  cacheBreaksAgent: number;
  cacheBreaksShaping: number;
}

// Bounds memory over a long run; the oldest are dropped first.
export const ENTRIES_MAX = 5000;
// Sessions tallied; the least recently heard from goes first.
export const TALLIES_MAX = 200;
// Stand-ins remembered, to log each value once. A value past the limit that
// comes back is logged again.
export const SEEN_MAX = 1000;
const SESSION_CHARS = 8;
// Characters of the sent request shown on each side of a stand-in.
const AROUND_CHARS = 100;
const PREVIEW_HEAD = 2;
const PREVIEW_TAIL = 1;
const PREVIEW_TAIL_FROM = 8;

// The first and last characters and the length. A short value shows only its
// first character: two characters of a four-character value are half of it.
export function preview(value: string): string {
  const chars = [...value];
  const head = chars.length < PREVIEW_TAIL_FROM ? 1 : PREVIEW_HEAD;
  const tail = chars.length < PREVIEW_TAIL_FROM ? 0 : PREVIEW_TAIL;
  const shown = chars.slice(0, head).join("") + "…" + chars.slice(chars.length - tail).join("");
  return `${shown} (${chars.length})`;
}

// A quote that ends or starts a JSON string: not escaped by a backslash.
function isStringQuote(text: string, at: number): boolean {
  let slashes = 0;
  while (text[at - 1 - slashes] === "\\") slashes++;
  return slashes % 2 === 0;
}

// JSON escapes read back as the text they stand for, when the piece allows.
function unescaped(piece: string): string {
  try {
    return JSON.parse(`"${piece}"`) as string;
  } catch {
    return piece;
  }
}

// The text either side of the stand-in's first place in what was sent, within
// the message it is in: a cut at the string's quote, else after AROUND_CHARS,
// with "…" where text goes on. Only the redacted request is read, so no real
// value can be in it.
// `others`: the request's other stand-ins, marked where they appear.
export function around(
  sent: string | undefined,
  standIn: string,
  others: string[] = [],
): { parts?: Part[] } {
  const at = sent === undefined || standIn === "" ? -1 : sent.indexOf(standIn);
  if (sent === undefined || at < 0) return {};
  const end = at + standIn.length;
  const marker = markerFor(others);
  // Read wider than shown, so a stand-in at the edge is whole before it is cut.
  const reach = AROUND_CHARS + marker.longest;
  let before = sent.slice(Math.max(0, at - reach), at);
  let after = sent.slice(end, end + reach);
  const more = { before: at > reach, after: sent.length > end + reach };
  for (let i = before.length - 1; i >= 0; i--) {
    if (before[i] === '"' && isStringQuote(sent, at - before.length + i)) {
      before = before.slice(i + 1);
      more.before = false;
      break;
    }
  }
  for (let i = 0; i < after.length; i++) {
    if (after[i] === '"' && isStringQuote(sent, end + i)) {
      after = after.slice(0, i);
      more.after = false;
      break;
    }
  }
  const left = trimParts(markOthers(unescaped(before), marker), true);
  const right = trimParts(markOthers(unescaped(after), marker), false);
  return {
    parts: [
      ...(more.before || left.cut ? [{ text: "…" }] : []),
      ...left.parts,
      { text: standIn, mark: "this" },
      ...right.parts,
      ...(more.after || right.cut ? [{ text: "…" }] : []),
    ],
  };
}

// The pieces nearest the stand-in, up to AROUND_CHARS of text: the text is cut
// where the budget ends, a marked stand-in is kept whole.
function trimParts(parts: Part[], fromEnd: boolean): { parts: Part[]; cut: boolean } {
  const ordered = fromEnd ? [...parts].reverse() : parts;
  const kept: Part[] = [];
  let left = AROUND_CHARS;
  let cut = false;
  for (const part of ordered) {
    if (left <= 0) {
      cut = true;
      break;
    }
    if (part.mark || part.text.length <= left) {
      kept.push(part);
      left -= part.text.length;
      continue;
    }
    const text = fromEnd ? part.text.slice(-left) : part.text.slice(0, left);
    kept.push({ ...part, text });
    cut = true;
    break;
  }
  return { parts: fromEnd ? kept.reverse() : kept, cut };
}

// A request's stand-ins by their first PREFIX_CHARS, longest first. A request
// can hold thousands, each with its own window to mark: searching every window
// for every stand-in was quadratic, and stalled the proxy on a large body.
const PREFIX_CHARS = 4;
interface Marker {
  byPrefix: Map<string, string[]>;
  short: string[];
  longest: number;
}
const markers = new WeakMap<string[], Marker>();

function markerFor(standIns: string[]): Marker {
  const known = markers.get(standIns);
  if (known) return known;
  const marker: Marker = { byPrefix: new Map(), short: [], longest: 0 };
  for (const standIn of new Set(standIns)) {
    if (standIn === "") continue;
    marker.longest = Math.max(marker.longest, standIn.length);
    if (standIn.length < PREFIX_CHARS) marker.short.push(standIn);
    else {
      const prefix = standIn.slice(0, PREFIX_CHARS);
      marker.byPrefix.set(prefix, [...(marker.byPrefix.get(prefix) ?? []), standIn]);
    }
  }
  for (const list of marker.byPrefix.values()) list.sort((a, b) => b.length - a.length);
  markers.set(standIns, marker);
  return marker;
}

// The longest stand-in that starts at `at`, if any.
function standInAt(text: string, at: number, marker: Marker): string | undefined {
  let found = marker.byPrefix
    .get(text.slice(at, at + PREFIX_CHARS))
    ?.find((standIn) => text.startsWith(standIn, at));
  for (const standIn of marker.short)
    if (text.startsWith(standIn, at) && standIn.length > (found?.length ?? 0)) found = standIn;
  return found;
}

// The text in pieces, with each of the stand-ins found in it marked: the
// earliest first, and the longest of those that start at the same place.
function markOthers(text: string, marker: Marker): Part[] {
  const pieces: Part[] = [];
  let from = 0;
  for (let at = 0; at < text.length; at++) {
    const found = standInAt(text, at, marker);
    if (found === undefined) continue;
    if (at > from) pieces.push({ text: text.slice(from, at) });
    pieces.push({ text: found, mark: "other" });
    from = at + found.length;
    at = from - 1;
  }
  if (from < text.length) pieces.push({ text: text.slice(from) });
  return pieces;
}

// Personal details are named by what they are; any secret is just a secret,
// with its rule beside it.
export function kindOf(event: { ruleId: string; category?: string }): string {
  return event.category === undefined || event.category === "pii"
    ? aliasKind(event.ruleId)
    : "secret";
}

function newStats(startedAt: number): Stats {
  return {
    startedAt,
    requests: 0,
    routes: {},
    scanMsTotal: 0,
    scanMsMax: 0,
    replacements: 0,
    distinct: 0,
    kinds: {},
    swappedText: 0,
    swappedCalls: 0,
    shapedMasked: 0,
    shapedCompacted: 0,
    shapedDeduped: 0,
    shapedSavedChars: 0,
    usageReplies: 0,
    usageInput: 0,
    usageCacheRead: 0,
    usageCacheWrite: 0,
    usageOutput: 0,
    cacheBreaksAgent: 0,
    cacheBreaksShaping: 0,
    blocked: 0,
    refused: 0,
    leaked: 0,
  };
}

function newTally(): Tally {
  return {
    shapedMasked: 0,
    shapedCompacted: 0,
    shapedDeduped: 0,
    shapedSavedChars: 0,
    usageInput: 0,
    usageCacheRead: 0,
    usageCacheWrite: 0,
    usageOutput: 0,
    cacheBreaksAgent: 0,
    cacheBreaksShaping: 0,
  };
}

type Masked = Extract<ActivityEvent, { type: "masked" }>;

export class EventLog {
  private readonly entries: Entry[] = [];
  private readonly seen = new Set<string>();
  private readonly leaks = new Set<string>();
  private readonly stats: Stats;
  private readonly tallies = new Map<string, Tally>();
  private readonly now: () => number;
  private lastId = 0;

  // No parameter property: Node's type stripping (the node checks) rejects it.
  constructor(now: () => number = Date.now) {
    this.now = now;
    this.stats = newStats(now());
  }

  private add(context: Context | undefined, entry: Omit<Entry, "id" | "time" | "route">): void {
    const session = context?.session?.slice(0, SESSION_CHARS);
    this.entries.push({
      ...entry,
      id: ++this.lastId,
      time: this.now(),
      route: context?.route ?? "",
      ...(context?.endpoint ? { endpoint: context.endpoint } : {}),
      ...(session ? { session } : {}),
      ...(context?.sessionName ? { sessionName: context.sessionName } : {}),
      ...(context?.turn ? { turn: context.turn } : {}),
    });
    if (this.entries.length > ENTRIES_MAX) this.entries.shift();
  }

  // Counts the replacement, and returns whether the value is a new one.
  private noteMasked(event: Masked, kind: string): boolean {
    const key = `${kind}\0${event.standIn}`;
    this.stats.replacements++;
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    if (this.seen.size > SEEN_MAX) this.seen.delete(this.seen.values().next().value!);
    this.stats.distinct++;
    this.stats.kinds[kind] = (this.stats.kinds[kind] ?? 0) + 1;
    return true;
  }

  // One thing the engine reported while a request or a reply was handled.
  // Returns true for a value masked for the first time. `sent` is the request
  // body as it went upstream, and `standIns` all it holds, for the context.
  record(context: Context, event: ActivityEvent, sent?: string, standIns?: string[]): boolean {
    if (event.type === "masked") {
      const kind = kindOf(event);
      if (!this.noteMasked(event, kind)) return false;
      this.add(context, {
        type: "masked",
        kind,
        rule: event.ruleId,
        standIn: event.standIn,
        preview: preview(event.value),
        ...around(sent, event.standIn, standIns),
      });
      return true;
    }
    if (event.type === "swapped") {
      const isText = event.tool === REPLY_TEXT;
      if (isText) this.stats.swappedText++;
      else this.stats.swappedCalls++;
      this.add(context, {
        type: "swapped",
        kind: kindOf(event),
        rule: event.ruleId,
        standIn: event.standIn,
        preview: preview(event.value),
        where: isText ? "reply text" : event.tool,
      });
      return false;
    }
    this.stats.blocked++;
    this.add(context, { type: "blocked", text: event.notice });
    return false;
  }

  // A request was scanned. `masked` is the number of new values it held.
  request(
    context: Context,
    ms: number,
    masked: number,
    shaped: { masked: number; compacted: number; deduped?: number; savedChars: number } = {
      masked: 0,
      compacted: 0,
      savedChars: 0,
    },
  ): void {
    this.stats.requests++;
    this.stats.routes[context.route] = (this.stats.routes[context.route] ?? 0) + 1;
    this.stats.scanMsTotal += ms;
    this.stats.scanMsMax = Math.max(this.stats.scanMsMax, ms);
    this.stats.shapedMasked += shaped.masked;
    this.stats.shapedCompacted += shaped.compacted;
    this.stats.shapedDeduped += shaped.deduped ?? 0;
    this.stats.shapedSavedChars += shaped.savedChars;
    const tally = this.tally(context);
    if (tally) {
      tally.shapedMasked += shaped.masked;
      tally.shapedCompacted += shaped.compacted;
      tally.shapedDeduped += shaped.deduped ?? 0;
      tally.shapedSavedChars += shaped.savedChars;
    }
    this.add(context, { type: "request", ms, count: masked });
  }

  // A reply's usage, as the provider reported it.
  usage(usage: Usage, context?: Context): void {
    this.stats.usageReplies++;
    this.stats.usageInput += usage.input;
    this.stats.usageCacheRead += usage.cacheRead;
    this.stats.usageCacheWrite += usage.cacheWrite;
    this.stats.usageOutput += usage.output;
    const tally = this.tally(context);
    if (!tally) return;
    tally.usageInput += usage.input;
    tally.usageCacheRead += usage.cacheRead;
    tally.usageCacheWrite += usage.cacheWrite;
    tally.usageOutput += usage.output;
  }

  // A request whose cached prefix broke, named by where and in which session.
  cacheBreak(context: Context, found: Break): void {
    if (found.cause === "agent") this.stats.cacheBreaksAgent++;
    else this.stats.cacheBreaksShaping++;
    const tally = this.tally(context);
    if (tally && found.cause === "agent") tally.cacheBreaksAgent++;
    else if (tally) tally.cacheBreaksShaping++;
    const where = context.sessionName ? ` in ${context.sessionName}` : "";
    this.stats.lastBreak = `${found.at}${where} (${found.cause})`;
  }

  // A watched string found in a request. Returns whether this place is new.
  // The preview is of the watched string, cut like any real value.
  leaked(
    context: Context,
    hit: { term: string; source: "watch" | "known"; where: string },
    action: "flag" | "block",
  ): boolean {
    // A digest, so the watched string itself is not kept.
    const digest = createHash("sha256").update(hit.term).digest("hex").slice(0, 16);
    const key = `${hit.source}\0${digest}\0${hit.where}`;
    if (this.leaks.has(key)) return false;
    this.leaks.add(key);
    if (this.leaks.size > SEEN_MAX) this.leaks.delete(this.leaks.values().next().value!);
    this.stats.leaked++;
    this.add(context, {
      type: "leaked",
      kind: hit.source,
      preview: preview(hit.term),
      where: hit.where,
      action,
    });
    return true;
  }

  refused(status: number, text: string): void {
    this.stats.refused++;
    this.add(undefined, { type: "refused", status, text });
  }

  // Everything after `since` (an entry id; 0 for all), with the stats.
  // A session's tally, moved to the back as the most recently heard from.
  private tally(context: Context | undefined): Tally | undefined {
    const key = context?.session?.slice(0, SESSION_CHARS);
    if (!key) return undefined;
    const tally = this.tallies.get(key) ?? newTally();
    this.tallies.delete(key);
    this.tallies.set(key, tally);
    if (this.tallies.size > TALLIES_MAX) this.tallies.delete(this.tallies.keys().next().value!);
    return tally;
  }

  snapshot(since: number): {
    entries: Entry[];
    next: number;
    stats: Stats;
    tallies: Record<string, Tally>;
  } {
    const tallies: Record<string, Tally> = {};
    for (const [key, tally] of this.tallies) tallies[key] = { ...tally };
    return {
      entries: this.entries.filter((entry) => entry.id > since),
      next: this.lastId,
      tallies,
      stats: {
        ...this.stats,
        routes: { ...this.stats.routes },
        kinds: { ...this.stats.kinds },
      },
    };
  }
}
