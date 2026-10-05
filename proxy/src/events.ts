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

export interface Context {
  route: string;
  // The path after the route, as the upstream gets it: already redacted.
  endpoint: string;
  session: string | undefined;
}

export interface Entry {
  id: number;
  time: number;
  type: "request" | "masked" | "swapped" | "blocked" | "refused" | "leaked";
  route: string;
  endpoint?: string;
  // First characters of the session id, enough to tell conversations apart.
  session?: string;
  kind?: string;
  rule?: string;
  standIn?: string;
  preview?: string;
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
  blocked: number;
  refused: number;
  // Distinct places a watched string was found in a request.
  leaked: number;
}

// Bounds memory over a long run; the oldest are dropped first.
export const ENTRIES_MAX = 5000;
// Stand-ins remembered, to log each value once. A value past the limit that
// comes back is logged again.
export const SEEN_MAX = 1000;
const SESSION_CHARS = 8;
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

// Personal details are named by what they are; any secret is just a secret,
// with its rule beside it.
function kindOf(event: { ruleId: string; category?: string }): string {
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
    blocked: 0,
    refused: 0,
    leaked: 0,
  };
}

type Masked = Extract<ActivityEvent, { type: "masked" }>;

export class EventLog {
  private readonly entries: Entry[] = [];
  private readonly seen = new Set<string>();
  private readonly leaks = new Set<string>();
  private readonly stats: Stats;
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
  // Returns true for a value masked for the first time.
  record(context: Context, event: ActivityEvent): boolean {
    if (event.type === "masked") {
      const kind = kindOf(event);
      if (!this.noteMasked(event, kind)) return false;
      this.add(context, {
        type: "masked",
        kind,
        rule: event.ruleId,
        standIn: event.standIn,
        preview: preview(event.value),
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
  request(context: Context, ms: number, masked: number): void {
    this.stats.requests++;
    this.stats.routes[context.route] = (this.stats.routes[context.route] ?? 0) + 1;
    this.stats.scanMsTotal += ms;
    this.stats.scanMsMax = Math.max(this.stats.scanMsMax, ms);
    this.add(context, { type: "request", ms, count: masked });
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
  snapshot(since: number): { entries: Entry[]; next: number; stats: Stats } {
    return {
      entries: this.entries.filter((entry) => entry.id > since),
      next: this.lastId,
      stats: {
        ...this.stats,
        routes: { ...this.stats.routes },
        kinds: { ...this.stats.kinds },
      },
    };
  }
}
