// The last few requests as they were sent upstream, kept in memory for the
// dashboard's view of each session's conversation. This is the text after redaction, so it is
// the proxy's own proof of what left the machine: a real value that masking
// missed is in it, and the page shows it as it is. Nothing is written to disk,
// and a restart clears it. Off when ITHILDIN_KEEP_REQUESTS is 0.

import { setting } from "../engine/lib/names.ts";
import type { Context } from "./events.ts";

export const KEEP_DEFAULT = 20;
export const KEEP_MAX = 200;
// Longest body kept whole. A longer one is cut, and the view says so.
export const BODY_BYTES_MAX = 1024 * 1024;
// Sessions whose latest turn is kept past the limit above.
export const SESSIONS_MAX = 20;
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

// How many requests to keep, from the settings: a whole number from 0 to
// KEEP_MAX, else the default.
export function keepFromSettings(value = setting("KEEP_REQUESTS")): number {
  if (value === undefined || !/^\d+$/.test(value)) return KEEP_DEFAULT;
  return Math.min(Number(value), KEEP_MAX);
}

export class SentRequests {
  private readonly kept: Sent[] = [];
  private readonly keep: number;
  private readonly now: () => number;
  private lastId = 0;

  // No parameter property: Node's type stripping (the node checks) rejects it.
  constructor(keep: number = keepFromSettings(), now: () => number = Date.now) {
    this.keep = keep;
    this.now = now;
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
      text: cut ? body.slice(0, BODY_BYTES_MAX) : body,
    });
    if (this.kept.length > this.keep) this.drop();
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
    this.kept.splice(at < 0 ? 0 : at, 1);
  }

  // Newest first, without the text.
  list(): { enabled: boolean; keep: number; requests: SentSummary[] } {
    const requests = this.kept.map(({ text: _text, ...summary }) => summary).reverse();
    return { enabled: this.enabled, keep: this.keep, requests };
  }

  // One request's text, laid out for reading when it is whole JSON.
  text(id: number): string | undefined {
    const sent = this.kept.find((entry) => entry.id === id);
    if (!sent) return undefined;
    if (sent.cut) return sent.text;
    try {
      return JSON.stringify(JSON.parse(sent.text), null, 1);
    } catch {
      return sent.text;
    }
  }
}
