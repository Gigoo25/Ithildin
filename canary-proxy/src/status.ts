// What the proxy did for each conversation, for the agents' status badges.
// Claude's status line and Pi's footer render the same text, built here, so
// the two cannot drift:
//
//   CANARY ON · 12m 1f 3l 2i (+2)
//
//   m  distinct values masked: swapped for stand-ins or generalized
//   f  tool results withheld: the call read a protected file
//   l  search lines withheld: they came from a protected file
//   i  inline images withheld
//   +N added since the user's latest prompt (all kinds)
//   N req  requests scanned in this conversation: it ticks every turn, so
//          a badge reading "0" still shows the proxy is in the path
//
// Counts cover the whole conversation, since every request carries all of
// it. Zero kinds are left out; nothing hidden reads "CANARY ON · 0".
//
// Conversations are keyed by the agent's session id: Claude sends
// X-Claude-Code-Session-Id, Pi's footer adds x-canary-session (stripped before
// forwarding). Without one, the route's latest conversation stands in.
// Subagents share their parent's session id, so while one runs its counts
// show.

import type { Counts } from "./canary.ts";

export interface Status extends Counts {
  route: string;
  // Hits since the latest typed prompt.
  turn: number;
  // Requests scanned for this conversation since the proxy started.
  requests: number;
  badge: string;
}

interface Entry {
  status: Status;
  prompts: number;
  total: number;
  // The total when the latest typed prompt arrived.
  baseline: number;
}

// Bounds memory across many short sessions; the oldest are dropped first.
const MAX_SESSIONS = 256;

export function badgeText(counts: Counts, turn: number, requests = 0): string {
  const scanned = requests > 0 ? ` · ${requests} req` : "";
  const parts = [
    counts.masked && `${counts.masked}m`,
    counts.files && `${counts.files}f`,
    counts.lines && `${counts.lines}l`,
    counts.images && `${counts.images}i`,
  ].filter(Boolean);
  if (parts.length === 0) return `CANARY ON · 0${scanned}`;
  return `CANARY ON · ${parts.join(" ")}${turn > 0 ? ` (+${turn})` : ""}${scanned}`;
}

export function createStatusBook() {
  const sessions = new Map<string, Entry>();
  const routes = new Map<string, Status>();

  return {
    // prompts: typed user prompts in the request, which mark a new turn.
    record(session: string | undefined, route: string, counts: Counts, prompts: number): void {
      const total = counts.masked + counts.files + counts.lines + counts.images;
      const key = session ?? `route:${route}`;
      const previous = sessions.get(key);
      // A conversation first seen here counts from zero: all of it is new.
      const baseline = !previous ? 0 : prompts > previous.prompts ? previous.total : previous.baseline;
      // Compaction can shrink the total below the baseline.
      const turn = Math.max(0, total - baseline);
      const requests = (previous?.status.requests ?? 0) + 1;
      const status = { ...counts, route, turn, requests, badge: badgeText(counts, turn, requests) };
      sessions.delete(key);
      sessions.set(key, { status, prompts, total, baseline });
      if (sessions.size > MAX_SESSIONS) sessions.delete(sessions.keys().next().value!);
      routes.set(route, status);
    },

    lookup(session: string | undefined, route: string | undefined): Status | undefined {
      return (session ? sessions.get(session)?.status : undefined) ?? (route ? routes.get(route) : undefined);
    },
  };
}
