// What the proxy did for each conversation, for the agents' status badges.
// Claude's status line and Pi's footer render the same text, built here, so
// the two cannot drift:
//
//   ITHILDIN ON · 12m 1f 3l 2i (+2)
//
//   m  distinct values masked: swapped for stand-ins or generalized
//   f  tool results withheld: the call read a protected file
//   l  search lines withheld: they came from a protected file
//   i  inline images withheld
//   +N added since the user's latest prompt (all kinds)
//   N req  requests scanned in this conversation: it ticks every turn, so
//          a badge reading "0" still shows the proxy is in the path
//   untrusted  the conversation has read content from outside the machine,
//          so commands that send data off it are blocked (trust.ts)
//   ?Nt    tools the agent offers that act but that no guard reads
//   +pii   allow tags the user's latest prompt carries (+pii, +secrets,
//          +all, +protected, +send, +once). The proxy strips tags before
//          forwarding, so the model never sees them; this is how the user
//          sees one landed.
//
// Counts cover the whole conversation, since every request carries all of
// it. Zero kinds are left out; nothing hidden reads "ITHILDIN ON · 0".
//
// Conversations are keyed by the agent's session id: Claude sends
// X-Claude-Code-Session-Id, Pi's footer adds x-ithildin-session (stripped before
// forwarding). Without one, the route's latest conversation stands in.
// Subagents share their parent's session id, so while one runs its counts
// show.

import type { Counts } from "./redact.ts";

export interface Status extends Counts {
  route: string;
  // Hits since the latest typed prompt.
  turn: number;
  // Requests scanned for this conversation since the proxy started.
  requests: number;
  // Allow tags in force for the latest prompt, as badgeText shows them.
  allowed: string[];
  // The conversation has read outside content (trust.ts).
  untrusted: boolean;
  // Tools offered that act and that no guard reads (trust.ts).
  unguarded: number;
  badge: string;
}

interface Entry {
  status: Status;
  prompts: number;
  total: number;
  // The total when the latest typed prompt arrived.
  baseline: number;
}

// What trust.ts found: an outside read, and unguarded tools offered.
export interface Trust {
  untrusted?: boolean;
  unguarded?: number;
}

// Bounds memory across many short sessions; the oldest are dropped first.
const MAX_SESSIONS = 256;

// The engine's tag set names the categories [allow-all] opens as well; the
// badge shows what the user typed.
export function allowLabels(tags: ReadonlySet<string>): string[] {
  if (tags.has("all")) return ["all", ...(tags.has("protected") ? ["protected"] : [])];
  const once = [...tags].some((tag) => tag.startsWith("once:")) ? ["once"] : [];
  return (["pii", "secret", "protected", "send"] as const)
    .filter((tag) => tags.has(tag))
    .map((tag): string => (tag === "secret" ? "secrets" : tag))
    .concat(once);
}

export function badgeText(
  counts: Counts,
  turn: number,
  requests = 0,
  allowed: readonly string[] = [],
  trust: Trust = {},
): string {
  const scanned =
    (requests > 0 ? ` · ${requests} req` : "") +
    (trust.untrusted ? " · untrusted" : "") +
    (trust.unguarded ? ` · ?${trust.unguarded}t` : "") +
    (allowed.length > 0 ? ` · ${allowed.map((tag) => `+${tag}`).join(" ")}` : "");
  const parts = [
    counts.masked && `${counts.masked}m`,
    counts.files && `${counts.files}f`,
    counts.lines && `${counts.lines}l`,
    counts.images && `${counts.images}i`,
  ].filter(Boolean);
  if (parts.length === 0) return `ITHILDIN ON · 0${scanned}`;
  return `ITHILDIN ON · ${parts.join(" ")}${turn > 0 ? ` (+${turn})` : ""}${scanned}`;
}

export function createStatusBook() {
  const sessions = new Map<string, Entry>();
  const routes = new Map<string, Status>();

  return {
    // prompts: typed user prompts in the request, which mark a new turn.
    // tags: the request's allow tags (requestAllowTags).
    record(
      session: string | undefined,
      route: string,
      counts: Counts,
      prompts: number,
      tags: ReadonlySet<string> = new Set(),
      trust: Trust = {},
    ): void {
      const total = counts.masked + counts.files + counts.lines + counts.images;
      const key = session ?? `route:${route}`;
      const previous = sessions.get(key);
      // A conversation first seen here counts from zero: all of it is new.
      const baseline = !previous
        ? 0
        : prompts > previous.prompts
          ? previous.total
          : previous.baseline;
      // Compaction can shrink the total below the baseline.
      const turn = Math.max(0, total - baseline);
      const requests = (previous?.status.requests ?? 0) + 1;
      const allowed = allowLabels(tags);
      const badge = badgeText(counts, turn, requests, allowed, trust);
      const status = {
        ...counts,
        route,
        turn,
        requests,
        allowed,
        untrusted: trust.untrusted ?? false,
        unguarded: trust.unguarded ?? 0,
        badge,
      };
      sessions.delete(key);
      sessions.set(key, { status, prompts, total, baseline });
      if (sessions.size > MAX_SESSIONS) sessions.delete(sessions.keys().next().value!);
      routes.set(route, status);
    },

    lookup(session: string | undefined, route: string | undefined): Status | undefined {
      return (
        (session ? sessions.get(session)?.status : undefined) ??
        (route ? routes.get(route) : undefined)
      );
    },
  };
}
