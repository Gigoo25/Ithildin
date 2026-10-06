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
//   private    the model has seen a secret file, or a command copied one:
//          sends are blocked the same way
//   ?Nt    tools the agent offers that act but that no guard reads
//   +pii   allow tags the user's latest prompt carries (+pii, +secrets,
//          +all, +protected, +send, +once), and +images while the session's
//          image switch is on. This is how the user sees one landed.
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
  // The conversation has seen or copied a secret file (trust.ts).
  private: boolean;
  // Tools offered that act and that no guard reads (trust.ts).
  unguarded: number;
  // Context shaping on for the latest request (shape.ts); undefined before
  // this conversation has sent one, or when the client named no session.
  shaping?: boolean | undefined;
  badge: string;
}

interface Entry {
  status: Status;
  prompts: number;
  total: number;
  // The total when the latest typed prompt arrived.
  baseline: number;
}

// What trust.ts found: the conversation's labels, and unguarded tools offered.
export interface Trust {
  untrusted?: boolean;
  private?: boolean;
  unguarded?: number;
}

// Bounds memory across many short sessions; the oldest are dropped first.
const MAX_SESSIONS = 256;

// The engine's tag set names the categories [allow-all] opens as well; the
// badge shows what the user typed.
export function allowLabels(tags: ReadonlySet<string>): string[] {
  if (tags.has("all")) return ["all", ...(tags.has("protected") ? ["protected"] : [])];
  const once = [...tags].some((tag) => tag.startsWith("once:")) ? ["once"] : [];
  return (["pii", "secret", "protected", "send", "images", "raw"] as const)
    .filter((tag) => tags.has(tag))
    .map((tag): string => (tag === "secret" ? "secrets" : tag))
    .concat(once);
}

// `shaping`: whether context shaping was on for the last request of this
// conversation. undefined when no request has been seen, so a badge never
// claims a layer is off before the proxy has shaped anything.
export function badgeText(
  counts: Counts,
  turn: number,
  requests = 0,
  allowed: readonly string[] = [],
  trust: Trust = {},
  shaping?: boolean,
): string {
  const scanned =
    (requests > 0 ? ` · ${requests} req` : "") +
    (trust.untrusted ? " · untrusted" : "") +
    (trust.private ? " · private" : "") +
    (trust.unguarded ? ` · ?${trust.unguarded}t` : "") +
    (allowed.length > 0 ? ` · ${allowed.map((tag) => `+${tag}`).join(" ")}` : "") +
    (shaping === false ? " · SHAPE OFF" : shaping === true ? " · SHAPE" : "");
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
      shaping?: boolean,
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
      const badge = badgeText(counts, turn, requests, allowed, trust, shaping);
      const status = {
        ...counts,
        route,
        turn,
        requests,
        allowed,
        untrusted: trust.untrusted ?? false,
        private: trust.private ?? false,
        unguarded: trust.unguarded ?? 0,
        shaping,
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
