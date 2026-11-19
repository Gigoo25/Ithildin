// Two ways a conversation pays to write its whole prompt to the cache again
// that no prefix break names (prefix.ts compares one request with the one
// before it, and both of these send the same prefix as before or the
// difference is the user's own doing), so each gets a warning line of its own
// in the journal, saying what it cost and how to avoid it.
//
// A cold start: the session was quiet longer than its cache entries live. An
// hour when every marker asks for one (mark.ts), five minutes otherwise. Two
// on 11-19 cost 190K tokens; nothing in the proxy caused them, but a pause
// is the one cost the user can see coming.
//
// A one-time [allow-all]: that prompt sends everything as it was, and the next
// one masks it again (redact.ts, "tags per turn"), so the prefix is rewritten
// twice, once each way, from the first masked value. One on 11-19 cost 126K.
// [allow-all:session] does it once; a narrower tag may not do it at all.

import type { Usage } from "./usage.ts";

// The longest a cache entry lives, by the shortest TTL a marker asked for.
const HOUR_MS = 60 * 60 * 1000;
const SHORT_MS = 5 * 60 * 1000;
// A write smaller than this is a turn's own new text, not the prompt again.
export const COLD_WRITE_MIN = 15_000;
const SESSIONS_MAX = 256;

// When each session's last reply came back, and the TTL its markers asked for.
export class Warmth {
  private readonly last = new Map<string, { at: number; ttl: number }>();
  // Each session's typed prompt last warned about: an agent's loop sends one
  // prompt's tag with every request it makes.
  private readonly warned = new Map<string, number>();
  constructor(private readonly now: () => number = Date.now) {}

  // Whether prompt `prompt` of `session` is not yet warned about, marking it.
  firstOf(session: string, prompt: number): boolean {
    if (this.warned.get(session) === prompt) return false;
    this.warned.delete(session);
    this.warned.set(session, prompt);
    if (this.warned.size > SESSIONS_MAX) this.warned.delete(this.warned.keys().next().value!);
    return true;
  }

  // When `session` was last heard from, before this request, and how long its
  // entries live; undefined for a session not seen since the proxy started.
  // Read before the request goes up, since its reply moves it.
  idle(session: string): { ms: number; ttl: number } | undefined {
    const seen = this.last.get(session);
    return seen && { ms: this.now() - seen.at, ttl: seen.ttl };
  }

  // A reply came back for `session`, which asked for `markers` (the journal's
  // marker text, mark.ts: a ":5m" names a short one).
  heard(session: string, markers: string): void {
    this.last.delete(session);
    this.last.set(session, { at: this.now(), ttl: markers.includes(":5m") ? SHORT_MS : HOUR_MS });
    if (this.last.size > SESSIONS_MAX) this.last.delete(this.last.keys().next().value!);
  }
}

// The journal's warning for a reply that wrote its prompt again after a
// pause longer than the cache keeps it, or "" when it was not one.
export function coldWarning(idle: { ms: number; ttl: number } | undefined, usage: Usage): string {
  if (!idle || idle.ms <= idle.ttl || usage.cacheWrite < COLD_WRITE_MIN) return "";
  if (usage.cacheRead > usage.cacheWrite) return "";
  const minutes = Math.round(idle.ms / 60_000);
  const lived = idle.ttl === HOUR_MS ? "an hour" : "5 minutes";
  return (
    `warning: cold start: ${minutes} min since this session's last reply, longer than its ` +
    `cache lives (${lived}); its prompt was written again (${usage.cacheWrite} tokens)`
  );
}

// The journal's warning for a prompt carrying a one-time [allow-all], or ""
// when it carried none. `tags` are the request's, `grants` the session's
// standing ones (redact.ts): [allow-all:session] is not a one-time tag.
export function allowAllWarning(tags: ReadonlySet<string>, grants: ReadonlySet<string>): string {
  if (!tags.has("all") || grants.has("all")) return "";
  return (
    "warning: one-time [allow-all]: this prompt is sent unmasked and the next masked again, " +
    "so the cached prompt is written twice; [allow-all:session] writes it once, " +
    "a narrower tag ([allow-secrets], [allow-pii]) may not at all"
  );
}
