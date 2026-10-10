// Cache diagnostics: Anthropic's answer to why a request missed the cache.
//
// A request that names an earlier response by its id, under the beta header,
// comes back with `diagnostics.cache_miss_reason` when it read less than that
// earlier request left cached: where the two diverged, or that the earlier one
// was not found. The proxy asks on every main Claude request, so a shaping step
// that misses says why in its journal line; on a step it names the session's
// last step, which is the request that wrote the entry the step should read.
//
// Only Anthropic's own API knows the header. The proxy adds the field after
// redaction, so the id goes up as it came down, and drops the whole thing for
// good the first time Anthropic refuses it.
//
// The same requests carry the thinking-binding beta, without its field: a
// thinking block is bound to the conversation before it, and masking edits
// that conversation. With the header alone the model still sees every block,
// and the reply lists each one whose conversation changed under
// `input_transformations`, which the journal names as thinking=. That is the
// evidence for whether a step's masking is what makes it miss (CACHING.md).

import { setting } from "../engine/lib/names.ts";
import type { Miss } from "./misses.ts";

export const BINDING_BETA = "thinking-binding-controls-2026-08-01";

export const DIAGNOSE_BETA = "cache-diagnosis-2026-04-07";
// Sessions remembered, newest kept: a restart forgets them, which costs only
// the next request's answer.
export const DIAGNOSED_MAX = 200;

// What a reply said: its id, why it missed the cache when it did, and which
// thinking blocks no longer matched their conversation.
export interface Heard {
  id?: string;
  reason?: string;
  thinking?: string;
}

type Fields = Record<string, unknown>;

function fields(value: unknown): Fields | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Fields)
    : undefined;
}

// The id and miss reason in a reply body or one stream event, wherever they
// sit: on the message itself, or on a stream's message_start or delta.
export function heardIn(value: unknown): Heard {
  const outer = fields(value);
  if (!outer) return {};
  const message = fields(outer.message) ?? outer;
  const id =
    typeof message.id === "string" && message.id.startsWith("msg_") ? message.id : undefined;
  const found =
    fields(message.diagnostics) ??
    fields(outer.diagnostics) ??
    fields(fields(outer.delta)?.diagnostics);
  const miss = fields(found?.cache_miss_reason);
  // A sibling of usage: on the message, or on a stream's delta event.
  const changed =
    message.input_transformations ??
    outer.input_transformations ??
    fields(outer.delta)?.input_transformations;
  const thinking = Array.isArray(changed) ? thinkingText(changed) : undefined;
  return {
    ...(id ? { id } : {}),
    ...(miss ? { reason: reasonText(miss) } : {}),
    ...(thinking ? { thinking } : {}),
  };
}

// How the journal names the thinking blocks a reply listed: per kind, how many
// and where the first one sits, e.g. mismatch_allowed:3@messages.32.content.1.
function thinkingText(entries: unknown[]): string | undefined {
  const kinds = new Map<string, { count: number; first: string }>();
  for (const entry of entries) {
    const found = fields(entry);
    if (!found) continue;
    const kind = typeof found.type === "string" ? found.type.replace(/^thinking_/, "") : "unknown";
    const seen = kinds.get(kind);
    if (seen) seen.count++;
    else kinds.set(kind, { count: 1, first: typeof found.path === "string" ? found.path : "?" });
  }
  const named = [...kinds].map(([kind, { count, first }]) => `${kind}:${count}@${first}`);
  return named.length > 0 ? named.join(",") : undefined;
}

// How the journal names a miss: its type, then what else it said, short.
function reasonText(miss: Fields): string {
  const { type, ...rest } = miss;
  const named = typeof type === "string" ? type : "unknown";
  const more = Object.keys(rest).length > 0 ? JSON.stringify(rest).slice(0, 200) : "";
  return more ? `${named}${more}` : named;
}

// ITHILDIN_DIAGNOSE=off asks nothing.
export function diagnosingOn(env: Record<string, string | undefined> = process.env): boolean {
  const value = setting("DIAGNOSE", env)?.trim().toLowerCase();
  return value !== "off" && value !== "false" && value !== "0";
}

// Conversation keys whose bodies are kept, newest kept: a body can run to
// megabytes, so far fewer than the ids.
export const BODIES_MAX = 16;

// A miss to keep: the request that missed, and the one it was compared with.
export type MissSaver = (miss: Miss) => void;

// Which conversation a request belongs to, and one digest per message as sent
// (prefix.ts), markers aside. A session's subagents share its id, and its forks
// its first message too, and they run side by side: compared with the
// session's last reply, nearly every request named another conversation's,
// and the kept misses were pairs of unrelated requests (CACHING.md). So the
// key separates subagents, and among the replies under one key a request is
// compared with the one whose messages it carries furthest: its own thread's.
export interface Thread {
  key: string;
  digests: string[];
  // The reply it was asked against, once asked; null when there was none.
  against?: Reply | null;
}

interface Reply {
  id: string;
  digests: string[];
  // As sent upstream; dropped for all but the newest BODIES_MAX keys.
  body?: string | undefined;
}

// Replies kept per key, and steps apart from them: enough for a thread and a
// few forks beside it. A step is compared with a step, which may be long ago.
export const REPLIES_MAX = 4;

function thread(of: Thread | string): Thread {
  return typeof of === "string" ? { key: of, digests: [] } : of;
}

function shared(a: string[], b: string[]): number {
  let at = 0;
  while (at < a.length && at < b.length && a[at] === b[at]) at++;
  return at;
}

function keepNewest(list: Reply[], reply: Reply): Reply[] {
  return [...list, reply].slice(-REPLIES_MAX);
}

// The replies heard per conversation key, and per key the steps among them.
export class Diagnoses {
  private known = new Map<string, { replies: Reply[]; steps: Reply[] }>();
  // Set for good when Anthropic refuses the field or the header.
  off = false;

  constructor(private readonly save?: MissSaver) {}

  // The earlier reply a request is compared with: of its key's replies (its
  // steps, on a step, when there are any), the one it shares most messages
  // with, the newest of those.
  private closest(of: Thread, step: boolean): Reply | null {
    const seen = this.known.get(of.key);
    if (!seen) return null;
    const pool = step && seen.steps.length > 0 ? seen.steps : seen.replies;
    let best: Reply | null = null;
    let most = -1;
    for (const reply of pool) {
      const count = shared(reply.digests, of.digests);
      if (count >= most) [best, most] = [reply, count];
    }
    return best;
  }

  // The body to send instead, asking about the cache against the closest
  // earlier reply of the request's conversation (closest), with the beta
  // header added; or undefined to send the body as it is.
  ask(of: Thread | string, step: boolean, body: string, headers: Headers): string | undefined {
    if (this.off || !body.startsWith("{") || body.slice(1).trimStart().startsWith("}")) return;
    const asked = thread(of);
    asked.against = this.closest(asked, step);
    const previous = asked.against?.id ?? null;
    // Added to what the agent sent, never in place of it: dropping its own
    // betas would change how the request is served.
    const betas = (headers.get("anthropic-beta") ?? "").split(",").map((beta) => beta.trim());
    const added = [DIAGNOSE_BETA, BINDING_BETA].filter((beta) => !betas.includes(beta));
    headers.set("anthropic-beta", [...betas.filter(Boolean), ...added].join(","));
    return `{"diagnostics":${JSON.stringify({ previous_message_id: previous })},${body.slice(1)}`;
  }

  // Remembers what a reply said, and returns the journal's words for a miss.
  // `body` is the request as sent: on a miss where Anthropic names what
  // changed, it is saved beside the body it was compared with (misses.ts).
  // The session in a kept miss is the key's first part (server.ts).
  answer(of: Thread | string, step: boolean, heard: Heard, body?: string): string {
    const asked = thread(of);
    if (heard.reason?.includes("_changed") && body !== undefined) {
      const previous = (asked.against === undefined ? this.closest(asked, step) : asked.against)
        ?.body;
      const session = asked.key.split("\0")[0]!;
      if (previous !== undefined)
        this.save?.({ session, step, reason: heard.reason, previous, missed: body });
    }
    if (heard.id) this.remember(asked, step, { id: heard.id, digests: asked.digests, body });
    const thinking = heard.thinking ? ` thinking=${heard.thinking}` : "";
    return (heard.reason ? ` cachemiss=${heard.reason}` : "") + thinking;
  }

  private remember(of: Thread, step: boolean, reply: Reply): void {
    const seen = this.known.get(of.key) ?? { replies: [], steps: [] };
    this.known.delete(of.key);
    this.known.set(of.key, {
      replies: keepNewest(seen.replies, reply),
      steps: step ? keepNewest(seen.steps, reply) : seen.steps,
    });
    while (this.known.size > DIAGNOSED_MAX) this.known.delete(this.known.keys().next().value!);
    // A body can run to megabytes: only the newest keys keep theirs.
    let older = this.known.size - BODIES_MAX;
    for (const kept of this.known.values()) {
      if (older-- <= 0) break;
      for (const old of [...kept.replies, ...kept.steps]) old.body = undefined;
    }
  }

  // Whether a refused reply was about the field or either header: then the
  // proxy stops asking, and the request goes again without them.
  refused(status: number, text: string): boolean {
    if (status !== 400 || !/diagnostics|cache-diagnos|thinking-binding/i.test(text)) return false;
    this.off = true;
    return true;
  }
}
