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

// Sessions whose last bodies are kept, newest kept: a body can run to
// megabytes, so far fewer than the ids.
export const BODIES_MAX = 16;

// A miss to keep: the request that missed, and the one it was compared with.
export type MissSaver = (miss: Miss) => void;

// The last response id per session, and per session the last step's.
export class Diagnoses {
  private last = new Map<string, { id?: string; step?: string | undefined }>();
  // The bodies those ids answered, sent as they went upstream.
  private bodies = new Map<string, { last?: string; step?: string | undefined }>();
  // Set for good when Anthropic refuses the field or the header.
  off = false;

  constructor(private readonly save?: MissSaver) {}

  // The body to send instead, asking about the cache against the session's
  // last request (its last step, on a step), with the beta header added; or
  // undefined to send the body as it is.
  ask(session: string, step: boolean, body: string, headers: Headers): string | undefined {
    if (this.off || !body.startsWith("{") || body.slice(1).trimStart().startsWith("}")) return;
    const seen = this.last.get(session);
    const previous = (step ? seen?.step : undefined) ?? seen?.id ?? null;
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
  answer(session: string, step: boolean, heard: Heard, body?: string): string {
    if (heard.reason?.includes("_changed") && body !== undefined) {
      const kept = this.bodies.get(session);
      const previous = (step ? kept?.step : undefined) ?? kept?.last;
      if (previous !== undefined)
        this.save?.({ session, step, reason: heard.reason, previous, missed: body });
    }
    if (heard.id) {
      const seen = this.last.get(session) ?? {};
      this.last.delete(session);
      this.last.set(session, { id: heard.id, step: step ? heard.id : seen.step });
      while (this.last.size > DIAGNOSED_MAX) this.last.delete(this.last.keys().next().value!);
      if (body !== undefined) this.keepBody(session, step, body);
    }
    const thinking = heard.thinking ? ` thinking=${heard.thinking}` : "";
    return (heard.reason ? ` cachemiss=${heard.reason}` : "") + thinking;
  }

  private keepBody(session: string, step: boolean, body: string): void {
    const seen = this.bodies.get(session) ?? {};
    this.bodies.delete(session);
    this.bodies.set(session, { last: body, step: step ? body : seen.step });
    while (this.bodies.size > BODIES_MAX) this.bodies.delete(this.bodies.keys().next().value!);
  }

  // Whether a refused reply was about the field or either header: then the
  // proxy stops asking, and the request goes again without them.
  refused(status: number, text: string): boolean {
    if (status !== 400 || !/diagnostics|cache-diagnos|thinking-binding/i.test(text)) return false;
    this.off = true;
    return true;
  }
}
