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

import { setting } from "../engine/lib/names.ts";
import type { Miss } from "./misses.ts";

export const DIAGNOSE_BETA = "cache-diagnosis-2026-04-07";
// Sessions remembered, newest kept: a restart forgets them, which costs only
// the next request's answer.
export const DIAGNOSED_MAX = 200;

// What a reply said: its id, and why it missed the cache when it did.
export interface Heard {
  id?: string;
  reason?: string;
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
  return {
    ...(id ? { id } : {}),
    ...(miss ? { reason: reasonText(miss) } : {}),
  };
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
    const betas = (headers.get("anthropic-beta") ?? "").split(",").map((beta) => beta.trim());
    headers.set("anthropic-beta", [...betas.filter(Boolean), DIAGNOSE_BETA].join(","));
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
    return heard.reason ? ` cachemiss=${heard.reason}` : "";
  }

  private keepBody(session: string, step: boolean, body: string): void {
    const seen = this.bodies.get(session) ?? {};
    this.bodies.delete(session);
    this.bodies.set(session, { last: body, step: step ? body : seen.step });
    while (this.bodies.size > BODIES_MAX) this.bodies.delete(this.bodies.keys().next().value!);
  }

  // Whether a refused reply was about the field or the header: then the proxy
  // stops asking, and the request goes again without it.
  refused(status: number, text: string): boolean {
    if (status !== 400 || !/diagnostics|cache-diagnos/i.test(text)) return false;
    this.off = true;
    return true;
  }
}
