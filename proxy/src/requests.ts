// The last few requests as they were sent upstream, kept in memory for the
// dashboard's "Sent requests" view. This is the text after redaction, so it is
// the proxy's own proof of what left the machine: a real value that masking
// missed is in it, and the page shows it as it is. Nothing is written to disk,
// and a restart clears it. Off when ITHILDIN_KEEP_REQUESTS is 0.

import { setting } from "../engine/lib/names.ts";

export const KEEP_DEFAULT = 20;
export const KEEP_MAX = 200;
// Longest body kept whole. A longer one is cut, and the view says so.
export const BODY_BYTES_MAX = 1024 * 1024;
const SESSION_CHARS = 8;

export interface SentSummary {
  id: number;
  time: number;
  route: string;
  endpoint: string;
  session?: string;
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

  record(route: string, endpoint: string, session: string | undefined, body: string): void {
    if (!this.enabled) return;
    const cut = body.length > BODY_BYTES_MAX;
    this.kept.push({
      id: ++this.lastId,
      time: this.now(),
      route,
      endpoint,
      ...(session ? { session: session.slice(0, SESSION_CHARS) } : {}),
      size: body.length,
      cut,
      text: cut ? body.slice(0, BODY_BYTES_MAX) : body,
    });
    if (this.kept.length > this.keep) this.kept.shift();
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
