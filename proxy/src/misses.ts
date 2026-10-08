// A cache miss kept on disk: the request that missed and the one it was
// compared with, byte for byte as they went upstream. The open question in
// CACHING.md needs exactly that pair, and both lived only in memory, so a
// restart before anyone looked lost them. Now each `*_changed` miss Anthropic
// names (diagnose.ts) leaves a directory under the state dir:
//
//   cachemiss/<time>-<session>/previous.json   the earlier request
//   cachemiss/<time>-<session>/missed.json     the request that missed
//   cachemiss/<time>-<session>/meta.json       reason, and where they diverge
//
// The bodies are the redacted ones the provider already saw, never what the
// agent sent; still, they are conversations, so the files are the user's
// only, and only the newest few are kept, bounded by count, age and size.

import { mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { setting, stateDir } from "../engine/lib/names.ts";

export interface Miss {
  session: string;
  step: boolean;
  reason: string;
  previous: string;
  missed: string;
}

// ITHILDIN_CACHEMISS_KEEP sets how many are kept; 0 keeps none.
export function missesKept(configured = setting("CACHEMISS_KEEP")): number {
  return configured !== undefined && /^\d+$/.test(configured) ? Number(configured) : 20;
}

export function missesDir(): string {
  return path.join(stateDir(), "cachemiss");
}

// Where two bodies first differ: the length of what they share.
export function firstDifference(a: string, b: string): number {
  const shorter = Math.min(a.length, b.length);
  let at = 0;
  while (at < shorter && a.charCodeAt(at) === b.charCodeAt(at)) at++;
  return at;
}

// What the miss is filed as, and enough of both bodies around the divergence
// to see it without opening them.
export function missMeta(miss: Miss, now: Date): Record<string, unknown> {
  const at = firstDifference(miss.previous, miss.missed);
  const around = (body: string) => body.slice(Math.max(0, at - 300), at + 300);
  return {
    time: now.toISOString(),
    session: miss.session,
    step: miss.step,
    reason: miss.reason,
    divergesAt: at,
    sizes: { previous: miss.previous.length, missed: miss.missed.length },
    previousAround: around(miss.previous),
    missedAround: around(miss.missed),
  };
}

// Two bodies can run to megabytes each, so the count alone does not bound the
// disk; past either limit the oldest go first.
export const MISSES_BYTES_MAX = 200 * 1024 * 1024;
export const MISS_AGE_MAX_MS = 14 * 24 * 60 * 60 * 1000;

function dirBytes(at: string): number {
  return readdirSync(at).reduce((sum, name) => sum + statSync(path.join(at, name)).size, 0);
}

// Drops the misses past the count, older than the age limit, or, oldest
// first, past the size limit; returns how many went. Run after each save and
// at start, so a lowered ITHILDIN_CACHEMISS_KEEP (0 included) takes effect
// without waiting for the next miss.
export function pruneMisses(
  dir = missesDir(),
  keep = missesKept(),
  now = Date.now(),
  bytesMax = MISSES_BYTES_MAX,
): number {
  let found: string[];
  try {
    found = readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
  } catch {
    return 0;
  }
  // Named by time, so a name sort is oldest first.
  const misses = found.sort().map((name) => {
    const at = path.join(dir, name);
    return { at, age: now - statSync(at).mtimeMs, bytes: dirBytes(at) };
  });
  let total = misses.reduce((sum, miss) => sum + miss.bytes, 0);
  let dropped = 0;
  for (const miss of misses) {
    const left = misses.length - dropped;
    if (left <= keep && miss.age <= MISS_AGE_MAX_MS && total <= bytesMax) continue;
    rmSync(miss.at, { recursive: true, force: true });
    total -= miss.bytes;
    dropped++;
  }
  return dropped;
}

// Writes one miss and drops what is past the limits (pruneMisses); returns
// its directory, or undefined when none are kept.
export function saveMiss(
  miss: Miss,
  dir = missesDir(),
  keep = missesKept(),
  now = new Date(),
): string | undefined {
  if (keep === 0) {
    pruneMisses(dir, 0);
    return undefined;
  }
  const session = miss.session.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 16);
  const at = path.join(dir, `${now.toISOString().replace(/[:.]/g, "-")}-${session}`);
  mkdirSync(at, { recursive: true, mode: 0o700 });
  const file = (name: string, text: string) =>
    writeFileSync(path.join(at, name), text, { mode: 0o600 });
  file("previous.json", miss.previous);
  file("missed.json", miss.missed);
  file("meta.json", `${JSON.stringify(missMeta(miss, now), null, 2)}\n`);
  pruneMisses(dir, keep);
  return at;
}
