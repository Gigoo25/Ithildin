// Exact round-trips for the model's own output.
//
// The harness stores the model's turns as it received them: tool arguments
// and reply text after swap-back, with real values. Redacting those turns
// again on the next request did not give back what the model wrote. A word it
// wrote itself (a 3-letter handle in its own Python, a generalized term) came
// back as a stand-in or ⟦…⟧ wording, so the model read its own write as
// "the wrong content" and rewrote the file until it wrote a stand-in as the
// whole file.
//
// So every reply block and tool call is recorded as the provider sent it,
// keyed by an HMAC of the form the harness stores. A later request carrying
// that exact form gets the provider's original back, unredacted: the provider
// wrote it, so nothing in it is news to the provider. Anything that does not
// match byte for byte (edited by the harness, or never recorded) is redacted
// as before.

import { createHmac } from "node:crypto";
import { appendFileSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { assert } from "../engine/lib/assert.ts";

export type ReplayKind = "text" | "args";

// Oldest first; a hit moves an entry to the end. null: the harness form is
// the original (nothing was swapped), so no text is kept.
const originals = new Map<string, string | null>();
const MAX_ENTRIES = 50_000;
const MAX_BYTES = 64 * 1024 * 1024;
let bytes = 0;
let key: Buffer | undefined;

// The file is a journal, one JSON line per change: [digest, original] for a
// record, [digest] for a hit. A save appends what changed since the last one
// instead of rewriting up to MAX_BYTES; the file is rewritten whole only once
// it holds twice what is live, so each change is written a bounded number of
// times. Replaying the lines through put() and touch() rebuilds the same map,
// evictions included.
let file: string | undefined;
let pending: string[] = [];
let fileChars = 0;
let compact = false;
// Per-entry overhead of a journal line beyond its original: digest and JSON.
const LINE_OVERHEAD = 72;
const COMPACT_SLACK = 1024 * 1024;

export function initReplay(hmacKey: Buffer, path?: string): void {
  key = hmacKey;
  file = undefined;
  originals.clear();
  bytes = 0;
  pending = [];
  fileChars = 0;
  compact = false;
  if (path) load(path);
  file = path;
}

function load(path: string): void {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return; // Absent or unreadable: turns from before are redacted as they come.
  }
  fileChars = text.length;
  // Cut short by a crash: the next line appended would join the torn one.
  if (text.length > 0 && !text.endsWith("\n")) compact = true;
  for (const line of text.split("\n")) {
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      continue; // A line cut short by a crash costs one re-redacted turn.
    }
    if (!Array.isArray(entry)) continue;
    // The whole map as one array: the format before the journal.
    if (Array.isArray(entry[0])) compact = true;
    for (const each of Array.isArray(entry[0]) ? entry : [entry]) apply(each);
  }
}

function apply(entry: unknown): void {
  if (!Array.isArray(entry) || typeof entry[0] !== "string") return;
  if (entry.length === 1) touch(entry[0]);
  else if (typeof entry[1] === "string" || entry[1] === null) put(entry[0], entry[1]);
}

function touch(id: string): void {
  const original = originals.get(id);
  if (original === undefined) return;
  originals.delete(id);
  originals.set(id, original);
  if (file) pending.push(JSON.stringify([id]));
}

function digest(kind: ReplayKind, harness: string): string | undefined {
  return key && createHmac("sha256", key).update(`${kind}\0${harness}`).digest("hex");
}

function put(id: string, original: string | null): void {
  const old = originals.get(id);
  if (old !== undefined) {
    bytes -= old?.length ?? 0;
    originals.delete(id);
  }
  originals.set(id, original);
  bytes += original?.length ?? 0;
  for (const [oldest, value] of originals) {
    if (originals.size <= MAX_ENTRIES && bytes <= MAX_BYTES) break;
    originals.delete(oldest);
    bytes -= value?.length ?? 0;
  }
  assert(bytes >= 0 && bytes <= MAX_BYTES && originals.size <= MAX_ENTRIES, "replay within bounds");
  if (file) pending.push(JSON.stringify([id, original]));
}

// `harness`: what the harness receives (and will send back); `original`:
// what the provider sent.
export function recordOriginal(kind: ReplayKind, harness: string, original: string): void {
  const id = digest(kind, harness);
  if (id !== undefined) put(id, harness === original ? null : original);
}

// The provider's original for a stored turn, or undefined when unknown.
export function replayOriginal(kind: ReplayKind, harness: string): string | undefined {
  const id = digest(kind, harness);
  if (id === undefined) return undefined;
  const original = originals.get(id);
  if (original === undefined) return undefined;
  touch(id);
  return original ?? harness;
}

// Tool arguments compare in one serialization: the harness may hand back an
// object (Anthropic input) or a re-serialized string (Chat arguments).
export function argsKey(args: unknown): string | undefined {
  try {
    return JSON.stringify(
      typeof args === "string" ? JSON.parse(args === "" ? "{}" : args) : (args ?? {}),
    );
  } catch {
    return undefined;
  }
}

export function saveReplay(): void {
  if (!file || (pending.length === 0 && !compact)) return;
  const added = pending.reduce((sum, line) => sum + line.length + 1, 0);
  const live = bytes + originals.size * LINE_OVERHEAD;
  try {
    if (compact || fileChars + added > 2 * live + COMPACT_SLACK) {
      const lines = [...originals].map((entry) => `${JSON.stringify(entry)}\n`).join("");
      writeFileSync(`${file}.tmp`, lines, { mode: 0o600 });
      renameSync(`${file}.tmp`, file);
      fileChars = lines.length;
      compact = false;
    } else {
      appendFileSync(file, pending.map((line) => `${line}\n`).join(""), { mode: 0o600 });
      fileChars += added;
    }
  } catch {
    // A lost replay file costs one re-redacted turn, never correctness. The
    // next save rewrites it whole, so lines missed here are not lost for good.
    compact = true;
  }
  pending = [];
}
