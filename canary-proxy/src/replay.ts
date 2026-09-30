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
import { readFileSync, renameSync, writeFileSync } from "node:fs";

export type ReplayKind = "text" | "args";

// Oldest first; a hit moves an entry to the end. null: the harness form is
// the original (nothing was swapped), so no text is kept.
const originals = new Map<string, string | null>();
const MAX_ENTRIES = 50_000;
const MAX_BYTES = 64 * 1024 * 1024;
let bytes = 0;
let key: Buffer | undefined;
let file: string | undefined;
let dirty = false;

export function initReplay(hmacKey: Buffer, path?: string): void {
  key = hmacKey;
  file = path;
  originals.clear();
  bytes = 0;
  if (!path) return;
  try {
    const saved = JSON.parse(readFileSync(path, "utf8")) as Array<[string, string | null]>;
    for (const [digest, original] of saved) put(digest, original);
  } catch {
    // Absent or unreadable: turns from before are redacted as they come.
  }
  dirty = false;
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
  dirty = true;
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
  originals.delete(id);
  originals.set(id, original);
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
  if (!file || !dirty) return;
  try {
    writeFileSync(`${file}.tmp`, JSON.stringify([...originals]), { mode: 0o600 });
    renameSync(`${file}.tmp`, file);
    dirty = false;
  } catch {
    // A lost replay file costs one re-redacted turn, never correctness.
  }
}
