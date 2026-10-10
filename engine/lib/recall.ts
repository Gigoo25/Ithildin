// Values the session learned, kept across a restart as digests, never values.
//
// A real value swapped into a tool call comes back in the agent's history
// raw, and only the memory of having swapped it masks it again (no rule
// finds a host composed from known parts). A restart emptied that memory:
// every such copy in every conversation went out raw, which leaked it and
// changed the prefix, so each conversation was written to the cache again,
// and again on the next request as the memory refilled.
//
// The file holds a keyed digest of each value with its shape: how many word
// runs it spans, its length, the separators before its first run and after
// its last. A text is searched by hashing each span of that shape; one whose
// digest is kept is the value, found again, and goes back into the memory.
// A 16-bit tag from a cheap keyed hash rejects nearly every span before the
// HMAC runs, and a text already searched is not searched again.

import { createHmac } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface KeptShape {
  ruleId: string;
  runs: number;
  length: number;
  lead: number;
  trail: number;
}

interface Kept extends KeptShape {
  digest: string;
  tag: number;
}

// One shape's spans: the lengths and tags any kept value of it has.
interface Shape {
  runs: number;
  lead: number;
  trail: number;
  lengths: Set<number>;
  tags: Set<number>;
}

const WORD = /[\p{L}\p{N}_]/u;
const RUNS = /[\p{L}\p{N}_]+/gu;
// Texts already searched, by length and hash. Collisions only skip a search.
export const SEARCHED_MAX = 100_000;

export function shapeOf(value: string, ruleId: string): KeptShape | undefined {
  const runs = [...value.matchAll(RUNS)];
  if (runs.length === 0) return undefined;
  const first = runs[0]!;
  const last = runs[runs.length - 1]!;
  return {
    ruleId,
    runs: runs.length,
    length: value.length,
    lead: first.index,
    trail: value.length - (last.index + last[0].length),
  };
}

// FNV-1a over the lowercased span, seeded from the key.
function fnv(seed: number, text: string, from: number, to: number): number {
  let hash = seed;
  for (let i = from; i < to; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 16777619);
  return hash >>> 0;
}

export class Recall {
  private readonly kept = new Map<string, Kept>();
  private shapes: Shape[] = [];
  private readonly searched = new Set<string>();
  private readonly seed: number;

  constructor(private readonly key: Buffer) {
    this.seed = createHmac("sha256", key).update("recall-seed").digest().readUInt32LE(0);
  }

  get size(): number {
    return this.kept.size;
  }

  digest(value: string): string {
    return createHmac("sha256", this.key).update(value.toLowerCase()).digest("hex").slice(0, 32);
  }

  tag(value: string): number {
    const lower = value.toLowerCase();
    return fnv(this.seed, lower, 0, lower.length) & 0xffff;
  }

  // What to write for a value still in memory.
  entry(value: string, ruleId: string): Record<string, unknown> | undefined {
    const shape = shapeOf(value, ruleId);
    if (!shape) return undefined;
    return { ...shape, digest: this.digest(value), tag: this.tag(value) };
  }

  // Values not yet found again, as written, so a second restart keeps them.
  entries(): Record<string, unknown>[] {
    return [...this.kept.values()].map((kept) => ({ ...kept }));
  }

  load(file: string): void {
    let lines: unknown;
    try {
      lines = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      return;
    }
    if (!Array.isArray(lines)) return;
    for (const line of lines) {
      const kept = line as Kept;
      if (typeof kept?.digest !== "string" || typeof kept.ruleId !== "string") continue;
      if (![kept.runs, kept.length, kept.lead, kept.trail, kept.tag].every(Number.isInteger))
        continue;
      this.kept.set(kept.digest, { ...kept });
    }
    this.reshape();
  }

  save(file: string, lines: Record<string, unknown>[]): void {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(lines), { mode: 0o600 });
      fs.renameSync(tmp, file);
    } catch {
      // A memory that is not kept costs one cache write after a restart.
    }
  }

  // Kept values this text holds, each with the rule that found it; each is
  // dropped from what is kept, since the caller remembers it again.
  find(text: string): { value: string; ruleId: string }[] {
    if (this.kept.size === 0) return [];
    const lower = text.toLowerCase();
    const id = `${text.length}:${fnv(this.seed, lower, 0, lower.length)}`;
    if (this.searched.has(id)) return [];
    const starts: number[] = [];
    const ends: number[] = [];
    for (const run of lower.matchAll(RUNS)) {
      starts.push(run.index);
      ends.push(run.index + run[0].length);
    }
    const found = this.spans(text, lower, starts, ends);
    if (found.length > 0) this.reshape();
    if (this.searched.size >= SEARCHED_MAX) this.searched.clear();
    this.searched.add(id);
    return found;
  }

  private spans(
    text: string,
    lower: string,
    starts: number[],
    ends: number[],
  ): { value: string; ruleId: string }[] {
    const found: { value: string; ruleId: string }[] = [];
    for (let i = 0; i < starts.length; i++) {
      for (const shape of this.shapes) {
        const j = i + shape.runs - 1;
        if (j >= starts.length) continue;
        const from = starts[i]! - shape.lead;
        const to = ends[j]! + shape.trail;
        if (from < 0 || to > text.length || !shape.lengths.has(to - from)) continue;
        if (WORD.test(text[from - 1] ?? "") || WORD.test(text[to] ?? "")) continue;
        if (!shape.tags.has(fnv(this.seed, lower, from, to) & 0xffff)) continue;
        const value = text.slice(from, to);
        const kept = this.kept.get(this.digest(value));
        if (!kept) continue;
        this.kept.delete(kept.digest);
        found.push({ value, ruleId: kept.ruleId });
      }
    }
    return found;
  }

  private reshape(): void {
    const byShape = new Map<string, Shape>();
    for (const kept of this.kept.values()) {
      const key = `${kept.runs}:${kept.lead}:${kept.trail}`;
      let shape = byShape.get(key);
      if (!shape) {
        const { runs, lead, trail } = kept;
        shape = { runs, lead, trail, lengths: new Set(), tags: new Set() };
        byShape.set(key, shape);
      }
      shape.lengths.add(kept.length);
      shape.tags.add(kept.tag);
    }
    this.shapes = [...byShape.values()];
    // A smaller set needs no text searched again: what it holds was looked
    // for already. Only a load adds values, and it runs before any search.
  }
}
