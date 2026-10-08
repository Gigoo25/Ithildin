// Regex scanning on other threads. Redaction is synchronous, so a large
// request held the one thread that serves every other request and stream
// until its scan finished; on a small host doing other work that was
// seconds, and the wall-clock scan caps tripped into omissions.
//
// The threads never redact. Each scans a request's long strings into the
// value-free window records the scan cache already persists to disk, and the
// serving thread imports them (importWindowCache, which drops an answer from
// a different rule set). The redaction then runs as before and finds those
// windows done. Anything a thread did not finish (slow, dead, tripped, a
// string a pre-pass changed) misses the cache and is scanned on the serving
// thread exactly as it was without threads: the threads can make a request
// faster, never redact it differently.

import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";
import { MAX_SCAN_BYTES, scanCached } from "../engine/core.ts";
import { setting } from "../engine/lib/names.ts";
import {
  currentScanBudgetMs,
  importWindowCache,
  type InventoryEntry,
  scanToSnapshot,
  setRuntimeInventory,
  type WindowCacheSnapshot,
} from "../engine/lib/rules.ts";

export type ScanAsk =
  { type: "inventory"; entries: InventoryEntry[] } | { type: "scan"; id: number; texts: string[] };
export type ScanAnswer = { id: number; snapshot: WindowCacheSnapshot };

// What a scan thread does with a message; scan-worker.ts only wires it up.
// The inventory comes from the serving thread, so a thread runs the same
// rules without collecting identity (ssh, git, tailscale) again.
export function answer(ask: ScanAsk): ScanAnswer | undefined {
  if (ask.type === "inventory") {
    setRuntimeInventory(ask.entries);
    return undefined;
  }
  return { id: ask.id, snapshot: scanToSnapshot(ask.texts) };
}

// Shorter strings cost less to scan than to send.
export const WARM_MIN_CHARS = 1_000;
// Past the scan budget the serving thread stops waiting and scans what is
// left itself; an answer that comes later is still imported.
const WARM_SLACK_MS = 2_000;
const THREADS_MAX = 8;

// Two by default and one core left to serve: an N100 has four.
// ITHILDIN_SCAN_THREADS sets it; 0 turns threads off.
export function scanThreadCount(
  configured = setting("SCAN_THREADS"),
  cores = availableParallelism(),
): number {
  if (configured !== undefined && /^\d+$/.test(configured))
    return Math.min(Number(configured), THREADS_MAX);
  return Math.max(0, Math.min(2, cores - 1));
}

// Base64 payloads (images, files) hold nothing a rule reads as text and are
// the largest strings a request carries.
function looksEncoded(text: string): boolean {
  return /^[A-Za-z0-9+/=_-]+$/.test(text.slice(0, 4096));
}

// The body's strings worth scanning ahead: long, not already in the scan
// memo, each once.
export function warmTexts(body: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const walk = (value: unknown): void => {
    if (typeof value === "string") {
      if (value.length < WARM_MIN_CHARS || value.length > MAX_SCAN_BYTES) return;
      if (seen.has(value) || scanCached(value) || looksEncoded(value)) return;
      seen.add(value);
      out.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) walk(item);
    } else if (value !== null && typeof value === "object") {
      for (const item of Object.values(value)) walk(item);
    }
  };
  walk(body);
  return out;
}

// Largest first onto the lightest batch, so one thread does not get every
// long string while the others idle.
export function spread(texts: string[], count: number): string[][] {
  const batches = Array.from({ length: count }, () => ({ size: 0, texts: [] as string[] }));
  for (const text of [...texts].sort((a, b) => b.length - a.length)) {
    const lightest = batches.reduce((min, batch) => (batch.size < min.size ? batch : min));
    lightest.texts.push(text);
    lightest.size += text.length;
  }
  return batches.map((batch) => batch.texts).filter((batch) => batch.length > 0);
}

export type Thread = Pick<Worker, "postMessage" | "on" | "terminate" | "unref">;

function spawnThread(): Thread {
  return new Worker(new URL("./scan-worker.ts", import.meta.url));
}

export class ScanPool {
  private readonly threads: Thread[] = [];
  private readonly waiting = new Map<number, { thread: Thread; done: () => void }>();
  private serial = 0;

  constructor(
    size: number,
    entries: InventoryEntry[],
    private readonly log: (line: string) => void,
    spawn: () => Thread = spawnThread,
    private readonly patience = () => currentScanBudgetMs() + WARM_SLACK_MS,
  ) {
    for (let i = 0; i < size; i++) {
      const thread = spawn();
      thread.unref();
      thread.on("message", (reply: ScanAnswer) => this.settle(reply));
      thread.on("error", (error: Error) => this.drop(thread, error.message));
      thread.on("exit", (code: number) => this.drop(thread, `exit ${code}`));
      thread.postMessage({ type: "inventory", entries } satisfies ScanAsk);
      this.threads.push(thread);
    }
  }

  get size(): number {
    return this.threads.length;
  }

  // Sent in order behind any scan already queued, so a scan sent after this
  // runs the new rules; one sent before answers with the old fingerprint and
  // is dropped on import.
  setInventory(entries: InventoryEntry[]): void {
    for (const thread of this.threads)
      thread.postMessage({ type: "inventory", entries } satisfies ScanAsk);
  }

  // Resolves when every thread has answered or the budget has passed,
  // whichever is first. Never rejects: a failure only means a cold cache.
  async warm(texts: string[]): Promise<void> {
    if (this.threads.length === 0 || texts.length === 0) return;
    const asked = spread(texts, this.threads.length).map((batch, i) =>
      this.ask(this.threads[i]!, batch),
    );
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, this.patience());
    });
    await Promise.race([Promise.all(asked), late]);
    clearTimeout(timer);
  }

  close(): void {
    for (const thread of this.threads.splice(0)) void thread.terminate();
    this.release(() => true);
  }

  private ask(thread: Thread, texts: string[]): Promise<void> {
    const id = ++this.serial;
    return new Promise((done) => {
      this.waiting.set(id, { thread, done });
      thread.postMessage({ type: "scan", id, texts } satisfies ScanAsk);
    });
  }

  private settle(reply: ScanAnswer): void {
    importWindowCache(reply.snapshot);
    this.waiting.get(reply.id)?.done();
    this.waiting.delete(reply.id);
  }

  private drop(thread: Thread, why: string): void {
    const index = this.threads.indexOf(thread);
    if (index < 0) return;
    this.threads.splice(index, 1);
    this.release((owner) => owner === thread);
    this.log(`a scan thread stopped (${why}); ${this.threads.length} left`);
  }

  private release(which: (thread: Thread) => boolean): void {
    for (const [id, entry] of this.waiting) {
      if (!which(entry.thread)) continue;
      entry.done();
      this.waiting.delete(id);
    }
  }
}
