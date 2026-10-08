import { afterEach, describe, expect, it } from "bun:test";
import { EventEmitter } from "node:events";
import { redactText } from "../engine/core.ts";
import {
  clearWindowCache,
  exportWindowCache,
  importWindowCache,
  SCAN_WINDOW_CHARS,
  scanToSnapshot,
  scanWindows,
  setRuntimeInventory,
} from "../engine/lib/rules.ts";
import {
  answer,
  ScanPool,
  scanThreadCount,
  spread,
  type Thread,
  WARM_MIN_CHARS,
  warmTexts,
} from "./scan-pool.ts";

const AWS_KEY = "AKIAQ3XJ7TZ2LM4PWB6R";
const EMAIL = "dana.okafor@fastmail.com";

// Longer than two windows, with secrets inside, near and across window edges.
function longText(salt: string): string {
  const line = (i: number) => `${salt} line ${i}: const value = compute(${i}) // ordinary code\n`;
  let text = "";
  for (let i = 0; text.length < SCAN_WINDOW_CHARS * 2.5; i++) {
    text += line(i);
    if (i % 400 === 7) text += `aws_access_key_id = ${AWS_KEY}\ncontact: ${EMAIL}\n`;
  }
  const edge = SCAN_WINDOW_CHARS - 10;
  return `${text.slice(0, edge)}${AWS_KEY} ${EMAIL}${text.slice(edge)}`;
}

afterEach(() => {
  clearWindowCache();
});

describe("scan snapshots", () => {
  it("give the same findings as scanning the text directly", () => {
    const text = longText("same");
    clearWindowCache();
    const direct = scanWindows(text);
    expect(direct.trips).toEqual([]);
    expect(direct.findings.some((f) => f.secretValue === AWS_KEY)).toBe(true);

    const snapshot = scanToSnapshot([text, ""]);
    clearWindowCache();
    expect(importWindowCache(snapshot)).toBe(snapshot.entries.length);
    expect(snapshot.entries.length).toBeGreaterThan(2);
    expect(scanWindows(text)).toEqual(direct);
  });

  it("carry ranges, never values", () => {
    const snapshot = scanToSnapshot([longText("ranges")]);
    const json = JSON.stringify(snapshot);
    expect(json).not.toContain(AWS_KEY);
    expect(json).not.toContain(EMAIL);
  });

  it("are dropped whole when the rules differ", () => {
    const snapshot = scanToSnapshot([longText("rules")]);
    clearWindowCache();
    expect(importWindowCache({ ...snapshot, fingerprint: "0".repeat(64) })).toBe(0);
    expect(exportWindowCache().entries).toEqual([]);
  });

  it("leave redaction unchanged", () => {
    const text = longText("redact");
    clearWindowCache();
    const snapshot = scanToSnapshot([text]);
    clearWindowCache();
    importWindowCache(snapshot);
    const warmed = redactText(text);
    expect(warmed.text).not.toContain(AWS_KEY);
    expect(warmed.text).not.toContain(EMAIL);
    expect(warmed.hits).toBeGreaterThan(0);
  });
});

describe("answer", () => {
  it("installs an inventory without replying, and scans a batch", () => {
    expect(answer({ type: "inventory", entries: [] })).toBeUndefined();
    const reply = answer({ type: "scan", id: 7, texts: [longText("answer")] });
    expect(reply?.id).toBe(7);
    expect(reply?.snapshot.entries.length).toBeGreaterThan(0);
  });
});

describe("warmTexts", () => {
  it("takes long strings once, from anywhere in the body", () => {
    const long = "word ".repeat(WARM_MIN_CHARS);
    const body = {
      model: "m",
      messages: [{ content: [{ text: long }, { text: long }] }, { content: "short" }],
      nested: { deeper: [`${long}x`] },
    };
    expect(warmTexts(body)).toEqual([long, `${long}x`]);
  });

  it("skips base64 payloads and what the scan memo already holds", () => {
    const encoded = "QUJD".repeat(WARM_MIN_CHARS);
    const cached = `cached ${"text ".repeat(WARM_MIN_CHARS)}`;
    redactText(cached);
    expect(warmTexts({ a: encoded, b: cached, c: null, d: 3 })).toEqual([]);
  });
});

describe("spread", () => {
  it("balances by length, largest first, with no empty batch", () => {
    const batches = spread(["a".repeat(10), "b".repeat(6), "c".repeat(5), "d"], 2);
    expect(batches.map((b) => b.join("").length)).toEqual([11, 11]);
    expect(spread(["only"], 3)).toEqual([["only"]]);
  });
});

describe("scanThreadCount", () => {
  it("leaves a core to serve, takes a setting, and caps it", () => {
    expect(scanThreadCount(undefined, 4)).toBe(2);
    expect(scanThreadCount(undefined, 2)).toBe(1);
    expect(scanThreadCount(undefined, 1)).toBe(0);
    expect(scanThreadCount("0", 4)).toBe(0);
    expect(scanThreadCount("3", 4)).toBe(3);
    expect(scanThreadCount("99", 4)).toBe(8);
    expect(scanThreadCount("many", 4)).toBe(2);
  });
});

// A thread that answers in-process, or not at all.
class FakeThread extends EventEmitter {
  sent: unknown[] = [];
  terminated = false;
  constructor(private readonly replies: boolean) {
    super();
  }
  postMessage(ask: unknown): void {
    this.sent.push(ask);
    if (!this.replies) return;
    const reply = answer(ask as Parameters<typeof answer>[0]);
    if (reply) queueMicrotask(() => this.emit("message", reply));
  }
  terminate(): Promise<number> {
    this.terminated = true;
    return Promise.resolve(0);
  }
  unref(): void {}
}

function fakePool(replies: boolean, count = 1, patience = 50_000) {
  const threads: FakeThread[] = [];
  const logged: string[] = [];
  const pool = new ScanPool(
    count,
    [],
    (line) => logged.push(line),
    () => {
      const thread = new FakeThread(replies);
      threads.push(thread);
      return thread as unknown as Thread;
    },
    () => patience,
  );
  return { pool, threads, logged };
}

describe("ScanPool", () => {
  it("fills the scan cache from its threads", async () => {
    const { pool, threads } = fakePool(true, 2);
    expect(pool.size).toBe(2);
    expect(threads[0]!.sent[0]).toEqual({ type: "inventory", entries: [] });
    clearWindowCache();
    await pool.warm([longText("pool-a"), longText("pool-b")]);
    expect(exportWindowCache().entries.length).toBeGreaterThan(4);
    pool.setInventory([]);
    expect(threads[1]!.sent.at(-1)).toEqual({ type: "inventory", entries: [] });
  });

  it("stops waiting once its patience runs out", async () => {
    const { pool } = fakePool(false, 1, 5);
    await pool.warm([longText("silent")]);
    expect(exportWindowCache().entries).toEqual([]);
  });

  it("drops a thread that fails and frees what waited on it", async () => {
    const { pool, threads, logged } = fakePool(false, 2);
    const warming = pool.warm([longText("x"), longText("y")]);
    threads[0]!.emit("error", new Error("boom"));
    threads[1]!.emit("exit", 1);
    threads[1]!.emit("exit", 1);
    await warming;
    expect(pool.size).toBe(0);
    expect(logged).toEqual([
      "a scan thread stopped (boom); 1 left",
      "a scan thread stopped (exit 1); 0 left",
    ]);
    await pool.warm([longText("none")]);
  });

  it("terminates its threads on close", async () => {
    const { pool, threads } = fakePool(false, 2);
    const warming = pool.warm([longText("closing")]);
    pool.close();
    await warming;
    expect(threads.every((thread) => thread.terminated)).toBe(true);
    expect(pool.size).toBe(0);
  });

  it("does nothing with no texts", async () => {
    const { pool, threads } = fakePool(true);
    await pool.warm([]);
    expect(threads[0]!.sent).toHaveLength(1);
  });

  it("scans on a real thread", async () => {
    setRuntimeInventory([]);
    const pool = new ScanPool(1, [], () => {});
    try {
      const text = longText("thread");
      clearWindowCache();
      const direct = scanWindows(text);
      clearWindowCache();
      await pool.warm([text]);
      expect(exportWindowCache().entries.length).toBeGreaterThan(2);
      expect(scanWindows(text)).toEqual(direct);
    } finally {
      pool.close();
    }
  });
});
