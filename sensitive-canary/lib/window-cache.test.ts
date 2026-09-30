import { afterEach, expect, it } from "bun:test";
import {
  activeRulesFingerprint,
  clearWindowCache,
  exportWindowCache,
  importWindowCache,
  scanWindows,
  WINDOW_CACHE_VERSION,
  windowCacheRevision,
} from "./rules.ts";

// The same round trip the Node gate runs, here so coverage sees it, plus
// every way a snapshot from disk can be malformed.
const secret = "AKIA" + "A".repeat(16);
const text = `key ${secret} ${"x".repeat(70_000)}`;
const digest = "a".repeat(64);
const record = { ruleId: "fixture", category: "secret", start: 0, end: 4, score: 1 };
const snapshot = (entries: unknown) => ({ version: WINDOW_CACHE_VERSION, fingerprint: activeRulesFingerprint(), entries });

afterEach(() => clearWindowCache());

it("exports completed windows without values and replays them", () => {
  clearWindowCache();
  const first = scanWindows(text);
  expect(first.trips).toEqual([]);
  expect(first.findings.map((f) => f.secretValue)).toEqual([secret]);
  const saved = exportWindowCache();
  expect(saved.entries.length).toBeGreaterThan(1);
  expect(JSON.stringify(saved)).not.toContain(secret);

  clearWindowCache();
  const revision = windowCacheRevision();
  expect(importWindowCache(JSON.parse(JSON.stringify(saved)))).toBe(saved.entries.length);
  // Imported windows not yet used are exported again as they came.
  expect(exportWindowCache().entries).toEqual(saved.entries);
  const replay = scanWindows(text);
  expect(replay.trips).toEqual([]);
  expect(replay.findings).toEqual(first.findings);
  // Reconstructed windows are promoted into the live cache.
  expect(windowCacheRevision()).toBeGreaterThan(revision);
});

it("ignores a snapshot from other rules or another version", () => {
  for (const bad of [null, 5, { ...snapshot([]), version: WINDOW_CACHE_VERSION + 1 },
    { ...snapshot([]), fingerprint: "0".repeat(64) }, snapshot({})]) {
    expect(importWindowCache(bad)).toBe(0);
  }
});

it("accepts only well-formed entries", () => {
  const entries = [
    null,
    { digest: "short", size: 10, findings: [] },
    { digest, size: -1, findings: [] },
    { digest, size: 1.5, findings: [] },
    { digest, size: 10, findings: "none" },
    { digest, size: 3, findings: [record] },
    { digest, size: 10, findings: [{ ...record, category: "other" }] },
    { digest, size: 10, findings: [{ ...record, start: -1 }] },
    { digest, size: 10, findings: [{ ...record, end: 2, start: 3 }] },
    { digest, size: 10, findings: [{ ...record, score: Number.NaN }] },
    { digest, size: 10, findings: [{ ...record, ruleId: 7 }] },
    { digest, size: 10, findings: [null] },
    { digest, size: 10, findings: [record] },
  ];
  expect(importWindowCache(snapshot(entries))).toBe(1);
});
