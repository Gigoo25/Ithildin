import { afterEach, expect, it } from "bun:test";
import { appendFileSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { initReplay, recordOriginal, replayOriginal, saveReplay } from "./replay.ts";

const key = Buffer.alloc(32, 7);
const fresh = () => path.join(mkdtempSync(path.join(tmpdir(), "ithildin-replay-")), "replay.json");
const lines = (file: string) => readFileSync(file, "utf8").trimEnd().split("\n");

afterEach(() => initReplay(key));

it("appends only what changed since the last save", () => {
  const file = fresh();
  initReplay(key, file);
  recordOriginal("text", "harness one", "original one");
  saveReplay();
  expect(lines(file)).toHaveLength(1);
  // Nothing changed: nothing written.
  const before = statSync(file).mtimeMs;
  saveReplay();
  expect(statSync(file).mtimeMs).toBe(before);
  recordOriginal("args", "harness two", "harness two");
  expect(replayOriginal("text", "harness one")).toBe("original one");
  saveReplay();
  expect(lines(file)).toHaveLength(3);

  initReplay(key, file);
  expect(replayOriginal("text", "harness one")).toBe("original one");
  expect(replayOriginal("args", "harness two")).toBe("harness two");
  expect(replayOriginal("text", "never recorded")).toBeUndefined();
});

it("loads the whole-map file from before the journal and rewrites it", () => {
  const file = fresh();
  initReplay(key, file);
  recordOriginal("text", "harness", "original");
  saveReplay();
  const [entry] = lines(file);
  writeFileSync(file, `[${entry}]`);
  initReplay(key, file);
  expect(replayOriginal("text", "harness")).toBe("original");
  saveReplay();
  expect(lines(file)).toHaveLength(1);
  expect(lines(file)[0]).toBe(entry!);
});

it("skips a line torn by a crash and rewrites before appending", () => {
  const file = fresh();
  initReplay(key, file);
  recordOriginal("text", "harness", "original");
  saveReplay();
  appendFileSync(file, '["torn');
  initReplay(key, file);
  expect(replayOriginal("text", "harness")).toBe("original");
  recordOriginal("text", "later", "its original");
  saveReplay();
  initReplay(key, file);
  expect(replayOriginal("text", "harness")).toBe("original");
  expect(replayOriginal("text", "later")).toBe("its original");
});

it("keeps the first original of a form: a later one does not move an older turn", () => {
  initReplay(key);
  recordOriginal("text", "the same form", "what the provider wrote first");
  recordOriginal("text", "the same form", "what it wrote later");
  expect(replayOriginal("text", "the same form")).toBe("what the provider wrote first");
  recordOriginal("args", "unchanged", "unchanged");
  recordOriginal("args", "unchanged", "a later original");
  expect(replayOriginal("args", "unchanged")).toBe("unchanged");
});

it("compacts once the journal holds far more than is live", () => {
  const file = fresh();
  initReplay(key, file);
  const big = "x".repeat(200_000);
  recordOriginal("text", "harness", big);
  // Each hit appends a line; enough of them outgrow twice what is live.
  for (let round = 0; round < 40; round++) {
    for (let hit = 0; hit < 1_000; hit++) replayOriginal("text", "harness");
    saveReplay();
  }
  expect(readFileSync(file, "utf8").length).toBeLessThan(2 * big.length + 1024 * 1024);
  initReplay(key, file);
  expect(replayOriginal("text", "harness")).toBe(big);
});

it("marks compact when the journal cannot be written", () => {
  const missing = path.join(
    mkdtempSync(path.join(tmpdir(), "ithildin-replay-")),
    "nope",
    "replay.json",
  );
  initReplay(key, missing);
  recordOriginal("text", "harness", "original");
  expect(() => saveReplay()).not.toThrow();
  initReplay(key);
});
