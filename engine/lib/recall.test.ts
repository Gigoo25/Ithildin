import { describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Recall, SEARCHED_MAX, shapeOf } from "./recall.ts";

const key = Buffer.alloc(32, 7);
const dir = () => mkdtempSync(join(tmpdir(), "recall-"));

// A Recall that kept these values, as a restart finds it.
function kept(values: Array<[string, string]>): { recall: Recall; file: string } {
  const file = join(dir(), "swapped.json");
  const writer = new Recall(key);
  writer.save(
    file,
    values.map(([value, rule]) => writer.entry(value, rule)!),
  );
  const recall = new Recall(key);
  recall.load(file);
  return { recall, file };
}

describe("shapeOf", () => {
  it("counts word runs and the separators around them", () => {
    expect(shapeOf("build-7.example.invalid", "r")).toEqual({
      ruleId: "r",
      runs: 4,
      length: 23,
      lead: 0,
      trail: 0,
    });
    expect(shapeOf("~/qorvant/", "r")).toMatchObject({ runs: 1, lead: 2, trail: 1 });
    expect(shapeOf("...", "r")).toBeUndefined();
  });
});

describe("Recall", () => {
  it("writes digests, never the values", () => {
    const { file } = kept([["zqxvelmarx-build7", "pii-host"]]);
    const text = readFileSync(file, "utf8");
    expect(text).not.toContain("zqxvelmarx");
    expect(JSON.parse(text)[0]).toMatchObject({ ruleId: "pii-host", runs: 2, length: 17 });
  });

  it("finds a kept value again in any case, with its rule, once", () => {
    const { recall } = kept([
      ["zqxvelmarx-build7", "pii-host"],
      ["kwvrt.olmsby@example.invalid", "pii-email"],
      ["~/qorvant/", "pii-path"],
    ]);
    expect(recall.size).toBe(3);
    const text = "ssh ZQXVELMARX-build7 then mail kwvrt.olmsby@example.invalid from ~/qorvant/ ok";
    expect(recall.find(text)).toEqual([
      { value: "ZQXVELMARX-build7", ruleId: "pii-host" },
      { value: "kwvrt.olmsby@example.invalid", ruleId: "pii-email" },
      { value: "~/qorvant/", ruleId: "pii-path" },
    ]);
    // Found values are the caller's to remember; they are no longer kept.
    expect(recall.size).toBe(0);
    expect(recall.find(`${text} again`)).toEqual([]);
  });

  it("takes whole tokens only, and nothing else of the same shape", () => {
    const { recall } = kept([["zqxvelmarx-build7", "pii-host"]]);
    expect(recall.find("xzqxvelmarx-build7 zqxvelmarx-build70 abcdefghij-build7")).toEqual([]);
    expect(recall.size).toBe(1);
  });

  it("does not search the same text twice, and forgets past its limit", () => {
    const { recall } = kept([["zqxvelmarx-build7", "pii-host"]]);
    const searched = (recall as unknown as { searched: Set<string> }).searched;
    expect(recall.find("nothing here")).toEqual([]);
    expect(searched.size).toBe(1);
    expect(recall.find("nothing here")).toEqual([]);
    expect(searched.size).toBe(1);
    for (let i = 0; searched.size < SEARCHED_MAX; i++) searched.add(`fake:${i}`);
    recall.find("something else");
    expect(searched.size).toBe(1);
  });

  it("keeps what it has not found yet, for a second restart", () => {
    const { recall } = kept([
      ["zqxvelmarx-build7", "pii-host"],
      ["kwvrt.olmsby@example.invalid", "pii-email"],
    ]);
    recall.find("ssh zqxvelmarx-build7");
    expect(recall.entries()).toEqual([expect.objectContaining({ ruleId: "pii-email" })]);
  });

  it("starts empty from a missing, unreadable or malformed file", () => {
    const recall = new Recall(key);
    recall.load(join(dir(), "absent.json"));
    expect(recall.size).toBe(0);
    expect(recall.find("anything")).toEqual([]);
    const bad = join(dir(), "bad.json");
    writeFileSync(bad, "{not json");
    recall.load(bad);
    writeFileSync(bad, JSON.stringify({ not: "a list" }));
    recall.load(bad);
    writeFileSync(bad, JSON.stringify([null, { digest: "x" }, { digest: "y", ruleId: "r" }]));
    recall.load(bad);
    expect(recall.size).toBe(0);
  });

  it("does not throw when the file cannot be written", () => {
    const blocker = join(dir(), "file");
    writeFileSync(blocker, "");
    expect(() => new Recall(key).save(join(blocker, "under-a-file.json"), [])).not.toThrow();
  });

  it("searches a megabyte against a full memory quickly", () => {
    const values: Array<[string, string]> = Array.from({ length: 2_000 }, (_, i) => [
      `host-${i.toString(36)}x.corp-${(i * 7919).toString(36)}.example.invalid`,
      "pii-host",
    ]);
    const { recall } = kept(values);
    const line = "the build at host-1x.corp-1 ran 42 steps in /srv/app/src_2 and wrote it\n";
    const text = line.repeat(Math.ceil(1_000_000 / line.length)) + values[1_500]![0];
    const started = performance.now();
    expect(recall.find(text)).toEqual([{ value: values[1_500]![0], ruleId: "pii-host" }]);
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});
