import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Format } from "../src/redact.ts";
import { modelItems } from "./agent.ts";
import { newestPerSession } from "./capture.ts";
import { canary, KINDS } from "./canaries.ts";
import { ddmin } from "./ddmin.ts";
import type { Turn } from "./model.ts";
import { Random } from "./random.ts";
import { loadTape, matches, plantedBody, saveTape, turnOf, type Tape } from "./tape.ts";

const dir = mkdtempSync(join(tmpdir(), "ithildin-tape-test-"));
process.on("exit", () => rmSync(dir, { recursive: true, force: true }));

describe("tapes", () => {
  test("save and load give the tape back, with no canary readable in the file", () => {
    const random = new Random(7);
    const canaries = KINDS.map((kind) => canary(random, kind));
    const text = canaries.map((c) => `see ${c.value} here`).join("\n");
    const tape: Tape = {
      format: "chat",
      session: "t1",
      seed: 7,
      canaries,
      target: { check: "leak", canary: 2 },
      requests: [
        {
          path: "p",
          headers: {},
          body: { messages: [{ role: "user", content: text }] },
          // In a call's arguments a value is escaped twice.
          answer: {
            thinking: "",
            text,
            calls: [{ id: "c", name: "Bash", input: { command: text } }],
          },
        },
      ],
    };
    const file = join(dir, "tape.json");
    saveTape(tape, file);
    const saved = readFileSync(file, "utf8");
    for (const c of canaries) {
      expect(saved).not.toContain(c.core);
      expect(saved).not.toContain(JSON.stringify(c.core).slice(1, -1));
    }
    expect(loadTape(file)).toEqual(tape);
  });

  test("a finding matches a target by its check, and a leak by its canary", () => {
    const random = new Random(3);
    const tape = { canaries: [canary(random, "email"), canary(random, "aws-key")] } as Tape;
    const leak = (i: number) => ({ check: "leak", detail: `x ${tape.canaries[i]!.core} reached` });
    expect(matches(tape, { check: "leak", canary: 1 }, leak(1))).toBe(true);
    expect(matches(tape, { check: "leak", canary: 1 }, leak(0))).toBe(false);
    expect(matches(tape, { check: "prefix" }, { check: "prefix", detail: "" })).toBe(true);
    expect(matches(tape, { check: "prefix" }, leak(0))).toBe(false);
  });
});

describe("turns", () => {
  const turn: Turn = {
    thinking: "looking",
    text: "done",
    calls: [{ id: "call_1", name: "Read", input: { file_path: "/tmp/a" } }],
  };
  for (const format of ["anthropic", "responses", "chat"] as Format[])
    test(`a ${format} turn reads back from the items a harness keeps of it`, () => {
      expect(turnOf(format, modelItems(format, turn))).toEqual(turn);
    });

  // The AI SDK sends a Gemini call back without an id; the proxy names it.
  test("a gemini turn reads back from its parts, its calls without ids", () => {
    const calls = turn.calls.map((c) => ({ ...c, id: "" }));
    expect(turnOf("gemini", modelItems("gemini", turn))).toEqual({ ...turn, calls });
  });

  test("arguments that are not JSON are kept whole", () => {
    const items = [{ type: "function_call", call_id: "c", name: "x", arguments: "not json" }];
    expect(turnOf("responses", items).calls[0]!.input).toEqual({ raw: "not json" });
  });
});

describe("a real body", () => {
  test("gets its canaries planted where a session shows a model text", () => {
    const body = {
      model: "m",
      messages: [
        { role: "user", content: "hello" },
        { role: "assistant", content: "", tool_calls: [] },
        { role: "tool", tool_call_id: "c", content: "output" },
      ],
    };
    const file = join(dir, "body.json");
    writeFileSync(file, JSON.stringify({ "ithildin-corpus": 1, body }));
    const one = plantedBody(file, 1);
    expect(one.format).toBe("chat");
    const text = JSON.stringify(one.body);
    // Planted as itself, or quoted (export X="..."), so escaped once or twice.
    const once = (value: string) => JSON.stringify(value).slice(1, -1);
    for (const c of one.canaries)
      expect(text.includes(once(c.core)) || text.includes(once(once(c.core)))).toBe(true);
    // The same body and seed plant the same canaries.
    expect(plantedBody(file, 1).canaries).toEqual(one.canaries);
  });

  test("capture keeps the newest whole main request of each session", () => {
    const base = { route: "r", endpoint: "e", main: true, cut: false };
    const kept = newestPerSession([
      { ...base, id: 1, session: "a" },
      { ...base, id: 3, session: "a" },
      { ...base, id: 4, session: "a", cut: true },
      { ...base, id: 5, session: "a", main: false },
      { ...base, id: 2, session: "b" },
      { ...base, id: 6 },
    ]);
    expect(kept.map((each) => each.id).sort()).toEqual([2, 3]);
  });
});

describe("ddmin", () => {
  test("finds the two items a failure needs among many", async () => {
    const items = Array.from({ length: 40 }, (_, i) => i);
    const fails = async (keep: number[]) => keep.includes(7) && keep.includes(31);
    expect(await ddmin(items, fails)).toEqual([7, 31]);
  });

  test("gives nothing when nothing is needed", async () => {
    expect(await ddmin([1, 2, 3], async () => true)).toEqual([]);
  });
});
