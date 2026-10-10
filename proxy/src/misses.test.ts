import { afterEach, describe, expect, it } from "bun:test";
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  firstChangedBlock,
  firstDifference,
  MISS_AGE_MAX_MS,
  type Miss,
  missesDir,
  missesKept,
  missMeta,
  pruneMisses,
  saveMiss,
} from "./misses.ts";
import { keepMiss, tidyMisses } from "./server.ts";

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "ithildin-misses-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const miss: Miss = {
  session: "a/b c:d-123",
  step: true,
  reason: "messages_changed",
  previous: '{"messages":[{"content":"one"},{"content":"two"}]}',
  missed: '{"messages":[{"content":"one"},{"content":"TWO"}]}',
};

describe("firstDifference", () => {
  it("is the length both share", () => {
    expect(firstDifference("abcd", "abXd")).toBe(2);
    expect(firstDifference("abc", "abc")).toBe(3);
    expect(firstDifference("ab", "abc")).toBe(2);
    expect(firstDifference("", "x")).toBe(0);
  });
});

describe("firstChangedBlock", () => {
  const body = (messages: unknown[], extra: Record<string, unknown> = {}) =>
    JSON.stringify({
      safeguards: [{ n: Math.random() }],
      tools: [{ name: "Bash" }],
      system: [{ type: "text", text: "you are", cache_control: { type: "ephemeral" } }],
      messages,
      ...extra,
    });
  const first = [{ role: "user", content: [{ type: "text", text: "note" }, "hi"] }];

  it("names the first block that changed, past uncached fields and moved markers", () => {
    const previous = body(first);
    const missed = body([{ role: "user", content: ["hi"] }], {
      system: [{ type: "text", text: "you are" }],
    });
    expect(firstChangedBlock(previous, missed)).toEqual({
      index: 2,
      previous: { at: "m0[0]", start: '{"type":"text","text":"note"}' },
      missed: { at: "m0[0]", start: '"hi"' },
    });
  });

  it("says null when the prompt is the same, and names what was added at the end", () => {
    expect(firstChangedBlock(body(first), body(first))).toBeNull();
    const longer = [...first, { role: "assistant", content: "ok" }];
    expect(firstChangedBlock(body(first), body(longer))).toEqual({
      index: 4,
      previous: undefined,
      missed: { at: "m1[0]", start: '"ok"' },
    });
  });

  it("gives up on a body that is not JSON", () => {
    expect(firstChangedBlock("not json", body(first))).toBeUndefined();
    expect(firstChangedBlock(body([null]), body([null]))).toBeNull();
  });
});

describe("missMeta", () => {
  it("names the divergence and shows both sides of it", () => {
    const meta = missMeta(miss, new Date("2026-10-08T12:00:00Z"));
    expect(meta).toMatchObject({
      time: "2026-10-08T12:00:00.000Z",
      session: miss.session,
      step: true,
      reason: "messages_changed",
      divergesAt: miss.previous.indexOf("two"),
      sizes: { previous: miss.previous.length, missed: miss.missed.length },
    });
    expect(meta.previousAround).toBe(miss.previous);
    expect(meta.missedAround).toBe(miss.missed);
  });
});

describe("saveMiss", () => {
  it("writes both bodies and the meta, for the user only", () => {
    const dir = scratch();
    const at = saveMiss(miss, dir, 5, new Date("2026-10-08T12:00:00.123Z"))!;
    expect(path.basename(at)).toBe("2026-10-08T12-00-00-123Z-abcd-123.step");
    expect(readFileSync(path.join(at, "previous.json"), "utf8")).toBe(miss.previous);
    expect(readFileSync(path.join(at, "missed.json"), "utf8")).toBe(miss.missed);
    expect(JSON.parse(readFileSync(path.join(at, "meta.json"), "utf8")).reason).toBe(
      "messages_changed",
    );
    expect(statSync(at).mode & 0o777).toBe(0o700);
    expect(statSync(path.join(at, "missed.json")).mode & 0o777).toBe(0o600);
  });

  it("keeps only the newest", () => {
    const dir = scratch();
    for (let second = 0; second < 4; second++)
      saveMiss(miss, dir, 2, new Date(Date.UTC(2026, 9, 8, 12, 0, second)));
    expect(readdirSync(dir).sort()).toEqual([
      "2026-10-08T12-00-02-000Z-abcd-123.step",
      "2026-10-08T12-00-03-000Z-abcd-123.step",
    ]);
  });

  it("drops a turn's miss before any step's, however old the step's", () => {
    const dir = scratch();
    const turn = { ...miss, step: false };
    const at = (second: number) => new Date(Date.UTC(2026, 9, 8, 12, 0, second));
    saveMiss(miss, dir, 2, at(0));
    for (let second = 1; second < 4; second++) saveMiss(turn, dir, 2, at(second));
    expect(readdirSync(dir).sort()).toEqual([
      "2026-10-08T12-00-00-000Z-abcd-123.step",
      "2026-10-08T12-00-03-000Z-abcd-123",
    ]);
  });

  it("writes nothing when none are kept", () => {
    const dir = path.join(scratch(), "never");
    expect(saveMiss(miss, dir, 0)).toBeUndefined();
    expect(() => readdirSync(dir)).toThrow();
  });

  it("removes what was kept once none are", () => {
    const dir = scratch();
    saveMiss(miss, dir, 5);
    expect(saveMiss(miss, dir, 0)).toBeUndefined();
    expect(readdirSync(dir)).toEqual([]);
  });
});

describe("pruneMisses", () => {
  const at = (second: number) => new Date(Date.UTC(2026, 9, 8, 12, 0, second));

  it("trims to a lowered count without a new miss", () => {
    const dir = scratch();
    for (let second = 0; second < 4; second++) saveMiss(miss, dir, 10, at(second));
    expect(pruneMisses(dir, 1)).toBe(3);
    expect(readdirSync(dir)).toEqual(["2026-10-08T12-00-03-000Z-abcd-123.step"]);
    expect(pruneMisses(dir, 1)).toBe(0);
  });

  it("drops what is older than the age limit", () => {
    const dir = scratch();
    const old = saveMiss(miss, dir, 10, at(0))!;
    saveMiss(miss, dir, 10, at(1));
    const longAgo = (Date.now() - MISS_AGE_MAX_MS - 60_000) / 1000;
    utimesSync(old, longAgo, longAgo);
    expect(pruneMisses(dir, 10)).toBe(1);
    expect(readdirSync(dir)).toEqual(["2026-10-08T12-00-01-000Z-abcd-123.step"]);
  });

  it("drops the oldest until the rest fit the size limit", () => {
    const dir = scratch();
    let one = 0;
    for (let second = 0; second < 3; second++) {
      const saved = saveMiss(miss, dir, 10, at(second))!;
      one = readdirSync(saved).reduce(
        (sum, name) => sum + statSync(path.join(saved, name)).size,
        0,
      );
    }
    // Room for two, not three.
    expect(pruneMisses(dir, 10, Date.now(), one * 2 + 1)).toBe(1);
    expect(readdirSync(dir).sort()).toEqual([
      "2026-10-08T12-00-01-000Z-abcd-123.step",
      "2026-10-08T12-00-02-000Z-abcd-123.step",
    ]);
  });

  it("leaves stray files alone, and a missing directory is nothing to do", () => {
    const dir = scratch();
    writeFileSync(path.join(dir, "notes.txt"), "mine");
    expect(pruneMisses(dir, 0)).toBe(0);
    expect(readdirSync(dir)).toEqual(["notes.txt"]);
    expect(pruneMisses(path.join(dir, "absent"), 0)).toBe(0);
  });
});

describe("settings", () => {
  it("keeps twenty unless ITHILDIN_CACHEMISS_KEEP says otherwise", () => {
    expect(missesKept(undefined)).toBe(20);
    expect(missesKept("3")).toBe(3);
    expect(missesKept("0")).toBe(0);
    expect(missesKept("lots")).toBe(20);
    expect(missesDir().endsWith(path.join("ithildin", "cachemiss"))).toBe(true);
  });
});

describe("tidyMisses", () => {
  it("never throws, and says when it dropped any", () => {
    tidyMisses(() => 0);
    tidyMisses(() => 2);
    tidyMisses(() => {
      throw new Error("no access");
    });
  });
});

describe("keepMiss", () => {
  it("never throws, whether the write works or not", () => {
    const dir = scratch();
    keepMiss(miss, (m) => saveMiss(m, dir, 5));
    expect(readdirSync(dir)).toHaveLength(1);
    keepMiss(miss, () => undefined);
    keepMiss(miss, () => {
      throw new Error("disk full");
    });
  });
});
