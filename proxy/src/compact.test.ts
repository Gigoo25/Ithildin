import { describe, expect, it } from "bun:test";
import {
  BLOB_MIN_CHARS,
  PASS_THRESHOLD_CHARS,
  collapseBlobs,
  collapseRepeatedLines,
  compact,
  minifyJsonOutput,
  stripControlSequences,
  stripLogTimestamps,
} from "./compact.ts";

const repeat = (line: string, times: number): string =>
  Array.from({ length: times }, () => line).join("\n");

describe("minifyJsonOutput", () => {
  it("drops the indentation of one JSON document", () => {
    expect(minifyJsonOutput('{\n  "a": 1,\n  "b": [2, 3]\n}')).toBe('{"a":1,"b":[2,3]}');
  });

  it("leaves text that is not one JSON document alone", () => {
    expect(minifyJsonOutput("{not json at all")).toBeUndefined();
    expect(minifyJsonOutput("plain text")).toBeUndefined();
    expect(minifyJsonOutput('{"a":1} and then some prose')).toBeUndefined();
  });

  it("keeps whitespace inside a string value", () => {
    expect(minifyJsonOutput('{\n "a": "two  words"\n}')).toBe('{"a":"two  words"}');
  });
});

describe("collapseRepeatedLines", () => {
  it("collapses a run of identical lines to one and a count", () => {
    const text = repeat("warning: unused variable", 12);
    expect(collapseRepeatedLines(text)).toBe("warning: unused variable\n[11 more identical lines]");
  });

  it("keeps every distinct line below the run length", () => {
    const text = Array.from({ length: 9 }, (_, i) => `row ${i}`).join("\n");
    expect(collapseRepeatedLines(text)).toBeUndefined();
  });

  it("collapses a blank run to one blank, so paragraphs survive", () => {
    expect(collapseRepeatedLines(`a${"\n".repeat(6)}b`)).toBe("a\n\nb");
  });

  it("keeps the first and last of a run of progress rows", () => {
    const text = Array.from({ length: 12 }, (_, i) => `Downloading ${i + 1}%`).join("\n");
    expect(collapseRepeatedLines(text)).toBe(
      "Downloading 1%\n[10 similar progress lines]\nDownloading 12%",
    );
  });

  it("keeps rows that differ by more than a number", () => {
    const text = Array.from({ length: 12 }, (_, i) => `test_case_${i} passed`).join("\n");
    expect(collapseRepeatedLines(text)).toBeUndefined();
  });

  it("ignores colour codes when deciding what repeats", () => {
    const text = repeat("\x1b[32mok\x1b[0m", 11);
    expect(collapseRepeatedLines(text)).toContain("more identical lines");
  });
});

describe("stripLogTimestamps", () => {
  it("removes ISO and syslog prefixes once there are enough of them", () => {
    const iso = Array.from(
      { length: 12 },
      (_, i) => `2026-01-0${(i % 9) + 1}T10:00:00Z line ${i}`,
    ).join("\n");
    expect(stripLogTimestamps(iso)?.startsWith("line 0")).toBe(true);
    const syslog = Array.from({ length: 12 }, (_, i) => `Jan  2 10:00:00 host line ${i}`).join(
      "\n",
    );
    expect(stripLogTimestamps(syslog)?.startsWith("host line 0")).toBe(true);
  });

  it("needs ten stamped lines, so a stray date-like line survives", () => {
    const few = Array.from({ length: 9 }, (_, i) => `2026-01-01T10:00:00Z line ${i}`).join("\n");
    expect(stripLogTimestamps(few)).toBeUndefined();
  });

  it("leaves a timestamp that is the whole line", () => {
    const only = repeat("2026-01-01T10:00:00Z", 12);
    expect(stripLogTimestamps(only)).toBeUndefined();
  });
});

describe("stripControlSequences", () => {
  it("drops cursor moves and nulls", () => {
    expect(stripControlSequences("a\x1b[2Jb\x00c")).toBe("abc");
  });

  it("keeps SGR colour codes, since retained lines keep their colour", () => {
    // Nothing but colour: nothing to strip, so the text is left alone.
    expect(stripControlSequences("\x1b[32mgreen\x1b[0m")).toBeUndefined();
    expect(stripControlSequences("a\x1b[2J\x1b[31mred\x1b[0m")).toBe("a\x1b[31mred\x1b[0m");
  });

  it("turns a carriage-return progress line into a real break", () => {
    expect(stripControlSequences("10%\r50%\r100%")).toBe("10%\n50%\n100%");
  });

  it("returns undefined when there is nothing to strip", () => {
    expect(stripControlSequences("plain text")).toBeUndefined();
  });
});

describe("compact", () => {
  it("leaves small output alone, whatever it holds", () => {
    const json = JSON.stringify({ a: 1 }, null, 4);
    expect(json.length).toBeLessThan(PASS_THRESHOLD_CHARS);
    expect(compact(json)).toBeUndefined();
  });

  it("compacts a large JSON body", () => {
    const json = JSON.stringify(
      { rows: Array.from({ length: 200 }, (_, i) => ({ i, name: `row ${i}` })) },
      null,
      2,
    );
    expect(compact(json)?.length).toBeLessThan(json.length);
  });

  it("compacts repeated lines inside a large body", () => {
    const text = repeat("FATAL: could not open socket", 400);
    expect(compact(text)).toContain("more identical lines");
  });

  it("returns undefined for large output none of the passes can improve", () => {
    const text = Array.from({ length: 500 }, (_, i) => `a unique line number ${i}`).join("\n");
    expect(compact(text)).toBeUndefined();
  });
});

describe("collapseBlobs", () => {
  const blob = Buffer.from(Array.from({ length: 1500 }, (_, i) => (i * 37) % 256)).toString(
    "base64",
  );

  it("turns a long base64 run into its length and first characters", () => {
    const out = collapseBlobs(`<img src="data:image/png;base64,${blob}"> after`);
    expect(out).toBe(
      `<img src="data:image/png;base64,[encoded blob, ${blob.length} chars, starting ` +
        `${blob.slice(0, 12)}]"> after`,
    );
  });

  it("leaves a short run, prose, and a long run of one character", () => {
    expect(collapseBlobs(blob.slice(0, BLOB_MIN_CHARS - 1))).toBeUndefined();
    expect(collapseBlobs("plain words ".repeat(200))).toBeUndefined();
    expect(collapseBlobs("-".repeat(2_000))).toBeUndefined();
  });

  it("runs as one of the passes", () => {
    expect(compact(`payload: ${blob}`)).toContain("[encoded blob,");
  });
});
