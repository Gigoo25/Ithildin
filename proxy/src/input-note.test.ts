import { describe, expect, it } from "bun:test";
import { holdsInputNote, NOTE_AS_INPUT } from "./input-note.ts";
import { blockedNotice, swapToolArguments } from "./redact.ts";

// The note as shaping wrote it while it cut old inputs.
const inputNote = (size: number) =>
  `[${size} more chars of this earlier call's input removed from the history to save ` +
  "context. The call ran with the full text; a new call needs its full text written out.]";

describe("an old input's note as a new call's input", () => {
  it("is found as a command, a file's content or one side of an edit", () => {
    expect(holdsInputNote({ command: inputNote(1298) })).toBe(true);
    expect(holdsInputNote({ file_path: "/w/a.py", content: ` ${inputNote(4005)}` })).toBe(true);
    const edits = [{ old_string: "x", new_string: inputNote(500) }];
    expect(holdsInputNote({ file_path: "/w/a.py", edits })).toBe(true);
  });

  it("is found closing the start of an old input, and as the note alone", () => {
    const noted = `git commit -m "${"x".repeat(185)}\n${inputNote(416)}`;
    expect(holdsInputNote({ command: noted })).toBe(true);
    expect(holdsInputNote({ command: `${noted}\n` })).toBe(true);
    const before = "[1298 chars of this earlier call's input removed from the history to save";
    expect(holdsInputNote({ command: `${before} context.]` })).toBe(true);
  });

  it("is not found in input that mentions it, or below the depth shaping cut", () => {
    const wording = "chars of this earlier call's input removed from the history";
    expect(holdsInputNote({ command: `grep -rn "${wording}" proxy/src` })).toBe(false);
    expect(holdsInputNote({ command: `echo "${inputNote(400)}" >> notes.md` })).toBe(false);
    expect(holdsInputNote({ command: "printf '%s' \"the decoder's _start\"" })).toBe(false);
    expect(holdsInputNote({ a: { b: { c: { d: { e: inputNote(400) } } } } })).toBe(false);
    expect(holdsInputNote(undefined)).toBe(false);
  });

  it("is not run, by any tool and under any tag", () => {
    const refused = swapToolArguments("bash", { command: inputNote(1298) }, new Set(), "toolu_n1");
    expect(refused).toEqual({ args: {}, swapped: 0, blocked: true });
    expect(blockedNotice("toolu_n1")).toBe(NOTE_AS_INPUT);
    const write = { file_path: "/w/a.py", content: inputNote(4005) };
    expect(swapToolArguments("Write", write, new Set(["all"]), "toolu_n2").blocked).toBe(true);
    expect(blockedNotice("toolu_n2")).toBe(NOTE_AS_INPUT);
    expect(swapToolArguments("bash", { command: "ls src" }, new Set()).blocked).toBeUndefined();
  });
});
