import { describe, expect, it } from "bun:test";
import { HEAD_CHARS, holdsInputNote, inputNote, notedInput, NOTE_AS_INPUT } from "./input-note.ts";
import { blockedNotice, swapToolArguments } from "./redact.ts";

describe("an old input's note as a new call's input", () => {
  it("is found as a command, a file's content or one side of an edit", () => {
    expect(holdsInputNote({ command: inputNote(1298) })).toBe(true);
    expect(holdsInputNote({ file_path: "/w/a.py", content: ` ${inputNote(4005)}` })).toBe(true);
    const edits = [{ old_string: "x", new_string: inputNote(500) }];
    expect(holdsInputNote({ file_path: "/w/a.py", edits })).toBe(true);
  });

  it("is found closing the start of an old input, and written by proxies before the start", () => {
    const old = `git commit -m "${"x".repeat(600)}"`;
    const noted = notedInput(old);
    expect(noted.startsWith(old.slice(0, HEAD_CHARS))).toBe(true);
    expect(noted).toContain(`[${old.length - HEAD_CHARS} more chars of this earlier call's`);
    expect(holdsInputNote({ command: noted })).toBe(true);
    expect(holdsInputNote({ command: `${noted}\n` })).toBe(true);
    const before = "[1298 chars of this earlier call's input removed from the history to save";
    expect(holdsInputNote({ command: `${before} context.]` })).toBe(true);
  });

  it("keeps a surrogate pair whole at the cut", () => {
    const noted = notedInput(`${"a".repeat(HEAD_CHARS - 1)}\u{1F600}${"b".repeat(400)}`);
    expect(noted.startsWith(`${"a".repeat(HEAD_CHARS - 1)}\n[402 more chars`)).toBe(true);
  });

  it("is not found in input that mentions it, or below the depth shaping masks", () => {
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
