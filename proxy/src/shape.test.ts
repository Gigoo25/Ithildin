import { describe, expect, it } from "bun:test";
import {
  MASK_KEEP_TURNS,
  MASK_MIN_CHARS,
  MASK_STEP_TURNS,
  MASK_THRESHOLD_TOKENS,
  DEDUPE_MIN_CHARS,
  INPUT_MIN_CHARS,
  shapingOn,
  shapeRequest,
} from "./shape.ts";

// A tool result big enough to be worth a stub.
const big = (lines = 60): string =>
  Array.from({ length: lines }, (_, i) => `line ${i} of output`).join("\n");

// A result the passes can improve: a JSON document big enough to be worth
// minifying, which is what a verbose API or fetch returns.
const verbose = (rows = 60): string =>
  JSON.stringify(
    { records: Array.from({ length: rows }, (_, i) => ({ id: i, name: `row ${i}` })) },
    null,
    2,
  );

// Turns of two messages each, so a message index is half a turn count and a
// fixture can place a call inside or outside the cutoff on purpose.
function pairs(count: number): Array<Record<string, unknown>> {
  const list: Array<Record<string, unknown>> = [];
  for (let i = 0; i < count; i++) {
    list.push({ role: "user", content: [{ type: "text", text: `do the thing ${i}` }] });
    list.push({ role: "assistant", content: [{ type: "text", text: pad() }] });
  }
  return list;
}

// A tool_use past the cutoff, so its result is compacted rather than stubbed.
// With twenty pairs the cutoff lands on turn ten, so a call in the last pair is
// recent: it gets the passes, while one near the start would be stubbed.
function turnsWithFreshResult(): Array<Record<string, unknown>> {
  const list = pairs(MASK_KEEP_TURNS * 2);
  const at = list.length - 2;
  list.splice(at, 0, {
    role: "assistant",
    content: [
      { type: "tool_use", id: "t9", name: "WebFetch", input: { url: "https://example.invalid" } },
    ],
  });
  list.splice(at + 1, 0, {
    role: "user",
    content: [{ type: "tool_result", tool_use_id: "t9", content: verbose() }],
  });
  // The result is the second-to-last message: one assistant turn follows it.
  FRESH_RESULT_INDEX = at + 1;
  return list;
}

// Where turnsWithFreshResult put the result, so a test can read it back.
let FRESH_RESULT_INDEX = 0;

// Real turns carry real context. Padding each one is what puts a fixture past
// MASK_THRESHOLD_TOKENS: twenty turns of 6k characters is 30k tokens, so the
// cutoff is live and the tests are about masking rather than about the gate.
const TURN_CHARS = 6_000;
const pad = (): string => `working on it ${"x".repeat(TURN_CHARS)}`;

function turns(count: number): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < count; i++) {
    out.push({ role: "user", content: `do the thing ${i}` });
    out.push({ role: "assistant", content: [{ type: "text", text: pad() }] });
  }
  return out;
}

// The messages a shaped body came back with, read by index.
function at(list: unknown, index: number): Record<string, unknown> {
  const entry = (list as Array<Record<string, unknown>>)[index];
  if (!entry) throw new Error(`no message at ${index}`);
  return entry;
}

// A tool result's text, whichever field the format holds it in.
function resultText(list: unknown, index: number, field = "content"): string {
  const value = at(list, index)[field];
  if (Array.isArray(value)) return String((value[0] as Record<string, unknown>)?.content ?? "");
  return String(value ?? "");
}

describe("kill switch", () => {
  it("is on unless the environment says otherwise", () => {
    expect(shapingOn({})).toBe(true);
    expect(shapingOn({ ITHILDIN_SHAPE: "on" })).toBe(true);
    for (const value of ["off", "OFF", " raw ", "false", "0"]) {
      expect(shapingOn({ ITHILDIN_SHAPE: value })).toBe(false);
    }
  });
});

describe("anthropic requests", () => {
  const messages = (results: number): Array<Record<string, unknown>> => {
    const list = turns(20);
    list.splice(2, 0, {
      role: "assistant",
      content: [
        { type: "tool_use", id: "t1", name: "Bash", input: { command: "cat /srv/data.log" } },
      ],
    });
    list.splice(3, 0, {
      role: "user",
      content: [{ type: "tool_result", tool_use_id: "t1", content: big() }],
    });
    for (let i = 1; i < results; i++) {
      const id = `t${i + 1}`;
      list.splice(2 + i * 2, 0, {
        role: "assistant",
        content: [{ type: "tool_use", id, name: "Read", input: { file_path: "/w/repo/a.ts" } }],
      });
      list.splice(3 + i * 2, 0, {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: id, content: big() }],
      });
    }
    return list;
  };

  it("masks an old result and keeps everything else", () => {
    const shaped = shapeRequest("anthropic", { messages: messages(2) });
    expect(shaped?.masked).toBe(2);
    expect(shaped?.savedChars).toBeGreaterThan(0);
    const list = shaped!.body.messages;
    expect(resultText(list, 3)).toContain("[masked to save context: Bash `cat /srv/data.log`");
    expect(resultText(list, 3)).toContain("60 lines");
    // The tool_use that named it, and the typed turns, are untouched.
    expect(JSON.stringify(list)).not.toContain("line 0 of output");
  });

  it("leaves a recent result whole", () => {
    // One old result, then twenty turns: only the old one is past the cutoff.
    const list = messages(1);
    const shaped = shapeRequest("anthropic", { messages: list });
    expect(shaped?.masked).toBe(1);
    expect(JSON.stringify(shaped!.body.messages)).not.toContain("line 5 of output");
  });

  it("masks nothing in a short conversation", () => {
    expect(shapeRequest("anthropic", { messages: messages(1).slice(0, 8) })).toBeUndefined();
    expect(shapeRequest("anthropic", { messages: turns(3) })).toBeUndefined();
  });

  it("keeps a small result, and one holding more than text and images", () => {
    const small = turns(20);
    small.splice(2, 0, {
      role: "assistant",
      content: [{ type: "tool_use", id: "t1", name: "Bash", input: { command: "ls" } }],
    });
    small.splice(3, 0, {
      role: "user",
      content: [{ type: "tool_result", tool_use_id: "t1", content: "one line" }],
    });
    expect(shapeRequest("anthropic", { messages: small })).toBeUndefined();

    const image = structuredClone(small);
    const blocks = (at(image, 3).content ?? []) as Array<Record<string, unknown>>;
    const first = blocks[0] ?? {};
    first.content = [{ type: "document", source: { data: big() } }];
    at(image, 3).content = blocks;
    expect(shapeRequest("anthropic", { messages: image })).toBeUndefined();
  });

  it("says nothing about when, so the stub is the same every request", () => {
    const first = shapeRequest("anthropic", { messages: messages(2) });
    const later = shapeRequest("anthropic", { messages: messages(2) });
    expect(JSON.stringify(first)).toBe(JSON.stringify(later));
    expect(resultText(first!.body.messages, 3)).not.toMatch(
      /turns? ago|later|earlier in this turn/,
    );
  });

  it("names the call's argument, or the tool alone when there is none", () => {
    const named = (args: Record<string, unknown>): string => {
      const list = turns(20);
      list.splice(2, 0, {
        role: "assistant",
        content: [{ type: "tool_use", id: "t1", name: "Grep", input: args }],
      });
      list.splice(3, 0, {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "t1", content: big() }],
      });
      const shaped = shapeRequest("anthropic", { messages: list });
      return String(
        (at(shaped!.body.messages, 3).content as Array<Record<string, unknown>>)[0]?.content ?? "",
      );
    };
    // Each field the stub can name, in the order it looks for them.
    expect(named({ pattern: "needle" })).toContain("Grep `needle`");
    expect(named({ url: "https://example.invalid/a" })).toContain(
      "Grep `https://example.invalid/a`",
    );
    expect(named({ path: "/w/repo/a.ts" })).toContain("Grep `/w/repo/a.ts`");
    // A long value is cut, and a call with nothing to name keeps the tool.
    expect(named({ pattern: "x".repeat(200) })).toContain("…`");
    expect(named({ unrelated: true })).toContain("masked to save context: Grep returned");
    expect(named({ pattern: "a\n  b" })).toContain("Grep `a b`");
  });

  it("compacts a recent result rather than stubbing it", () => {
    // rtk already condensed command output at the source; what arrives
    // uncondensed is what it does not know, and those still get the passes.
    // Enough turns that the cutoff is live, with the call placed in the last one
    // so its result is still recent: the passes run instead of the stub.
    const list = turnsWithFreshResult();
    const shaped = shapeRequest("anthropic", { messages: list });
    expect(shaped?.compacted).toBe(1);
    expect(shaped?.masked).toBe(0);
    // Every record survives: only the duplicate bytes went. The result is the
    // message the fixture put it in, which is `at + 1` in the original list.
    const text = resultText(shaped!.body.messages, FRESH_RESULT_INDEX);
    expect(text).toContain('"id":0');
    expect(text).toContain('"id":59');
  });

  it("is a pure function of the body: same input, same bytes", () => {
    const body = { messages: messages(2) };
    expect(JSON.stringify(shapeRequest("anthropic", body))).toBe(
      JSON.stringify(shapeRequest("anthropic", structuredClone(body))),
    );
    // Nothing about the request was touched in place.
    expect(JSON.stringify(body.messages)).toContain("line 0 of output");
  });

  it("moves the cutoff in whole steps, so the prefix stays stable", () => {
    const masked = (list: unknown[]): string => {
      const shaped = shapeRequest("anthropic", { messages: list });
      return JSON.stringify((shaped?.body.messages as unknown[]).slice(0, 8));
    };
    // Five more turns land inside the same step, so the masked prefix the
    // provider caches is byte-identical: that is what keeps the cache.
    expect(masked(messages(2).concat(turns(5)))).toBe(masked(messages(2)));
    expect(MASK_STEP_TURNS).toBeGreaterThan(0);
    expect(MASK_KEEP_TURNS).toBeGreaterThan(0);
  });
});

describe("chat requests", () => {
  it("masks an old tool message by tool_call_id", () => {
    const list: Array<Record<string, unknown>> = turns(20);
    list.splice(2, 0, {
      role: "assistant",
      content: null,
      tool_calls: [
        { id: "c1", function: { name: "bash", arguments: JSON.stringify({ command: "git log" }) } },
      ],
    });
    list.splice(3, 0, { role: "tool", tool_call_id: "c1", content: big() });
    const shaped = shapeRequest("chat", { messages: list });
    expect(shaped?.masked).toBe(1);
    const out = shaped!.body.messages;
    expect(resultText(out, 3)).toContain("bash `git log`");
    expect(resultText(out, 3)).toContain("[masked to save context:");
  });

  it("leaves an assistant message alone", () => {
    const list = turns(20);
    list.splice(2, 0, { role: "tool", tool_call_id: "c9", content: big() });
    // No matching call, so the stub names the tool, and it is still masked.
    const shaped = shapeRequest("chat", { messages: list });
    expect(resultText(shaped!.body.messages, 2)).toContain("masked to save context: tool returned");
  });
});

describe("responses requests", () => {
  it("masks an old function_call_output by call_id", () => {
    const input: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 20; i++) {
      input.push({ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] });
      input.push({
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text: pad() }],
      });
    }
    input.splice(2, 0, {
      type: "function_call",
      call_id: "r1",
      name: "bash",
      arguments: '{"command":"ls"}',
    });
    input.splice(3, 0, { type: "function_call_output", call_id: "r1", output: big() });
    const shaped = shapeRequest("responses", { input });
    expect(shaped?.masked).toBe(1);
    expect(shaped && "input" in shaped.body).toBe(true);
    expect(resultText(shaped!.body.input, 3, "output")).toContain("bash `ls`");
  });

  it("masks a custom_tool_call_output too", () => {
    const input: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 20; i++) {
      input.push({ type: "message", role: "user", content: "go" });
      input.push({ type: "message", role: "assistant", content: pad() });
    }
    input.splice(3, 0, { type: "custom_tool_call_output", call_id: "r1", output: big() });
    expect(shapeRequest("responses", { input })?.masked).toBe(1);
  });
});

describe("requests with nothing to shape", () => {
  it("returns undefined rather than an empty change", () => {
    expect(shapeRequest("anthropic", {})).toBeUndefined();
    expect(shapeRequest("chat", { messages: "not a list" })).toBeUndefined();
    expect(shapeRequest("responses", { input: { nope: true } })).toBeUndefined();
  });

  it("copes with entries that are not objects", () => {
    const messages = turns(20).concat([null, "text", 7] as never[]);
    expect(shapeRequest("anthropic", { messages })).toBeUndefined();
  });

  it("only shapes a conversation past the token threshold", () => {
    // Twenty turns, but every message tiny: turns alone are not enough.
    const small = turns(20).map((message) => ({ ...message, content: "x" }));
    expect(shapeRequest("anthropic", { messages: small })).toBeUndefined();
    expect(MASK_THRESHOLD_TOKENS).toBeGreaterThan(0);
    expect(MASK_MIN_CHARS).toBeGreaterThan(0);
  });
});

// Twenty padded turns, so the cutoff sits at ten, with `early` spliced in at
// turn two (old) and `late` appended after the last turn (recent).
function around(early: unknown[], late: unknown[]): Array<Record<string, unknown>> {
  const list = turns(20);
  list.splice(2, 0, ...(early as Array<Record<string, unknown>>));
  return list.concat(late as Array<Record<string, unknown>>);
}

const call = (id: string, name: string, input: unknown) => ({
  role: "assistant",
  content: [{ type: "tool_use", id, name, input }],
});
const result = (id: string, content: unknown) => ({
  role: "user",
  content: [{ type: "tool_result", tool_use_id: id, content }],
});
// The first tool_result's content in the message at `index`.
const contentAt = (list: unknown, index: number): unknown =>
  ((at(list, index).content as Array<Record<string, unknown>>)[0] ?? {}).content;

describe("a conversation too short to shape", () => {
  it("leaves its first turn's result whole, however big", () => {
    // One turn, and a result big enough to pass the token threshold alone.
    const huge = "word ".repeat(MASK_THRESHOLD_TOKENS);
    const messages: unknown[] = [{ role: "user", content: "go" }, call("t1", "Bash", {})];
    messages.push(result("t1", huge));
    const shaped = shapeRequest("anthropic", { messages });
    expect(JSON.stringify(shaped?.body ?? {})).not.toContain("[masked");
  });
});

describe("images in tool results", () => {
  const picture = { type: "image", source: { type: "base64", data: "AAAA" } };

  it("masks an old one, and names how many the stub replaced", () => {
    const list = around([call("t1", "Screenshot", {}), result("t1", [picture, picture])], []);
    const shaped = shapeRequest("anthropic", { messages: list });
    expect(shaped?.masked).toBe(1);
    expect(String(contentAt(shaped!.body.messages, 3))).toContain("and 2 images earlier");
    expect(shaped!.savedChars).toBeGreaterThan(10_000);
  });

  it("leaves a recent one for the model to look at", () => {
    const list = around([], [call("t9", "Screenshot", {}), result("t9", [picture])]);
    expect(shapeRequest("anthropic", { messages: list })).toBeUndefined();
  });
});

describe("repeated outputs", () => {
  const output = "same file contents\n".repeat(60);

  it("notes a repeat of an output still whole above it, and keeps the first", () => {
    const late = [
      call("a", "Read", { file_path: "/w/a.ts" }),
      result("a", output),
      call("b", "Read", { file_path: "/w/a.ts" }),
      result("b", output),
    ];
    const list = around([], late);
    const shaped = shapeRequest("anthropic", { messages: list });
    expect(shaped?.deduped).toBe(1);
    const out = shaped!.body.messages as unknown[];
    expect(contentAt(out, out.length - 3)).toBe(output);
    expect(String(contentAt(out, out.length - 1))).toContain(
      "[same output as Read `/w/a.ts` earlier in this session: 61 lines",
    );
  });

  it("sends a repeat whole once its first copy is masked", () => {
    const early = [call("a", "Read", { file_path: "/w/a.ts" }), result("a", output)];
    const late = [call("b", "Read", { file_path: "/w/a.ts" }), result("b", output)];
    const shaped = shapeRequest("anthropic", { messages: around(early, late) });
    expect(shaped?.masked).toBe(1);
    expect(shaped?.deduped).toBe(0);
    const out = shaped!.body.messages as unknown[];
    expect(contentAt(out, out.length - 1)).toBe(output);
  });

  it("leaves a short repeat alone", () => {
    const short = "x".repeat(DEDUPE_MIN_CHARS - 1);
    const late = [
      call("a", "Bash", {}),
      result("a", short),
      call("b", "Bash", {}),
      result("b", short),
    ];
    expect(shapeRequest("anthropic", { messages: around([], late) })).toBeUndefined();
  });
});

describe("old call inputs", () => {
  const file = "const x = 1;\n".repeat(200);

  it("masks a long string in an old call, and leaves a recent call whole", () => {
    const early = [
      call("w1", "Write", { file_path: "/w/a.ts", content: file }),
      result("w1", "ok"),
    ];
    const late = [call("w2", "Write", { file_path: "/w/b.ts", content: file }), result("w2", "ok")];
    const shaped = shapeRequest("anthropic", { messages: around(early, late) });
    expect(shaped?.masked).toBe(1);
    const out = shaped!.body.messages as unknown[];
    const old = ((at(out, 2).content as Array<Record<string, unknown>>)[0] ?? {}).input;
    expect(old).toEqual({
      file_path: "/w/a.ts",
      content: expect.stringContaining("The call ran with the full text"),
    });
    expect(JSON.stringify(at(out, out.length - 2))).toContain("const x = 1;");
    expect(INPUT_MIN_CHARS).toBeGreaterThan(0);
  });

  it("reaches a list of edits inside an input", () => {
    const edits = [{ old_string: file, new_string: file }];
    const early = [call("e1", "MultiEdit", { file_path: "/w/a.ts", edits }), result("e1", "ok")];
    const shaped = shapeRequest("anthropic", { messages: around(early, []) });
    expect(JSON.stringify(shaped?.body)).not.toContain("const x = 1;");
  });

  it("masks chat arguments, and leaves ones that do not parse", () => {
    const args = (text: string) => ({
      role: "assistant",
      content: null,
      tool_calls: [{ id: "c1", function: { name: "write", arguments: text } }],
    });
    const good = JSON.stringify({ path: "/w/a.ts", content: file });
    const shaped = shapeRequest("chat", { messages: around([args(good)], []) });
    expect(shaped?.masked).toBe(1);
    expect(JSON.stringify(shaped?.body)).not.toContain("const x = 1;");
    const broken = `{"content": "${"x".repeat(INPUT_MIN_CHARS)}`;
    expect(shapeRequest("chat", { messages: around([args(broken)], []) })).toBeUndefined();
  });

  it("masks a Responses call's arguments and a custom call's input", () => {
    const input: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 20; i++) {
      input.push({ type: "message", role: "user", content: "go" });
      input.push({ type: "message", role: "assistant", content: pad() });
    }
    const args = JSON.stringify({ content: file });
    input.splice(2, 0, { type: "function_call", call_id: "r1", name: "write", arguments: args });
    input.splice(3, 0, {
      type: "custom_tool_call",
      call_id: "r2",
      name: "apply_patch",
      input: file,
    });
    const shaped = shapeRequest("responses", { input });
    expect(shaped?.masked).toBe(2);
    expect(JSON.stringify(shaped?.body)).not.toContain("const x = 1;");
  });
});
