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
// Big enough to pay for the cache write that masking it costs: the old result
// is most of a fixture's conversation.
const big = (lines = 7_000): string =>
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
    list.push({ role: "assistant", content: [{ type: "text", text: pad(i) }] });
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

// The turns themselves are small: the old result is what puts a fixture past
// MASK_THRESHOLD_TOKENS, so masking it is a step that pays.
const pad = (_turn = 1): string => "working on it";

function turns(count: number): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < count; i++) {
    out.push({ role: "user", content: `do the thing ${i}` });
    out.push({ role: "assistant", content: [{ type: "text", text: pad(i) }] });
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
    expect(resultText(list, 3)).toContain("7000 lines");
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

// A long first prompt, one old result of `size` characters, then twenty turns
// of `after` characters each: the rewrite a step would cost.
function weighed(size: number, after: number): Array<Record<string, unknown>> {
  const list: Array<Record<string, unknown>> = [
    { role: "user", content: "start" },
    {
      role: "assistant",
      content: [{ type: "tool_use", id: "w1", name: "Bash", input: { command: "cat log" } }],
    },
    {
      role: "user",
      content: [{ type: "tool_result", tool_use_id: "w1", content: big(size / 20) }],
    },
  ];
  for (let i = 0; i < 20; i++) {
    list.push({ role: "assistant", content: [{ type: "text", text: "y".repeat(after) }] });
    list.push({ role: "user", content: `next ${i}` });
  }
  return list;
}

describe("superseded harness notes", () => {
  // A conversation whose big old result makes a step pay, with a harness note
  // on every typed turn: a tokens-left count, and an instruction given once.
  const noted = (): Array<Record<string, unknown>> => {
    const list = pairs(20);
    list.splice(2, 0, {
      role: "assistant",
      content: [{ type: "tool_use", id: "t1", name: "Bash", input: { command: "cat log" } }],
    });
    list.splice(3, 0, {
      role: "user",
      content: [{ type: "tool_result", tool_use_id: "t1", content: big() }],
    });
    list.forEach((entry, index) => {
      if (entry.role !== "user" || index === 3) return;
      (entry.content as unknown[]).push({
        type: "text",
        text: `<total_tokens>${1000 - index} tokens left</total_tokens>`,
      });
    });
    (list[0]!.content as unknown[]).push({
      type: "text",
      text: "<system-reminder>\nAlways answer in French.\n</system-reminder>",
    });
    return list;
  };
  const notes = (list: unknown[], kind: string) =>
    list.flatMap((entry, index) =>
      ((entry as { content: unknown }).content as Array<{ text?: string }>)
        .filter((block) => block.text?.includes(kind))
        .map(() => index),
    );

  it("drops old notes a newer one of their kind replaces, and keeps the newest", () => {
    const list = noted();
    const shaped = shapeRequest("anthropic", { messages: list })!;
    const before = notes(list, "tokens left");
    const after = notes(shaped.body.messages as unknown[], "tokens left");
    // The old part keeps its newest count; every recent one stays.
    expect(after.length).toBeLessThan(before.length);
    expect(after.length).toBeGreaterThan(1);
    expect(before.slice(-10).every((index) => after.includes(index))).toBe(true);
    // An instruction given once has nothing newer, so it stays.
    expect(notes(shaped.body.messages as unknown[], "French")).toEqual([0]);
    // Each turn keeps its typed text.
    for (const entry of shaped.body.messages as Array<{ content: unknown[] }>)
      expect(entry.content.length).toBeGreaterThan(0);
  });

  it("never empties a turn that is nothing but notes", () => {
    const list = noted();
    list[4] = { role: "user", content: [{ type: "text", text: "<total_tokens>9</total_tokens>" }] };
    const shaped = shapeRequest("anthropic", { messages: list })!;
    expect((shaped.body.messages as Array<{ content: unknown[] }>)[4]!.content).toHaveLength(1);
  });

  // A tool loop with a tokens-left note on every result, and one reminder
  // given at turn 0 and again at turn 25: what a harness re-sends when its
  // instructions change. Early results are the biggest, as a session's first
  // look around usually is, so masking them pays for the rewrite even at the
  // hour-long cache's price and the steps are taken.
  const loop = (turns: number): Array<Record<string, unknown>> => {
    const list: Array<Record<string, unknown>> = [];
    for (let i = 0; i < turns; i++) {
      const output = big(Math.max(10, 6000 - i * 150));
      const content: unknown[] =
        i === 0
          ? [{ type: "text", text: "do the thing" }]
          : [{ type: "tool_result", tool_use_id: `t${i - 1}`, content: output }];
      content.push({ type: "text", text: `<total_tokens>${9000 - i} left</total_tokens>` });
      if (i === 0 || i === 25)
        content.push({
          type: "text",
          text: `<system-reminder>\nAttribution: v${i}\n</system-reminder>`,
        });
      list.push({ role: "user", content });
      list.push({
        role: "assistant",
        content: [{ type: "tool_use", id: `t${i}`, name: "Bash", input: { command: `ls ${i}` } }],
      });
    }
    // A request ends on the user's turn.
    list.pop();
    return list;
  };

  it("never changes a message before the previous cutoff on a step", () => {
    // Every length from short to long, as the conversation grows; each step
    // must leave the turns the request before it had masked byte for byte.
    let before: { messages: unknown[]; cutoff: number } | undefined;
    let steps = 0;
    for (let turns = 15; turns <= 60; turns++) {
      const shaped = shapeRequest("anthropic", { messages: loop(turns) });
      const messages = (shaped?.body.messages ?? loop(turns)) as unknown[];
      const cutoff = shaped?.step?.to ?? before?.cutoff ?? 0;
      if (shaped?.step && before && before.cutoff > 0) {
        steps++;
        expect(shaped.step.from).toBe(before.cutoff);
        let turn = 0;
        for (let at = 0; at < before.messages.length; at++) {
          if ((messages[at] as { role: string }).role === "assistant") turn++;
          if (turn > before.cutoff) break;
          expect(JSON.stringify(messages[at])).toBe(JSON.stringify(before.messages[at]));
        }
      }
      before = { messages, cutoff };
    }
    // The step from 10 to 30, the one with a cutoff before it, takes the
    // reminder at turn 25 into the old part.
    expect(steps).toBeGreaterThanOrEqual(1);
  });

  it("is pure, and leaves a short conversation alone", () => {
    const list = noted();
    expect(JSON.stringify(shapeRequest("anthropic", { messages: list }))).toBe(
      JSON.stringify(shapeRequest("anthropic", { messages: noted() })),
    );
    expect(shapeRequest("anthropic", { messages: list.slice(0, 6) })).toBeUndefined();
  });
});

describe("the cost of a step", () => {
  const hour = [{ type: "text", text: "sys", cache_control: { type: "ephemeral", ttl: "1h" } }];

  it("masks nothing when the rewrite after it costs more than it saves", () => {
    // About 40k tokens saved, read back over twenty turns, against twenty
    // turns of 5k tokens each to write again.
    expect(shapeRequest("anthropic", { messages: weighed(160_000, 20_000) })).toBeUndefined();
    expect(shapeRequest("anthropic", { messages: weighed(160_000, 10) })?.masked).toBe(1);
  });

  it("counts a read at what the model charges for one", () => {
    // Worth it where a read is a tenth of input (Sonnet 5.5), not where it is
    // a twentieth (Opus 5.5): there the masked tokens save half as much.
    const list = weighed(160_000, 5_000);
    expect(shapeRequest("anthropic", { model: "claude-sonnet-5-5", messages: list })?.masked).toBe(
      1,
    );
    expect(shapeRequest("anthropic", { model: "claude-opus-5-5", messages: list })).toBeUndefined();
    // A cheap step is still taken on Opus 5.5.
    const cheap = weighed(160_000, 10);
    expect(shapeRequest("anthropic", { model: "claude-opus-5-5", messages: cheap })?.masked).toBe(
      1,
    );
  });

  it("decides a step the same whichever cache lifetime the markers ask for", () => {
    // About 80k of reads saved against 57k of turns to rewrite: worth it at
    // 1.25x, not at the hour-long cache's 2x. A session that switches between
    // 1h and 5m must not see its past steps move, so both are priced at 2x.
    const list = weighed(160_000, 12_000);
    const short = [{ type: "text", text: "sys", cache_control: { type: "ephemeral" } }];
    expect(shapeRequest("anthropic", { system: hour, messages: list })).toBeUndefined();
    expect(shapeRequest("anthropic", { system: short, messages: list })).toBeUndefined();
    expect(shapeRequest("anthropic", { messages: list })).toBeUndefined();
    // And a step that pays at 2x is taken in both.
    const cheap = weighed(160_000, 10);
    expect(shapeRequest("anthropic", { system: hour, messages: cheap })?.masked).toBe(1);
    expect(shapeRequest("anthropic", { system: short, messages: cheap })?.masked).toBe(1);
  });

  it("keeps a step it took, however much comes after", () => {
    const first = weighed(160_000, 10);
    const masked = shapeRequest("anthropic", { messages: first });
    expect(masked?.masked).toBe(1);
    // Turns big enough that the step would not pay if it were decided now.
    const later = first.concat(
      Array.from({ length: 10 }, (_, i) => [
        { role: "assistant", content: [{ type: "text", text: "z".repeat(80_000) }] },
        { role: "user", content: `more ${i}` },
      ]).flat(),
    );
    const again = shapeRequest("anthropic", { messages: later });
    // The cutoff's cache marker moves with the cutoff; what it marks does not.
    const unmarked = (list: unknown) =>
      JSON.stringify(list, (key, value) => (key === "cache_control" ? undefined : value));
    expect(unmarked((again?.body.messages as unknown[]).slice(0, first.length))).toBe(
      unmarked(masked?.body.messages),
    );
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
        content: [{ type: "output_text", text: pad(i) }],
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
      input.push({ type: "message", role: "assistant", content: pad(i) });
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
  // One big old result, so the step pays and carries the small ones with it.
  const carried = [call("b0", "Bash", { command: "cat big.log" }), result("b0", big())];
  list.splice(2, 0, ...carried, ...(early as Array<Record<string, unknown>>));
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
    expect(shaped?.masked).toBe(2);
    expect(String(contentAt(shaped!.body.messages, 5))).toContain("and 2 images earlier");
    expect(shaped!.savedChars).toBeGreaterThan(10_000);
  });

  it("leaves a recent one for the model to look at", () => {
    const list = around([], [call("t9", "Screenshot", {}), result("t9", [picture])]);
    const out = shapeRequest("anthropic", { messages: list })!.body.messages as unknown[];
    expect(contentAt(out, out.length - 1)).toEqual([picture]);
  });
});

describe("repeated outputs", () => {
  const output = Array.from({ length: 300 }, (_, i) => `file line ${i}`).join("\n");

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
      "[same output as Read `/w/a.ts` earlier in this session: 300 lines",
    );
  });

  it("sends a repeat whole once its first copy is masked", () => {
    const early = [call("a", "Read", { file_path: "/w/a.ts" }), result("a", output)];
    const late = [call("b", "Read", { file_path: "/w/a.ts" }), result("b", output)];
    const shaped = shapeRequest("anthropic", { messages: around(early, late) });
    expect(shaped?.masked).toBe(2);
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
    expect(shapeRequest("anthropic", { messages: around([], late) })?.deduped).toBe(0);
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
    expect(shaped?.masked).toBe(2);
    const out = shaped!.body.messages as unknown[];
    const old = ((at(out, 4).content as Array<Record<string, unknown>>)[0] ?? {}).input;
    expect(old).toEqual({
      file_path: "/w/a.ts",
      content: expect.stringContaining("The call ran with the full text"),
    });
    expect(JSON.stringify(at(out, out.length - 2))).toContain("const x = 1;");
    expect(INPUT_MIN_CHARS).toBeGreaterThan(0);
  });

  it("notes an old shell command from 400 characters, and keeps a short one", () => {
    const long = `for f in src/*.ts; do ${"echo $f; ".repeat(45)}done`;
    const early = [
      call("c1", "Bash", { command: long }),
      result("c1", "ok"),
      call("c2", "Bash", { command: "ls src" }),
      result("c2", "ok"),
    ];
    const body = JSON.stringify(shapeRequest("anthropic", { messages: around(early, []) })?.body);
    expect(long.length).toBeGreaterThanOrEqual(400);
    expect(long.length).toBeLessThan(1_000);
    expect(body).not.toContain(long);
    expect(body).toContain('"command":"ls src"');
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
    // A big old chat result, so the step pays.
    const carried = [
      { role: "assistant", tool_calls: [{ id: "c0", function: { name: "cat", arguments: "{}" } }] },
      { role: "tool", tool_call_id: "c0", content: big() },
    ];
    const good = JSON.stringify({ path: "/w/a.ts", content: file });
    const shaped = shapeRequest("chat", { messages: around([...carried, args(good)], []) });
    expect(shaped?.masked).toBe(2);
    expect(JSON.stringify(shaped?.body)).not.toContain("const x = 1;");
    const broken = `{"content": "${"x".repeat(INPUT_MIN_CHARS)}`;
    const kept = shapeRequest("chat", { messages: around([...carried, args(broken)], []) });
    expect(kept?.masked).toBe(1);
    expect(JSON.stringify(kept?.body)).toContain(JSON.stringify(broken).slice(1, -1));
  });

  it("masks a Responses call's arguments and a custom call's input", () => {
    const input: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 20; i++) {
      input.push({ type: "message", role: "user", content: "go" });
      input.push({ type: "message", role: "assistant", content: pad(i) });
    }
    const args = JSON.stringify({ content: file });
    input.splice(2, 0, { type: "function_call", call_id: "r1", name: "write", arguments: args });
    input.splice(3, 0, {
      type: "custom_tool_call",
      call_id: "r2",
      name: "apply_patch",
      input: file,
    });
    input.splice(4, 0, { type: "function_call", call_id: "r0", name: "cat", arguments: "{}" });
    input.splice(5, 0, { type: "function_call_output", call_id: "r0", output: big() });
    const shaped = shapeRequest("responses", { input });
    expect(shaped?.masked).toBe(3);
    expect(JSON.stringify(shaped?.body)).not.toContain("const x = 1;");
  });
});

describe("old thinking", () => {
  const thought = { type: "thinking", thinking: "t".repeat(2_000), signature: "sig" };
  const hidden = { type: "redacted_thinking", data: "d".repeat(500) };
  const said = { type: "text", text: "done" };

  it("drops an old turn's thinking whole, and keeps a recent turn's", () => {
    const early = [{ role: "assistant", content: [thought, hidden, said] }];
    const late = [{ role: "assistant", content: [thought, said] }];
    const shaped = shapeRequest("anthropic", { messages: around(early, late) });
    const out = shaped!.body.messages as Array<Record<string, unknown>>;
    expect(at(out, 4).content).toEqual([said]);
    expect(out.at(-1)?.content).toEqual([thought, said]);
    expect(shaped!.savedChars).toBeGreaterThan(2_500);
  });

  it("keeps the thinking of a turn that has nothing else", () => {
    const early = [{ role: "assistant", content: [thought] }];
    const out = shapeRequest("anthropic", { messages: around(early, []) })!.body.messages;
    expect(at(out, 4).content).toEqual([thought]);
  });
});

describe("old chat reasoning", () => {
  const reasoning = "r".repeat(2_000);
  // A big old chat result, so the step pays.
  const carried = [
    { role: "assistant", tool_calls: [{ id: "c0", function: { name: "cat", arguments: "{}" } }] },
    { role: "tool", tool_call_id: "c0", content: big() },
  ];
  const reasoned = (extra: Record<string, unknown>) => ({
    role: "assistant",
    content: "done",
    reasoning_content: reasoning,
    ...extra,
  });

  it("drops an old turn's reasoning in every field, and keeps a recent turn's", () => {
    const details = [{ type: "reasoning.encrypted", data: "e".repeat(500) }];
    const early = [reasoned({ reasoning: "", reasoning_details: details })];
    const late = [reasoned({})];
    const shaped = shapeRequest("chat", { messages: around([...carried, ...early], late) });
    const out = shaped!.body.messages as Array<Record<string, unknown>>;
    // An empty field is left as it came; only the two with something in them count.
    expect(at(out, 6)).toEqual({ role: "assistant", content: "done", reasoning: "" });
    expect(out.at(-1)).toEqual(late[0]!);
    expect(shaped!.masked).toBe(3);
    expect(shaped!.savedChars).toBeGreaterThan(2_500);
  });

  it("keeps the reasoning of a turn that says and calls nothing", () => {
    const early = [{ role: "assistant", content: null, reasoning_content: reasoning }];
    const out = shapeRequest("chat", { messages: around([...carried, ...early], []) })!.body
      .messages;
    expect(at(out, 6).reasoning_content).toBe(reasoning);
  });

  it("drops it beside a call, and shapes the same body the same way twice", () => {
    const early = [
      reasoned({
        content: null,
        tool_calls: [{ id: "c1", function: { name: "ls", arguments: "{}" } }],
      }),
      { role: "tool", tool_call_id: "c1", content: "a.ts" },
    ];
    const body = { messages: around([...carried, ...early], []) };
    const first = JSON.stringify(shapeRequest("chat", body)?.body);
    expect(first).not.toContain(reasoning);
    expect(first).toContain('"name":"ls"');
    expect(JSON.stringify(shapeRequest("chat", body)?.body)).toBe(first);
  });
});

describe("small old results", () => {
  it("masks one from MASK_MIN_CHARS, with a stub shorter than it", () => {
    // A stub quotes at most 80 characters of the command, however long.
    const small = "s".repeat(MASK_MIN_CHARS);
    const long = { command: `echo ${"c".repeat(MASK_MIN_CHARS)}` };
    const early = [call("s1", "Bash", long), result("s1", small)];
    const shaped = shapeRequest("anthropic", { messages: around(early, []) });
    const stub = String(contentAt(shaped!.body.messages, 5));
    expect(stub).toContain("[masked");
    expect(stub.length).toBeLessThan(MASK_MIN_CHARS);
  });
});
