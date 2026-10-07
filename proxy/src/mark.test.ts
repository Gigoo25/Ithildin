import { describe, expect, it } from "bun:test";
import { markBoundaries, markRoom, MARKERS_MAX } from "./mark.ts";
import { shapeRequest } from "./shape.ts";

const hour = { type: "ephemeral", ttl: "1h" };
const text = (words: string, marker?: object) => ({
  type: "text",
  text: words,
  ...(marker ? { cache_control: marker } : {}),
});
const said = (role: string, ...content: unknown[]) => ({ role, content });

// Where the markers sit in a list of messages: message index and block index.
function marks(messages: unknown[]): string[] {
  return messages.flatMap((message, at) => {
    const content = (message as { content: unknown }).content;
    if (!Array.isArray(content)) return [];
    return content.flatMap((block, i) => (block.cache_control ? [`${at}.${i}`] : []));
  });
}

describe("markRoom", () => {
  it("counts the markers left, and a system marker another makes redundant", () => {
    const tools = [{ name: "Bash", cache_control: hour }];
    expect(MARKERS_MAX).toBe(4);
    expect(markRoom({ system: [text("a", hour)], messages: [] })).toBe(3);
    // Claude Code: two adjacent system markers and one on the newest message.
    const claude = {
      system: [text("a", hour), text("b", hour)],
      messages: [said("user", text("c", hour))],
    };
    expect(markRoom(claude)).toBe(2);
    expect(markRoom({ ...claude, tools })).toBe(1);
  });
});

// The messages of a marked body.
const messagesOf = (body: Record<string, unknown>) => body.messages as unknown[];
const markerOf = (message: unknown, block: number) =>
  (message as { content: Array<{ cache_control: unknown }> }).content[block]!.cache_control;

describe("markBoundaries", () => {
  const messages = [
    said("user", text("one")),
    said("assistant", { type: "thinking", thinking: "t", signature: "s" }, text("two")),
    said("user", text("three", hour)),
  ];

  it("marks a boundary's last block with the TTL of the marker before it", () => {
    const out = messagesOf(
      markBoundaries({ system: [text("sys", hour)], messages }, messages, [1]),
    );
    expect(marks(out)).toEqual(["1.1", "2.0"]);
    expect(markerOf(out[1], 1)).toEqual(hour);
    // Pure: the list it was given is unchanged.
    expect(marks(messages)).toEqual(["2.0"]);
  });

  it("takes the TTL of the marker after it, or the default with none", () => {
    expect(markerOf(messagesOf(markBoundaries({ messages }, messages, [0]))[0], 0)).toEqual(hour);
    const plain = [said("user", text("one")), said("assistant", text("two"))];
    const out = messagesOf(markBoundaries({ messages: plain }, plain, [1]));
    expect(markerOf(out[1], 0)).toEqual({ type: "ephemeral" });
  });

  it("steps back past a message it cannot mark, and never respells a string", () => {
    const list = [
      said("user", text("one")),
      said("assistant", { type: "thinking", thinking: "t", signature: "s" }),
      said("user", text("")),
      { role: "user", content: "plain" },
    ];
    const out = messagesOf(markBoundaries({ messages: list }, list, [3]));
    expect(marks(out)).toEqual(["0.0"]);
    expect(out[3]).toBe(list[3]);
    // A message that already carries a marker is passed for the one before.
    expect(marks(messagesOf(markBoundaries({ messages }, messages, [2])))).toEqual(["1.1", "2.0"]);
  });

  it("marks two boundaries, and one where both fall on the same message", () => {
    const list = [
      said("user", text("a")),
      said("assistant", text("b")),
      said("user", text("c", hour)),
    ];
    expect(marks(messagesOf(markBoundaries({ messages: list }, list, [0, 1])))).toEqual([
      "0.0",
      "1.0",
      "2.0",
    ]);
    expect(marks(messagesOf(markBoundaries({ messages: list }, list, [1, 1])))).toEqual([
      "1.0",
      "2.0",
    ]);
  });

  it("frees the first of two system markers when it needs the room, and only then", () => {
    const list = [
      said("user", text("a")),
      said("assistant", text("b")),
      said("user", text("c", hour)),
    ];
    const system = [text("x", hour), text("y", hour)];
    const one = markBoundaries({ system, messages: list }, list, [0]);
    expect(one.system).toBe(system);
    const two = markBoundaries({ system, messages: list }, list, [0, 1]);
    expect(
      (two.system as Array<Record<string, unknown>>).map((block) => "cache_control" in block),
    ).toEqual([false, true]);
    expect(marks(messagesOf(two))).toEqual(["0.0", "1.0", "2.0"]);
    // Markers too far apart to stand for each other are both kept, and the
    // second boundary goes unmarked.
    const far = [text("x", hour), ...Array.from({ length: 25 }, () => text("p")), text("y", hour)];
    const apart = markBoundaries({ system: far, messages: list }, list, [0, 1]);
    expect(apart.system).toBe(far);
    expect(marks(messagesOf(apart))).toEqual(["0.0", "2.0"]);
  });

  it("leaves the body's messages as they came with no room or nothing to mark", () => {
    const tools = [{ name: "a", cache_control: hour }];
    const far = [text("a", hour), ...Array.from({ length: 25 }, () => text("p")), text("b", hour)];
    expect(
      marks(messagesOf(markBoundaries({ system: far, tools, messages }, messages, [1]))),
    ).toEqual(["2.0"]);
    expect(marks(messagesOf(markBoundaries({ messages }, messages, [])))).toEqual(["2.0"]);
    const strings = [{ role: "user", content: "plain" }, null];
    expect(messagesOf(markBoundaries({ messages: strings }, strings, [1]))).toEqual(strings);
  });
});

// A long Claude Code conversation: a big result in turn 1, and again in turn
// 11, so two cutoff steps are due; the agent's own markers on the system
// prompt and the newest message.
function conversation(turns: number, filler: number): Array<Record<string, unknown>> {
  const list: Array<Record<string, unknown>> = [said("user", text("start"))];
  for (let turn = 1; turn <= turns; turn++) {
    const id = `t${turn}`;
    list.push(said("assistant", { type: "tool_use", id, name: "Bash", input: { command: "ls" } }));
    const output = turn === 1 || turn === 11 ? "x".repeat(400_000) : "y".repeat(filler);
    list.push(said("user", { type: "tool_result", tool_use_id: id, content: output }));
  }
  const last = list.at(-1) as { content: Array<Record<string, unknown>> };
  last.content = [{ ...last.content[0], cache_control: hour }];
  return list;
}
const claude = (messages: unknown[]) => ({ system: [text("sys", hour)], messages });

describe("the cutoff marker", () => {
  it("marks where the previous request's cutoff ended, and where a step's ends", () => {
    // Turn 21 just arrived: the request before ended at turn 20, cut at 10,
    // and so is this one, so both boundaries are the same message.
    const list = conversation(21, 10);
    const out = shapeRequest("anthropic", claude(list))!.body.messages as unknown[];
    expect(marks(out)).toEqual(["20.0", `${list.length - 1}.0`]);
    // The first step has no earlier cutoff to read back, but writes its own.
    const first = conversation(20, 10);
    const stepped = shapeRequest("anthropic", claude(first))!.body.messages as unknown[];
    expect(marks(stepped)).toEqual(["20.0", `${first.length - 1}.0`]);
  });

  it("marks both the old boundary and the new one on a step", () => {
    // Turn 30: the request before was cut at 10, this one at 20.
    const list = conversation(30, 10);
    const system = [text("x", hour), text("y", hour)];
    const out = shapeRequest("anthropic", { system, messages: list })!.body;
    expect(marks(out.messages as unknown[])).toEqual(["20.0", "40.0", `${list.length - 1}.0`]);
    // The first system marker made room: the second stands for it.
    const kept = (out.system as Array<Record<string, unknown>>).map(
      (block) => "cache_control" in block,
    );
    expect(kept).toEqual([false, true]);
  });

  it("gives the same bytes twice", () => {
    const body = claude(conversation(21, 10));
    expect(JSON.stringify(shapeRequest("anthropic", body))).toBe(
      JSON.stringify(shapeRequest("anthropic", body)),
    );
  });

  it("lets a step pay that a rewrite of the whole conversation would not", () => {
    // Prose in turns 2-10 that masking never touches, about 40k tokens, and a
    // 10k-token result in turn 11: worth masking only if the step to 20 reads
    // the prose back rather than writing it again.
    const list: Array<Record<string, unknown>> = [said("user", text("start"))];
    for (let turn = 1; turn <= 30; turn++) {
      const id = `t${turn}`;
      const prose = turn >= 2 && turn <= 10 ? [text("p".repeat(18_000))] : [];
      const call = { type: "tool_use", id, name: "Bash", input: { command: "ls" } };
      list.push(said("assistant", ...prose, call));
      const output = turn === 1 ? "w".repeat(2_000_000) : turn === 11 ? "x".repeat(40_000) : "ok";
      list.push(said("user", { type: "tool_result", tool_use_id: id, content: output }));
    }
    const kept = (body: Record<string, unknown>) =>
      JSON.stringify(shapeRequest("anthropic", body)?.body.messages).includes("x".repeat(40_000));
    expect(kept(claude(list))).toBe(false);
    // With all four markers taken, the same step is not worth it.
    const system = [text("a", hour), text("b", hour), text("c", hour)];
    const tools = [{ name: "a", cache_control: hour }];
    expect(kept({ system, tools, messages: list })).toBe(true);
  });
});
