import { describe, expect, it } from "bun:test";
import { markBoundary, markRoom, MARKERS_MAX } from "./mark.ts";
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
  it("counts markers on tools, system and messages against the limit", () => {
    const system = [text("a", hour), text("b", hour)];
    const tools = [{ name: "Bash", cache_control: hour }];
    expect(markRoom({ system, messages: [] })).toBe(true);
    const full = { system, tools, messages: [said("user", text("c", hour))] };
    expect(MARKERS_MAX).toBe(4);
    expect(markRoom(full)).toBe(false);
  });
});

describe("markBoundary", () => {
  const messages = [
    said("user", text("one")),
    said("assistant", { type: "thinking", thinking: "t", signature: "s" }, text("two")),
    said("user", text("three", hour)),
  ];

  it("marks the boundary's last block with the TTL of the marker before it", () => {
    const body = { system: [text("sys", hour)], messages };
    const out = markBoundary(body, messages, 1);
    expect(marks(out)).toEqual(["1.1", "2.0"]);
    expect(
      (out[1] as { content: Array<{ cache_control: unknown }> }).content[1]!.cache_control,
    ).toEqual(hour);
    // Pure: the list it was given is unchanged.
    expect(marks(messages)).toEqual(["2.0"]);
  });

  it("takes the TTL of the marker after it when there is none before", () => {
    const out = markBoundary({ messages }, messages, 0);
    expect(
      (out[0] as { content: Array<{ cache_control: unknown }> }).content[0]!.cache_control,
    ).toEqual(hour);
  });

  it("marks with the default TTL when the request has no markers", () => {
    const plain = [said("user", text("one")), said("assistant", text("two"))];
    const out = markBoundary({ messages: plain }, plain, 1);
    expect(
      (out[1] as { content: Array<{ cache_control: unknown }> }).content[0]!.cache_control,
    ).toEqual({ type: "ephemeral" });
  });

  it("steps back past a message it cannot mark, and never respells a string", () => {
    const list = [
      said("user", text("one")),
      said("assistant", { type: "thinking", thinking: "t", signature: "s" }),
      said("user", text("")),
      { role: "user", content: "plain" },
    ];
    const out = markBoundary({ messages: list }, list, 3);
    expect(marks(out)).toEqual(["0.0"]);
    expect(out[3]).toBe(list[3]);
  });

  it("leaves a message alone that already carries a marker, and steps back", () => {
    expect(marks(markBoundary({ messages }, messages, 2))).toEqual(["1.1", "2.0"]);
  });

  it("leaves the list as it came with no room, no place, or nothing to mark", () => {
    const tools = [{ name: "a", cache_control: hour }];
    const full = { system: [text("a", hour), text("b", hour)], tools, messages };
    expect(markBoundary(full, messages, 1)).toBe(messages);
    expect(markBoundary({ messages }, messages, 3)).toBe(messages);
    const strings = [{ role: "user", content: "plain" }, null];
    expect(markBoundary({ messages: strings }, strings, 1)).toBe(strings);
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
  it("marks where the previous request's cutoff ended, and nowhere on a first step", () => {
    // Turn 21 just arrived: the request before ended at turn 20, cut at 10.
    const list = conversation(21, 10);
    const out = shapeRequest("anthropic", claude(list))!.body.messages as unknown[];
    expect(marks(out)).toEqual(["20.0", `${list.length - 1}.0`]);
    // On the first step there is no earlier cutoff to read back.
    const first = shapeRequest("anthropic", claude(conversation(20, 10)))!.body.messages;
    expect(marks(first as unknown[])).toEqual([`${conversation(20, 10).length - 1}.0`]);
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
