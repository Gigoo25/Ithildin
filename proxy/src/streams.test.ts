import { beforeAll, describe, expect, it } from "bun:test";
import { initEngine, redactRequest } from "./redact.ts";
import { createRewriter, swapResponseBody, type SseEvent } from "./streams.ts";

// The edges each format's rewriter meets that the end-to-end server tests do
// not reach: events that are not JSON objects, text with no space for a long
// stretch, parts closed with no output_text.done, and a whole reply's custom
// tool calls and message text.

const EMAIL = "jane.doe@acme-corp.com";
let standIn = "";

beforeAll(() => {
  initEngine();
  const body = redactRequest("anthropic", { messages: [{ role: "user", content: EMAIL }] })
    .body as { messages: Array<{ content: string }> };
  standIn = body.messages[0]!.content;
});

const sse = (data: unknown, event?: string): SseEvent => ({
  ...(event ? { event } : {}),
  data: JSON.stringify(data),
});
const parsed = (events: SseEvent[]) => events.map((e) => JSON.parse(e.data) as Record<string, any>);

describe("every rewriter", () => {
  it("passes on an event whose data is not a JSON object", () => {
    for (const format of ["anthropic", "responses"] as const) {
      const rewriter = createRewriter(format, new Set());
      for (const data of ["[1, 2]", "null", "not json"])
        expect(rewriter.push({ data })).toEqual([{ data }]);
    }
  });
});

describe("held text", () => {
  // No space for longer than the hold allows: release all but a tail long
  // enough to hold any stand-in, rather than hold the text forever.
  it("releases a long run with no space, and still swaps what follows", () => {
    const rewriter = createRewriter("anthropic", new Set());
    rewriter.push(sse({ type: "content_block_start", index: 0, content_block: { type: "text" } }));
    const run = "x".repeat(5000);
    const delta = (text: string) =>
      sse({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text } });
    const first = parsed(rewriter.push(delta(run)));
    expect(first[0]!.delta.text.length).toBeGreaterThan(0);
    expect(first[0]!.delta.text.length).toBeLessThan(run.length);
    const rest = parsed([
      ...rewriter.push(delta(` ${standIn} end`)),
      ...rewriter.push(sse({ type: "content_block_stop", index: 0 })),
    ]);
    const text = [...first, ...rest].map((d) => d.delta?.text ?? "").join("");
    expect(text).toBe(`${run} ${EMAIL} end`);
  });

  it("passes an Anthropic delta that is not text, and adds nothing to an empty block", () => {
    const rewriter = createRewriter("anthropic", new Set());
    rewriter.push(sse({ type: "content_block_start", index: 0, content_block: { type: "text" } }));
    const other = sse({
      type: "content_block_delta",
      index: 0,
      delta: { type: "citations_delta" },
    });
    expect(rewriter.push(other)).toEqual([other]);
    const stop = sse({ type: "content_block_stop", index: 0 });
    expect(rewriter.push(stop)).toEqual([stop]);
    expect(rewriter.flush()).toEqual([]);
  });

  it("swaps a Chat Completions stream's held text when it finishes", () => {
    const rewriter = createRewriter("chat", new Set());
    const chunk = (delta: Record<string, unknown>, finish: unknown = null) =>
      sse({ id: "c", choices: [{ index: 0, delta, finish_reason: finish }] });
    const out = parsed([
      ...rewriter.push(chunk({ content: `to ${standIn}` })),
      ...rewriter.push(chunk({}, "stop")),
    ]);
    expect(out.map((d) => d.choices[0].delta.content ?? "").join("")).toBe(`to ${EMAIL}`);
  });
});

describe("a Responses stream", () => {
  const added = (item: Record<string, unknown>) =>
    sse({ type: "response.output_item.added", output_index: 0, item });

  it("swaps a closed part's text, and passes one that is not output text", () => {
    const rewriter = createRewriter("responses", new Set());
    const done = (part: unknown) =>
      parsed(
        rewriter.push(
          sse({ type: "response.content_part.done", item_id: "m", content_index: 0, part }),
        ),
      )[0]!;
    expect(done({ type: "output_text", text: standIn }).part.text).toBe(EMAIL);
    expect(done({ type: "refusal", refusal: standIn }).part.refusal).toBe(standIn);
  });

  it("swaps a call's arguments given as an object, not a string", () => {
    const rewriter = createRewriter("responses", new Set());
    const item = { type: "function_call", id: "fc", call_id: "c1", name: "bash" };
    rewriter.push(added({ ...item, arguments: "" }));
    const out = parsed(
      rewriter.push(
        sse({
          type: "response.output_item.done",
          output_index: 0,
          item: { ...item, arguments: { command: `echo ${standIn}` } },
        }),
      ),
    );
    expect(out.at(-1)!.item.arguments).toEqual({ command: `echo ${EMAIL}` });
    expect(rewriter.swapped).toBe(1);
  });
});

describe("a whole Responses reply", () => {
  it("swaps message text and a custom tool call's input", () => {
    const body = {
      output: [
        { type: "message", content: [{ type: "output_text", text: standIn }, { type: "refusal" }] },
        { type: "custom_tool_call", call_id: "c", name: "apply_patch", input: `+ ${standIn}` },
        { type: "reasoning" },
      ],
    };
    expect(swapResponseBody("responses", body, new Set())).toBe(2);
    expect(body.output[0]!.content![0]!.text).toBe(EMAIL);
    expect(body.output[1]!.input).toBe(`+ ${EMAIL}`);
  });
});
