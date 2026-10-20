import { describe, expect, it } from "bun:test";
import { SentRequests, THINKING_CHARS_MAX } from "./requests.ts";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";
import { THINKING_BREAK, thinkingOfBody, thinkingOfEvent } from "./thinking.ts";

const data = (value: unknown) => JSON.stringify(value);

describe("the thinking in a reply", () => {
  it("reads Anthropic's thinking deltas, with a break at each thinking block", () => {
    const start = (type: string) => data({ type: "content_block_start", content_block: { type } });
    expect(thinkingOfEvent("anthropic", start("thinking"))).toBe(THINKING_BREAK);
    expect(thinkingOfEvent("anthropic", start("redacted_thinking"))).toBe("");
    const delta = (value: unknown) => data({ type: "content_block_delta", delta: value });
    expect(thinkingOfEvent("anthropic", delta({ type: "thinking_delta", thinking: "hm" }))).toBe(
      "hm",
    );
    // The signature that closes a block is not thinking, nor is a missing field.
    expect(thinkingOfEvent("anthropic", delta({ type: "signature_delta", signature: "s" }))).toBe(
      "",
    );
    expect(thinkingOfEvent("anthropic", delta({ type: "thinking_delta" }))).toBe("");
    expect(thinkingOfEvent("anthropic", data({ type: "message_stop", thinking: 1 }))).toBe("");
  });

  it("reads the chat providers' reasoning fields", () => {
    const chunk = (delta: unknown) => data({ choices: [{ delta }] });
    expect(thinkingOfEvent("chat", chunk({ reasoning_content: "a" }))).toBe("a");
    expect(thinkingOfEvent("chat", chunk({ reasoning: "b" }))).toBe("b");
    expect(thinkingOfEvent("chat", chunk({ content: "reasoning is fun" }))).toBe("");
    expect(thinkingOfEvent("chat", data({ reasoning: "no choices" }))).toBe("");
  });

  it("reads Responses' summary and reasoning text, a break at each summary part", () => {
    const event = (type: string, delta?: string) => data({ type, delta });
    expect(thinkingOfEvent("responses", event("response.reasoning_summary_text.delta", "s"))).toBe(
      "s",
    );
    expect(thinkingOfEvent("responses", event("response.reasoning_text.delta", "t"))).toBe("t");
    expect(thinkingOfEvent("responses", event("response.reasoning_summary_part.added"))).toBe(
      THINKING_BREAK,
    );
    expect(thinkingOfEvent("responses", event("response.output_text.delta", "reasoning"))).toBe("");
  });

  it("skips events that are not JSON objects, or never name thinking", () => {
    expect(thinkingOfEvent("anthropic", "[DONE]")).toBe("");
    expect(thinkingOfEvent("anthropic", "thinking, not JSON")).toBe("");
    expect(thinkingOfEvent("anthropic", '["thinking"]')).toBe("");
    expect(thinkingOfEvent("chat", data({ choices: [{ delta: { content: "hi" } }] }))).toBe("");
  });

  it("reads a whole reply in each format, blocks joined by a break", () => {
    const anthropic = {
      content: [
        { type: "thinking", thinking: "one" },
        { type: "redacted_thinking", data: "x" },
        { type: "text", text: "said" },
        { type: "thinking", thinking: "two" },
      ],
    };
    expect(thinkingOfBody("anthropic", anthropic)).toBe(`one${THINKING_BREAK}two`);
    const chat = {
      choices: [{ message: { reasoning_content: "a" } }, { message: { reasoning: "b" } }, {}],
    };
    expect(thinkingOfBody("chat", chat)).toBe(`a${THINKING_BREAK}b`);
    const responses = {
      output: [
        { type: "reasoning", summary: [{ text: "s1" }, { text: "s2" }], content: [{ text: "r" }] },
        { type: "reasoning" },
        { type: "message", content: [{ type: "output_text", text: "said" }] },
      ],
    };
    expect(thinkingOfBody("responses", responses)).toBe(["s1", "s2", "r"].join(THINKING_BREAK));
    expect(thinkingOfBody("anthropic", { choices: [] })).toBe("");
  });
});

describe("a request's reply thinking, kept", () => {
  const context = { route: "anthropic", endpoint: "/v1/messages", session: undefined };

  it("grows until the reply ends, without a break in front, and not in the list", () => {
    const kept = new SentRequests();
    const id = kept.record(context, "{}")!;
    expect(kept.thinking(id)).toEqual({ text: "", done: false });
    for (const more of [THINKING_BREAK, "first", "", THINKING_BREAK, "second"])
      kept.think(id, more);
    expect(kept.thinking(id)).toEqual({ text: `first${THINKING_BREAK}second`, done: false });
    kept.ended(id);
    kept.think(id, "late");
    expect(kept.thinking(id)).toEqual({ text: `first${THINKING_BREAK}second`, done: true });
    expect(Object.keys(kept.list().requests[0]!)).not.toContain("reply");
    // A request no longer kept, or never: nothing to add to, nothing to read.
    kept.think(99, "x");
    kept.ended(99);
    expect(kept.thinking(99)).toBeUndefined();
  });

  it("is capped, and counts against the budget of kept text", () => {
    const kept = new SentRequests(10, Date.now, THINKING_CHARS_MAX + 10);
    const first = kept.record(context, "{}")!;
    kept.think(first, "x".repeat(THINKING_CHARS_MAX - 1));
    kept.think(first, "yy");
    kept.think(first, "z");
    expect(kept.thinking(first)!.text).toBe("x".repeat(THINKING_CHARS_MAX - 1) + "y");
    // The first request's thinking fills the budget, so the next pushes it out.
    const second = kept.record(context, "x".repeat(20))!;
    expect(kept.list().requests.map((request) => request.id)).toEqual([second]);
  });

  it("is nothing when requests are not kept", () => {
    expect(new SentRequests(0).record(context, "{}")).toBeUndefined();
  });
});

describe("the dashboard's reply thinking", () => {
  const ask = () =>
    new Request("http://127.0.0.1/anthropic/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer sub-token" },
      body: data({ model: "claude-x", messages: [{ role: "user", content: "hello" }] }),
    });
  const read = async (handler: ReturnType<typeof createHandler>, id: number) => {
    const url = `http://127.0.0.1/dashboard/request?thinking&id=${id}`;
    return (await (await handler(new Request(url))).json()) as { text: string; done: boolean };
  };

  it("follows a stream as it arrives, and is done when it ends", async () => {
    let send!: (text: string) => void;
    let close!: () => void;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        send = (text) => controller.enqueue(new TextEncoder().encode(text));
        close = () => controller.close();
      },
    });
    const event = (value: unknown) => `data: ${data(value)}\n\n`;
    const handler = createHandler(
      DEFAULT_ROUTES,
      (async () =>
        new Response(body, {
          headers: { "content-type": "text/event-stream" },
        })) as unknown as typeof fetch,
    );
    const reply = await handler(ask());
    const reader = reply.body!.getReader();
    send(event({ type: "content_block_start", index: 0, content_block: { type: "thinking" } }));
    send(
      event({
        type: "content_block_delta",
        index: 0,
        delta: { type: "thinking_delta", thinking: "Mulling" },
      }),
    );
    await reader.read();
    await reader.read();
    expect(await read(handler, 1)).toEqual({ text: "Mulling", done: false });
    close();
    while (!(await reader.read()).done);
    expect(await read(handler, 1)).toEqual({ text: "Mulling", done: true });
  });

  it("reads a whole reply at once", async () => {
    const answer = {
      content: [
        { type: "thinking", thinking: "Whole" },
        { type: "text", text: "" },
      ],
    };
    const handler = createHandler(DEFAULT_ROUTES, (async () =>
      Response.json(answer)) as unknown as typeof fetch);
    await (await handler(ask())).text();
    expect(await read(handler, 1)).toEqual({ text: "Whole", done: true });
    const gone = await handler(new Request("http://127.0.0.1/dashboard/request?thinking&id=9"));
    expect(gone.status).toBe(404);
  });

  it("ends when the agent hangs up mid-stream", async () => {
    const abort = new AbortController();
    const endless = new ReadableStream<Uint8Array>({ start() {} });
    const handler = createHandler(
      DEFAULT_ROUTES,
      (async () =>
        new Response(endless, {
          headers: { "content-type": "text/event-stream" },
        })) as unknown as typeof fetch,
    );
    const request = new Request(ask(), { signal: abort.signal });
    await handler(request);
    expect((await read(handler, 1)).done).toBe(false);
    abort.abort();
    expect((await read(handler, 1)).done).toBe(true);
  });
});
