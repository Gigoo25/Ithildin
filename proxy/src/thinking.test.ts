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

describe("earlier turns' thinking, from the replies kept", () => {
  const session = { route: "anthropic", endpoint: "/v1/messages", session: "s1" };
  const ask = { role: "user", content: "hello" };
  const call = { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Bash" }] };
  const result = { role: "user", content: [{ type: "tool_result", tool_use_id: "t1" }] };
  const body = (messages: unknown[]) => data({ messages });

  it("finds the request each turn answered, by where its conversation ended", () => {
    const kept = new SentRequests();
    // The agent marks the newest entry for the cache, and moves the mark on.
    const first = kept.record(session, body([{ ...ask, cache_control: { type: "ephemeral" } }]))!;
    kept.think(first, "Plan the call");
    const second = kept.record(session, body([ask, call, result]))!;
    kept.think(second, "Read the result");
    // A retry of the first that thought differently: the newest wins.
    const retry = kept.record(session, body([ask]))!;
    kept.think(retry, "Plan again");
    const last = kept.record(session, body([ask, call, result, { role: "assistant" }, ask]))!;
    expect(kept.earlier(last)).toEqual([
      { at: 1, text: "Plan again" },
      { at: 3, text: "Read the result" },
    ]);
    expect(kept.earlier(second)).toEqual([{ at: 1, text: "Plan the call" }]);
    expect(kept.earlier(99)).toBeUndefined();
  });

  it("skips another session, another conversation, a reply without thinking, and non-JSON", () => {
    const kept = new SentRequests();
    kept.think(kept.record({ ...session, session: "s2" }, body([ask]))!, "Elsewhere");
    kept.think(kept.record(session, body([{ role: "user", content: "other" }]))!, "Other");
    kept.record(session, body([ask]));
    kept.think(kept.record(session, "not JSON")!, "Odd");
    kept.think(kept.record(session, body([]))!, "Empty");
    const last = kept.record(session, body([ask, call, result]))!;
    expect(kept.earlier(last)).toEqual([]);
    expect(kept.earlier(kept.record(session, '"text"')!)).toEqual([]);
  });

  it("reads Responses input and Gemini contents too", () => {
    const kept = new SentRequests();
    kept.think(kept.record(session, data({ input: [ask] }))!, "Responses");
    kept.think(kept.record(session, data({ contents: [{ role: "user", parts: [] }] }))!, "Gemini");
    const responses = kept.record(session, data({ input: [ask, call, result] }))!;
    expect(kept.earlier(responses)).toEqual([{ at: 1, text: "Responses" }]);
    const gemini = kept.record(session, data({ contents: [{ role: "user", parts: [] }, call] }))!;
    expect(kept.earlier(gemini)).toEqual([{ at: 1, text: "Gemini" }]);
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

  it("serves earlier turns' thinking, and a 404 for a request not kept", async () => {
    const answer = { content: [{ type: "thinking", thinking: "First" }] };
    const handler = createHandler(DEFAULT_ROUTES, (async () =>
      Response.json(answer)) as unknown as typeof fetch);
    await (await handler(ask())).text();
    const next = data({
      model: "claude-x",
      messages: [
        { role: "user", content: "hello" },
        { role: "assistant", content: "hi" },
        { role: "user", content: "again" },
      ],
    });
    const post = new Request(ask(), { body: next });
    await (await handler(post)).text();
    const earlier = (id: number) =>
      handler(new Request(`http://127.0.0.1/dashboard/request?earlier&id=${id}`));
    expect(await (await earlier(2)).json()).toEqual([{ at: 1, text: "First" }]);
    expect((await earlier(9)).status).toBe(404);
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
