import { describe, expect, it, spyOn } from "bun:test";
import { markerText } from "./mark.ts";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";
import { PrefixWatch } from "./prefix.ts";
import { merge, usageOf, usageOfEvent, usageText, writtenText } from "./usage.ts";

describe("usage from a reply", () => {
  it("reads Anthropic's split as it is", () => {
    const body = {
      usage: {
        input_tokens: 12,
        cache_read_input_tokens: 900,
        cache_creation_input_tokens: 40,
        output_tokens: 7,
      },
    };
    expect(usageOf("anthropic", body)).toEqual({
      input: 12,
      cacheRead: 900,
      cacheWrite: 40,
      output: 7,
    });
    // A stream's message_start carries it inside the message.
    expect(usageOf("anthropic", { message: body })?.cacheRead).toBe(900);
  });

  it("takes the cached tokens out of chat's and Responses' totals", () => {
    const chat = {
      usage: {
        prompt_tokens: 100,
        completion_tokens: 5,
        prompt_tokens_details: { cached_tokens: 80 },
      },
    };
    expect(usageOf("chat", chat)).toEqual({ input: 20, cacheRead: 80, cacheWrite: 0, output: 5 });
    const responses = {
      response: {
        usage: { input_tokens: 50, output_tokens: 3, input_tokens_details: { cached_tokens: 50 } },
      },
    };
    expect(usageOf("responses", responses)).toEqual({
      input: 0,
      cacheRead: 50,
      cacheWrite: 0,
      output: 3,
    });
  });

  it("reads nothing from a reply without usage, or figures that are not counts", () => {
    expect(usageOf("chat", { choices: [] })).toBeUndefined();
    expect(usageOf("chat", "text")).toBeUndefined();
    expect(usageOf("anthropic", { usage: { input_tokens: -3, output_tokens: "9" } })).toEqual({
      input: 0,
      cacheRead: 0,
      cacheWrite: 0,
      output: 0,
    });
  });

  it("parses a stream event only when it names usage, and survives a broken one", () => {
    expect(usageOfEvent("anthropic", '{"type":"content_block_delta"}')).toBeUndefined();
    expect(usageOfEvent("anthropic", '{"usage": broken')).toBeUndefined();
    expect(usageOfEvent("anthropic", '{"usage":{"output_tokens":4}}')?.output).toBe(4);
  });

  it("combines a stream's parts, keeping running totals rather than adding them", () => {
    const start = { input: 10, cacheRead: 500, cacheWrite: 0, output: 1 };
    const delta = { input: 10, cacheRead: 0, cacheWrite: 0, output: 30 };
    const total = merge(merge(undefined, start), delta);
    expect(total).toEqual({ input: 10, cacheRead: 500, cacheWrite: 0, output: 30 });
    expect(usageText(total)).toBe("10/500/0/30");
  });

  it("reads how long Anthropic keeps what it wrote, and names it when it wrote", () => {
    const usage = usageOf("anthropic", {
      usage: {
        input_tokens: 2,
        cache_read_input_tokens: 100,
        cache_creation_input_tokens: 70,
        cache_creation: { ephemeral_1h_input_tokens: 50, ephemeral_5m_input_tokens: 20 },
        output_tokens: 4,
      },
    })!;
    expect(usage.written).toEqual({ hour: 50, short: 20 });
    expect(writtenText(usage)).toBe(" written=1h:50,5m:20");
    expect(writtenText({ ...usage, cacheWrite: 0 })).toBe("");
    expect(writtenText({ input: 1, cacheRead: 0, cacheWrite: 9, output: 1 })).toBe("");
  });

  it("keeps the split when only one part of a stream carries it", () => {
    const start = {
      input: 1,
      cacheRead: 0,
      cacheWrite: 9,
      output: 1,
      written: { hour: 9, short: 0 },
    };
    const delta = { input: 0, cacheRead: 0, cacheWrite: 0, output: 30 };
    expect(merge(merge(undefined, start), delta).written).toEqual({ hour: 9, short: 0 });
    expect(merge(delta, start).written).toEqual({ hour: 9, short: 0 });
    const later = { ...delta, written: { hour: 3, short: 5 } };
    expect(merge(start, later).written).toEqual({ hour: 9, short: 5 });
  });
});

describe("markerText", () => {
  it("names each marker by where it sits, and its TTL only when it is not an hour", () => {
    const hour = { type: "ephemeral", ttl: "1h" };
    const body = {
      tools: [{ name: "a" }, { name: "b", cache_control: { type: "ephemeral" } }],
      system: [
        { type: "text", text: "x", cache_control: hour },
        { type: "text", text: "y", cache_control: hour },
      ],
      messages: [
        { role: "user", content: "plain" },
        { role: "user", content: [{ type: "text", text: "z", cache_control: hour }] },
        {
          role: "user",
          content: [{ type: "text", text: "w", cache_control: { ...hour, ttl: "5m" } }],
        },
      ],
    };
    expect(markerText(body)).toBe("t1:5m,s0,s1,m1,m2:5m");
    expect(markerText({ system: "plain", messages: [] })).toBe("");
  });
});

describe("the journal names a main request's session and markers", () => {
  it("logs both, and the write split after usage", async () => {
    const lines: string[] = [];
    const write = spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    });
    const usage = {
      input_tokens: 1,
      cache_read_input_tokens: 0,
      cache_creation_input_tokens: 8,
      cache_creation: { ephemeral_1h_input_tokens: 8, ephemeral_5m_input_tokens: 0 },
      output_tokens: 1,
    };
    const handler = createHandler(DEFAULT_ROUTES, (() =>
      Promise.resolve(Response.json({ content: [], usage }))) as never);
    const body = {
      model: "m",
      system: [{ type: "text", text: "s", cache_control: { type: "ephemeral", ttl: "1h" } }],
      tools: [{ name: "Bash", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: "hello" }],
    };
    const sent = new Request("http://127.0.0.1/anthropic/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-claude-code-session-id": "abcdef12-3456-7890",
      },
      body: JSON.stringify(body),
    });
    try {
      await (await handler(sent)).text();
    } finally {
      write.mockRestore();
    }
    const line = lines.find((text) => text.includes("v1/messages 200"))!;
    expect(line).toContain(" session=abcdef12 markers=s0");
    expect(line).toContain(" usage=1/0/8/1 written=1h:8,5m:0");
  });
});

describe("prefix breaks", () => {
  const turn = (text: string) => ({ role: "user", content: text });
  const body = (system: string, ...texts: string[]) => ({
    model: "m",
    system,
    tools: [{ name: "Bash" }],
    messages: texts.map(turn),
  });

  it("says nothing when a conversation only appends", () => {
    const watch = new PrefixWatch();
    const first = body("sys", "a");
    expect(watch.check("anthropic", "s", first, first)).toBeUndefined();
    const next = body("sys", "a", "b", "c");
    expect(watch.check("anthropic", "s", next, next)).toBeUndefined();
  });

  it("ignores the cache breakpoint moving to the newest message", () => {
    const watch = new PrefixWatch();
    const marked = {
      ...body("sys"),
      messages: [{ role: "user", content: "a", cache_control: { type: "ephemeral" } }],
    };
    watch.check("anthropic", "s", marked, marked);
    const moved = { ...body("sys"), messages: [turn("a"), turn("b")] };
    expect(watch.check("anthropic", "s", moved, moved)).toBeUndefined();
  });

  it("reads a string and the one text block that carried the breakpoint as the same", () => {
    // Claude Code wraps the newest message's string in a block to mark it,
    // and sends the string again once the marker has moved on.
    const watch = new PrefixWatch();
    const block = [{ type: "text", text: "a", cache_control: { type: "ephemeral" } }];
    const marked = { ...body("sys"), messages: [{ role: "user", content: block }] };
    watch.check("anthropic", "s", marked, marked);
    const moved = { ...body("sys"), messages: [turn("a"), turn("b")] };
    expect(watch.check("anthropic", "s", moved, moved)).toBeUndefined();
  });

  it("names the agent when what arrived changed, at the first part that did", () => {
    const watch = new PrefixWatch();
    watch.check("anthropic", "s", body("sys at 10:00", "a"), body("sys at 10:00", "a"));
    const changed = body("sys at 10:05", "a", "b");
    expect(watch.check("anthropic", "s", changed, changed)).toEqual({
      at: "system",
      cause: "agent",
    });
  });

  it("names shaping when only the forwarded copy changed", () => {
    const watch = new PrefixWatch();
    const arrived = body("sys", "a", "big result", "c");
    watch.check("anthropic", "s", arrived, arrived);
    const next = body("sys", "a", "big result", "c", "d");
    const shaped = body("sys", "a", "[masked]", "c", "d");
    expect(watch.check("anthropic", "s", next, shaped)).toEqual({
      at: "message 2",
      cause: "shaping",
    });
  });

  it("counts a history that got shorter as a break where it ends", () => {
    const watch = new PrefixWatch();
    const long = body("sys", "a", "b", "c");
    watch.check("anthropic", "s", long, long);
    const short = body("sys", "a");
    expect(watch.check("anthropic", "s", short, short)?.at).toBe("message 2");
  });

  it("keeps a subagent apart from its parent, and skips a chained Responses request", () => {
    const watch = new PrefixWatch();
    const parent = body("sys", "parent task");
    watch.check("anthropic", "s", parent, parent);
    const child = body("other sys", "child task");
    expect(watch.check("anthropic", "s", child, child)).toBeUndefined();
    const chained = { model: "m", previous_response_id: "r1", input: [turn("x")] };
    expect(watch.check("responses", "s", chained, chained)).toBeUndefined();
    expect(watch.check("responses", "s", chained, chained)).toBeUndefined();
  });

  it("forgets the oldest conversation past its limit", () => {
    const watch = new PrefixWatch();
    const first = body("sys", "first");
    watch.check("anthropic", "s0", first, first);
    for (let i = 1; i <= 256; i++) {
      const other = body("sys", `conversation ${i}`);
      watch.check("anthropic", `s${i}`, other, other);
    }
    // Forgotten, so a changed system prompt reads as a first request.
    const changed = body("changed", "first");
    expect(watch.check("anthropic", "s0", changed, changed)).toBeUndefined();
  });
});

describe("the request path counts usage and breaks", () => {
  const post = (body: unknown) =>
    new Request("http://127.0.0.1/anthropic/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-claude-code-session-id": "c1" },
      body: JSON.stringify(body),
    });
  const stats = async (handler: ReturnType<typeof createHandler>) =>
    (
      (await (await handler(new Request("http://127.0.0.1/dashboard/activity"))).json()) as {
        stats: Record<string, unknown>;
      }
    ).stats;
  const request = (system: string, ...texts: string[]) => ({
    model: "m",
    system,
    tools: [{ name: "Bash", input_schema: { type: "object" } }],
    messages: texts.map((content) => ({ role: "user", content })),
  });
  const usage = {
    input_tokens: 10,
    cache_read_input_tokens: 90,
    cache_creation_input_tokens: 5,
    output_tokens: 3,
  };

  it("adds up a JSON reply's usage, and counts a changed system prompt as a break", async () => {
    const handler = createHandler(DEFAULT_ROUTES, (() =>
      Promise.resolve(Response.json({ content: [], usage }))) as never);
    await (await handler(post(request("today is monday", "a")))).text();
    await (await handler(post(request("today is tuesday", "a", "b")))).text();
    expect(await stats(handler)).toMatchObject({
      usageReplies: 2,
      usageInput: 20,
      usageCacheRead: 180,
      usageCacheWrite: 10,
      usageOutput: 6,
      cacheBreaksAgent: 1,
      cacheBreaksShaping: 0,
      lastBreak: "system in claude 1 (agent)",
    });
  });

  it("reads a stream's usage from its start and its delta", async () => {
    const events = [
      { type: "message_start", message: { content: [], usage: { ...usage, output_tokens: 1 } } },
      { type: "message_delta", delta: {}, usage: { output_tokens: 42 } },
      { type: "message_stop" },
    ];
    const sse = events.map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
    const handler = createHandler(DEFAULT_ROUTES, (() =>
      Promise.resolve(
        new Response(sse.join(""), { headers: { "content-type": "text/event-stream" } }),
      )) as never);
    await (await handler(post(request("sys", "a")))).text();
    expect(await stats(handler)).toMatchObject({
      usageReplies: 1,
      usageCacheRead: 90,
      usageOutput: 42,
    });
  });
});
