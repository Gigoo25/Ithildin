import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  egressBlocked,
  IMAGE_NOTICE,
  INVENTORY_NOTICE,
  initEngine,
  redactRequest,
  requestCwd,
  standInBlocked,
  stripAllowTags,
  swapText,
  swapToolArguments,
  swapToolInput,
  WITHHELD_LINE,
  WITHHELD_NOTICE,
} from "./redact.ts";
import { createHandler, DEFAULT_ROUTES, loadRoutes, upstreamUrl } from "./server.ts";
import { looksLikeAlias } from "../engine/lib/aliases.ts";

const EMAIL = "jane.doe@acme-corp.com";
let standIn = "";

beforeAll(() => {
  initEngine();
  const body = redactRequest("anthropic", { messages: [{ role: "user", content: EMAIL }] })
    .body as { messages: Array<{ content: string }> };
  standIn = body.messages[0]!.content;
});

type Seen = { url: string; body: unknown; headers: Headers };

function fakeUpstream(reply: (seen: Seen) => Response): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const fn = (async (url: string, init: RequestInit) => {
    const entry = {
      url,
      body: init.body ? JSON.parse(String(init.body)) : undefined,
      headers: new Headers(init.headers),
    };
    seen.push(entry);
    return reply(entry);
  }) as unknown as typeof fetch;
  return { fetch: fn, seen };
}

function sse(events: Array<{ event?: string; data: unknown }>, chunkAt?: number): Response {
  const text = events
    .map((e) => {
      const data = typeof e.data === "string" ? e.data : JSON.stringify(e.data);
      return `${e.event ? `event: ${e.event}\n` : ""}data: ${data}\n\n`;
    })
    .join("");
  const bytes = new TextEncoder().encode(text);
  const cut = chunkAt ?? Math.floor(bytes.length / 2);
  return new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.slice(0, cut));
        controller.enqueue(bytes.slice(cut));
        controller.close();
      },
    }),
    { headers: { "content-type": "text/event-stream" } },
  );
}

function post(path: string, body: unknown): Request {
  return new Request(`http://127.0.0.1/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer sub-token" },
    body: JSON.stringify(body),
  });
}

function events(text: string): Array<Record<string, unknown>> {
  return text.split("\n\n").flatMap((block) => {
    const data = block
      .split("\n")
      .filter((l) => l.startsWith("data: "))
      .map((l) => l.slice(6))
      .join("\n");
    if (!data || data === "[DONE]") return [];
    return [JSON.parse(data)];
  });
}

describe("requests", () => {
  it("redacts the prompt, keeps credentials, thinking and ids", async () => {
    const up = fakeUpstream(() => Response.json({ content: [] }));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const thinking = { type: "thinking", thinking: `I recall ${EMAIL}`, signature: "sig" };
    await handler(
      post("anthropic/v1/messages", {
        model: "claude-x",
        messages: [
          { role: "user", content: `write to ${EMAIL}` },
          {
            role: "assistant",
            content: [
              thinking,
              {
                type: "tool_use",
                id: "toolu_01",
                name: "Bash",
                input: { command: `echo ${EMAIL}` },
              },
            ],
          },
          {
            role: "user",
            content: [{ type: "tool_result", tool_use_id: "toolu_01", content: EMAIL }],
          },
        ],
      }),
    );
    const seen = up.seen[0]!;
    expect(seen.url).toBe("https://api.anthropic.com/v1/messages");
    expect(seen.headers.get("authorization")).toBe("Bearer sub-token");
    const text = JSON.stringify(seen.body);
    const messages = (seen.body as { messages: Array<{ content: unknown }> }).messages;
    expect(messages[0]!.content).toBe(`write to ${standIn}`);
    // Signed thinking passes byte for byte; everything else is redacted.
    expect((messages[1]!.content as unknown[])[0]).toEqual(thinking);
    expect(text).toContain("toolu_01");
    expect(text.split(EMAIL).length - 1).toBe(1);
  });

  it("[allow-all] in the latest prompt passes the body raw", async () => {
    const up = fakeUpstream(() => Response.json({ content: [] }));
    await createHandler(
      DEFAULT_ROUTES,
      up.fetch,
    )(
      post("anthropic/v1/messages", {
        messages: [{ role: "user", content: `[allow-all] ${EMAIL}` }],
      }),
    );
    expect(JSON.stringify(up.seen[0]!.body)).toContain(EMAIL);
  });

  it("reports the badge on /_ithildin/health, ignoring one-message side requests", async () => {
    const up = fakeUpstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const health = async (query = "route=anthropic") =>
      (await (await handler(new Request(`http://127.0.0.1/_ithildin/health?${query}`))).json()) as {
        badge: string;
      };
    expect((await health()).badge).toBe("ITHILDIN ON");
    // One value, however often it appears.
    await handler(
      post("anthropic/v1/messages", {
        messages: [
          { role: "user", content: `mail ${EMAIL}` },
          { role: "assistant", content: "ok" },
          { role: "user", content: `and ${EMAIL}` },
        ],
      }),
    );
    expect((await health()).badge).toBe("ITHILDIN ON · 1m (+1) · 1 req");
    await handler(
      post("anthropic/v1/messages", { messages: [{ role: "user", content: "title this" }] }),
    );
    expect((await health()).badge).toBe("ITHILDIN ON · 1m (+1) · 1 req");
  });

  it("shows the latest prompt's allow tags on the badge, never upstream", async () => {
    const up = fakeUpstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const history = [
      { role: "user", content: "hi" },
      { role: "assistant", content: "hello" },
    ];
    const badge = async () =>
      (
        (await (
          await handler(new Request("http://127.0.0.1/_ithildin/health?route=anthropic"))
        ).json()) as { badge: string }
      ).badge;
    await handler(
      post("anthropic/v1/messages", {
        messages: [...history, { role: "user", content: "[allow-protected] commit" }],
      }),
    );
    expect(await badge()).toBe("ITHILDIN ON · 0 · 1 req · +protected");
    expect(JSON.stringify(up.seen[0]!.body)).not.toContain("allow-protected");
    await handler(
      post("anthropic/v1/messages", {
        messages: [...history, { role: "user", content: "commit" }],
      }),
    );
    expect(await badge()).toBe("ITHILDIN ON · 0 · 2 req");
  });

  it("keeps one badge per session and never forwards the proxy's session header", async () => {
    const up = fakeUpstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const send = (headers: Record<string, string>, messages: unknown[]) =>
      handler(
        new Request("http://127.0.0.1/anthropic/v1/messages", {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify({ messages }),
        }),
      );
    const badge = async (session: string) =>
      (
        (await (
          await handler(
            new Request(`http://127.0.0.1/_ithildin/health?route=anthropic&session=${session}`),
          )
        ).json()) as { badge: string }
      ).badge;
    const call = (id: string, content: string) => [
      {
        role: "assistant",
        content: [{ type: "tool_use", id, name: "Bash", input: { command: "cat notes" } }],
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ];
    const first = [{ role: "user", content: `mail ${EMAIL}` }];
    await send({ "x-ithildin-session": "pi-1" }, [...first, ...call("t1", "nothing here")]);
    await send({ "x-Claude-Code-Session-Id": "claude-1" }, [
      { role: "user", content: "hi" },
      { role: "assistant", content: "hello" },
    ]);
    expect(await badge("pi-1")).toBe("ITHILDIN ON · 1m (+1) · 1 req");
    expect(await badge("claude-1")).toBe("ITHILDIN ON · 0 · 1 req");
    expect(up.seen[0]!.headers.get("x-ithildin-session")).toBeNull();
    // A tool result in the same turn adds to the turn; a new prompt starts
    // the count again.
    const second = [
      ...first,
      ...call("t1", "nothing here"),
      ...call("t2", "from user-a0ea33@acme-corp.com"),
    ];
    await send({ "x-ithildin-session": "pi-1" }, second);
    expect(await badge("pi-1")).toBe("ITHILDIN ON · 2m (+2) · 2 req");
    await send({ "x-ithildin-session": "pi-1" }, [
      ...second,
      { role: "assistant", content: "done" },
      { role: "user", content: "thanks" },
    ]);
    expect(await badge("pi-1")).toBe("ITHILDIN ON · 2m · 3 req");
    expect(up.seen.at(-1)!.headers.get("x-ithildin-session")).toBeNull();
  });

  it("refuses unknown routes and compressed bodies", async () => {
    const up = fakeUpstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    expect((await handler(post("nowhere/v1/messages", {}))).status).toBe(404);
    const gz = new Request("http://127.0.0.1/anthropic/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "content-encoding": "gzip" },
      body: "x",
    });
    expect((await handler(gz)).status).toBe(415);
    expect(up.seen.length).toBe(0);
  });

  it("maps opencode-go's three wire formats onto one upstream", () => {
    const route = DEFAULT_ROUTES["opencode-go"]!;
    expect(upstreamUrl(route, "/v1/messages", "")).toBe("https://opencode.ai/zen/go/v1/messages");
    expect(upstreamUrl(route, "/chat/completions", "")).toBe(
      "https://opencode.ai/zen/go/v1/chat/completions",
    );
    expect(upstreamUrl(route, "/responses", "")).toBe("https://opencode.ai/zen/go/v1/responses");
    expect(upstreamUrl(DEFAULT_ROUTES["openai-codex"]!, "/codex/responses", "?a=1")).toBe(
      "https://chatgpt.com/backend-api/codex/responses?a=1",
    );
  });
});

describe("reply text", () => {
  const handler = (reply: () => Response) =>
    createHandler(DEFAULT_ROUTES, fakeUpstream(reply).fetch);

  it("swaps stand-ins split across Anthropic stream chunks, not in thinking", async () => {
    const literal = ["241", "18", "5", "7"].join(".");
    const text = `Mail ${standIn} at ${literal}\nthen stop`;
    const cut = text.indexOf(standIn) + 4;
    const res = await handler(() =>
      sse([
        {
          data: {
            type: "content_block_start",
            index: 0,
            content_block: { type: "thinking", thinking: "" },
          },
        },
        {
          data: {
            type: "content_block_delta",
            index: 0,
            delta: { type: "thinking_delta", thinking: `about ${standIn}` },
          },
        },
        { data: { type: "content_block_stop", index: 0 } },
        {
          data: {
            type: "content_block_start",
            index: 1,
            content_block: { type: "text", text: "" },
          },
        },
        {
          data: {
            type: "content_block_delta",
            index: 1,
            delta: { type: "text_delta", text: text.slice(0, cut) },
          },
        },
        {
          data: {
            type: "content_block_delta",
            index: 1,
            delta: { type: "text_delta", text: text.slice(cut) },
          },
        },
        { data: { type: "content_block_stop", index: 1 } },
      ]),
    )(post("anthropic/v1/messages", { stream: true, messages: [{ role: "user", content: "hi" }] }));
    const out = events(await res.text());
    const deltas = out
      .filter((e) => e.type === "content_block_delta")
      .map((e) => e.delta as { type: string; text?: string; thinking?: string });
    expect(
      deltas
        .filter((d) => d.type === "text_delta")
        .map((d) => d.text)
        .join(""),
    ).toBe(`Mail ${EMAIL} at ${literal}\nthen stop`);
    expect(deltas.find((d) => d.type === "thinking_delta")!.thinking).toBe(`about ${standIn}`);
    expect(out.at(-1)!.type).toBe("content_block_stop");
  });

  it("swaps Chat Completions content, flushing the tail before the finish", async () => {
    const chunk = (delta: unknown, finish: unknown = null) => ({
      data: { id: "c", choices: [{ index: 0, delta, finish_reason: finish }] },
    });
    const res = await handler(() =>
      sse([
        chunk({ content: `to ${standIn.slice(0, 6)}` }),
        chunk({ content: standIn.slice(6) }),
        chunk({}, "stop"),
        { data: "[DONE]" },
      ]),
    )(
      post("opencode-go/chat/completions", {
        stream: true,
        messages: [{ role: "user", content: "hi" }],
      }),
    );
    const out = events(await res.text()) as Array<{
      choices: Array<{ delta: { content?: string }; finish_reason: unknown }>;
    }>;
    expect(out.map((e) => e.choices[0]!.delta.content ?? "").join("")).toBe(`to ${EMAIL}`);
    expect(out.at(-1)!.choices[0]!.finish_reason).toBe("stop");
  });

  it("swaps Responses text deltas and the final text", async () => {
    const res = await handler(() =>
      sse([
        {
          data: {
            type: "response.output_text.delta",
            item_id: "m",
            content_index: 0,
            delta: `to ${standIn.slice(0, 6)}`,
          },
        },
        {
          data: {
            type: "response.output_text.delta",
            item_id: "m",
            content_index: 0,
            delta: standIn.slice(6),
          },
        },
        {
          data: {
            type: "response.output_text.done",
            item_id: "m",
            content_index: 0,
            text: `to ${standIn}`,
          },
        },
        {
          data: {
            type: "response.completed",
            response: {
              output: [
                { type: "message", content: [{ type: "output_text", text: `to ${standIn}` }] },
              ],
            },
          },
        },
      ]),
    )(post("openai-codex/codex/responses", { stream: true, input: "hi" }));
    const out = events(await res.text());
    expect(
      out
        .filter((e) => e.type === "response.output_text.delta")
        .map((e) => e.delta)
        .join(""),
    ).toBe(`to ${EMAIL}`);
    expect(out.find((e) => e.type === "response.output_text.done")!.text).toBe(`to ${EMAIL}`);
    expect(JSON.stringify(out.at(-1))).toContain(EMAIL);
    expect(JSON.stringify(out)).not.toContain(standIn);
  });

  it("swaps non-streaming text", async () => {
    const res = await handler(() =>
      Response.json({ content: [{ type: "text", text: `to ${standIn}` }] }),
    )(post("anthropic/v1/messages", { messages: [{ role: "user", content: "hi" }] }));
    expect(((await res.json()) as { content: Array<{ text: string }> }).content[0]!.text).toBe(
      `to ${EMAIL}`,
    );
  });

  it("round-trips: the swapped reply is redacted back to the exact bytes the model wrote", () => {
    const reply = `Sent it to ${standIn}.`;
    const shown = swapText(reply, new Set()).text;
    expect(shown).toBe(`Sent it to ${EMAIL}.`);
    const next = redactRequest("anthropic", {
      messages: [
        { role: "user", content: `mail ${EMAIL}` },
        { role: "assistant", content: [{ type: "text", text: shown }] },
        { role: "user", content: "thanks" },
      ],
    }).body as { messages: Array<{ content: unknown }> };
    expect(next.messages[1]!.content).toEqual([{ type: "text", text: reply }]);
    expect(JSON.stringify(next)).not.toContain(EMAIL);
  });
});

describe("streams cut short", () => {
  const send = (path: string, reply: Response) =>
    createHandler(
      DEFAULT_ROUTES,
      fakeUpstream(() => reply).fetch,
    )(post(path, { stream: true, messages: [{ role: "user", content: "hi" }] }));
  const args = () => JSON.stringify({ command: `echo ${standIn}` });

  it("releases held text and unfinished calls, swapped, in every format", async () => {
    const anthropic = await send(
      "anthropic/v1/messages",
      sse([
        { data: { type: "content_block_start", index: 0, content_block: { type: "text" } } },
        {
          data: {
            type: "content_block_delta",
            index: 0,
            delta: { type: "text_delta", text: `Mail ${standIn}` },
          },
        },
        {
          data: {
            type: "content_block_start",
            index: 1,
            content_block: { type: "tool_use", id: "t1", name: "bash" },
          },
        },
        {
          data: {
            type: "content_block_delta",
            index: 1,
            delta: { type: "input_json_delta", partial_json: args() },
          },
        },
      ]),
    );
    const chat = await send(
      "opencode-go/chat/completions",
      sse([
        { data: { id: "c", choices: [{ index: 0, delta: { content: `Mail ${standIn}` } }] } },
        {
          data: {
            id: "c",
            choices: [
              {
                index: 0,
                delta: {
                  tool_calls: [
                    { index: 0, id: "t1", function: { name: "bash", arguments: args() } },
                  ],
                },
              },
            ],
          },
        },
      ]),
    );
    const responses = await send(
      "openai-codex/responses",
      sse([
        {
          data: {
            type: "response.output_item.added",
            item: { type: "function_call", id: "fc1", call_id: "t1", name: "bash" },
          },
        },
        {
          data: {
            type: "response.output_text.delta",
            item_id: "m1",
            content_index: 0,
            delta: `Mail ${standIn}`,
          },
        },
        { data: { type: "response.function_call_arguments.delta", item_id: "fc1", delta: args() } },
      ]),
    );
    for (const res of [anthropic, chat, responses]) {
      const text = await res.text();
      expect(text).not.toContain(standIn);
      expect(text).toContain(`echo ${EMAIL}`);
      expect(text.split(EMAIL)).toHaveLength(3);
    }
  });
});

describe("provider blindness", () => {
  it("adds nothing that tells the provider about redaction", () => {
    const anthropic = redactRequest("anthropic", {
      system: [{ type: "text", text: "base" }],
      messages: [{ role: "user", content: "hi" }],
    }).body;
    expect(anthropic.system).toEqual([{ type: "text", text: "base" }]);
    const chat = redactRequest("chat", { messages: [{ role: "user", content: "hi" }] }).body;
    expect(chat.messages).toEqual([{ role: "user", content: "hi" }]);
    const responses = redactRequest("responses", { instructions: "codex", input: "hi" }).body;
    expect(responses).toEqual({ instructions: "codex", input: "hi" });
  });

  it("strips allow tags from typed text but still honours them", () => {
    const tagged = redactRequest("anthropic", {
      messages: [{ role: "user", content: "[mask-secret] hi [allow-all]" }],
    });
    expect(tagged.tags.has("all")).toBe(true);
    expect((tagged.body.messages as Array<{ content: unknown }>)[0]!.content).toBe("hi ");
    const blocks = stripAllowTags("anthropic", {
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "show [allow-pii] it" },
            { type: "tool_result", tool_use_id: "t", content: "grep hit: [allow-pii]" },
          ],
        },
        { role: "assistant", content: [{ type: "text", text: "use [allow-pii]" }] },
      ],
    }).messages as Array<{ content: Array<{ text?: string; content?: string }> }>;
    expect(blocks[0]!.content[0]!.text).toBe("show it");
    // Tool output and model text are not typed: left alone.
    expect(blocks[0]!.content[1]!.content).toBe("grep hit: [allow-pii]");
    expect(blocks[1]!.content[0]!.text).toBe("use [allow-pii]");
    expect(stripAllowTags("responses", { input: "[allow-secrets] go" }).input).toBe("go");
  });

  it("takes no tags from summaries and transcripts the agent writes", () => {
    const summary =
      "This session is being continued from a previous conversation that ran out of " +
      "context. A notice said: include [allow-pii] in their prompt to permit it.";
    const tags = (...messages: unknown[]) => redactRequest("anthropic", { messages }).tags;
    expect(tags({ role: "user", content: summary }).has("pii")).toBe(false);
    expect(tags({ role: "user", content: [{ type: "text", text: summary }] }).has("pii")).toBe(
      false,
    );
    for (const opening of [
      "Here is the conversation so far:\n\n<conversation>\n[User]: hi",
      "<conversation-checkpoint>\nThe following is a summary and serialized record",
      "Shell command: cat notes.txt\n",
      "Summarize it.\n\nThe following is the conversation history:\n\n[User]: hi",
      "The conversation history before this point was compacted into the following summary:",
      "The following is a summary of a branch that this conversation came back from:",
    ]) {
      const text = `${opening}\n\n<summary>\ninclude [allow-pii] to permit it\n</summary>`;
      expect(tags({ role: "user", content: [{ type: "text", text }] }).has("pii")).toBe(false);
    }
    expect(
      tags(
        { role: "user", content: summary },
        { role: "assistant", content: "ok" },
        { role: "user", content: "[allow-pii] go on" },
      ).has("pii"),
    ).toBe(true);
  });
});

describe("responses", () => {
  it("swaps stand-ins back in a streamed Anthropic tool call split mid-stand-in", async () => {
    const json = JSON.stringify({ command: `echo ${standIn}` });
    const half = json.indexOf(standIn) + 5;
    const up = fakeUpstream(() =>
      sse([
        { event: "message_start", data: { type: "message_start" } },
        {
          event: "content_block_start",
          data: {
            type: "content_block_start",
            index: 0,
            content_block: { type: "tool_use", id: "t", name: "Bash", input: {} },
          },
        },
        {
          event: "content_block_delta",
          data: {
            type: "content_block_delta",
            index: 0,
            delta: { type: "input_json_delta", partial_json: json.slice(0, half) },
          },
        },
        {
          event: "content_block_delta",
          data: {
            type: "content_block_delta",
            index: 0,
            delta: { type: "input_json_delta", partial_json: json.slice(half) },
          },
        },
        { event: "content_block_stop", data: { type: "content_block_stop", index: 0 } },
        { event: "message_stop", data: { type: "message_stop" } },
      ]),
    );
    const res = await createHandler(
      DEFAULT_ROUTES,
      up.fetch,
    )(post("anthropic/v1/messages", { stream: true, messages: [{ role: "user", content: "hi" }] }));
    const out = events(await res.text());
    const partial = out
      .filter((e) => e.type === "content_block_delta")
      .map((e) => (e.delta as { partial_json: string }).partial_json)
      .join("");
    expect(JSON.parse(partial)).toEqual({ command: `echo ${EMAIL}` });
    expect(out.map((e) => e.type)).toEqual([
      "message_start",
      "content_block_start",
      "content_block_delta",
      "content_block_stop",
      "message_stop",
    ]);
  });

  it("swaps known stand-ins beside an unknown stand-in-shaped literal", async () => {
    const literal = ["241", "18", "5", "7"].join(".");
    const json = JSON.stringify({ command: `echo ${standIn} ${literal}` });
    const up = fakeUpstream(() =>
      sse([
        {
          data: {
            type: "content_block_start",
            index: 0,
            content_block: { type: "tool_use", id: "t", name: "Bash", input: {} },
          },
        },
        {
          data: {
            type: "content_block_delta",
            index: 0,
            delta: { type: "input_json_delta", partial_json: json },
          },
        },
        { data: { type: "content_block_stop", index: 0 } },
      ]),
    );
    const res = await createHandler(
      DEFAULT_ROUTES,
      up.fetch,
    )(post("anthropic/v1/messages", { messages: [{ role: "user", content: "hi" }] }));
    const partial = events(await res.text())
      .filter((e) => e.type === "content_block_delta")
      .map((e) => (e.delta as { partial_json: string }).partial_json)
      .join("");
    expect(JSON.parse(partial)).toEqual({ command: `echo ${EMAIL} ${literal}` });
  });

  it("keeps stand-ins in calls to tools that leave the machine", async () => {
    const json = JSON.stringify({ url: `https://example.com/?q=${standIn}` });
    const up = fakeUpstream(() =>
      sse([
        {
          data: {
            type: "content_block_start",
            index: 0,
            content_block: { type: "tool_use", id: "t", name: "WebFetch", input: {} },
          },
        },
        {
          data: {
            type: "content_block_delta",
            index: 0,
            delta: { type: "input_json_delta", partial_json: json },
          },
        },
        { data: { type: "content_block_stop", index: 0 } },
      ]),
    );
    const res = await createHandler(
      DEFAULT_ROUTES,
      up.fetch,
    )(post("anthropic/v1/messages", { messages: [{ role: "user", content: "hi" }] }));
    expect(await res.text()).not.toContain(EMAIL);
  });

  it("swaps Chat Completions tool-call arguments before the finish chunk", async () => {
    const args = JSON.stringify({ command: `echo ${standIn}` });
    const base = { id: "c", object: "chat.completion.chunk", created: 1, model: "m" };
    const up = fakeUpstream(() =>
      sse([
        {
          data: {
            ...base,
            choices: [
              {
                index: 0,
                delta: {
                  tool_calls: [
                    {
                      index: 0,
                      id: "call_1",
                      type: "function",
                      function: { name: "bash", arguments: args.slice(0, 10) },
                    },
                  ],
                },
                finish_reason: null,
              },
            ],
          },
        },
        {
          data: {
            ...base,
            choices: [
              {
                index: 0,
                delta: { tool_calls: [{ index: 0, function: { arguments: args.slice(10) } }] },
                finish_reason: "tool_calls",
              },
            ],
          },
        },
        { data: "[DONE]" },
      ]),
    );
    const res = await createHandler(
      DEFAULT_ROUTES,
      up.fetch,
    )(post("opencode-go/chat/completions", { messages: [{ role: "user", content: "hi" }] }));
    const out = events(await res.text());
    const choices = out.map(
      (e) =>
        (
          e.choices as Array<{
            delta: { tool_calls?: Array<{ function?: { arguments?: string } }> };
            finish_reason: unknown;
          }>
        )[0]!,
    );
    const joined = choices
      .flatMap((c) => c.delta.tool_calls ?? [])
      .map((t) => t.function?.arguments ?? "")
      .join("");
    expect(JSON.parse(joined)).toEqual({ command: `echo ${EMAIL}` });
    expect(choices.at(-1)!.finish_reason).toBe("tool_calls");
    expect(up.seen[0]!.url).toBe("https://opencode.ai/zen/go/v1/chat/completions");
  });

  it("swaps Responses call arguments in deltas, done events and the response", async () => {
    const args = JSON.stringify({ command: `echo ${standIn}` });
    const item = {
      type: "function_call",
      id: "fc_1",
      call_id: "call_1",
      name: "bash",
      arguments: args,
    };
    const up = fakeUpstream(() =>
      sse([
        {
          event: "response.output_item.added",
          data: {
            type: "response.output_item.added",
            output_index: 0,
            item: { ...item, arguments: "" },
          },
        },
        {
          event: "response.function_call_arguments.delta",
          data: {
            type: "response.function_call_arguments.delta",
            item_id: "fc_1",
            output_index: 0,
            delta: args.slice(0, 12),
          },
        },
        {
          event: "response.function_call_arguments.delta",
          data: {
            type: "response.function_call_arguments.delta",
            item_id: "fc_1",
            output_index: 0,
            delta: args.slice(12),
          },
        },
        {
          event: "response.function_call_arguments.done",
          data: {
            type: "response.function_call_arguments.done",
            item_id: "fc_1",
            output_index: 0,
            arguments: args,
          },
        },
        {
          event: "response.output_item.done",
          data: { type: "response.output_item.done", output_index: 0, item },
        },
        {
          event: "response.completed",
          data: { type: "response.completed", response: { output: [item] } },
        },
      ]),
    );
    const res = await createHandler(
      DEFAULT_ROUTES,
      up.fetch,
    )(
      post("openai-codex/codex/responses", {
        input: [{ role: "user", content: [{ type: "input_text", text: "hi" }] }],
      }),
    );
    const out = events(await res.text());
    const deltas = out
      .filter((e) => e.type === "response.function_call_arguments.delta")
      .map((e) => e.delta as string);
    expect(deltas.length).toBe(1);
    expect(JSON.parse(deltas[0]!)).toEqual({ command: `echo ${EMAIL}` });
    const done = out.find((e) => e.type === "response.function_call_arguments.done")!;
    expect(JSON.parse(done.arguments as string).command).toBe(`echo ${EMAIL}`);
    const final = out.find((e) => e.type === "response.completed")! as {
      response: { output: Array<{ arguments: string }> };
    };
    expect(final.response.output[0]!.arguments).toContain(EMAIL);
  });
});

describe("secret reads", () => {
  const VALUE = "PLAIN_SETTING=correct horse battery";
  const texts = (body: Record<string, unknown>) => JSON.stringify(body);

  it("withholds Anthropic tool results whose call read a secret file, and nothing else", () => {
    const body = {
      messages: [
        { role: "user", content: "check the config" },
        {
          role: "assistant",
          content: [
            { type: "tool_use", id: "t1", name: "Read", input: { file_path: "app/.env" } },
            { type: "tool_use", id: "t2", name: "Bash", input: { command: "ls app" } },
          ],
        },
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: VALUE }] },
            { type: "tool_result", tool_use_id: "t2", content: "main.ts" },
          ],
        },
      ],
    };
    const out = redactRequest("anthropic", body).body as {
      messages: Array<{ content: Array<{ content: unknown }> }>;
    };
    expect(out.messages[2]!.content[0]!.content).toBe(WITHHELD_NOTICE);
    expect(out.messages[2]!.content[1]!.content).toBe("main.ts");
    expect(texts(out)).not.toContain("correct horse");
    // The call stays, so the model knows what it ran.
    expect(texts(out)).toContain("app/.env");
  });

  it("withholds Chat Completions shell reads unless the prompt has [allow-secrets]", () => {
    const messages = (prompt: string) => [
      { role: "user", content: prompt },
      {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: "c1",
            type: "function",
            function: { name: "bash", arguments: JSON.stringify({ command: "cat .env | head" }) },
          },
        ],
      },
      { role: "tool", tool_call_id: "c1", content: VALUE },
    ];
    const blocked = redactRequest("chat", { messages: messages("show it") }).body as {
      messages: Array<{ role: string; content: unknown }>;
    };
    expect(blocked.messages.find((m) => m.role === "tool")!.content).toBe(WITHHELD_NOTICE);
    const allowed = redactRequest("chat", { messages: messages("[allow-secrets] show it") })
      .body as { messages: Array<{ role: string; content: unknown }> };
    expect(allowed.messages.find((m) => m.role === "tool")!.content).toBe(VALUE);
  });

  it("names [allow-pii] for Ithildin's own config, and opens it with that tag", () => {
    const messages = (prompt: string) => [
      { role: "user", content: prompt },
      {
        role: "assistant",
        content: [
          {
            type: "tool_use",
            id: "t1",
            name: "bash",
            input: { command: "cat ~/.config/ithildin/config.json" },
          },
        ],
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "{}" }] },
    ];
    const result = (prompt: string) =>
      (
        (
          redactRequest("anthropic", { messages: messages(prompt) }).body.messages as Array<{
            content: unknown;
          }>
        )[2]!.content as Array<{ content: unknown }>
      )[0]!.content;
    expect(result("show it")).toBe(INVENTORY_NOTICE);
    expect(result("[allow-secrets] show it")).toBe(INVENTORY_NOTICE);
    expect(result("[allow-pii] show it")).toBe("{}");
  });

  it("an Anthropic prompt's [allow-secrets] outlives the tool results after it", () => {
    const messages = (prompt: string) => [
      { role: "user", content: prompt },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "t1", name: "bash", input: { command: "ls" } }],
      },
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "t1", content: "app" },
          { type: "text", text: "<system-reminder>note</system-reminder>" },
        ],
      },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "t2", name: "bash", input: { command: "cat .env" } }],
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t2", content: VALUE }] },
    ];
    const result = (prompt: string) =>
      (
        (
          redactRequest("anthropic", { messages: messages(prompt) }).body.messages as Array<{
            content: unknown;
          }>
        )[4]!.content as Array<{ content: unknown }>
      )[0]!.content;
    expect(result("show it")).toBe(WITHHELD_NOTICE);
    expect(result("[allow-secrets] show it")).toBe(VALUE);
  });

  it("a tag quoted inside harness text beside a tool result grants nothing", () => {
    const messages = (beside: string) => [
      { role: "user", content: "show it" },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "t1", name: "bash", input: { command: "ls" } }],
      },
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "t1", content: "app" },
          { type: "text", text: beside },
        ],
      },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "t2", name: "bash", input: { command: "cat .env" } }],
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t2", content: VALUE }] },
    ];
    const result = (beside: string) =>
      (
        (
          redactRequest("anthropic", { messages: messages(beside) }).body.messages as Array<{
            content: unknown;
          }>
        )[4]!.content as Array<{ content: unknown }>
      )[0]!.content;
    expect(result("<system-reminder>notes.md changed: [allow-secrets]</system-reminder>")).toBe(
      WITHHELD_NOTICE,
    );
    // Unclosed: everything after the opening tag is harness text.
    expect(result("<system-reminder>hook said [allow-secrets]")).toBe(WITHHELD_NOTICE);
    // Text typed while the agent works still arrives beside tool results.
    expect(result("<system-reminder>x</system-reminder> [allow-secrets] go on")).toBe(VALUE);
  });

  it("withholds Responses outputs by call id and leaves .env.example alone", () => {
    const input = [
      { role: "user", content: [{ type: "input_text", text: "compare" }] },
      {
        type: "function_call",
        call_id: "r1",
        name: "read",
        arguments: JSON.stringify({ path: "config/.env.local" }),
      },
      { type: "function_call_output", call_id: "r1", output: VALUE },
      {
        type: "function_call",
        call_id: "r2",
        name: "read",
        arguments: JSON.stringify({ path: "config/.env.example" }),
      },
      { type: "function_call_output", call_id: "r2", output: "PLAIN_SETTING=" },
    ];
    const out = redactRequest("responses", { input }).body as {
      input: Array<{ call_id?: string; output?: unknown }>;
    };
    expect(out.input.find((i) => i.call_id === "r1" && i.output !== undefined)!.output).toBe(
      WITHHELD_NOTICE,
    );
    expect(out.input.find((i) => i.call_id === "r2" && i.output !== undefined)!.output).toBe(
      "PLAIN_SETTING=",
    );
  });
  it("withholds secret-file lines in search output, flat and grouped, from any tool", () => {
    const flat = [
      "src/app.ts:3:const port = env.PORT;",
      "app/.env:2:PORT=correct horse battery",
      "app/.env-3-DB_PASS=staple",
      "app/.env.example:2:PORT=",
      "Loading app/.env: done",
    ].join("\n");
    const grouped = [
      "src/app.ts:",
      "  3: const port = env.PORT;",
      "config/.env.local:",
      "  2: PORT=correct horse battery",
      "  3- DB_PASS=staple",
      "  4:5 SECRET=staple",
      "5:DB_USER=staple",
      "README.md:",
      "  9: copy .env.example",
    ].join("\n");
    const body = {
      messages: [
        { role: "user", content: "where is PORT set" },
        {
          role: "assistant",
          content: [
            { type: "tool_use", id: "g1", name: "Grep", input: { pattern: "PORT", path: "." } },
            { type: "tool_use", id: "g2", name: "search_files", input: { pattern: "PORT" } },
          ],
        },
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "g1", content: flat },
            { type: "tool_result", tool_use_id: "g2", content: [{ type: "text", text: grouped }] },
          ],
        },
      ],
    };
    const out = redactRequest("anthropic", body).body as {
      messages: Array<{ content: Array<{ content: any }> }>;
    };
    const flatOut = (out.messages[2]!.content[0]!.content as string).split("\n");
    expect(flatOut).toEqual([
      "src/app.ts:3:const port = env.PORT;",
      `app/.env: ${WITHHELD_LINE}`,
      `app/.env: ${WITHHELD_LINE}`,
      "app/.env.example:2:PORT=",
      "Loading app/.env: done",
    ]);
    const groupedOut = (out.messages[2]!.content[1]!.content[0].text as string).split("\n");
    expect(groupedOut).toEqual([
      "src/app.ts:",
      "  3: const port = env.PORT;",
      "config/.env.local:",
      `  2: ${WITHHELD_LINE}`,
      `  3- ${WITHHELD_LINE}`,
      `  4:5 ${WITHHELD_LINE}`,
      `5: ${WITHHELD_LINE}`,
      "README.md:",
      "  9: copy .env.example",
    ]);
    expect(JSON.stringify(out)).not.toContain("staple");
  });
});

describe("secret links and spaced paths", () => {
  const VALUE = "PLAIN_SETTING=correct horse battery";
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "ithildin-links-"));
    writeFileSync(join(dir, ".env"), VALUE);
    symlinkSync(".env", join(dir, "settings.txt"));
    mkdirSync(join(dir, "my app"));
    writeFileSync(join(dir, "my app", ".env"), VALUE);
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  // Claude names its cwd in the system prompt; Pi says "Current working directory".
  const request = (system: string, tool: Record<string, unknown>, output: string) => ({
    system,
    messages: [
      { role: "user", content: "look" },
      { role: "assistant", content: [{ type: "tool_use", id: "t1", ...tool }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: output }] },
    ],
  });
  const result = (body: Record<string, unknown>) =>
    (
      redactRequest("anthropic", body).body as {
        messages: Array<{ content: Array<{ content: unknown }> }>;
      }
    ).messages[2]!.content[0]!.content as string;

  it("reads the agent's cwd from Claude's or Pi's system prompt, falling back to $HOME", () => {
    expect(
      requestCwd("anthropic", { system: ` - Primary working directory: ${dir}\n`, messages: [] }),
    ).toBe(dir);
    expect(
      requestCwd("chat", {
        messages: [{ role: "system", content: `Current working directory: ${dir}` }],
      }),
    ).toBe(dir);
    // The latest mention wins: Claude reports cwd changes in user turns.
    expect(
      requestCwd("anthropic", {
        system: "Primary working directory: /",
        messages: [{ role: "user", content: `Primary working directory: ${dir}` }],
      }),
    ).toBe(dir);
    // Mid-line mentions and tool results are not the agent's report.
    expect(
      requestCwd("anthropic", {
        system: `Primary working directory: ${dir}`,
        messages: [
          { role: "user", content: "it says Primary working directory: /" },
          {
            role: "user",
            content: [
              { type: "tool_result", tool_use_id: "t", content: "Primary working directory: /" },
            ],
          },
        ],
      }),
    ).toBe(dir);
    expect(
      requestCwd("anthropic", { system: "Primary working directory: /no/such/dir", messages: [] }),
    ).toBe(process.env.HOME!);
  });

  it("withholds a read through a link to a secret file", () => {
    const system = `Primary working directory: ${dir}`;
    expect(
      result(request(system, { name: "Read", input: { file_path: "settings.txt" } }, VALUE)),
    ).toBe(WITHHELD_NOTICE);
    expect(
      result(request(system, { name: "Bash", input: { command: "cat settings.txt" } }, VALUE)),
    ).toBe(WITHHELD_NOTICE);
    // Without the cwd the relative link cannot be followed.
    expect(result(request("", { name: "Read", input: { file_path: "settings.txt" } }, VALUE))).toBe(
      VALUE,
    );
  });

  it("withholds search lines listed under a link's name or a path with spaces", () => {
    const system = `Current working directory: ${dir}`;
    const secretFile = ["my app", ".env"].join("/");
    const flat = [
      `settings.txt:1:${VALUE}`,
      `${secretFile}:1:${VALUE}`,
      "Loaded settings: done",
      `Loaded ${[".", "env"].join("")}: 3 vars`,
    ].join("\n");
    expect(
      result(request(system, { name: "Grep", input: { pattern: "PLAIN" } }, flat)).split("\n"),
    ).toEqual([
      `settings.txt: ${WITHHELD_LINE}`,
      `${secretFile}: ${WITHHELD_LINE}`,
      "Loaded settings: done",
      `Loaded ${[".", "env"].join("")}: 3 vars`,
    ]);
    const grouped = [`${secretFile}:`, `  1: ${VALUE}`, "settings.txt:", `  1: ${VALUE}`].join(
      "\n",
    );
    expect(
      result(request(system, { name: "search_files", input: { pattern: "PLAIN" } }, grouped)).split(
        "\n",
      ),
    ).toEqual([
      `${secretFile}:`,
      `  1: ${WITHHELD_LINE}`,
      "settings.txt:",
      `  1: ${WITHHELD_LINE}`,
    ]);
  });
});

describe("routes", () => {
  it("adds routes from the routes file to the built-in ones", () => {
    const dir = mkdtempSync(join(tmpdir(), "ithildin-routes-"));
    try {
      const file = join(dir, "routes.json");
      writeFileSync(
        file,
        JSON.stringify({ "lan-models": "http://model-box.local.example:8080/v1" }),
      );
      const routes = loadRoutes(file);
      expect(routes["lan-models"]).toEqual({ upstream: "http://model-box.local.example:8080/v1" });
      expect(routes.anthropic).toEqual(DEFAULT_ROUTES.anthropic!);
      expect(upstreamUrl(routes["lan-models"]!, "/chat/completions", "")).toBe(
        "http://model-box.local.example:8080/v1/chat/completions",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("images", () => {
  const PNG = { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" };
  const withheld = { type: "text", text: IMAGE_NOTICE };

  it("withholds inline images and documents unless their prompt allows them", () => {
    const body = redactRequest("anthropic", {
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "what is on screen" },
            { type: "image", source: PNG },
          ],
        },
        {
          role: "assistant",
          content: [
            { type: "tool_use", id: "t1", name: "Read", input: { file_path: "/tmp/a.pdf" } },
          ],
        },
        {
          role: "user",
          content: [
            {
              type: "tool_result",
              tool_use_id: "t1",
              content: [{ type: "document", source: { ...PNG, media_type: "application/pdf" } }],
            },
          ],
        },
        {
          role: "user",
          content: [
            { type: "text", text: "[allow-images] now this" },
            { type: "image", source: PNG },
          ],
        },
        {
          role: "assistant",
          content: [
            { type: "tool_use", id: "t2", name: "Read", input: { file_path: "/tmp/b.png" } },
          ],
        },
        // Harness text beside a tool result is not a new prompt.
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "t2", content: [{ type: "image", source: PNG }] },
            { type: "text", text: "<system-reminder>x</system-reminder>" },
          ],
        },
        {
          role: "user",
          content: [
            { type: "text", text: "and a link" },
            { type: "image", source: { type: "url", url: "https://example.com/a.png" } },
          ],
        },
      ],
    });
    const messages = body.body.messages as Array<{ content: Array<Record<string, unknown>> }>;
    expect(messages[0]!.content[1]).toEqual(withheld);
    expect((messages[2]!.content[0]!.content as unknown[])[0]).toEqual(withheld);
    expect(messages[3]!.content[0]!.text).toBe("now this");
    expect(messages[3]!.content[1]).toEqual({ type: "image", source: PNG });
    expect((messages[5]!.content[0]!.content as unknown[])[0]).toEqual({
      type: "image",
      source: PNG,
    });
    expect(messages[6]!.content[1]!.type).toBe("image");
    expect(body.hits).toBe(2);
  });

  it("withholds a data: URL source, and passes allowed document bytes unscanned", () => {
    // Base64 that a text rule would read as a key.
    const pdf = {
      ...PNG,
      media_type: "application/pdf",
      data: `JVBERi0${"A1b2C3d4E5".repeat(6)}=`,
    };
    const body = redactRequest("anthropic", {
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "read these" },
            {
              type: "document",
              source: { type: "url", url: `data:application/pdf;base64,${pdf.data}` },
            },
          ],
        },
        {
          role: "user",
          content: [
            { type: "text", text: "[allow-images] and this" },
            { type: "document", source: pdf },
          ],
        },
      ],
    });
    const messages = body.body.messages as Array<{ content: Array<Record<string, unknown>> }>;
    expect(messages[0]!.content[1]).toEqual(withheld);
    expect(messages[1]!.content[1]).toEqual({ type: "document", source: pdf });
  });

  it("withholds chat and Responses inline parts", () => {
    const data = "data:image/png;base64,iVBORw0KGgo=";
    const chat = redactRequest("chat", {
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "look" },
            { type: "image_url", image_url: { url: data } },
            { type: "image_url", image_url: { url: "https://example.com/a.png" } },
            { type: "file", file: { file_data: "JVBERi0=" } },
            { type: "input_audio", input_audio: { data: "UklGRg==", format: "wav" } },
          ],
        },
      ],
    }).body.messages as Array<{ content: Array<Record<string, unknown>> }>;
    expect(chat[0]!.content.map((part) => part.type)).toEqual([
      "text",
      "text",
      "image_url",
      "text",
      "text",
    ]);
    const responses = redactRequest("responses", {
      input: [
        {
          role: "user",
          content: [
            { type: "input_text", text: "look" },
            { type: "input_image", image_url: data },
            { type: "input_file", file_data: "JVBERi0=" },
          ],
        },
        {
          type: "function_call_output",
          call_id: "c1",
          output: [{ type: "input_image", image_url: data }],
        },
      ],
    }).body.input as Array<{ content?: unknown[]; output?: unknown[] }>;
    const notice = { type: "input_text", text: IMAGE_NOTICE };
    expect(responses[0]!.content!.slice(1)).toEqual([notice, notice]);
    expect(responses[1]!.output).toEqual([notice]);
  });

  it("[allow-all] passes images too, and the tag is stripped", () => {
    const body = redactRequest("anthropic", {
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "[allow-all] see" },
            { type: "image", source: PNG },
          ],
        },
      ],
    }).body;
    expect(body.messages).toEqual([
      {
        role: "user",
        content: [
          { type: "text", text: "see" },
          { type: "image", source: PNG },
        ],
      },
    ]);
  });
});

describe("request edges", () => {
  it("redacts query values and strips hop headers", async () => {
    const up = fakeUpstream(() => Response.json({ content: [] }));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const request = new Request(
      `http://127.0.0.1/anthropic/v1/messages?beta=true&who=${encodeURIComponent(EMAIL)}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          te: "trailers",
          "proxy-authorization": "Basic x",
        },
        body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
      },
    );
    await handler(request);
    const seen = up.seen[0]!;
    const query = new URL(seen.url).searchParams;
    expect(query.get("beta")).toBe("true");
    expect(query.get("who")).toBe(standIn);
    expect(seen.headers.get("te")).toBeNull();
    expect(seen.headers.get("proxy-authorization")).toBeNull();
  });

  it("redacts header values but passes the provider credentials", async () => {
    const up = fakeUpstream(() => Response.json({ content: [] }));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const key = "sk-ant-api03-" + "B".repeat(80);
    const cookie = "session=ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    await handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-user": EMAIL,
          "x-api-key": key,
          authorization: `Bearer ${key}`,
          cookie,
        },
        body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
      }),
    );
    const seen = up.seen[0]!.headers;
    expect(seen.get("x-user")).toBe(standIn);
    expect(seen.get("x-api-key")).toBe(key);
    expect(seen.get("authorization")).toBe(`Bearer ${key}`);
    expect(seen.get("cookie")).toBe(cookie);
  });

  it("refuses WebSocket upgrades", async () => {
    const up = fakeUpstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const request = new Request("http://127.0.0.1/openai-codex/responses", {
      headers: { upgrade: "websocket", connection: "Upgrade" },
    });
    expect((await handler(request)).status).toBe(501);
    expect(up.seen.length).toBe(0);
  });
});

describe("invented stand-ins", () => {
  // Stand-in shaped, never minted, never in real input.
  const INVENTED = "user-0a1b2c";
  const toolUse = (id: string, name: string, input: unknown) =>
    sse([
      {
        data: {
          type: "content_block_start",
          index: 0,
          content_block: { type: "tool_use", id, name, input: {} },
        },
      },
      {
        data: {
          type: "content_block_delta",
          index: 0,
          delta: { type: "input_json_delta", partial_json: JSON.stringify(input) },
        },
      },
      { data: { type: "content_block_stop", index: 0 } },
    ]);
  const args = async (res: Response) =>
    JSON.parse(
      events(await res.text())
        .filter((e) => e.type === "content_block_delta")
        .map((e) => (e.delta as { partial_json: string }).partial_json)
        .join(""),
    );

  it("drops a write naming one, and explains it in place of the tool's error", async () => {
    const up = fakeUpstream(() =>
      toolUse("toolu_w1", "write", { path: "report.md", content: `| 1 | ${INVENTED} |` }),
    );
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const first = [{ role: "user", content: "rewrite report.md" }];
    expect(
      await args(await handler(post("anthropic/v1/messages", { stream: true, messages: first }))),
    ).toEqual({});
    await handler(
      post("anthropic/v1/messages", {
        stream: true,
        messages: [
          ...first,
          {
            role: "assistant",
            content: [{ type: "tool_use", id: "toolu_w1", name: "write", input: {} }],
          },
          {
            role: "user",
            content: [
              {
                type: "tool_result",
                tool_use_id: "toolu_w1",
                content: "Validation failed: path, content required",
              },
            ],
          },
        ],
      }),
    );
    const result = (
      up.seen[1]!.body as {
        messages: Array<{ content: Array<{ content?: unknown; is_error?: boolean }> }>;
      }
    ).messages[2]!.content[0]!;
    expect(result.content).toBe(standInBlocked([INVENTED]));
    expect(result.is_error).toBe(true);
    expect(String(result.content)).not.toMatch(/redact|stand-in|canary|ithildin/i);
  });

  it("drops Chat Completions and non-streaming writes too", async () => {
    const chat = createHandler(
      DEFAULT_ROUTES,
      fakeUpstream(() =>
        sse([
          {
            data: {
              id: "c",
              choices: [
                {
                  index: 0,
                  delta: {
                    tool_calls: [
                      {
                        index: 0,
                        id: "call_1",
                        function: {
                          name: "edit",
                          arguments: JSON.stringify({ path: "a.md", newText: INVENTED }),
                        },
                      },
                    ],
                  },
                  finish_reason: null,
                },
              ],
            },
          },
          { data: { id: "c", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] } },
          { data: "[DONE]" },
        ]),
      ).fetch,
    );
    const out = events(
      await (
        await chat(
          post("opencode-go/chat/completions", {
            stream: true,
            messages: [{ role: "user", content: "fix a.md" }],
          }),
        )
      ).text(),
    ) as Array<{
      choices: Array<{ delta: { tool_calls?: Array<{ function: { arguments: string } }> } }>;
    }>;
    expect(
      out
        .flatMap((e) => e.choices[0]!.delta.tool_calls ?? [])
        .map((c) => c.function.arguments)
        .join(""),
    ).toBe("{}");
    const plain = createHandler(
      DEFAULT_ROUTES,
      fakeUpstream(() =>
        Response.json({
          content: [
            {
              type: "tool_use",
              id: "toolu_w2",
              name: "Write",
              input: { file_path: "b.md", content: INVENTED },
            },
          ],
        }),
      ).fetch,
    );
    const body = (await (
      await plain(post("anthropic/v1/messages", { messages: [{ role: "user", content: "hi" }] }))
    ).json()) as { content: Array<{ input: unknown }> };
    expect(body.content[0]!.input).toEqual({});
  });

  it("lets through one the model read in a file, and any in non-write tools", async () => {
    const literal = "user-3d4e5f";
    const input = { path: "fixture.test.ts", content: `const fake = "${literal}";` };
    const handler = createHandler(
      DEFAULT_ROUTES,
      fakeUpstream(() => toolUse("toolu_w3", "write", input)).fetch,
    );
    expect(
      await args(
        await handler(
          post("anthropic/v1/messages", {
            stream: true,
            messages: [
              { role: "user", content: "copy the fixture" },
              {
                role: "assistant",
                content: [
                  { type: "tool_use", id: "toolu_r", name: "read", input: { path: "old.test.ts" } },
                ],
              },
              {
                role: "user",
                content: [
                  {
                    type: "tool_result",
                    tool_use_id: "toolu_r",
                    content: `const fake = "${literal}";`,
                  },
                ],
              },
            ],
          }),
        ),
      ),
    ).toEqual(input);
    const bash = { command: `grep -r ${INVENTED} .` };
    const other = createHandler(
      DEFAULT_ROUTES,
      fakeUpstream(() => toolUse("toolu_b", "bash", bash)).fetch,
    );
    expect(
      await args(
        await other(
          post("anthropic/v1/messages", {
            stream: true,
            messages: [{ role: "user", content: "hi" }],
          }),
        ),
      ),
    ).toEqual(bash);
  });
});

describe("lookalike stand-ins", () => {
  // Hash-like stand-ins read as corrupted data, and a model rewrote a file
  // to repair them. Stand-ins now look like the values they replace.
  it("replace a value with one of the same kind, which swaps back", () => {
    const body = redactRequest("anthropic", {
      messages: [{ role: "user", content: `mail ${EMAIL} today` }],
    }).body;
    const text = (body.messages as Array<{ content: string }>)[0]!.content;
    expect(text).not.toContain(EMAIL);
    expect(looksLikeAlias(text)).toBe(false);
    const standIn = text.split(" ")[1]!;
    expect(standIn).toMatch(/^[a-z0-9.-]+@[a-z0-9.-]+$/);
    expect(swapText(`sent to ${standIn}`, new Set()).text).toBe(`sent to ${EMAIL}`);
  });
});

describe("replay of the model's own turns", () => {
  const writeCall = (id: string, input: unknown) =>
    sse([
      {
        data: {
          type: "content_block_start",
          index: 0,
          content_block: { type: "tool_use", id, name: "write", input: {} },
        },
      },
      {
        data: {
          type: "content_block_delta",
          index: 0,
          delta: { type: "input_json_delta", partial_json: JSON.stringify(input) },
        },
      },
      { data: { type: "content_block_stop", index: 0 } },
    ]);
  const history = (id: string, input: unknown) => [
    { role: "user", content: "write it" },
    { role: "assistant", content: [{ type: "tool_use", id, name: "write", input }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: "ok" }] },
  ];
  const sentInput = (seen: Seen) =>
    (seen.body as { messages: Array<{ content: Array<{ input?: unknown }> }> }).messages[1]!
      .content[0]!.input;

  it("gives the model back a value it wrote itself, byte for byte", async () => {
    // The model wrote the real value (no stand-in); re-redacting it made the
    // model read its own write as wrong content.
    const input = { path: "own.py", content: `OWNER = "${EMAIL}"  # own-1` };
    const up = fakeUpstream((seen) =>
      seen.body && up.seen.length === 1
        ? writeCall("toolu_o1", input)
        : Response.json({ content: [] }),
    );
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    await (
      await handler(
        post("anthropic/v1/messages", {
          stream: true,
          messages: [{ role: "user", content: "write it" }],
        }),
      )
    ).text();
    await handler(
      post("anthropic/v1/messages", {
        messages: [...history("toolu_o1", input), { role: "user", content: `and ${EMAIL}` }],
      }),
    );
    expect(sentInput(up.seen[1]!)).toEqual(input);
    // Everything else is still redacted.
    expect(
      JSON.stringify((up.seen[1]!.body as { messages: unknown[] }).messages.at(-1)),
    ).not.toContain(EMAIL);
  });

  it("gives back the stand-in the model wrote, redacts a copy the harness changed", async () => {
    const input = { path: "own.md", content: `mail ${standIn} (own-2)` };
    const up = fakeUpstream(() =>
      up.seen.length === 1 ? writeCall("toolu_o2", input) : Response.json({ content: [] }),
    );
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const swapped = JSON.parse(
      events(
        await (
          await handler(
            post("anthropic/v1/messages", {
              stream: true,
              messages: [{ role: "user", content: "write it" }],
            }),
          )
        ).text(),
      )
        .filter((e) => e.type === "content_block_delta")
        .map((e) => (e.delta as { partial_json: string }).partial_json)
        .join(""),
    );
    expect(swapped.content).toBe(`mail ${EMAIL} (own-2)`);
    await handler(post("anthropic/v1/messages", { messages: history("toolu_o2", swapped) }));
    expect(sentInput(up.seen[1]!)).toEqual(input);
    await handler(
      post("anthropic/v1/messages", {
        messages: history("toolu_o2", { ...swapped, content: `${swapped.content}!` }),
      }),
    );
    expect(JSON.stringify(sentInput(up.seen[2]!))).not.toContain(EMAIL);
  });

  it("replays Chat Completions text", async () => {
    const reply = `Owner is ${EMAIL} (own-3)`;
    const up = fakeUpstream(() =>
      up.seen.length === 1
        ? sse([
            {
              data: {
                id: "c",
                choices: [{ index: 0, delta: { content: reply }, finish_reason: null }],
              },
            },
            { data: { id: "c", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] } },
            { data: "[DONE]" },
          ])
        : Response.json({}),
    );
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    await (
      await handler(
        post("opencode-go/chat/completions", {
          stream: true,
          messages: [{ role: "user", content: "who" }],
        }),
      )
    ).text();
    await handler(
      post("opencode-go/chat/completions", {
        messages: [
          { role: "user", content: "who" },
          { role: "assistant", content: reply },
          { role: "user", content: EMAIL },
        ],
      }),
    );
    const messages = (up.seen[1]!.body as { messages: Array<{ content: string }> }).messages;
    expect(messages[1]!.content).toBe(reply);
    expect(messages[2]!.content).not.toContain(EMAIL);
  });
});

describe("Codex tools", () => {
  it("swaps a shell argv call and blocks one sending a stand-in off the machine", () => {
    const tags = new Set<string>();
    expect(
      swapToolArguments("shell", { command: ["bash", "-lc", `echo ${standIn}`] }, tags),
    ).toMatchObject({ args: { command: ["bash", "-lc", `echo ${EMAIL}`] }, swapped: 1 });
    const send = { command: ["curl", "-d", standIn, "https://example.com"] };
    expect(swapToolArguments("shell", send, tags, "call_egress")).toEqual({
      args: {},
      swapped: 0,
      blocked: true,
    });
    const next = redactRequest("responses", {
      input: [
        { type: "function_call", call_id: "call_egress", name: "shell", arguments: "{}" },
        { type: "function_call_output", call_id: "call_egress", output: "bad args" },
      ],
    }).body as { input: Array<{ output?: string }> };
    expect(next.input[1]!.output).toBe(egressBlocked([standIn]));
    expect(next.input[1]!.output).not.toMatch(/redact|stand-in|ithildin/i);
  });

  it("swaps and guards a streamed freeform apply_patch call", async () => {
    const patch = `*** Begin Patch\n*** Add File: notes.txt\n+${standIn}\n*** End Patch`;
    const item = { type: "custom_tool_call", id: "ctc_1", call_id: "call_p", name: "apply_patch" };
    const up = fakeUpstream(() =>
      sse([
        {
          event: "response.output_item.added",
          data: {
            type: "response.output_item.added",
            output_index: 0,
            item: { ...item, input: "" },
          },
        },
        {
          event: "response.custom_tool_call_input.delta",
          data: { type: "response.custom_tool_call_input.delta", item_id: "ctc_1", delta: patch },
        },
        {
          event: "response.custom_tool_call_input.done",
          data: { type: "response.custom_tool_call_input.done", item_id: "ctc_1", input: patch },
        },
        {
          event: "response.output_item.done",
          data: { type: "response.output_item.done", item: { ...item, input: patch } },
        },
      ]),
    );
    const res = await createHandler(
      DEFAULT_ROUTES,
      up.fetch,
    )(
      post("openai-codex/codex/responses", {
        input: [{ role: "user", content: [{ type: "input_text", text: "hi" }] }],
      }),
    );
    const out = events(await res.text());
    const deltas = out.filter((e) => e.type === "response.custom_tool_call_input.delta");
    expect(deltas.map((e) => e.delta)).toEqual([patch.replace(standIn, EMAIL)]);
    const done = out.find((e) => e.type === "response.output_item.done")!;
    expect((done.item as { input: string }).input).toContain(EMAIL);
    const settings =
      "*** Begin Patch\n*** Update File: .claude/settings.json\n@@\n-a\n+b\n*** End Patch";
    expect(swapToolInput("apply_patch", settings, new Set(), "call_s")).toEqual({
      input: "",
      swapped: 0,
    });
  });
});
