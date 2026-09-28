import { beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SYNTHESIS_SYSTEM_REMINDER } from "../engine/core.ts";
import { initEngine, redactRequest, swapText, WITHHELD_LINE, WITHHELD_NOTICE } from "./canary.ts";
import { createHandler, DEFAULT_ROUTES, loadRoutes, upstreamUrl } from "./server.ts";

const EMAIL = "jane.doe@acme-corp.com";
let standIn = "";

beforeAll(() => {
  initEngine();
  const body = redactRequest("anthropic", { messages: [{ role: "user", content: EMAIL }] }).body as { messages: Array<{ content: string }> };
  standIn = body.messages[0]!.content;
});

type Seen = { url: string; body: unknown; headers: Headers };

function fakeUpstream(reply: (seen: Seen) => Response): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const fn = (async (url: string, init: RequestInit) => {
    const entry = { url, body: init.body ? JSON.parse(String(init.body)) : undefined, headers: new Headers(init.headers) };
    seen.push(entry);
    return reply(entry);
  }) as unknown as typeof fetch;
  return { fetch: fn, seen };
}

function sse(events: Array<{ event?: string; data: unknown }>, chunkAt?: number): Response {
  const text = events.map((e) => `${e.event ? `event: ${e.event}\n` : ""}data: ${typeof e.data === "string" ? e.data : JSON.stringify(e.data)}\n\n`).join("");
  const bytes = new TextEncoder().encode(text);
  const cut = chunkAt ?? Math.floor(bytes.length / 2);
  return new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(bytes.slice(0, cut));
      controller.enqueue(bytes.slice(cut));
      controller.close();
    },
  }), { headers: { "content-type": "text/event-stream" } });
}

function post(path: string, body: unknown): Request {
  return new Request(`http://127.0.0.1/${path}`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer sub-token" }, body: JSON.stringify(body) });
}

function events(text: string): Array<Record<string, unknown>> {
  return text.split("\n\n").flatMap((block) => {
    const data = block.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).join("\n");
    if (!data || data === "[DONE]") return [];
    return [JSON.parse(data)];
  });
}

describe("requests", () => {
  it("redacts the prompt, keeps credentials, thinking and ids", async () => {
    const up = fakeUpstream(() => Response.json({ content: [] }));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const thinking = { type: "thinking", thinking: `I recall ${EMAIL}`, signature: "sig" };
    await handler(post("anthropic/v1/messages", {
      model: "claude-x",
      messages: [
        { role: "user", content: `write to ${EMAIL}` },
        { role: "assistant", content: [thinking, { type: "tool_use", id: "toolu_01", name: "Bash", input: { command: `echo ${EMAIL}` } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_01", content: EMAIL }] },
      ],
    }));
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
    await createHandler(DEFAULT_ROUTES, up.fetch)(post("anthropic/v1/messages", { messages: [{ role: "user", content: `[allow-all] ${EMAIL}` }] }));
    expect(JSON.stringify(up.seen[0]!.body)).toContain(EMAIL);
  });

  it("refuses unknown routes and compressed bodies", async () => {
    const up = fakeUpstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    expect((await handler(post("nowhere/v1/messages", {}))).status).toBe(404);
    const gz = new Request("http://127.0.0.1/anthropic/v1/messages", { method: "POST", headers: { "content-type": "application/json", "content-encoding": "gzip" }, body: "x" });
    expect((await handler(gz)).status).toBe(415);
    expect(up.seen.length).toBe(0);
  });

  it("maps opencode-go's three wire formats onto one upstream", () => {
    const route = DEFAULT_ROUTES["opencode-go"]!;
    expect(upstreamUrl(route, "/v1/messages", "")).toBe("https://opencode.ai/zen/go/v1/messages");
    expect(upstreamUrl(route, "/chat/completions", "")).toBe("https://opencode.ai/zen/go/v1/chat/completions");
    expect(upstreamUrl(route, "/responses", "")).toBe("https://opencode.ai/zen/go/v1/responses");
    expect(upstreamUrl(DEFAULT_ROUTES["openai-codex"]!, "/codex/responses", "?a=1")).toBe("https://chatgpt.com/backend-api/codex/responses?a=1");
  });
});

describe("reply text", () => {
  const handler = (reply: () => Response) => createHandler(DEFAULT_ROUTES, fakeUpstream(reply).fetch);

  it("swaps stand-ins in streamed Anthropic text split mid-stand-in, and leaves thinking alone", async () => {
    const literal = ["241", "18", "5", "7"].join(".");
    const text = `Mail ${standIn} at ${literal}\nthen stop`;
    const cut = text.indexOf(standIn) + 4;
    const res = await handler(() => sse([
      { data: { type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "" } } },
      { data: { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: `about ${standIn}` } } },
      { data: { type: "content_block_stop", index: 0 } },
      { data: { type: "content_block_start", index: 1, content_block: { type: "text", text: "" } } },
      { data: { type: "content_block_delta", index: 1, delta: { type: "text_delta", text: text.slice(0, cut) } } },
      { data: { type: "content_block_delta", index: 1, delta: { type: "text_delta", text: text.slice(cut) } } },
      { data: { type: "content_block_stop", index: 1 } },
    ]))(post("anthropic/v1/messages", { stream: true, messages: [{ role: "user", content: "hi" }] }));
    const out = events(await res.text());
    const deltas = out.filter((e) => e.type === "content_block_delta").map((e) => e.delta as { type: string; text?: string; thinking?: string });
    expect(deltas.filter((d) => d.type === "text_delta").map((d) => d.text).join("")).toBe(`Mail ${EMAIL} at ${literal}\nthen stop`);
    expect(deltas.find((d) => d.type === "thinking_delta")!.thinking).toBe(`about ${standIn}`);
    expect(out.at(-1)!.type).toBe("content_block_stop");
  });

  it("swaps Chat Completions content, flushing the tail before the finish", async () => {
    const chunk = (delta: unknown, finish: unknown = null) => ({ data: { id: "c", choices: [{ index: 0, delta, finish_reason: finish }] } });
    const res = await handler(() => sse([chunk({ content: `to ${standIn.slice(0, 6)}` }), chunk({ content: standIn.slice(6) }), chunk({}, "stop"), { data: "[DONE]" }]))(
      post("opencode-go/chat/completions", { stream: true, messages: [{ role: "user", content: "hi" }] }),
    );
    const out = events(await res.text()) as Array<{ choices: Array<{ delta: { content?: string }; finish_reason: unknown }> }>;
    expect(out.map((e) => e.choices[0]!.delta.content ?? "").join("")).toBe(`to ${EMAIL}`);
    expect(out.at(-1)!.choices[0]!.finish_reason).toBe("stop");
  });

  it("swaps Responses text deltas and the final text", async () => {
    const res = await handler(() => sse([
      { data: { type: "response.output_text.delta", item_id: "m", content_index: 0, delta: `to ${standIn.slice(0, 6)}` } },
      { data: { type: "response.output_text.delta", item_id: "m", content_index: 0, delta: standIn.slice(6) } },
      { data: { type: "response.output_text.done", item_id: "m", content_index: 0, text: `to ${standIn}` } },
      { data: { type: "response.completed", response: { output: [{ type: "message", content: [{ type: "output_text", text: `to ${standIn}` }] }] } } },
    ]))(post("openai-codex/codex/responses", { stream: true, input: "hi" }));
    const out = events(await res.text());
    expect(out.filter((e) => e.type === "response.output_text.delta").map((e) => e.delta).join("")).toBe(`to ${EMAIL}`);
    expect(out.find((e) => e.type === "response.output_text.done")!.text).toBe(`to ${EMAIL}`);
    expect(JSON.stringify(out.at(-1))).toContain(EMAIL);
    expect(JSON.stringify(out)).not.toContain(standIn);
  });

  it("swaps non-streaming text", async () => {
    const res = await handler(() => Response.json({ content: [{ type: "text", text: `to ${standIn}` }] }))(
      post("anthropic/v1/messages", { messages: [{ role: "user", content: "hi" }] }),
    );
    expect(((await res.json()) as { content: Array<{ text: string }> }).content[0]!.text).toBe(`to ${EMAIL}`);
  });

  it("round-trips: the swapped reply is redacted back to the exact bytes the model wrote", () => {
    const reply = `Sent it to ${standIn}.`;
    const shown = swapText(reply, new Set()).text;
    expect(shown).toBe(`Sent it to ${EMAIL}.`);
    const next = redactRequest("anthropic", { messages: [
      { role: "user", content: `mail ${EMAIL}` },
      { role: "assistant", content: [{ type: "text", text: shown }] },
      { role: "user", content: "thanks" },
    ] }).body as { messages: Array<{ content: unknown }> };
    expect(next.messages[1]!.content).toEqual([{ type: "text", text: reply }]);
    expect(JSON.stringify(next)).not.toContain(EMAIL);
  });
});

describe("reminder", () => {
  it("tells every format's model about stand-ins, once, without redacting its examples", () => {
    const anthropic = redactRequest("anthropic", { system: [{ type: "text", text: "base" }], messages: [{ role: "user", content: "hi" }] }).body;
    expect((anthropic.system as Array<{ text: string }>).at(-1)!.text).toBe(SYNTHESIS_SYSTEM_REMINDER);
    expect(redactRequest("anthropic", { system: "base", messages: [] }).body.system).toBe(`base\n\n${SYNTHESIS_SYSTEM_REMINDER}`);
    const chat = redactRequest("chat", { messages: [{ role: "user", content: "hi" }] }).body.messages as Array<{ role: string; content: string }>;
    expect(chat[0]).toEqual({ role: "system", content: SYNTHESIS_SYSTEM_REMINDER });
    const merged = redactRequest("chat", { messages: [{ role: "system", content: "base" }, { role: "user", content: "hi" }] }).body.messages as Array<{ content: string }>;
    expect(merged.length).toBe(2);
    expect(merged[0]!.content).toBe(`base\n\n${SYNTHESIS_SYSTEM_REMINDER}`);
    const responses = redactRequest("responses", { instructions: "codex", input: "hi" }).body;
    expect(responses.instructions).toBe("codex");
    expect((responses.input as unknown[])[0]).toEqual({ role: "developer", content: SYNTHESIS_SYSTEM_REMINDER });
    // A system prompt that already carries it is left alone.
    const pi = redactRequest("anthropic", { system: `base\n\n${SYNTHESIS_SYSTEM_REMINDER}`, messages: [] }).body;
    expect(pi.system).toBe(`base\n\n${SYNTHESIS_SYSTEM_REMINDER}`);
    // Quoting it in the conversation does not count.
    const quoted = redactRequest("anthropic", { messages: [{ role: "user", content: SYNTHESIS_SYSTEM_REMINDER }] }).body;
    expect(quoted.system).toBe(SYNTHESIS_SYSTEM_REMINDER);
    // [allow-all] passes the body untouched.
    expect(redactRequest("anthropic", { messages: [{ role: "user", content: "[allow-all] hi" }] }).body.system).toBeUndefined();
  });
});

describe("responses", () => {
  it("swaps stand-ins back in a streamed Anthropic tool call split mid-stand-in", async () => {
    const json = JSON.stringify({ command: `echo ${standIn}` });
    const half = json.indexOf(standIn) + 5;
    const up = fakeUpstream(() => sse([
      { event: "message_start", data: { type: "message_start" } },
      { event: "content_block_start", data: { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "t", name: "Bash", input: {} } } },
      { event: "content_block_delta", data: { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: json.slice(0, half) } } },
      { event: "content_block_delta", data: { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: json.slice(half) } } },
      { event: "content_block_stop", data: { type: "content_block_stop", index: 0 } },
      { event: "message_stop", data: { type: "message_stop" } },
    ]));
    const res = await createHandler(DEFAULT_ROUTES, up.fetch)(post("anthropic/v1/messages", { stream: true, messages: [{ role: "user", content: "hi" }] }));
    const out = events(await res.text());
    const partial = out.filter((e) => e.type === "content_block_delta").map((e) => (e.delta as { partial_json: string }).partial_json).join("");
    expect(JSON.parse(partial)).toEqual({ command: `echo ${EMAIL}` });
    expect(out.map((e) => e.type)).toEqual(["message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_stop"]);
  });

  it("swaps known stand-ins even when an unknown stand-in-shaped literal sits beside them", async () => {
    const literal = ["241", "18", "5", "7"].join(".");
    const json = JSON.stringify({ command: `echo ${standIn} ${literal}` });
    const up = fakeUpstream(() => sse([
      { data: { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "t", name: "Bash", input: {} } } },
      { data: { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: json } } },
      { data: { type: "content_block_stop", index: 0 } },
    ]));
    const res = await createHandler(DEFAULT_ROUTES, up.fetch)(post("anthropic/v1/messages", { messages: [{ role: "user", content: "hi" }] }));
    const partial = events(await res.text()).filter((e) => e.type === "content_block_delta").map((e) => (e.delta as { partial_json: string }).partial_json).join("");
    expect(JSON.parse(partial)).toEqual({ command: `echo ${EMAIL} ${literal}` });
  });

  it("keeps stand-ins in calls to tools that leave the machine", async () => {
    const json = JSON.stringify({ url: `https://example.com/?q=${standIn}` });
    const up = fakeUpstream(() => sse([
      { data: { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "t", name: "WebFetch", input: {} } } },
      { data: { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: json } } },
      { data: { type: "content_block_stop", index: 0 } },
    ]));
    const res = await createHandler(DEFAULT_ROUTES, up.fetch)(post("anthropic/v1/messages", { messages: [{ role: "user", content: "hi" }] }));
    expect(await res.text()).not.toContain(EMAIL);
  });

  it("swaps Chat Completions tool-call arguments before the finish chunk", async () => {
    const args = JSON.stringify({ command: `echo ${standIn}` });
    const base = { id: "c", object: "chat.completion.chunk", created: 1, model: "m" };
    const up = fakeUpstream(() => sse([
      { data: { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "bash", arguments: args.slice(0, 10) } }] }, finish_reason: null }] } },
      { data: { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: args.slice(10) } }] }, finish_reason: "tool_calls" }] } },
      { data: "[DONE]" },
    ]));
    const res = await createHandler(DEFAULT_ROUTES, up.fetch)(post("opencode-go/chat/completions", { messages: [{ role: "user", content: "hi" }] }));
    const out = events(await res.text());
    const choices = out.map((e) => (e.choices as Array<{ delta: { tool_calls?: Array<{ function?: { arguments?: string } }> }; finish_reason: unknown }>)[0]!);
    const joined = choices.flatMap((c) => c.delta.tool_calls ?? []).map((t) => t.function?.arguments ?? "").join("");
    expect(JSON.parse(joined)).toEqual({ command: `echo ${EMAIL}` });
    expect(choices.at(-1)!.finish_reason).toBe("tool_calls");
    expect(up.seen[0]!.url).toBe("https://opencode.ai/zen/go/v1/chat/completions");
  });

  it("swaps Responses function-call arguments in deltas, done events and the final response", async () => {
    const args = JSON.stringify({ command: `echo ${standIn}` });
    const item = { type: "function_call", id: "fc_1", call_id: "call_1", name: "bash", arguments: args };
    const up = fakeUpstream(() => sse([
      { event: "response.output_item.added", data: { type: "response.output_item.added", output_index: 0, item: { ...item, arguments: "" } } },
      { event: "response.function_call_arguments.delta", data: { type: "response.function_call_arguments.delta", item_id: "fc_1", output_index: 0, delta: args.slice(0, 12) } },
      { event: "response.function_call_arguments.delta", data: { type: "response.function_call_arguments.delta", item_id: "fc_1", output_index: 0, delta: args.slice(12) } },
      { event: "response.function_call_arguments.done", data: { type: "response.function_call_arguments.done", item_id: "fc_1", output_index: 0, arguments: args } },
      { event: "response.output_item.done", data: { type: "response.output_item.done", output_index: 0, item } },
      { event: "response.completed", data: { type: "response.completed", response: { output: [item] } } },
    ]));
    const res = await createHandler(DEFAULT_ROUTES, up.fetch)(post("openai-codex/codex/responses", { input: [{ role: "user", content: [{ type: "input_text", text: "hi" }] }] }));
    const out = events(await res.text());
    const deltas = out.filter((e) => e.type === "response.function_call_arguments.delta").map((e) => e.delta as string);
    expect(deltas.length).toBe(1);
    expect(JSON.parse(deltas[0]!)).toEqual({ command: `echo ${EMAIL}` });
    const done = out.find((e) => e.type === "response.function_call_arguments.done")!;
    expect(JSON.parse(done.arguments as string).command).toBe(`echo ${EMAIL}`);
    const final = out.find((e) => e.type === "response.completed")! as { response: { output: Array<{ arguments: string }> } };
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
        { role: "assistant", content: [
          { type: "tool_use", id: "t1", name: "Read", input: { file_path: "app/.env" } },
          { type: "tool_use", id: "t2", name: "Bash", input: { command: "ls app" } },
        ] },
        { role: "user", content: [
          { type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: VALUE }] },
          { type: "tool_result", tool_use_id: "t2", content: "main.ts" },
        ] },
      ],
    };
    const out = redactRequest("anthropic", body).body as { messages: Array<{ content: Array<{ content: unknown }> }> };
    expect(out.messages[2]!.content[0]!.content).toBe(WITHHELD_NOTICE);
    expect(out.messages[2]!.content[1]!.content).toBe("main.ts");
    expect(texts(out)).not.toContain("correct horse");
    // The call stays, so the model knows what it ran.
    expect(texts(out)).toContain("app/.env");
  });

  it("withholds Chat Completions results of shell reads, unless [allow-secrets] is in the latest prompt", () => {
    const messages = (prompt: string) => [
      { role: "user", content: prompt },
      { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "bash", arguments: JSON.stringify({ command: "cat .env | head" }) } }] },
      { role: "tool", tool_call_id: "c1", content: VALUE },
    ];
    const blocked = redactRequest("chat", { messages: messages("show it") }).body as { messages: Array<{ role: string; content: unknown }> };
    expect(blocked.messages.find((m) => m.role === "tool")!.content).toBe(WITHHELD_NOTICE);
    const allowed = redactRequest("chat", { messages: messages("[allow-secrets] show it") }).body as { messages: Array<{ role: string; content: unknown }> };
    expect(allowed.messages.find((m) => m.role === "tool")!.content).toBe(VALUE);
  });

  it("withholds Responses outputs by call id and leaves .env.example alone", () => {
    const input = [
      { role: "user", content: [{ type: "input_text", text: "compare" }] },
      { type: "function_call", call_id: "r1", name: "read", arguments: JSON.stringify({ path: "config/.env.local" }) },
      { type: "function_call_output", call_id: "r1", output: VALUE },
      { type: "function_call", call_id: "r2", name: "read", arguments: JSON.stringify({ path: "config/.env.example" }) },
      { type: "function_call_output", call_id: "r2", output: "PLAIN_SETTING=" },
    ];
    const out = redactRequest("responses", { input }).body as { input: Array<{ call_id?: string; output?: unknown }> };
    expect(out.input.find((i) => i.call_id === "r1" && i.output !== undefined)!.output).toBe(WITHHELD_NOTICE);
    expect(out.input.find((i) => i.call_id === "r2" && i.output !== undefined)!.output).toBe("PLAIN_SETTING=");
  });
  it("withholds secret-file lines in search output, flat and grouped, from any tool", () => {
    const flat = [
      "src/app.ts:3:const port = env.PORT;",
      "app/.env:2:PORT=correct horse battery",
      "app/.env-3-DB_PASS=staple",
      "app/.env.example:2:PORT=",
      "Loading app/.env: done",
    ].join("\n");
    const grouped = ["src/app.ts:", "  3: const port = env.PORT;", "config/.env.local:", "  2: PORT=correct horse battery", "  3- DB_PASS=staple", "  4:5 SECRET=staple", "5:DB_USER=staple", "README.md:", "  9: copy .env.example"].join("\n");
    const body = {
      messages: [
        { role: "user", content: "where is PORT set" },
        { role: "assistant", content: [
          { type: "tool_use", id: "g1", name: "Grep", input: { pattern: "PORT", path: "." } },
          { type: "tool_use", id: "g2", name: "search_files", input: { pattern: "PORT" } },
        ] },
        { role: "user", content: [
          { type: "tool_result", tool_use_id: "g1", content: flat },
          { type: "tool_result", tool_use_id: "g2", content: [{ type: "text", text: grouped }] },
        ] },
      ],
    };
    const out = redactRequest("anthropic", body).body as { messages: Array<{ content: Array<{ content: any }> }> };
    const flatOut = (out.messages[2]!.content[0]!.content as string).split("\n");
    expect(flatOut).toEqual([
      "src/app.ts:3:const port = env.PORT;",
      `app/.env: ${WITHHELD_LINE}`,
      `app/.env: ${WITHHELD_LINE}`,
      "app/.env.example:2:PORT=",
      "Loading app/.env: done",
    ]);
    const groupedOut = (out.messages[2]!.content[1]!.content[0].text as string).split("\n");
    expect(groupedOut).toEqual(["src/app.ts:", "  3: const port = env.PORT;", "config/.env.local:", `  2: ${WITHHELD_LINE}`, `  3- ${WITHHELD_LINE}`, `  4:5 ${WITHHELD_LINE}`, `5: ${WITHHELD_LINE}`, "README.md:", "  9: copy .env.example"]);
    expect(JSON.stringify(out)).not.toContain("staple");
  });
});

describe("routes", () => {
  it("adds routes from the routes file to the built-in ones", () => {
    const dir = mkdtempSync(join(tmpdir(), "canary-routes-"));
    try {
      const file = join(dir, "routes.json");
      writeFileSync(file, JSON.stringify({ "lan-models": "http://model-box.local.example:8080/v1" }));
      const routes = loadRoutes(file);
      expect(routes["lan-models"]).toEqual({ upstream: "http://model-box.local.example:8080/v1" });
      expect(routes.anthropic).toEqual(DEFAULT_ROUTES.anthropic!);
      expect(upstreamUrl(routes["lan-models"]!, "/chat/completions", "")).toBe("http://model-box.local.example:8080/v1/chat/completions");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
