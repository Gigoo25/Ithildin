import { beforeAll, describe, expect, it } from "bun:test";
import path from "node:path";
import {
  geminiCallIds,
  geminiView,
  mapGeminiResults,
  nextGeminiCallId,
  noteGeminiCalls,
  resultContent,
} from "./gemini.ts";
import { initEngine, redactRequest, WITHHELD_NOTICE, IMAGE_NOTICE } from "./redact.ts";
import { createRewriter, swapResponseBody } from "./streams.ts";
import { createHandler, DEFAULT_ROUTES, formatForPath, splitVia } from "./server.ts";
import { thinkingOfBody, thinkingOfEvent } from "./thinking.ts";
import { usageOf, usageOfEvent } from "./usage.ts";

const EMAIL = "jane.doe@acme-corp.com";
let standIn = "";

beforeAll(() => {
  initEngine();
  const body = redactRequest("anthropic", { messages: [{ role: "user", content: EMAIL }] })
    .body as { messages: Array<{ content: string }> };
  standIn = body.messages[0]!.content;
});

const user = (...parts: unknown[]) => ({ role: "user", parts });
const model = (...parts: unknown[]) => ({ role: "model", parts });
const call = (name: string, args: unknown) => ({ functionCall: { name, args } });
const result = (name: string, content: unknown) => ({
  functionResponse: { name, response: { name, content } },
});

describe("the Gemini path", () => {
  it("is read on generateContent and streamGenerateContent alone", () => {
    expect(formatForPath("/v1beta/models/gemini-4-argon:streamGenerateContent")).toBe("gemini");
    expect(formatForPath("/models/gemini-4-argon:generateContent")).toBe("gemini");
    expect(formatForPath("/models/gemini-4-argon:countTokens")).toBeUndefined();
    expect(formatForPath("/models")).toBeUndefined();
  });

  it("goes to opencode Go under /v1, as its other paths do", async () => {
    const seen: string[] = [];
    const handler = createHandler(DEFAULT_ROUTES, (async (url: string) => {
      seen.push(url);
      return Response.json({ candidates: [] });
    }) as unknown as typeof fetch);
    await handler(
      new Request("http://127.0.0.1/opencode-go/models/gemini-4-argon:generateContent", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ contents: [user({ text: "hi" })] }),
      }),
    );
    expect(seen).toEqual(["https://opencode.ai/zen/go/v1/models/gemini-4-argon:generateContent"]);
  });

  it("is not sent through a via host, which serves no such endpoint", () => {
    const route = { upstream: "https://up.example", via: "http://via.example" };
    expect(splitVia(route, "/models/g:generateContent", "", "gemini")).toBeUndefined();
  });
});

describe("call ids", () => {
  it("names calls and results without one by tool and count, the same in both", () => {
    const contents = [
      user({ text: "go" }),
      model(call("bash", { command: "ls" }), call("bash", { command: "pwd" })),
      user(result("bash", "a"), result("bash", "b")),
    ];
    const ids = geminiCallIds(contents);
    const id = (turn: number, part: number, key: "functionCall" | "functionResponse") =>
      ids.get((contents[turn]!.parts[part] as Record<string, object>)[key]!);
    expect(id(1, 0, "functionCall")).toBe(id(2, 0, "functionResponse"));
    expect(id(1, 1, "functionCall")).toBe(id(2, 1, "functionResponse"));
    expect(id(1, 0, "functionCall")).not.toBe(id(1, 1, "functionCall"));
  });

  it("keeps an id the client sent", () => {
    const functionCall = { id: "c9", name: "bash", args: {} };
    expect(geminiCallIds([model({ functionCall })]).get(functionCall)).toBe("c9");
  });

  it("gives a reply's call the id the next request will give it", () => {
    const tags = new Set<string>();
    const contents: unknown[] = [user({ text: "go" }), model(call("bash", { command: "ls" }))];
    noteGeminiCalls(tags, contents);
    const next = { name: "bash", args: { command: "pwd" } };
    const named = nextGeminiCallId(tags, next);
    const later = [...contents, user(result("bash", "a")), model({ functionCall: next })];
    expect(geminiCallIds(later).get(next)).toBe(named);
    expect(nextGeminiCallId(new Set(), { name: "x" })).toBeUndefined();
    expect(nextGeminiCallId(tags, { id: "own", name: "x" })).toBe("own");
  });
});

describe("the view", () => {
  it("reads turns as Anthropic messages, thoughts as thinking, functions as tools", () => {
    const view = geminiView({
      systemInstruction: { parts: [{ text: "be brief" }] },
      contents: [
        user({ text: "hi" }, { inlineData: { mimeType: "image/png", data: "AA" } }),
        model({ text: "hm", thought: true }, call("bash", { command: "ls" })),
        user(result("bash", "out")),
      ],
      tools: [{ functionDeclarations: [{ name: "bash", parameters: { type: "object" } }] }],
    });
    const messages = view.messages as Array<{ role: string; content: Array<Fields> }>;
    expect(view.system).toEqual([{ type: "text", text: "be brief" }]);
    expect(messages.map((m) => m.role)).toEqual(["user", "assistant", "user"]);
    expect(messages[0]!.content[1]).toEqual({ type: "other" });
    expect(messages[1]!.content[0]).toEqual({ type: "thinking", thinking: "hm" });
    expect(messages[1]!.content[1]!.type).toBe("tool_use");
    expect(messages[2]!.content[0]!.tool_use_id).toBe(messages[1]!.content[1]!.id);
    expect(messages[2]!.content[0]!.content).toBe("out");
    expect(view.tools).toEqual([{ name: "bash", input_schema: { type: "object" } }]);
  });

  it("takes a body without contents or tools", () => {
    expect(geminiView({ tools: [{}] })).toEqual({ system: [], messages: [], tools: [] });
    expect(geminiView({ contents: [{ role: "user" }, null] }).messages).toEqual([
      { role: "user", content: [] },
      { role: "user", content: [] },
    ]);
  });

  it("reads a result's content wherever the client put it", () => {
    expect(resultContent({ content: "a" })).toBe("a");
    expect(resultContent({ output: "b" })).toBe("b");
    expect(resultContent({ result: "c" })).toBe("c");
    expect(resultContent({ other: 1 })).toBe('{"other":1}');
    expect(resultContent("plain")).toBe("plain");
  });
});

type Fields = Record<string, unknown>;

describe("results", () => {
  it("replaces content under the key it was read from, and only what changed", () => {
    const untouched = user({ text: "go" });
    const contents = [
      untouched,
      model(call("a", {}), call("b", {}), call("c", {})),
      user(
        { functionResponse: { name: "a", response: { output: "1" } } },
        { functionResponse: { name: "b", response: "2" } },
        { functionResponse: { name: "c", response: { content: "3" } } },
      ),
    ];
    const out = mapGeminiResults(contents, (_id, content) =>
      content === "3" ? undefined : `new ${String(content)}`,
    );
    expect(out[0]).toBe(untouched);
    expect(out[1]).toBe(contents[1]);
    const parts = (out[2] as { parts: Array<{ functionResponse: Fields }> }).parts;
    expect(parts.map((part) => part.functionResponse.response)).toEqual([
      { output: "new 1" },
      { name: "b", content: "new 2" },
      { content: "3" },
    ]);
  });
});

describe("redacting a Gemini request", () => {
  it("masks what the user and tools said, keeps thoughts, names and ids", () => {
    const thought = { text: `I recall ${EMAIL}`, thought: true, thoughtSignature: "sig" };
    const { body, hits } = redactRequest("gemini", {
      systemInstruction: { parts: [{ text: "be brief" }] },
      contents: [
        user({ text: `write to ${EMAIL}` }),
        model(thought, { functionCall: { id: "c1", name: "bash", args: { command: "ls" } } }),
        user({ functionResponse: { id: "c1", name: "bash", response: { content: EMAIL } } }),
      ],
    });
    const contents = body.contents as Array<{ parts: Fields[] }>;
    expect(hits).toBeGreaterThan(0);
    expect(contents[0]!.parts[0]!.text).toBe(`write to ${standIn}`);
    expect(contents[1]!.parts[0]).toBe(thought);
    expect(contents[1]!.parts[1]!.functionCall).toEqual({
      id: "c1",
      name: "bash",
      args: { command: "ls" },
    });
    expect(contents[2]!.parts[0]!.functionResponse).toEqual({
      id: "c1",
      name: "bash",
      response: { content: standIn },
    });
    expect(body.systemInstruction).toEqual({ parts: [{ text: "be brief" }] });
  });

  it("takes turns it does not expect", () => {
    const { body } = redactRequest("gemini", {
      contents: [null, "text", { role: "user" }, user(7, null)],
    });
    expect(body.contents).toEqual([null, "text", { role: "user" }, user(7, null)]);
    expect(redactRequest("gemini", { contents: EMAIL }).body.contents).toBe(standIn);
    expect(redactRequest("gemini", {}).body.contents).toBeUndefined();
  });

  it("withholds the result of a call that read a secret file", () => {
    const key = path.join("~", ".ssh", "id_" + "ed25519");
    const { body } = redactRequest("gemini", {
      contents: [model(call("bash", { command: `cat ${key}` })), user(result("bash", "material"))],
    });
    const contents = body.contents as Array<{ parts: Array<{ functionResponse?: Fields }> }>;
    expect(contents[1]!.parts[0]!.functionResponse!.response).toEqual({
      name: "bash",
      content: WITHHELD_NOTICE,
    });
  });

  it("holds back pictures as a text part", () => {
    const { body } = redactRequest(
      "gemini",
      {
        contents: [
          user({ text: "look" }),
          user(
            { text: "[allow-images] and" },
            { inlineData: { mimeType: "image/png", data: "AA" } },
          ),
        ],
      },
      "s",
    );
    const parts = (body.contents as Array<{ parts: unknown[] }>)[1]!.parts;
    expect(parts).toContainEqual({ inlineData: { mimeType: "image/png", data: "AA" } });
    const held = redactRequest("gemini", {
      contents: [user({ inlineData: { mimeType: "image/png", data: "AA" } })],
    }).body;
    expect((held.contents as Array<{ parts: unknown[] }>)[0]!.parts).toEqual([
      { text: IMAGE_NOTICE },
    ]);
  });

  it("explains a blocked call where its result goes", () => {
    const tags = new Set<string>();
    const contents: unknown[] = [user({ text: "go" })];
    noteGeminiCalls(tags, contents);
    // A write naming a stand-in the proxy never minted is held back.
    const write = call("write", { path: "a.md", content: "user-0a1b2c" });
    const reply = { candidates: [{ content: { role: "model", parts: [write] } }] };
    swapResponseBody("gemini", reply, tags);
    const later = [
      ...contents,
      reply.candidates[0]!.content,
      user(result("write", "it was written")),
    ];
    const { body } = redactRequest("gemini", { contents: later });
    const parts = (body.contents as Array<{ parts: Array<{ functionResponse?: Fields }> }>)[2]!
      .parts;
    const content = (parts[0]!.functionResponse!.response as Fields).content;
    expect(String(content)).toStartWith("Not run: user-0a1b2c does not appear");
  });
});

describe("a Gemini reply", () => {
  const event = (parts: unknown[], extra: Fields = {}) => ({
    data: JSON.stringify({ candidates: [{ content: { role: "model", parts }, ...extra }] }),
  });
  const partsOf = (data: string) =>
    (JSON.parse(data) as { candidates: Array<{ content: { parts: Fields[] } }> }).candidates[0]!
      .content.parts;

  it("gives text its real values back, held to the last space, in order", () => {
    const rewriter = createRewriter("gemini", new Set());
    const half = Math.floor(standIn.length / 2);
    const out = [
      ...rewriter.push(event([{ text: `mail ${standIn.slice(0, half)}` }])),
      ...rewriter.push(event([{ text: `${standIn.slice(half)} now` }])),
      ...rewriter.push(event([call("bash", { command: `echo ${standIn}` })])),
      ...rewriter.push(event([{ text: "done" }], { finishReason: "STOP" })),
    ];
    const parts = out.flatMap((e) => partsOf(e.data));
    const text = parts.map((part) => part.text ?? "|").join("");
    expect(text).toBe(`mail ${EMAIL} now|done`);
    expect((parts.find((part) => part.functionCall)!.functionCall as Fields).args).toEqual({
      command: `echo ${EMAIL}`,
    });
    expect(rewriter.swapped).toBe(2);
    expect(rewriter.flush()).toEqual([]);
  });

  it("passes thoughts, a signature and events without candidates as they came", () => {
    const rewriter = createRewriter("gemini", new Set());
    const thought = { text: standIn, thought: true };
    expect(partsOf(rewriter.push(event([thought]))[0]!.data)).toEqual([thought]);
    expect(partsOf(rewriter.push(event([{ text: "", thoughtSignature: "s" }]))[0]!.data)).toEqual([
      { text: "", thoughtSignature: "s" },
    ]);
    const usage = { data: JSON.stringify({ usageMetadata: {} }) };
    expect(rewriter.push(usage)).toEqual([usage]);
    expect(rewriter.push({ data: "not json" })).toEqual([{ data: "not json" }]);
  });

  it("sends what text it held when the stream is cut", () => {
    const rewriter = createRewriter("gemini", new Set());
    expect(partsOf(rewriter.push(event([{ text: "half" }]))[0]!.data)).toEqual([]);
    expect(partsOf(rewriter.flush()[0]!.data)).toEqual([{ text: "half" }]);
  });

  it("swaps a whole reply", () => {
    const body = {
      candidates: [
        { content: { parts: [{ text: standIn }, { text: standIn, thought: true }] } },
        { content: { parts: [call("bash", { command: standIn })] } },
        {},
      ],
    };
    expect(swapResponseBody("gemini", body, new Set())).toBe(2);
    expect(body.candidates[0]!.content!.parts).toEqual([
      { text: EMAIL },
      { text: standIn, thought: true },
    ]);
    expect(swapResponseBody("gemini", {}, new Set())).toBe(0);
  });

  it("reads its thoughts and usage", () => {
    const thought = event([{ text: "hm", thought: true }, { text: "said" }]).data;
    expect(thinkingOfEvent("gemini", thought)).toBe("hm");
    expect(thinkingOfEvent("gemini", event([{ text: "thinking" }]).data)).toBe("");
    expect(thinkingOfEvent("gemini", '{"thought": true')).toBe("");
    expect(thinkingOfBody("gemini", JSON.parse(thought))).toBe("hm");
    expect(thinkingOfBody("gemini", {})).toBe("");
    const usageMetadata = {
      promptTokenCount: 100,
      cachedContentTokenCount: 40,
      candidatesTokenCount: 7,
      thoughtsTokenCount: 3,
    };
    const counted = { input: 60, cacheRead: 40, cacheWrite: 0, output: 10 };
    expect(usageOf("gemini", { usageMetadata })).toEqual(counted);
    expect(usageOfEvent("gemini", JSON.stringify({ usageMetadata }))).toEqual(counted);
    expect(usageOfEvent("gemini", JSON.stringify({ usage: {} }))).toBeUndefined();
    expect(usageOf("gemini", {})).toBeUndefined();
  });
});

describe("through the proxy", () => {
  it("redacts the request, swaps the stream back and keeps its thinking", async () => {
    const seen: Fields[] = [];
    const lines = [
      { candidates: [{ content: { role: "model", parts: [{ text: "hm", thought: true }] } }] },
      {
        candidates: [
          { content: { role: "model", parts: [{ text: `to ${standIn}` }] }, finishReason: "STOP" },
        ],
      },
    ];
    const handler = createHandler(DEFAULT_ROUTES, (async (_url: string, init: RequestInit) => {
      seen.push(JSON.parse(String(init.body)));
      const text = lines.map((line) => `data: ${JSON.stringify(line)}\r\n\r\n`).join("");
      return new Response(text, { headers: { "content-type": "text/event-stream" } });
    }) as unknown as typeof fetch);
    const response = await handler(
      new Request(
        "http://127.0.0.1/opencode-go/models/gemini-4-argon:streamGenerateContent?alt=sse",
        {
          method: "POST",
          headers: { "content-type": "application/json", "x-opencode-session": "ses_g" },
          body: JSON.stringify({ contents: [user({ text: `mail ${EMAIL}` })] }),
        },
      ),
    );
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain(`to ${EMAIL}`);
    expect(JSON.stringify(seen[0])).not.toContain(EMAIL);
    const thinking = await handler(new Request("http://127.0.0.1/dashboard/request?thinking&id=1"));
    expect(await thinking.json()).toEqual({ text: "hm", done: true });
  });
});
