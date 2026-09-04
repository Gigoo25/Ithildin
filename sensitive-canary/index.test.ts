// Behavioral checks for the port glue (not upstream rules — see rules.test.ts).
// index.ts's @earendil-works/pi-coding-agent import is type-only, so Bun erases it
// and a stub ExtensionAPI drives the real handlers.
import { beforeEach, describe, expect, it } from "bun:test";
import sensitiveCanary from "./index.ts";

type Handler = (event: any, ctx?: any) => Promise<any>;
const handlers: Record<string, Handler> = {};
const notifications: string[] = [];
const emittedEvents: Array<{ name: string; event: unknown }> = [];
sensitiveCanary({
  on: (name: string, fn: any) => {
    handlers[name] = fn;
  },
  events: {
    emit: (name: string, event: unknown) => emittedEvents.push({ name, event }),
  },
} as any);
const ctx = {
  ui: {
    notify: (message: string) => notifications.push(message),
  },
};

const AWS_KEY = "AKIA" + "A".repeat(16);
const ANTHROPIC_KEY = `sk-ant-${"a".repeat(95)}`;

describe("sensitive-canary port", () => {
  beforeEach(() => {
    handlers.agent_start({}, ctx);
  });

  it("redacts secrets from error tool results", async () => {
    const res = await handlers.tool_result(
      {
        isError: true,
        toolName: "bash",
        content: [{ type: "text", text: `curl failed with ${ANTHROPIC_KEY}` }],
      },
      ctx,
    );
    expect(res.content[0].text).not.toContain(ANTHROPIC_KEY);
    expect(emittedEvents.at(-1)).toEqual({
      name: "sensitive-canary:tool-result-sanitized",
      event: { toolCallId: undefined, digest: expect.any(String) },
    });
  });

  it("redacts string-content user messages", async () => {
    const res = await handlers.context(
      {
        messages: [
          {
            role: "user",
            content: `my key is ${AWS_KEY} thanks`,
          },
        ],
      },
      ctx,
    );
    expect(res.messages[0].content).toMatch(/[A-Z0-9]{20}/);
    expect(res.messages[0].content).not.toContain(AWS_KEY);
  });

  it("names assignment keys without exposing values", async () => {
    const before = notifications.length;
    await handlers.context(
      { messages: [{ role: "user", content: `API_KEY=${AWS_KEY}` }] },
      ctx,
    );
    await handlers.agent_end({}, ctx);
    const notice = notifications.at(-1);
    expect(notifications.length).toBe(before + 1);
    expect(notice).toContain("synthesized 1 value(s) during this response");
    expect(notice).not.toContain(AWS_KEY);
  });

  it("suppresses provider cache metadata from warning labels", async () => {
    const before = notifications.length;
    await handlers.before_provider_request(
      {
        payload: {
          prompt_cache_key: "cache-id",
          prompt: `API_KEY=${AWS_KEY}`,
        },
      },
      ctx,
    );
    await handlers.agent_end({}, ctx);
    const notice = notifications.at(-1);
    expect(notifications.length).toBe(before + 1);
    expect(notice).toContain("synthesized 1 value(s) during this response");
    expect(notice).not.toContain("prompt_cache_key");
  });

  it("aggregates warnings across a response", async () => {
    const before = notifications.length;
    await handlers.context(
      { messages: [{ role: "user", content: `API_KEY=${AWS_KEY}` }] },
      ctx,
    );
    await handlers.before_provider_request(
      { payload: { prompt: `API_KEY=${AWS_KEY}` } },
      ctx,
    );
    await handlers.agent_end({}, ctx);
    expect(notifications.length).toBe(before + 1);
    expect(notifications.at(-1)).toContain("synthesized 2 value(s) during this response");
  });

  it("does not resynthesize an already sanitized context", async () => {
    const first = await handlers.context(
      { messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] },
      ctx,
    );
    expect(
      await handlers.context({ messages: first.messages }, ctx),
    ).toBeUndefined();
  });

  it("does not warn again for a sanitized provider payload", async () => {
    const first = await handlers.context(
      { messages: [{ role: "user", content: `API_KEY=${AWS_KEY}` }] },
      ctx,
    );
    const before = notifications.length;
    expect(
      await handlers.before_provider_request({
        payload: { prompt: first.messages[0].content },
      }, ctx),
    ).toBeUndefined();
    expect(notifications.length).toBe(before);
  });

  it("separates synthesis notices from tool output", async () => {
    const res = await handlers.tool_result(
      {
        toolName: "bash",
        content: [{ type: "text", text: `API_KEY=${AWS_KEY}` }],
      },
      ctx,
    );
    expect(res.content[1].text).toMatch(/^\n\n\[sensitive-canary\]/);
  });

  it("ignores allow tags from older turns", async () => {
    const res = await handlers.context(
      {
        messages: [
          { role: "user", content: [{ type: "text", text: "[allow-secret]" }] },
          { role: "assistant", content: [{ type: "text", text: "ok" }] },
          {
            role: "user",
            content: [{ type: "text", text: `leak: ${AWS_KEY}` }],
          },
        ],
      },
      ctx,
    );
    expect(res?.messages?.[2]?.content?.[0]?.text).toMatch(/[A-Z0-9]{20}/);
  });

  it("preserves email format with synthetic values", async () => {
    const original = ["begjm.qnqbh", "tqxu.znatyfu"].join("@");
    const res = await handlers.context(
      { messages: [{ role: "user", content: `contact ${original}` }] },
      ctx,
    );
    const text = res?.messages?.[0]?.content;
    expect(text).toMatch(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/);
    expect(text).not.toContain(original);
    expect(text).toContain("[sensitive-canary]");
  });

  it("synthesizes .env values without hiding keys", async () => {
    const res = await handlers.tool_result(
      {
        toolName: "read",
        input: { path: ".env" },
        content: [{ type: "text", text: "API_KEY=plain-password" }],
      },
      ctx,
    );
    expect(res?.content?.[0]?.text).toMatch(/^API_KEY=[a-z-]+$/);
    expect(res?.content?.[0]?.text).not.toContain("urzgh-pevcttvl");
  });


  it("blocks sensitive env reads before execution", async () => {
    expect(
      await handlers.tool_call({ toolName: "bash", input: { command: "head < .env" } }),
    ).toMatchObject({ block: true });
    expect(
      await handlers.tool_call({ toolName: "read", input: { path: ".env.local" } }),
    ).toMatchObject({ block: true });
    expect(
      await handlers.tool_call({
        toolName: "bash",
        input: { command: "env cat .env.production" },
      }),
    ).toMatchObject({ block: true });
    expect(
      await handlers.tool_call({ toolName: "read", input: { path: ".env:img" } }),
    ).toMatchObject({ block: true });
    expect(
      await handlers.tool_call({
        toolName: "bash",
        input: { command: "ls\ncat .env" },
      }),
    ).toMatchObject({ block: true });
  });

  it("allows example and non-dotenv filenames", async () => {
    expect(
      await handlers.tool_call({ toolName: "read", input: { path: ".env.example" } }),
    ).toBeUndefined();
    expect(
      await handlers.tool_call({ toolName: "bash", input: { command: "cat prod.env" } }),
    ).toBeUndefined();
  });

  it("preserves opaque encrypted provider fields", async () => {
    const encrypted = `sk-ant-${"a".repeat(95)}`;
    const payloadSecret = ["Kz0gF8zK9uN7qV4v", "Fx0mTm2vLi5r"].join("");
    const payload = {
      input: [
        { type: "reasoning", encrypted_content: encrypted },
        { type: "compaction", encryptedContent: encrypted },
        { type: "message", text: `api_key=${payloadSecret}` },
      ],
    };
    const res = await handlers.before_provider_request({ payload }, ctx);

    expect(res.input[0].encrypted_content).toBe(encrypted);
    expect(res.input[1].encryptedContent).toBe(encrypted);
    expect(res.input[2].text).not.toBe(`api_key=${payloadSecret}`);
  });
});
