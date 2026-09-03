// Behavioral checks for the port glue (not upstream rules — see rules.test.ts).
// index.ts's @oh-my-pi/pi-coding-agent import is type-only, so Bun erases it
// and a stub ExtensionAPI drives the real handlers.
import { describe, expect, it } from "bun:test";
import sensitiveCanary from "./index.ts";

type Handler = (event: any, ctx?: any) => Promise<any>;
const handlers: Record<string, Handler> = {};
sensitiveCanary({
  on: (name: string, fn: any) => {
    handlers[name] = fn;
  },
} as any);
const ctx = { ui: { notify: () => {} } };

const AWS_KEY = "AKIA" + "A".repeat(16);
const ANTHROPIC_KEY = `sk-ant-${"a".repeat(95)}`;

describe("sensitive-canary port", () => {
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

  it("synthesizes .env values returned by zvec search", async () => {
    const secret = "low-entropy-password";
    const res = await handlers.tool_result(
      {
        toolName: "zvec_grep_search",
        input: { root: "/repo", query: "configuration" },
        content: [
          {
            type: "text",
            text: `freshness: fresh\n.env:1-1\nmatched: 1\nsource:\n1 API_KEY=${secret}`,
          },
        ],
      },
      ctx,
    );
    expect(res?.content?.[0]?.text).toContain("1 API_KEY=");
    expect(res?.content?.[0]?.text).not.toContain(secret);
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
