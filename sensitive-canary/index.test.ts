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

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"; // canonical AKIA + 16 [A-Z0-9]
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
    const original = "alice.smith@corp.example";
    const res = await handlers.context(
      { messages: [{ role: "user", content: `contact ${original}` }] },
      ctx,
    );
    const text = res?.messages?.[0]?.content;
    expect(text).toMatch(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/);
    expect(text).not.toContain(original);
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
    expect(res?.content?.[0]?.text).not.toContain("plain-password");
  });
});
