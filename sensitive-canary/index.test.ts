// Behavioral checks for the port glue (not upstream rules — see rules.test.ts).
// index.ts's @earendil-works/pi-coding-agent import is type-only, so Bun erases it
// and a stub ExtensionAPI drives the real handlers.
import { beforeEach, describe, expect, it } from "bun:test";
import sensitiveCanary from "./index.ts";

type Handler = (event: any, ctx?: any) => Promise<any>;
const handlers: Record<string, Handler> = {};
const notifications: string[] = [];
const emittedEvents: Array<{ name: string; event: unknown }> = [];
const internalHandlers: Record<string, (event: any) => void> = {};
sensitiveCanary({
  on: (name: string, fn: any) => {
    handlers[name] = fn;
  },
  events: {
    emit: (name: string, event: unknown) => emittedEvents.push({ name, event }),
    on: (name: string, handler: (event: any) => void) => { internalHandlers[name] = handler; },
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

  it("certifies and sanitizes persisted text", () => {
    const event = { text: `API_KEY=${AWS_KEY}`, certified: false };
    internalHandlers["sensitive-canary:sanitize-stored-text"](event);
    expect(event.certified).toBeTrue();
    expect(event.text).not.toContain(AWS_KEY);
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

  it("always reminds the model that synthetic values are not real", async () => {
    const result = await handlers.before_agent_start({ prompt: "ordinary prompt", systemPrompt: "base" });
    expect(result.systemPrompt).toContain("synthetic placeholders");
    expect(result.systemPrompt).toContain("not real credentials");
    expect(result.systemPrompt).toContain("Preserve only their structure and relationships");
    expect(result.systemPrompt).toContain("Never pass a placeholder to a tool");
    expect(result.systemPrompt).toContain("[allow-pii]");
  });

  it("does not duplicate the system reminder", async () => {
    const first = await handlers.before_agent_start({ prompt: "ordinary prompt", systemPrompt: "base" });
    expect(await handlers.before_agent_start({ prompt: "retry", systemPrompt: first.systemPrompt })).toBeUndefined();
  });

  it("replaces PII with obvious numbered tokens, not realistic fakes", async () => {
    const res = await handlers.tool_result(
      {
        toolName: "bash",
        content: [{ type: "text", text: "deploy to FatMan via 10.1.2.3 as rstocchi" }],
      },
      ctx,
    );
    const text = res.content[0].text;
    expect(text).not.toContain("FatMan");
    expect(text).not.toContain("10.1.2.3");
    expect(text).not.toContain("rstocchi");
    expect(text).toMatch(/__CANARY_HOST_\d+__/);
    expect(text).toMatch(/__CANARY_IP_\d+__/);
    expect(text).toMatch(/__CANARY_USER_\d+__/);
  });

  it("keeps token identity stable for repeated PII", async () => {
    const run = () =>
      handlers.tool_result(
        { toolName: "bash", content: [{ type: "text", text: "peer 100.96.26.43 up" }] },
        ctx,
      );
    const first = (await run()).content[0].text;
    const second = (await run()).content[0].text;
    expect(first).toMatch(/__CANARY_IP_\d+__/);
    expect(second).toBe(first);
  });

  it("does not rescan its own tokens", async () => {
    expect(
      await handlers.context(
        { messages: [{ role: "user", content: "see __CANARY_HOST_9__ config" }] },
        ctx,
      ),
    ).toBeUndefined();
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

  it("does not duplicate an existing synthesis notice", async () => {
    const res = await handlers.tool_result(
      {
        toolName: "bash",
        content: [{ type: "text", text: `API_KEY=${AWS_KEY}` }, { type: "text", text: "\n\n[sensitive-canary] Some sensitive values in this context were replaced with synthetic placeholders. Treat them as non-real data; preserve their structure only. Do not use placeholders as file paths, command arguments, URLs, or identifiers." }],
      },
      ctx,
    );
    expect(res.content.filter((chunk) => chunk.type === "text" && chunk.text.includes("[sensitive-canary]"))).toHaveLength(1);
  });

  it("allows secrets for the current user turn", async () => {
    const prompt = `[allow-secrets]\nAPI_KEY=${AWS_KEY}`;
    expect(await handlers.context({ messages: [{ role: "user", content: prompt }] }, ctx)).toBeUndefined();
    expect(await handlers.before_provider_request({ payload: { prompt } }, ctx)).toBeUndefined();
    expect(await handlers.tool_call({ toolName: "read", input: { path: ".env" } })).toBeUndefined();
    expect(await handlers.tool_result({
      toolCallId: "allowed-secret",
      toolName: "read",
      input: { path: ".env" },
      content: [{ type: "text", text: `API_KEY=${AWS_KEY}` }],
    }, ctx)).toBeUndefined();
  });

  it("keeps the singular secret tag as an alias", async () => {
    const prompt = `[allow-secret]\nAPI_KEY=${AWS_KEY}`;
    expect(await handlers.context({ messages: [{ role: "user", content: prompt }] }, ctx)).toBeUndefined();
  });

  it("persists the redacted view of user messages", async () => {
    const res = await handlers.message_end(
      { message: { role: "user", content: "deploy to Mini" } },
      ctx,
    );
    expect(res.message.role).toBe("user");
    expect(res.message.content).toMatch(/__CANARY_HOST_\d+__/);
    expect(res.message.content).not.toContain("Mini");
  });

  it("persists approved values when the message allows them", async () => {
    expect(
      await handlers.message_end(
        { message: { role: "user", content: "[allow-pii]\ndeploy to Mini" } },
        ctx,
      ),
    ).toBeUndefined();
  });

  it("persists the redacted view of assistant messages", async () => {
    const res = await handlers.message_end(
      {
        message: {
          role: "assistant",
          content: [{ type: "text", text: `key is ${AWS_KEY}` }],
        },
      },
      ctx,
    );
    expect(res.message.content[0].text).not.toContain(AWS_KEY);
  });

  it("redacts secrets hiding in tool result details", async () => {
    const res = await handlers.message_end(
      {
        message: {
          role: "toolResult",
          content: [{ type: "text", text: "ok" }],
          details: { answers: [{ id: "q", value: AWS_KEY }] },
        },
      },
      ctx,
    );
    expect(res.message.content[0].text).toBe("ok");
    expect(JSON.stringify(res.message.details)).not.toContain(AWS_KEY);
  });

  it("leaves clean messages unpersisted-by-canary", async () => {
    expect(
      await handlers.message_end(
        { message: { role: "user", content: "hello there" } },
        ctx,
      ),
    ).toBeUndefined();
  });

  it("allows PII but continues to synthesize secrets", async () => {
    const email = "person@realcompany.io";
    const prompt = `[allow-pii]\ncontact=${email}\nAPI_KEY=${AWS_KEY}`;
    const res = await handlers.context({ messages: [{ role: "user", content: prompt }] }, ctx);
    expect(res.messages[0].content).toContain(email);
    expect(res.messages[0].content).not.toContain(AWS_KEY);
  });

  it("allows all checks for the current user turn", async () => {
    const prompt = `[allow-all]\ncontact=person@realcompany.io\nAPI_KEY=${AWS_KEY}`;
    expect(await handlers.context({ messages: [{ role: "user", content: prompt }] }, ctx)).toBeUndefined();
    expect(await handlers.before_provider_request({ payload: { prompt } }, ctx)).toBeUndefined();
  });

  it("ignores allow tags in quoted code", async () => {
    const prompt = `Quoted documentation:\n\`\`\`\n[allow-all]\n\`\`\`\nAPI_KEY=${AWS_KEY}`;
    const res = await handlers.context({ messages: [{ role: "user", content: prompt }] }, ctx);
    expect(res.messages[0].content).not.toContain(AWS_KEY);
  });

  it("uses only the last allow tag", async () => {
    const prompt = `[allow-all] then [allow-pii]\nAPI_KEY=${AWS_KEY}`;
    const res = await handlers.context({ messages: [{ role: "user", content: prompt }] }, ctx);
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

  it("replaces email addresses with obvious tokens", async () => {
    const original = ["begjm.qnqbh", "tqxu.znatyfu"].join("@");
    const res = await handlers.context(
      { messages: [{ role: "user", content: `contact ${original}` }] },
      ctx,
    );
    const text = res?.messages?.[0]?.content;
    expect(text).toMatch(/__CANARY_EMAIL_\d+__/);
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


  it("synthesizes cookie values at ingress and provider egress", async () => {
    const session = "opaque-browser-session-value";
    const prompt = `Cookie: sessionid=${session}; theme=dark`;
    const contextResult = await handlers.context(
      { messages: [{ role: "user", content: prompt }] },
      ctx,
    );
    expect(contextResult.messages[0].content).toContain("Cookie: sessionid=");
    expect(contextResult.messages[0].content).toContain("; theme=");
    expect(contextResult.messages[0].content).not.toContain(session);
    expect(contextResult.messages[0].content).not.toContain("theme=dark");

    const providerResult = await handlers.before_provider_request(
      { payload: { headers: { Cookie: `sessionid=${session}` } } },
      ctx,
    );
    expect(providerResult.headers.Cookie).toStartWith("sessionid=");
    expect(providerResult.headers.Cookie).not.toContain(session);
  });

  it("synthesizes Set-Cookie values in tool results", async () => {
    const session = "opaque-browser-session-value";
    const result = await handlers.tool_result(
      {
        toolName: "bash",
        input: { command: "curl -i https://example.com" },
        content: [{ type: "text", text: `Set-Cookie: sessionid=${session}; Path=/; HttpOnly` }],
      },
      ctx,
    );
    expect(result.content[0].text).toContain("Set-Cookie: sessionid=");
    expect(result.content[0].text).toContain("; Path=/; HttpOnly");
    expect(result.content[0].text).not.toContain(session);
  });

  it("blocks curl commands that send cookies unless secrets are allowed", async () => {
    expect(
      await handlers.tool_call({
        toolName: "bash",
        input: { command: "curl -H 'Cookie: sessionid=opaque-browser-session-value' https://example.com" },
      }),
    ).toMatchObject({ block: true });
    expect(
      await handlers.tool_call({
        toolName: "bash",
        input: { command: "curl --cookie 'sessionid=opaque-browser-session-value' https://example.com" },
      }),
    ).toMatchObject({ block: true });
    expect(
      await handlers.tool_call({ toolName: "bash", input: { command: "curl https://example.com" } }),
    ).toBeUndefined();

    await handlers.context(
      { messages: [{ role: "user", content: "[allow-secrets]" }] },
      ctx,
    );
    expect(
      await handlers.tool_call({
        toolName: "bash",
        input: { command: "curl -H 'Cookie: sessionid=opaque-browser-session-value' https://example.com" },
      }),
    ).toBeUndefined();
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

  it("preserves image bytes and scans adjacent text", async () => {
    const data = "A".repeat(2_000_004);
    const uri = `data:image/png;base64,${data}`;
    const bytes = new Uint8Array([1, 2, 3]);
    const payload = {
      content: [
        { type: "image", source: { type: "base64", media_type: "image/png", data } },
        { type: "image_url", image_url: { url: uri } },
        { type: "input_image", image_url: uri },
        { inlineData: { mimeType: "image/png", data } },
        { image: { source: { bytes } } },
        { text: `API_KEY=${AWS_KEY}` },
      ],
    };
    const result = await handlers.before_provider_request({ payload }, ctx);
    expect(result.content.slice(0, 5)).toEqual(payload.content.slice(0, 5));
    expect(result.content[5].text).not.toContain(AWS_KEY);
    expect(result.content[4].image.source.bytes).toBe(bytes);
  });

  it("does not exempt ordinary data fields from scanning", async () => {
    const payload = { data: AWS_KEY, url: `https://example.com/${AWS_KEY}` };
    const result = await handlers.before_provider_request({ payload }, ctx);
    expect(result.data).not.toBe(AWS_KEY);
    expect(result.url).not.toContain(AWS_KEY);
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
