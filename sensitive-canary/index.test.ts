// Behavioral checks for the port glue (not upstream rules — see rules.test.ts).
// index.ts's @earendil-works/pi-coding-agent import is type-only, so Bun erases it
// and a stub ExtensionAPI drives the real handlers.
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { join, relative } from "node:path";
import { beginScanBudget, setRuntimeInventory } from "./lib/rules.ts";
import sensitiveCanary from "./index.ts";

type Handler = (event: any, ctx?: any) => Promise<any>;
const handlers: Record<string, Handler> = {};
const notifications: string[] = [];
const emittedEvents: Array<{ name: string; event: unknown }> = [];
const internalHandlers: Record<string, (event: any) => void> = {};
let noCanaryFlag = false;
let canaryCommand: { handler: Handler } | undefined;
const appendedEntries: Array<{ customType: string; data: unknown }> = [];
sensitiveCanary({
  appendEntry: (customType: string, data?: unknown) => { appendedEntries.push({ customType, data }); },
  getFlag: (name: string) => name === "no-canary" && noCanaryFlag,
  on: (name: string, fn: any) => {
    handlers[name] = fn;
  },
  registerCommand: (name: string, command: any) => { if (name === "canary") canaryCommand = command; },
  registerFlag: () => {},
  events: {
    emit: (name: string, event: unknown) => emittedEvents.push({ name, event }),
    on: (name: string, handler: (event: any) => void) => { internalHandlers[name] = handler; },
  },
} as any);
const ctx = {
  sessionManager: { getSessionFile: (): string | undefined => undefined },
  ui: {
    notify: (message: string) => notifications.push(message),
  },
};

const AWS_KEY = "AKIA" + "A".repeat(16);
const ANTHROPIC_KEY = `sk-ant-${"a".repeat(95)}`;

describe("sensitive-canary port", () => {
  beforeEach(() => {
    handlers.agent_start({}, ctx);
    setRuntimeInventory([]);
  });
  afterEach(() => {
    setRuntimeInventory([]);
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

  it("emits no per-message notice on redacted tool output", async () => {
    const res = await handlers.tool_result(
      {
        toolName: "bash",
        content: [{ type: "text", text: `API_KEY=${AWS_KEY}` }],
      },
      ctx,
    );
    expect(res.content).toHaveLength(1);
    expect(res.content[0].text).not.toContain(AWS_KEY);
    expect(res.content[0].text).not.toContain("[sensitive-canary]");
  });

  it("does not duplicate an existing synthesis notice", async () => {
    const res = await handlers.tool_result(
      {
        toolName: "bash",
        content: [{ type: "text", text: `API_KEY=${AWS_KEY}` }, { type: "text", text: "\n\n[sensitive-canary] Synthesized placeholders above are not real data — use only as labels. Never pass to tools, use as paths/commands/identifiers, or reverse." }],
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

  it("marks unscannable spans instead of passing them through", async () => {
    beginScanBudget(0);
    try {
      const res = await handlers.tool_result(
        {
          toolName: "bash",
          content: [{ type: "text", text: "host __CANARY_IP_6__ reachable" }],
        },
        ctx,
      );
      const text = res.content[0].text;
      expect(text).toContain("scan budget exceeded");
      expect(text).not.toContain("__CANARY_IP_6__");
    } finally {
      beginScanBudget(null);
    }
  });

  it("writes private value-free ledgers to the active session, never the inherited shell session", async () => {
    const { existsSync, mkdtempSync, readFileSync, rmSync, statSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "canary-ledger-"));
    const previous = process.env.PI_SESSION_FILE;
    const inherited = join(dir, "parent.jsonl");
    let sessionFile: string | undefined;
    const sessionCtx = { ...ctx, sessionManager: { getSessionFile: () => sessionFile } };
    delete process.env.PI_SESSION_FILE;
    try {
      for (const name of ["first", "resumed"]) {
        sessionFile = join(dir, `${name}.jsonl`);
        await handlers.agent_start({}, sessionCtx);
        await handlers.context(
          { messages: [{ role: "user", content: `API_KEY=${AWS_KEY}` }] },
          sessionCtx,
        );
        await handlers.agent_end({}, sessionCtx);
        const dest = `${sessionFile}.canary-ledger.json`;
        const ledger = JSON.parse(readFileSync(dest, "utf8"));
        expect(ledger.totalHits).toBeGreaterThan(0);
        expect(Object.keys(ledger.byRule).length).toBeGreaterThan(0);
        expect(JSON.stringify(ledger)).not.toContain(AWS_KEY);
        expect(statSync(dest).mode & 0o777).toBe(0o600);
        process.env.PI_SESSION_FILE = inherited;
      }
      // An ephemeral session must not fall back to a parent agent's file.
      sessionFile = undefined;
      await handlers.agent_start({}, sessionCtx);
      await handlers.context({ messages: [{ role: "user", content: AWS_KEY }] }, sessionCtx);
      await handlers.agent_end({}, sessionCtx);
      expect(existsSync(`${inherited}.canary-ledger.json`)).toBe(false);
    } finally {
      if (previous === undefined) delete process.env.PI_SESSION_FILE;
      else process.env.PI_SESSION_FILE = previous;
      rmSync(dir, { recursive: true, force: true });
    }
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
    expect(text).not.toContain("[sensitive-canary]");
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

  it("blocks reads of the local PII inventory", async () => {
    const inv = "~/.config/sensitive-canary/config.json";
    expect(await handlers.tool_call({ toolName: "read", input: { path: inv } })).toMatchObject({ block: true });
    expect((await handlers.tool_call({ toolName: "read", input: { path: inv } }) as { reason: string }).reason).toContain("PII inventory");
    expect(await handlers.tool_call({ toolName: "bash", input: { command: `cat ${inv}` } })).toMatchObject({ block: true });
    const homeAbs = `${process.env.HOME}/.config/sensitive-canary/config.json`;
    expect(await handlers.tool_call({ toolName: "read", input: { path: homeAbs } })).toMatchObject({ block: true });
    // Inert shipped template and fake-only spec stay readable.
    expect(await handlers.tool_call({ toolName: "read", input: { path: "home-manager/config/pi/extensions/sensitive-canary/user-config.example.json" } })).toBeUndefined();
    expect(await handlers.tool_call({ toolName: "read", input: { path: relative(process.cwd(), join(process.env.HOME ?? ".", ".config", "sensitive-canary", "CUSTOMER-RULES-SPEC.md")) } })).toBeUndefined();
  });

  it("lets allow-pii bypass the inventory block", async () => {
    await handlers.context({ messages: [{ role: "user", content: "[allow-pii]\nshow config" }] }, ctx);
    expect(await handlers.tool_call({ toolName: "read", input: { path: relative(process.cwd(), join(process.env.HOME ?? ".", ".config", "sensitive-canary", "config.json")) } })).toBeUndefined();
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
    ).toMatchObject({ block: true });
    expect(
      await handlers.tool_call({ toolName: "read", input: { path: "id_rsa.pub" } }),
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

  it("preserves provider control enums even when the scan budget is exhausted", async () => {
    const payload = {
      include: ["reasoning.encrypted_content"],
      reasoning: { effort: "medium", summary: "auto" },
      service_tier: "auto",
      input: [{ type: "message", role: "user", text: `api_key=${AWS_KEY}` }],
      // Chat Completions compat fields are written after the (huge) message
      // body, which is the region the budget trip omits first.
      reasoning_effort: "low",
      reasoningEffort: "max",
    };
    beginScanBudget(0);
    try {
      const res = await handlers.before_provider_request({ payload }, ctx);
      expect(res.include).toEqual(["reasoning.encrypted_content"]);
      expect(res.reasoning).toEqual({ effort: "medium", summary: "auto" });
      expect(res.service_tier).toBe("auto");
      expect(res.input[0].type).toBe("message");
      expect(res.input[0].role).toBe("user");
      expect(res.reasoning_effort).toBe("low");
      expect(res.reasoningEffort).toBe("max");
      expect(JSON.stringify(res)).not.toContain(AWS_KEY);
    } finally {
      beginScanBudget(null);
    }
  });

  it("toggles redaction via /canary on|off", async () => {
    const cmdCtx = { ui: { notify: (message: string) => notifications.push(message) } } as any;
    await canaryCommand!.handler("off", cmdCtx);
    expect(notifications.at(-1)).toContain("disabled");
    // Every interception point passes through raw while off.
    expect(
      await handlers.context({ messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] }, ctx),
    ).toBeUndefined();
    expect(
      await handlers.before_provider_request({ payload: { prompt: `API_KEY=${AWS_KEY}` } }, ctx),
    ).toBeUndefined();
    expect(
      await handlers.tool_result(
        { toolName: "bash", content: [{ type: "text", text: `API_KEY=${AWS_KEY}` }] },
        ctx,
      ),
    ).toBeUndefined();
    expect(
      await handlers.message_end({ message: { role: "user", content: `API_KEY=${AWS_KEY}` } }, ctx),
    ).toBeUndefined();
    expect(await handlers.before_agent_start({ prompt: "p", systemPrompt: "base" })).toBeUndefined();
    expect(await handlers.tool_call({ toolName: "read", input: { path: ".env" } })).toBeUndefined();
    const stored = { text: `API_KEY=${AWS_KEY}`, certified: false };
    internalHandlers["sensitive-canary:sanitize-stored-text"](stored);
    expect(stored.certified).toBeTrue();
    expect(stored.text).toContain(AWS_KEY);
    await canaryCommand!.handler("on", cmdCtx);
    expect(notifications.at(-1)).toContain("enabled");
    const res = await handlers.context(
      { messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] },
      ctx,
    );
    expect(res.messages[0].content).not.toContain(AWS_KEY);
  });

  it("reports /canary status and usage", async () => {
    const cmdCtx = { ui: { notify: (message: string) => notifications.push(message) } } as any;
    await canaryCommand!.handler("status", cmdCtx);
    expect(notifications.at(-1)).toContain("enabled");
    await canaryCommand!.handler("off", cmdCtx);
    await canaryCommand!.handler("status", cmdCtx);
    expect(notifications.at(-1)).toContain("disabled");
    await canaryCommand!.handler("on", cmdCtx);
    await canaryCommand!.handler("bogus", cmdCtx);
    expect(notifications.at(-1)).toContain("Usage: /canary [on|off|status]");
  });

  it("toggles on bare /canary", async () => {
    const cmdCtx = { ui: { notify: (message: string) => notifications.push(message) } } as any;
    await canaryCommand!.handler("", cmdCtx);
    expect(notifications.at(-1)).toContain("disabled");
    expect(emittedEvents.at(-1)).toEqual({ name: "sensitive-canary:mode", event: { enabled: false } });
    expect(
      await handlers.context({ messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] }, ctx),
    ).toBeUndefined();
    await canaryCommand!.handler("  ", cmdCtx);
    expect(notifications.at(-1)).toContain("enabled");
    expect(emittedEvents.at(-1)).toEqual({ name: "sensitive-canary:mode", event: { enabled: true } });
    const res = await handlers.context(
      { messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] },
      ctx,
    );
    expect(res.messages[0].content).not.toContain(AWS_KEY);
  });

  it("announces toggle state for the footer", async () => {
    const cmdCtx = { ui: { notify: () => {} } } as any;
    await canaryCommand!.handler("off", cmdCtx);
    expect(emittedEvents.at(-1)).toEqual({ name: "sensitive-canary:mode", event: { enabled: false } });
    expect(appendedEntries.at(-1)).toMatchObject({ customType: "sensitive-canary", data: { enabled: false } });
    await canaryCommand!.handler("on", cmdCtx);
    expect(emittedEvents.at(-1)).toEqual({ name: "sensitive-canary:mode", event: { enabled: true } });
  });

  it("restores the persisted toggle on session_start", async () => {
    const branch = [{ type: "custom", customType: "sensitive-canary", data: { enabled: false } }];
    const sessionCtx = { ...ctx, sessionManager: { getBranch: () => branch, getSessionFile: () => undefined } };
    await handlers.session_start({}, sessionCtx);
    expect(
      await handlers.context({ messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] }, ctx),
    ).toBeUndefined();
    expect(emittedEvents.at(-1)).toEqual({ name: "sensitive-canary:mode", event: { enabled: false } });
    // Restore the default so later tests see redaction on.
    await handlers.session_start({}, { ...ctx, sessionManager: { getBranch: () => [], getSessionFile: () => undefined } });
    const res = await handlers.context(
      { messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] },
      ctx,
    );
    expect(res.messages[0].content).not.toContain(AWS_KEY);
  });

  it("forces redaction off at startup with --no-canary", async () => {
    noCanaryFlag = true;
    try {
      const sessionCtx = { ...ctx, sessionManager: { getBranch: () => [], getSessionFile: () => undefined } };
      await handlers.session_start({}, sessionCtx);
      expect(
        await handlers.context({ messages: [{ role: "user", content: `my key is ${AWS_KEY}` }] }, ctx),
      ).toBeUndefined();
      expect(emittedEvents.at(-1)).toEqual({ name: "sensitive-canary:mode", event: { enabled: false } });
    } finally {
      noCanaryFlag = false;
      await handlers.session_start({}, { ...ctx, sessionManager: { getBranch: () => [], getSessionFile: () => undefined } });
    }
  });

  it("blocks placeholders passed to tools with recovery guidance", async () => {
    const blocked = await handlers.tool_call({ toolName: "bash", input: { command: "ls /home/__CANARY_USER_9__/project" } });
    expect(blocked).toMatchObject({ block: true });
    expect(blocked.reason).toContain("__CANARY_USER_9__");
    expect(blocked.reason).toContain("$HOME");
    expect(await handlers.tool_call({ toolName: "read", input: { path: "/home/__CANARY_USER_9__/notes.md" } })).toMatchObject({ block: true });
    expect(await handlers.tool_call({ toolName: "bash", input: { command: "ls ~/project" } })).toBeUndefined();
  });

  it("lets allow tags bypass the placeholder guard per category", async () => {
    await handlers.context({ messages: [{ role: "user", content: "[allow-pii]\ncheck paths" }] }, ctx);
    expect(await handlers.tool_call({ toolName: "bash", input: { command: "ls /home/__CANARY_USER_9__/project" } })).toBeUndefined();
    // SECRET-tagged placeholders still need their own category.
    expect(await handlers.tool_call({ toolName: "bash", input: { command: "echo __CANARY_SECRET_9__" } })).toMatchObject({ block: true });
    await handlers.context({ messages: [{ role: "user", content: "[allow-all]\ncheck all" }] }, ctx);
    expect(await handlers.tool_call({ toolName: "bash", input: { command: "echo __CANARY_SECRET_9__" } })).toBeUndefined();
  });

  it("passes provider chain references through even when a rule matches them", async () => {
    // A rule-shaped value in a reasoning id or previous_response_id must
    // survive: the provider rejects redacted chain references (400). The
    // 11070-shaped value below is synthetic fixture data, not a real id.
    const chainId = "1107046800026";
    const res = await handlers.before_provider_request(
      {
        payload: {
          previous_response_id: chainId,
          input: [
            { type: "reasoning", id: chainId, encrypted_content: "opaque" },
            { type: "message", role: "user", text: `ref ${chainId}` },
          ],
        },
      },
      ctx,
    );
    expect(res.previous_response_id).toBe(chainId);
    expect(res.input[0].id).toBe(chainId);
    expect(res.input[0].encrypted_content).toBe("opaque");
    // Same value outside a chain reference still scans.
    expect(res.input[1].text).not.toContain(chainId);
  });

  it("preserves function call routing fields when the scan budget is exhausted", async () => {
    // Starved budgets mark content with omission text; routing keys must
    // stay byte-identical or the provider 400s (call_id length <= 64).
    // Needs no user rules, so this test is hermetic.
    const callId = "call_abc123def456ghi789jkl012mno345pq";
    const payload = {
      input: [
        { type: "function_call", id: "fc_123", call_id: callId, name: "bash", arguments: "{\"command\":\"ls\"}" },
        { type: "function_call_output", call_id: callId, output: "file1\nfile2" },
      ],
    };
    beginScanBudget(0);
    try {
      const out = (await handlers.before_provider_request({ payload }, ctx)) ?? payload;
      const text = JSON.stringify(out);
      expect(text).toContain(`"call_id":"${callId}"`);
      expect(text).not.toContain("call_id\":\"[sensitive-canary");
    } finally {
      beginScanBudget(null);
    }
  });

  it("preserves completions-API routing fields", async () => {
    // Assistant tool_calls ids, tool_call_id echoes, and the call item name
    // route execution; only the arguments content still scans.
    const callId = "call_1107046800026 insects";
    const payload = {
      messages: [
        {
          role: "assistant",
          tool_calls: [
            { id: "call_1107046800026", type: "function", function: { name: "bash", arguments: "{\"command\":\"ref 1107046800026\"}" } },
          ],
        },
        { role: "tool", tool_call_id: "call_1107046800026", content: "ok" },
      ],
    };
    expect(callId.length).toBeGreaterThan(0);
    const out = (await handlers.before_provider_request({ payload }, ctx)) ?? payload;
    const text = JSON.stringify(out);
    expect(text).toContain("call_1107046800026");
    expect(text).toContain("\"name\":\"bash\"");
    // The arguments content itself still scans.
    expect(text).not.toContain("ref 1107046800026");
    // And an identical value outside routing shapes still scans.
    const plain = await handlers.before_provider_request({ payload: { record: { id: "1107046800026" } } }, ctx);
    expect(JSON.stringify(plain)).not.toContain("1107046800026");
  });

  it("preserves tool definitions and schema identifiers when the scan budget is exhausted", async () => {
    // Completions bodies put messages before tools, so a starved budget hits
    // tool names and JSON-Schema `required` entries after the content.
    const payload = {
      model: "fixture-model",
      messages: [{ role: "user", content: `api_key=${AWS_KEY}` }],
      tools: [
        {
          type: "function",
          function: {
            name: "search_files",
            description: "search the project",
            parameters: {
              type: "object",
              properties: { pattern: { type: "string" } },
              required: ["pattern"],
            },
          },
        },
      ],
      response_format: { type: "json_schema", json_schema: { name: "plan_schema", schema: { type: "object", required: ["step"] } } },
      reasoning_effort: "low",
    };
    beginScanBudget(0);
    try {
      const res = await handlers.before_provider_request({ payload }, ctx);
      expect(res.tools[0].function.name).toBe("search_files");
      expect(res.tools[0].function.parameters.required).toEqual(["pattern"]);
      expect(res.response_format.json_schema.name).toBe("plan_schema");
      expect(res.response_format.json_schema.schema.required).toEqual(["step"]);
      expect(res.reasoning_effort).toBe("low");
      expect(res.model).toBe("fixture-model");
      expect(JSON.stringify(res.messages)).not.toContain(AWS_KEY);
    } finally {
      beginScanBudget(null);
    }
  });

  it("preserves Responses tool and format identifiers when the scan budget is exhausted", async () => {
    const payload = {
      model: "fixture-model",
      input: [{ type: "message", role: "user", content: `api_key=${AWS_KEY}` }],
      tools: [{ type: "function", name: "search_files", parameters: { type: "object", required: ["pattern"] } }],
      text: { format: { type: "json_schema", name: "plan_schema", schema: { type: "object", required: ["step"] } } },
    };
    beginScanBudget(0);
    try {
      const res = await handlers.before_provider_request({ payload }, ctx);
      expect(res.tools[0].name).toBe("search_files");
      expect(res.tools[0].parameters.required).toEqual(["pattern"]);
      expect(res.text.format.name).toBe("plan_schema");
      expect(res.text.format.schema.required).toEqual(["step"]);
      expect(res.model).toBe("fixture-model");
      expect(JSON.stringify(res.input)).not.toContain(AWS_KEY);
    } finally {
      beginScanBudget(null);
    }
  });

  it("never redacts canary boilerplate even when a user rule matches it", () => {
    // Isolated fresh process: a user rule colliding with notice wording must
    // not rewrite canary's own strings, anywhere they travel.
    const { mkdtempSync, writeFileSync } = require("node:fs");
    const { tmpdir } = require("node:os");
    const { join } = require("node:path");
    const home = mkdtempSync(join(tmpdir(), "canary-boilerplate-"));
    const file = join(home, "config.json");
    writeFileSync(file, JSON.stringify({ rules: [{ id: "pii-boilerplate-fixture", description: "fixture", regex: "\\bplaceholders\\b", category: "pii" }], inventory: [] }), { mode: 0o600 });
    const script = [
      "const m = await import(" + JSON.stringify(new URL("./index.ts", import.meta.url).href) + ");",
      "const handlers = {};",
      "m.default({ on: (n, fn) => { handlers[n] = fn; }, registerFlag(){}, registerCommand(){}, appendEntry(){}, getFlag: () => false, events: { on(){}, emit(){} } });",
      "const ctx = { sessionManager: { getBranch: () => [], getSessionFile: () => undefined }, ui: { notify(){} } };",
      "handlers.agent_start({}, ctx);",
      "const key = \"AKIA\" + \"A\".repeat(16);",
      "const seeded = await handlers.tool_result({ toolName: \"bash\", content: [{ type: \"text\", text: `k=${key}` }] }, ctx);",
      
      "const res = seeded;",
      "const markers = res.content.filter((c) => c.type === \"text\" && c.text.includes(\"[sensitive-canary\]\"));",
      "const reminder = (await handlers.before_agent_start({ prompt: \"p\", systemPrompt: \"base\" })).systemPrompt;",
      "const via = await handlers.before_provider_request({ payload: { systemPrompt: reminder } }, ctx);",
      "const live = await handlers.before_provider_request({ payload: { note: \"user placeholders here\" } }, ctx);",
      "console.log(JSON.stringify({ markers: markers.length, reminderKept: via === undefined, liveFires: live !== undefined && JSON.stringify(live).includes(\"__CANARY_\") }));",
    ].join("\n");
    const child = Bun.spawnSync({ cmd: [process.execPath, "-e", script], env: { ...process.env, HOME: home, XDG_CACHE_HOME: join(home, "cache"), SENSITIVE_CANARY_CONFIG: file }, timeout: 30000 });
    expect(child.exitCode).toBe(0);
    expect(JSON.parse(child.stdout.toString())).toEqual({ markers: 0, reminderKept: true, liveFires: true });
  });
});
