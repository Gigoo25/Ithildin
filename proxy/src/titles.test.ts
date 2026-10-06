import { describe, expect, it } from "bun:test";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";
import { SessionNames } from "./sessions.ts";
import { renamedIn, replyText, titleAsk, titleFrom } from "./titles.ts";

const CLAUDE_SYSTEM =
  "You are naming a coding session so the user can pick it out of a long list of sessions.";
const OPENCODE_SYSTEM = "You are a title generator. You output ONLY a thread title. Nothing else.";

describe("session titles", () => {
  it("knows each agent's naming request by its system prompt, in each format", () => {
    expect(titleAsk({ system: [{ type: "text", text: CLAUDE_SYSTEM }], messages: [] })).toBe(
      "title",
    );
    expect(titleAsk({ system: "Generate a short kebab-case name (2-4 words) that…" })).toBe("name");
    expect(titleAsk({ messages: [{ role: "system", content: OPENCODE_SYSTEM }] })).toBe("line");
    expect(titleAsk({ instructions: OPENCODE_SYSTEM, input: [] })).toBe("line");
    expect(titleAsk({ system: "You are Claude Code", messages: [] })).toBeUndefined();
    expect(titleAsk({ messages: [{ role: "user", content: OPENCODE_SYSTEM }] })).toBeUndefined();
  });

  it("reads the title from a whole or streamed reply", () => {
    const whole = JSON.stringify({ content: [{ type: "text", text: '{"title": "Fix login"}' }] });
    expect(titleFrom("title", replyText(whole))).toBe("Fix login");
    const sse = [
      { type: "content_block_delta", delta: { type: "text_delta", text: '{"ti' } },
      { type: "content_block_delta", delta: { type: "text_delta", text: 'tle":"Dash"}' } },
    ]
      .map((event) => `event: x\ndata: ${JSON.stringify(event)}\n\n`)
      .join("");
    expect(titleFrom("title", replyText(sse))).toBe("Dash");
    const chat = [{ choices: [{ delta: { content: "<think>hm</think>\n\n" } }] }, {
      choices: [{ delta: { content: '"Proxy dashboard"\nmore' } }],
    }]
      .map((event) => `data: ${JSON.stringify(event)}\n\n`)
      .concat("data: [DONE]\n\n")
      .join("");
    expect(titleFrom("line", replyText(chat))).toBe("Proxy dashboard");
    const delta = { type: "response.output_text.delta", delta: "Hi" };
    const responses = `data: ${JSON.stringify(delta)}\n\n`;
    expect(titleFrom("line", replyText(responses))).toBe("Hi");
    expect(titleFrom("name", '{"name": "fix-login-bug"}')).toBe("fix-login-bug");
    expect(titleFrom("title", "no json")).toBeUndefined();
    expect(titleFrom("line", "x".repeat(200))!.length).toBe(80);
  });

  it("takes the user's name for a session from the conversation, the latest one", () => {
    const named = (name: string) => ({
      role: "user",
      content: [{ type: "text", text: `The user named this session "${name}". This may…` }],
    });
    expect(renamedIn({ messages: [named("one"), { role: "user", content: "x" }, named("two")] }))
      .toBe("two");
    const said = { role: "assistant", content: 'The user named this session "a".' };
    expect(renamedIn({ messages: [said] })).toBeUndefined();
  });

  it("keeps the user's name over a model's title", () => {
    const names = new SessionNames();
    names.name("claude", "0123456789");
    names.title("0123456789", "Model title", false);
    names.title("0123456789", "mine", true);
    names.title("0123456789", "Later model title", false);
    names.title("unknown", "nope", false);
    expect(names.list()).toEqual([{ id: "01234567", name: "claude 1", title: "mine" }]);
  });

  it("names a session from its agent's naming request, with stand-ins only", async () => {
    const email = "jane.doe@acme-corp.com";
    let standIn = "";
    const handler = createHandler(DEFAULT_ROUTES, (async (_url: string, init: RequestInit) => {
      const sent = JSON.parse(String(init.body)) as { messages: Array<{ content: string }> };
      standIn = sent.messages[0]!.content.split(" ").at(-1)!;
      const text = JSON.stringify({ title: `Mail ${standIn}` });
      return Response.json({ content: [{ type: "text", text }] });
    }) as unknown as typeof fetch);
    await handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-claude-code-session-id": "abcdef0123" },
        body: JSON.stringify({
          system: CLAUDE_SYSTEM,
          messages: [{ role: "user", content: `write to ${email}` }],
        }),
      }),
    );
    // The title is read beside the client's copy; let it land.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const activity = (await (
      await handler(new Request("http://127.0.0.1/dashboard/activity"))
    ).json()) as { sessions: Array<{ id: string; name: string; title?: string }> };
    expect(standIn).not.toBe(email);
    expect(activity.sessions).toEqual([
      { id: "abcdef01", name: "claude 1", title: `Mail ${standIn}` },
    ]);
    expect(JSON.stringify(activity)).not.toContain(email);
  });
});
