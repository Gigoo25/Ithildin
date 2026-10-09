import { describe, expect, it } from "bun:test";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";
import { AGENT, GUESS, SessionNames, USER } from "./sessions.ts";
import {
  firstPrompt,
  looksLikeNaming,
  renamedIn,
  replyText,
  titleAsk,
  titleFrom,
} from "./titles.ts";

// Each agent's naming prompt as it stands now. The patterns match on what these
// say they produce, not on how they open, so a reworded preamble still matches.
const CLAUDE_TITLE =
  "Generate a concise, sentence-case title (3-7 words) that captures the main topic or goal " +
  "of this coding session. The title should be clear enough that the user recognizes the " +
  'session in a list.\n\nReturn JSON with a single "title" field.\n\n' +
  'Good examples:\n{"title": "Fix login button on mobile"}';
const CLAUDE_NAME =
  "Generate a short kebab-case name (2-4 words) that captures the main topic of this " +
  "conversation. Use lowercase words separated by hyphens.";
const OPENCODE_SYSTEM =
  "You are a title generator. You output ONLY a thread title. Nothing else.\n\n<task>\n" +
  "Generate a brief title that would help the user find this conversation later.\n</task>";

describe("session titles", () => {
  it("knows each agent's naming request by what its prompt says it produces", () => {
    expect(titleAsk({ system: [{ type: "text", text: CLAUDE_TITLE }], messages: [] })).toBe(
      "title",
    );
    expect(titleAsk({ system: CLAUDE_NAME })).toBe("name");
    expect(titleAsk({ messages: [{ role: "system", content: OPENCODE_SYSTEM }] })).toBe("line");
    expect(titleAsk({ instructions: OPENCODE_SYSTEM, input: [] })).toBe("line");
    expect(titleAsk({ system: "You are Claude Code", messages: [] })).toBeUndefined();
    expect(titleAsk({ messages: [{ role: "user", content: OPENCODE_SYSTEM }] })).toBeUndefined();
  });

  it("finds the prompt whether or not it is the first message", () => {
    // opencode sends its title agent as a developer item; nothing holds an
    // agent to putting it first.
    const body = {
      input: [
        { role: "user", content: [{ type: "input_text", text: "go" }] },
        { role: "developer", content: OPENCODE_SYSTEM },
      ],
    };
    expect(titleAsk(body)).toBe("line");
    expect(titleAsk({ input: [{ role: "developer", content: OPENCODE_SYSTEM }] })).toBe("line");
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
    const chat = [
      { choices: [{ delta: { content: "<think>hm</think>\n\n" } }] },
      {
        choices: [{ delta: { content: '"Proxy dashboard"\nmore' } }],
      },
    ]
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
    expect(
      renamedIn({ messages: [named("one"), { role: "user", content: "x" }, named("two")] }),
    ).toBe("two");
    const said = { role: "assistant", content: 'The user named this session "a".' };
    expect(renamedIn({ messages: [said] })).toBeUndefined();
  });

  it("reads a title by the shape of the reply when the prompt will not say", () => {
    // A title agent that answers with a "name" field is still a title.
    expect(titleFrom("title", '{"name": "Fix login"}')).toBe("Fix login");
    expect(titleFrom("title", '{"title": "Fix login"}')).toBe("Fix login");
    expect(titleFrom("line", "Fix login")).toBe("Fix login");
    expect(titleFrom("title", '{"other": "x"}')).toBeUndefined();
    expect(titleFrom("title", "no json here")).toBeUndefined();
  });

  it("keeps the user's name over a model's title, and a model's over a guess", () => {
    const names = new SessionNames();
    names.name("claude", "0123456789");
    names.title("0123456789", "From the first prompt", GUESS);
    names.title("0123456789", "Model title", AGENT);
    names.title("0123456789", "mine", USER);
    names.title("0123456789", "Later model title", AGENT);
    names.title("0123456789", "Later guess", GUESS);
    names.title("unknown", "nope", AGENT);
    names.title("0123456789", "", AGENT);
    expect(names.list()).toEqual([{ id: "01234567", name: "claude 1", title: "mine" }]);
  });

  it("marks a title taken from the conversation as a guess", () => {
    const names = new SessionNames();
    names.name("pi", "aaaa");
    names.title("aaaa", "Fix the login", GUESS);
    expect(names.list()).toEqual([
      { id: "aaaa", name: "pi 1", title: "Fix the login", guessed: true },
    ]);
    // An agent's own title replaces it, and stops being a guess.
    names.title("aaaa", "Real title", AGENT);
    expect(names.list()).toEqual([{ id: "aaaa", name: "pi 1", title: "Real title" }]);
  });

  it("names a session no agent names, from what its user asked first", () => {
    expect(firstPrompt({ messages: [{ role: "user", content: "Fix the login button" }] })).toBe(
      "Fix the login button",
    );
    // Harness text is not something the user typed.
    expect(
      firstPrompt({
        messages: [
          { role: "user", content: [{ type: "text", text: "<system-reminder>be brief" }] },
          { role: "assistant", content: "ok" },
          { role: "user", content: [{ type: "text", text: "Now the dashboard" }] },
        ],
      }),
    ).toBe("Now the dashboard");
    // Long prompts become one line, and one sentence.
    expect(
      firstPrompt({ messages: [{ role: "user", content: "a".repeat(400) + "\nsecond line" }] }),
    ).toBe("a".repeat(79) + "…");
    expect(firstPrompt({ input: [{ role: "user", content: "One. Two." }] })).toBe("One.");
    expect(firstPrompt({ messages: [{ role: "assistant", content: "hi" }] })).toBeUndefined();
    expect(firstPrompt({})).toBeUndefined();
    expect(firstPrompt("not a body")).toBeUndefined();
    expect(firstPrompt({ messages: "not a list" })).toBeUndefined();
    // Blocks that are not text, and a user message with none.
    expect(
      firstPrompt({
        messages: [{ role: "user", content: [{ type: "image" }, { type: "text", text: "after" }] }],
      }),
    ).toBe("after");
    expect(
      firstPrompt({ messages: [{ role: "user", content: [{ type: "image" }] }] }),
    ).toBeUndefined();
  });

  it("reads a reply it cannot make sense of as no title", () => {
    // A whole reply that is not JSON, and a stream with junk in it.
    expect(replyText("{not json")).toBe("");
    expect(titleFrom("line", replyText("data: {broken\n\n"))).toBeUndefined();
    // The Responses and chat shapes a naming agent may answer in.
    expect(titleFrom("line", replyText(JSON.stringify({ output_text: "Flat" })))).toBe("Flat");
    expect(titleFrom("line", replyText(JSON.stringify({ output: [{ content: "Deep" }] })))).toBe(
      "Deep",
    );
    expect(
      titleFrom("line", replyText(JSON.stringify({ choices: [{ message: { content: "Ch" } }] }))),
    ).toBe("Ch");
    expect(titleFrom("line", replyText(JSON.stringify({ nothing: true })))).toBeUndefined();
  });

  it("says when a naming request is one but no pattern knows it", () => {
    // The proxy logs this, so a reworded agent is not silent.
    expect(looksLikeNaming({ system: "You are Claude Code", messages: [] })).toBe(false);
    expect(looksLikeNaming({ system: CLAUDE_TITLE })).toBe(false);
    expect(looksLikeNaming({ system: "Please write a thread title for the chat below." })).toBe(
      true,
    );
    expect(looksLikeNaming({ system: "Summarise, then return JSON with a title." })).toBe(true);
    expect(looksLikeNaming("not a body")).toBe(false);
    // An agent's own turn: it offers tools, or its prompt is far longer than
    // any naming prompt, whatever words it happens to contain.
    const tools = [{ name: "Bash", input_schema: { type: "object" } }];
    expect(looksLikeNaming({ system: "Return JSON with a title.", tools })).toBe(false);
    const long = `${"You are an agent. ".repeat(500)}Reply in JSON; the title field is optional.`;
    expect(looksLikeNaming({ system: long })).toBe(false);
    expect(looksLikeNaming({ system: "Return JSON with a title.", tools: [] })).toBe(true);
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
          system: CLAUDE_TITLE,
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
