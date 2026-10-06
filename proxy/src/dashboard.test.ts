import { beforeAll, describe, expect, it } from "bun:test";
import { observeActivity, REPLY_TEXT, reportActivity } from "../engine/lib/activity.ts";
import { DASHBOARD_HTML } from "./dashboard.ts";
import { ENTRIES_MAX, around, EventLog, preview, SEEN_MAX } from "./events.ts";
import { initEngine, redactRequest } from "./redact.ts";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";

const EMAIL = "jane.doe@acme-corp.com";
const TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
let standIn = "";

beforeAll(() => {
  initEngine();
  const body = redactRequest("anthropic", { messages: [{ role: "user", content: EMAIL }] })
    .body as { messages: Array<{ content: string }> };
  standIn = body.messages[0]!.content;
});

const EMAIL_PREVIEW = `${EMAIL.slice(0, 2)}…${EMAIL.slice(-1)} (${EMAIL.length})`;
// A stand-in for fetch: the handler only calls it.
const upstream = (reply: () => Response) => (async () => reply()) as unknown as typeof fetch;
const context = {
  route: "anthropic",
  endpoint: "/v1/messages",
  session: "0123456789abcdef",
  sessionName: "claude 1",
};

function masked(value: string, standIn: string, ruleId = "pii-email") {
  return { type: "masked", ruleId, category: "pii", value, standIn } as const;
}

describe("preview", () => {
  it("keeps the ends of a long value and the first character of a short one", () => {
    expect(preview(EMAIL)).toBe(EMAIL_PREVIEW);
    expect(preview("abcdefg")).toBe("a… (7)");
    expect(preview("abcdefgh")).toBe("ab…h (8)");
    expect(preview("é🙂")).toBe("é… (2)");
  });
});

describe("event log", () => {
  it("records a value once, and counts the repeats", () => {
    let time = 1000;
    const log = new EventLog(() => time++);
    expect(log.record(context, masked(EMAIL, "ana@corp.com"))).toBe(true);
    expect(log.record(context, masked(EMAIL, "ana@corp.com"))).toBe(false);
    const { entries, stats } = log.snapshot(0);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      id: 1,
      type: "masked",
      kind: "email",
      standIn: "ana@corp.com",
      session: "01234567",
      sessionName: "claude 1",
      route: "anthropic",
      endpoint: "/v1/messages",
    });
    expect(JSON.stringify(entries)).not.toContain(EMAIL);
    expect(stats).toMatchObject({ replacements: 2, distinct: 1, kinds: { email: 1 } });
    expect(entries[0]!.preview).toBe(EMAIL_PREVIEW);
  });

  it("names a secret by its rule, not its category", () => {
    const log = new EventLog();
    const event = { ...masked(TOKEN, "ghp_x", "github-pat"), category: "secret" } as const;
    log.record(context, event);
    const [entry] = log.snapshot(0).entries;
    expect(entry).toMatchObject({ kind: "secret", rule: "github-pat" });
    expect(JSON.stringify(entry)).not.toContain(TOKEN);
  });

  it("tells reply text from a tool call, and counts guard blocks", () => {
    const log = new EventLog();
    const swap = {
      type: "swapped" as const,
      ruleId: "pii-swapback-host",
      value: "db.corp",
      standIn: "x.y",
    };
    log.record(context, { ...swap, tool: REPLY_TEXT });
    log.record(context, { ...swap, tool: "bash" });
    log.record(context, { type: "blocked", notice: "Not run: git reset --hard" });
    const { entries, stats } = log.snapshot(0);
    expect(entries.map((entry) => entry.where ?? entry.text)).toEqual([
      "reply text",
      "bash",
      "Not run: git reset --hard",
    ]);
    expect(entries[0]).toMatchObject({ kind: "host", standIn: "x.y", preview: "d… (7)" });
    expect(stats).toMatchObject({ swappedText: 1, swappedCalls: 1, blocked: 1 });
  });

  it("totals requests, scan time and refusals", () => {
    const log = new EventLog();
    log.request(context, 10, 2);
    log.request({ route: "openai-codex", endpoint: "/responses", session: undefined }, 30, 0);
    log.refused(502, "upstream redirected");
    const { entries, stats } = log.snapshot(0);
    expect(stats).toMatchObject({
      requests: 2,
      routes: { anthropic: 1, "openai-codex": 1 },
      scanMsTotal: 40,
      scanMsMax: 30,
      refused: 1,
    });
    expect(entries[1]).not.toHaveProperty("session");
    expect(entries[1]).toMatchObject({ route: "openai-codex", endpoint: "/responses" });
    expect(entries[2]).toMatchObject({ type: "refused", status: 502, route: "" });
    expect(entries[2]).not.toHaveProperty("endpoint");
  });

  it("returns only what came after `since`", () => {
    const log = new EventLog();
    log.request(context, 1, 0);
    log.request(context, 2, 0);
    const second = log.snapshot(1);
    expect(second.entries.map((entry) => entry.id)).toEqual([2]);
    expect(log.snapshot(second.next).entries).toEqual([]);
  });

  it("bounds the entries and the stand-ins it remembers", () => {
    const log = new EventLog();
    for (let index = 0; index < SEEN_MAX + 5; index++)
      log.record(context, masked(`value-${index}`, `stand-${index}`));
    for (let index = 0; index < ENTRIES_MAX; index++) log.request(context, 1, 0);
    const { entries, stats } = log.snapshot(0);
    expect(entries).toHaveLength(ENTRIES_MAX);
    expect(stats.distinct).toBe(SEEN_MAX + 5);
    // The oldest stand-in was forgotten, so it logs again; a recent one does not.
    expect(log.record(context, masked("value-0", "stand-0"))).toBe(true);
    expect(log.record(context, masked("value-1004", "stand-1004"))).toBe(false);
  });
});

describe("activity observer", () => {
  const blocked = { type: "blocked", notice: "Not run" } as const;

  it("reports to the innermost observer, and to the outer one after the inner throws", () => {
    reportActivity(blocked);
    const outer: string[] = [];
    const inner: string[] = [];
    observeActivity(
      (event) => outer.push(event.type),
      () => {
        expect(() =>
          observeActivity(
            (event) => inner.push(event.type),
            () => {
              reportActivity(blocked);
              throw new Error("scan failed");
            },
          ),
        ).toThrow("scan failed");
        reportActivity(blocked);
      },
    );
    expect(inner).toEqual(["blocked"]);
    expect(outer).toEqual(["blocked"]);
  });
});

describe("dashboard", () => {
  const dashboard = (path: string, host = "127.0.0.1") => new Request(`http://${host}${path}`);
  const messages = (content: string) => ({
    messages: [
      { role: "user", content },
      { role: "assistant", content: "ok" },
      { role: "user", content: "again" },
    ],
  });
  const send = (handler: ReturnType<typeof createHandler>, body: unknown) =>
    handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-ithildin-session": "abcdef123456" },
        body: JSON.stringify(body),
      }),
    );
  const activity = async (handler: ReturnType<typeof createHandler>, query = "") =>
    (await handler(dashboard(`/dashboard/activity${query}`))).json() as Promise<{
      entries: Array<Record<string, unknown>>;
      next: number;
      stats: Record<string, unknown>;
    }>;

  it("shows what a request masked, without the real value", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({ content: [] })),
    );
    await send(handler, messages(`write to ${EMAIL} with ${TOKEN}`));
    const data = await activity(handler);
    expect(JSON.stringify(data)).not.toContain(EMAIL);
    expect(JSON.stringify(data)).not.toContain(TOKEN);
    const kinds = data.entries.filter((entry) => entry.type === "masked").map((e) => e.kind);
    expect(kinds).toEqual(expect.arrayContaining(["email", "secret"]));
    expect(data.entries.at(-1)).toMatchObject({
      type: "request",
      route: "anthropic",
      endpoint: "/v1/messages",
    });
    expect(data.entries.at(-1)!.count).toBeGreaterThanOrEqual(2);
    expect(data.stats).toMatchObject({ requests: 1 });
    const again = await activity(handler, `?since=${data.next}`);
    expect(again.entries).toEqual([]);
  });

  it("shows the text around a masked value as it was sent, never the real value", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({ content: [] })),
    );
    await send(handler, messages(`write to ${EMAIL} about the invoice`));
    const masked = (await activity(handler)).entries.find((entry) => entry.type === "masked")!;
    expect(masked.parts).toEqual([
      { text: "write to " },
      { text: masked.standIn, mark: "this" },
      { text: " about the invoice" },
    ]);
    expect(JSON.stringify(masked)).not.toContain(EMAIL);
  });

  it("cuts the context at the message, and marks text that goes on", () => {
    const sent = JSON.stringify({
      messages: [
        { role: "user", content: "first" },
        { role: "user", content: `${"a".repeat(150)} STANDIN ${"b".repeat(150)}\nsaid "hi"` },
        { role: "user", content: "last" },
      ],
    });
    const found = around(sent, "STANDIN").parts!;
    expect(found.map((part) => part.text)).toEqual([
      "…",
      `${"a".repeat(99)} `,
      "STANDIN",
      ` ${"b".repeat(99)}`,
      "…",
    ]);
    expect(found[2]!.mark).toBe("this");
    const short = around(sent.replace(/b{150}/, "b"), "STANDIN").parts!;
    expect(short.at(-1)!.text).toBe(' b\nsaid "hi"');
    expect(around(sent, "absent")).toEqual({});
    expect(around(undefined, "STANDIN")).toEqual({});
  });

  it("marks the request's other stand-ins in the message, the longer one first", () => {
    const sent = JSON.stringify({ content: "write Ann Lee at ann@x.io, or Ann Lee Jr" });
    expect(around(sent, "ann@x.io", ["Ann Lee", "Ann Lee Jr", ""]).parts).toEqual([
      { text: "write " },
      { text: "Ann Lee", mark: "other" },
      { text: " at " },
      { text: "ann@x.io", mark: "this" },
      { text: ", or " },
      { text: "Ann Lee Jr", mark: "other" },
    ]);
  });

  it("names each session by its agent, in the feed and the sent requests", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({ content: [] })),
    );
    const as = (headers: Record<string, string>) =>
      handler(
        new Request("http://127.0.0.1/anthropic/v1/messages", {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify(messages(`mail ${EMAIL}`)),
        }),
      );
    await as({ "x-claude-code-session-id": "aaaaaaaa1111" });
    await as({ "x-claude-code-session-id": "bbbbbbbb2222" });
    await as({ "x-opencode-session-id": "cccccccc3333" });
    await as({ "x-claude-code-session-id": "aaaaaaaa1111" });
    const seen = (await activity(handler)).entries
      .filter((entry) => entry.type === "request")
      .map((entry) => [entry.session, entry.sessionName]);
    expect(seen).toEqual([
      ["aaaaaaaa", "claude 1"],
      ["bbbbbbbb", "claude 2"],
      ["cccccccc", "opencode 1"],
      ["aaaaaaaa", "claude 1"],
    ]);
    const list = (await (await handler(dashboard("/dashboard/requests"))).json()) as {
      requests: Array<{ sessionName?: string }>;
    };
    expect(list.requests.map((sent) => sent.sessionName)).toEqual([
      "claude 1",
      "opencode 1",
      "claude 2",
      "claude 1",
    ]);
  });

  it("shows the endpoint as the upstream gets it, with a value in the path masked", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({ content: [] })),
    );
    await handler(
      new Request(`http://127.0.0.1/anthropic/${EMAIL}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(messages("hi")),
      }),
    );
    const { entries } = await activity(handler);
    const request = entries.find((entry) => entry.type === "request")!;
    expect(String(request.endpoint)).toMatch(/\/v1\/messages$/);
    expect(JSON.stringify(entries)).not.toContain(EMAIL);
  });

  it("shows a stand-in the model wrote being swapped back in a JSON reply", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({ content: [{ type: "text", text: `mail ${standIn}` }] })),
    );
    const reply = await send(handler, messages("hi"));
    expect(JSON.stringify(await reply.json())).toContain(EMAIL);
    const data = await activity(handler);
    const swap = data.entries.find((entry) => entry.type === "swapped")!;
    expect(swap).toMatchObject({ kind: "email", standIn, where: "reply text" });
    expect(JSON.stringify(data)).not.toContain(EMAIL);
    expect(data.stats).toMatchObject({ swappedText: 1 });
  });

  it("shows a swap in a streamed reply and a guard blocking a call", async () => {
    const event = (data: unknown) => `data: ${JSON.stringify(data)}\n\n`;
    const stream = [
      event({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }),
      event({
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: `mail ${standIn}\n` },
      }),
      event({ type: "content_block_stop", index: 0 }),
      event({
        type: "content_block_start",
        index: 1,
        content_block: { type: "tool_use", id: "toolu_9", name: "bash", input: {} },
      }),
      event({
        type: "content_block_delta",
        index: 1,
        delta: { type: "input_json_delta", partial_json: '{"command": "rm -rf .git"}' },
      }),
      event({ type: "content_block_stop", index: 1 }),
    ].join("");
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => new Response(stream, { headers: { "content-type": "text/event-stream" } })),
    );
    await (await send(handler, { ...messages("hi"), stream: true })).text();
    const data = await activity(handler);
    expect(data.entries.map((entry) => entry.type)).toEqual(
      expect.arrayContaining(["swapped", "blocked"]),
    );
    expect(data.stats).toMatchObject({ swappedText: 1, blocked: 1 });
  });

  it("logs a refusal and keeps its marker off the response", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({})),
    );
    const response = await handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{not json",
      }),
    );
    expect(response.status).toBe(400);
    expect(response.headers.get("x-ithildin-refused")).toBeNull();
    const data = await activity(handler);
    expect(data.entries[0]).toMatchObject({ type: "refused", status: 400 });
    expect(data.stats).toMatchObject({ refused: 1 });
  });

  it("serves the page with a policy that allows no outside content", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({})),
    );
    const response = await handler(dashboard("/dashboard"));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("content-security-policy")).toContain("img-src data:");
    expect(await response.text()).toBe(DASHBOARD_HTML);
    expect(DASHBOARD_HTML).not.toContain("innerHTML");
  });

  it("ships a script that parses, and a crescent drawn where its mask is", () => {
    const script = DASHBOARD_HTML.split("<script>")[1]!.split("</script>")[0]!;
    expect(() => new Function(script)).not.toThrow();
    expect(DASHBOARD_HTML).toMatch(/translate\(100 50\)[^>]*>\s*<circle r="13"/);
  });

  it("carries its own icon, so the browser never asks the proxy for /favicon.ico", () => {
    expect(DASHBOARD_HTML).toMatch(/<link id="icon" rel="icon" href="data:image\/svg\+xml,%3Csvg/);
  });

  it("has tabs, a search, a session menu, and alerts for a leak", () => {
    for (const id of ["tab_activity", "tab_sent", "search", "session", "sent_search", "viewer"])
      expect(DASHBOARD_HTML).toContain(`id="${id}"`);
    expect(DASHBOARD_HTML).toContain("/dashboard/requests");
    expect(DASHBOARD_HTML).toContain("/dashboard/request?id=");
    expect(DASHBOARD_HTML).toContain("new Notification(");
    expect(DASHBOARD_HTML).toMatch(/const ICON_ALERT = "data:image\/svg\+xml,/);
    expect(DASHBOARD_HTML).toContain("ff6b5e");
  });

  it("cuts a guard notice to its first sentence for the page", () => {
    const source = /function firstSentence[\s\S]*?\n\}/.exec(DASHBOARD_HTML)![0];
    const firstSentence = new Function(`${source}; return firstSentence;`)() as (
      text: string,
    ) => string;
    expect(firstSentence("Not run: it would lose work. Use git stash. Or ask.")).toBe(
      "Not run: it would lose work.",
    );
    expect(firstSentence("No full stop here")).toBe("No full stop here");
  });

  it("keeps as many events as the proxy does, in a box that scrolls", () => {
    expect(DASHBOARD_HTML).toContain(`const FEED_MAX = ${ENTRIES_MAX};`);
    expect(DASHBOARD_HTML).toMatch(/id="feed_box" class="scroll tall"/);
    // The page fills the window and only this box scrolls.
    expect(DASHBOARD_HTML).toMatch(/\.tall \{ flex: 1; min-height: \d+px; overflow-y: auto; \}/);
    expect(DASHBOARD_HTML).toMatch(/height: 100vh; display: flex; flex-direction: column;/);
  });

  it("turns away a name that is not local, and reads a bad `since` as zero", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({})),
    );
    for (const path of ["/dashboard", "/dashboard/activity"])
      expect((await handler(dashboard(path, "evil.example"))).status).toBe(403);
    expect((await activity(handler, "?since=abc")).entries).toEqual([]);
    expect((await activity(handler, "?since=1.5")).entries).toEqual([]);
  });

  it("answers while the self-test has not passed", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({})),
      undefined,
      true,
    );
    expect((await handler(dashboard("/dashboard"))).status).toBe(200);
    expect((await handler(dashboard("/dashboard/activity"))).status).toBe(200);
  });
});
