import { beforeAll, describe, expect, it } from "bun:test";
import { observeActivity, REPLY_TEXT, reportActivity } from "../engine/lib/activity.ts";
import { DASHBOARD_HTML } from "./dashboard.ts";
import { ENTRIES_MAX, around, EventLog, preview, SEEN_MAX } from "./events.ts";
import { BODY_BYTES_MAX } from "./requests.ts";
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
    await as({ "x-opencode-session": "cccccccc3333" });
    await as({ "x-opencode-session": "dddddddd4444", "x-opencode-client": "pi" });
    await as({ "x-claude-code-session-id": "aaaaaaaa1111" });
    const seen = (await activity(handler)).entries
      .filter((entry) => entry.type === "request")
      .map((entry) => [entry.session, entry.sessionName]);
    expect(seen).toEqual([
      ["aaaaaaaa", "claude 1"],
      ["bbbbbbbb", "claude 2"],
      ["cccccccc", "opencode 1"],
      ["dddddddd", "pi 1"],
      ["aaaaaaaa", "claude 1"],
    ]);
    const list = (await (await handler(dashboard("/dashboard/requests"))).json()) as {
      requests: Array<{ sessionName?: string }>;
    };
    expect(list.requests.map((sent) => sent.sessionName)).toEqual([
      "claude 1",
      "pi 1",
      "opencode 1",
      "claude 2",
      "claude 1",
    ]);
  });

  it("ties a request's events and its kept text together by its turn", async () => {
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => Response.json({ content: [{ type: "text", text: `mail ${standIn}` }] })),
    );
    await send(handler, messages(`mail ${EMAIL}`));
    await send(handler, messages("hi"));
    const turns = (await activity(handler)).entries.map((entry) => [entry.type, entry.turn]);
    expect(turns).toEqual(
      expect.arrayContaining([
        ["masked", 1],
        ["request", 1],
        ["request", 2],
      ]),
    );
    expect(turns).toContainEqual(["swapped", 2]);
    const list = (await (await handler(dashboard("/dashboard/requests"))).json()) as {
      requests: Array<{ turn?: number }>;
    };
    expect(list.requests.map((sent) => sent.turn)).toEqual([2, 1]);
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

  it("runs: picks the latest session, names it, and lays out its conversation", async () => {
    const script = DASHBOARD_HTML.split("<script>")[1]!.split("</script>")[0]!;
    type Fake = Record<string, unknown> & { children: Fake[]; textContent: string };
    const fake = (): Fake => {
      const node: Fake = {
        children: [],
        textContent: "",
        value: "",
        dataset: {},
        style: { setProperty() {} },
        classList: { add() {}, remove() {}, toggle() {} },
        append: (...kids: Fake[]) => node.children.push(...kids),
        appendChild: (kid: Fake) => node.children.push(kid),
        replaceChildren: (...kids: Fake[]) => (node.children = kids),
        addEventListener: (type: string, listener: () => void) => {
          node["on" + type] = listener;
        },
        setAttribute() {},
        querySelector: () => null,
        querySelectorAll: () => [],
        scrollIntoView() {},
        scrollTop: 0,
        scrollHeight: 0,
      };
      Object.defineProperty(node, "firstChild", { get: () => node.children[0] });
      Object.defineProperty(node, "parentElement", { get: () => byId("main") });
      return node;
    };
    const nodes = new Map<string, Fake>();
    const byId = (id: string) => nodes.get(id) ?? nodes.set(id, fake()).get(id)!;
    const sent = JSON.stringify({
      tools: [{ name: "Bash" }],
      messages: [
        { role: "user", content: "first ask" },
        { role: "assistant", content: [{ type: "tool_use", id: "t", name: "Bash", input: {} }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t", content: "ok" }] },
        { role: "assistant", content: "done" },
        { role: "user", content: "second ask" },
      ],
    });
    const answers: Record<string, unknown> = {
      "/dashboard/activity?since=0": {
        entries: [{ id: 1, time: 1, type: "request", route: "anthropic", session: "s1", turn: 1 }],
        next: 1,
        stats: {
          leaked: 0,
          kinds: {},
          routes: { anthropic: 1 },
          requests: 1,
          startedAt: Date.now() - 60000,
          scanMsTotal: 5,
          scanMsMax: 9,
          replacements: 2,
          distinct: 1,
          swappedText: 0,
          swappedCalls: 0,
          shapedMasked: 91,
          shapedCompacted: 0,
          shapedDeduped: 2,
          shapedSavedChars: 355276,
          usageReplies: 1,
          usageInput: 1000,
          usageCacheRead: 8000,
          usageCacheWrite: 1000,
          usageOutput: 420,
          cacheBreaksAgent: 1,
          cacheBreaksShaping: 0,
          lastBreak: "system in claude 1 (agent)",
          blocked: 0,
          refused: 0,
        },
        watch: { known: 0, terms: 0, action: "flag" },
        sessions: [{ id: "s1", name: "claude 1", title: "Fix the login" }],
      },
      "/dashboard/requests": {
        enabled: true,
        keep: 20,
        requests: [{ id: 7, session: "s1", main: true, time: 1, turn: 1 }],
      },
      "/dashboard/request?id=7": sent,
    };
    const fetch = async (url: string) => {
      const answer = answers[url];
      return {
        ok: answer !== undefined,
        json: async () => answer,
        text: async () => answer,
      };
    };
    const document = {
      getElementById: byId,
      createElement: () => fake(),
      querySelectorAll: () => [],
    };
    const storage = { getItem: () => null, setItem() {} };
    new Function("document", "fetch", "localStorage", "window", "setInterval", script)(
      document,
      fetch,
      storage,
      {},
      () => 0,
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(byId("state").textContent).toBe("proxy up");
    expect(byId("session_title").textContent).toBe("Fix the login");
    // Newest turn first, and only it open.
    const shown = byId("viewer").children;
    const heads = shown.map((turn) =>
      [turn.children[0]!, ...turn.children[0]!.children].map((part) => part.textContent),
    );
    expect(heads).toEqual([
      ["Turn 2", "second ask", "latest", ""],
      ["Turn 1", "first ask", "1 tool call", ""],
      ["Before the first prompt", "", ""],
    ]);
    expect(shown.map((turn) => turn.open)).toEqual([true, false, false]);
    // Inside a turn too: the reply, above the call, above the prompt.
    expect(shown[1]!.children.slice(1).map((step) => step.className)).toEqual([
      "step reply",
      "step call",
      "step prompt",
    ]);
    // Each says who spoke in a word, not an arrow that reads as a control;
    // a call's sits in the head it shares with the tool's name.
    const label = (step: Fake) => (step.className === "step call" ? step.children[0]! : step);
    expect(shown[1]!.children.slice(1).map((step) => label(step).children[0]!.textContent)).toEqual(
      ["agent", "tool", "you"],
    );
    // A fold the reader opened stays open across the rebuild a new request makes.
    const toggle = (node: Fake, open: boolean) => {
      node.open = open;
      (node.ontoggle as () => void)();
    };
    toggle(shown[1]!, true);
    toggle(shown[1]!.children[2]!.children[1]!, true);
    toggle(shown[0]!, false);
    (byId("detail_search").oninput as () => void)();
    const again = byId("viewer").children;
    expect(again.map((turn) => turn.open)).toEqual([false, true, false]);
    expect(again[1]!.children[2]!.children[1]!.open).toBe(true);
    // Put back the way the page had it, the choice is forgotten.
    toggle(again[0]!, true);
    (byId("detail_search").oninput as () => void)();
    expect(byId("viewer").children.map((turn) => turn.open)).toEqual([true, true, false]);
    // The totals are three groups, each with its figures laid out in order.
    const read = (id: string) =>
      byId(id).children.flatMap((child: { textContent: string }) =>
        child.textContent ? [child.textContent] : [],
      );
    expect(read("num_traffic")).toEqual([
      "Scanned",
      "1",
      "Rate",
      "1.0 /min",
      "Busiest",
      "anthropic (1)",
      "Scan time",
      "5 ms avg, 9 max",
    ]);
    expect(read("num_masking")).toEqual([
      "Values masked",
      "2",
      "Distinct",
      "1",
      "Swapped back",
      "0",
    ]);
    expect(read("num_safety")).toEqual(["Leaks found", "none", "Held back", "0", "Refused", "0"]);
    // One request, 355276 characters saved by 91 stubbed results.
    expect(read("num_shaping")).toEqual([
      "Saved",
      "0.3 MiB",
      "Per request",
      "0.3 MiB",
      "Stubbed",
      "91",
      "Compacted",
      "0",
      "Repeats",
      "2",
    ]);
    // 8000 of 10000 prompt tokens read from the cache, one break by the agent.
    expect(read("num_cache")).toEqual([
      "Read from cache",
      "80%",
      "Prompt tokens",
      "10,000 (1,000 written)",
      "Output tokens",
      "420",
      "Prefix breaks",
      "1 agent, 0 shaping",
      "Last break",
      "system in claude 1 (agent)",
    ]);
  });

  it("carries its own icon, so the browser never asks the proxy for /favicon.ico", () => {
    expect(DASHBOARD_HTML).toMatch(/<link id="icon" rel="icon" href="data:image\/svg\+xml,%3Csvg/);
  });

  it("has a verdict, sessions, a search, the request viewer, and alerts for a leak", () => {
    const ids = ["verdict", "sessions", "session_title", "alerts", "detail_search", "viewer"];
    for (const id of ids) expect(DASHBOARD_HTML).toContain(`id="${id}"`);
    expect(DASHBOARD_HTML).toContain("/dashboard/requests");
    expect(DASHBOARD_HTML).toContain("/dashboard/request?id=");
    expect(DASHBOARD_HTML).toContain("new Notification(");
    expect(DASHBOARD_HTML).toMatch(/const ICON_ALERT = "data:image\/svg\+xml,/);
    expect(DASHBOARD_HTML).toContain("ff6b5e");
  });

  it("sums up each session, and places its leaks on the message they are in", () => {
    const pick = (name: string) =>
      /function \w+[\s\S]*?\n\}/.exec(
        DASHBOARD_HTML.slice(DASHBOARD_HTML.indexOf(`function ${name}(`)),
      )![0];
    const feed = [
      { type: "leaked", session: "s1", where: "messages[4].content", time: 3 },
      { type: "swapped", session: "s1", standIn: "x", time: 2 },
      { type: "masked", session: "s1", standIn: "x", time: 1, sessionName: "claude 1" },
      { type: "refused", time: 4 },
      { type: "leaked", session: "s1", where: "path", time: 5 },
    ];
    const run = new Function(
      "feed",
      `const OTHER = ''; const sessions = new Map(); ${pick("noteEntries")} ${pick("leaksFor")}` +
        " noteEntries(feed); return { sessions: [...sessions.values()], leaks: leaksFor('s1') };",
    ) as (feed: unknown[]) => { sessions: unknown[]; leaks: Map<number, unknown[]> };
    const { sessions, leaks } = run(feed);
    expect(sessions).toEqual([
      { id: "s1", name: "s1", last: 5, masked: 1, swapped: 1, held: 0, leaked: 2 },
      { id: "", name: "Other traffic", last: 4, masked: 0, swapped: 0, held: 1, leaked: 0 },
    ]);
    expect([...leaks.keys()]).toEqual([4]);
  });

  it("lays out a request as a conversation in each format", () => {
    const source = /function turns[\s\S]*?\n\}/.exec(DASHBOARD_HTML)![0];
    const turns = new Function(`${source}; return turns;`)() as (
      body: unknown,
    ) => Array<{ who: string; kind: string; text: string; name?: unknown; id?: string }>;
    const brief = (body: unknown) =>
      turns(body).map((item) => [item.kind, item.name ?? "", item.text].join("|"));
    expect(
      brief({
        system: [{ type: "text", text: "be brief" }],
        tools: [{ name: "Bash" }, { name: "Read" }],
        messages: [
          { role: "user", content: "hi" },
          {
            role: "assistant",
            content: [
              { type: "thinking", thinking: "hm" },
              { type: "tool_use", id: "t", name: "Bash", input: { command: "ls" } },
            ],
          },
          {
            role: "user",
            content: [
              { type: "tool_result", tool_use_id: "t", content: [{ type: "text", text: "a" }] },
              { type: "image", source: {} },
            ],
          },
        ],
      }),
    ).toEqual([
      "tools|2|Bash, Read",
      "system||be brief",
      "user||hi",
      "thinking||hm",
      'tool_call|Bash|{\n "command": "ls"\n}',
      "tool_result||a",
      "media||[image]",
    ]);
    expect(
      brief({
        messages: [
          { role: "system", content: "sys" },
          {
            role: "assistant",
            content: null,
            tool_calls: [{ function: { name: "grep", arguments: '{"q":1}' } }],
          },
          { role: "tool", content: "found" },
        ],
      }),
    ).toEqual(["system||sys", 'tool_call|grep|{"q":1}', "tool_result||found"]);
    expect(
      brief({
        instructions: "codex",
        input: [
          { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] },
          { type: "function_call", name: "shell", arguments: "{}" },
          { type: "function_call_output", output: "ok" },
        ],
      }),
    ).toEqual(["system||codex", "user||go", "tool_call|shell|{}", "tool_result||ok"]);
    expect(brief({ input: "plain" })).toEqual(["user||plain"]);
    // A call and its result share an id, so the page can show them together.
    const paired = turns({
      messages: [
        { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Bash", input: {} }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "ok" }] },
      ],
    });
    expect(paired.map((item) => item.id)).toEqual(["t1", "t1"]);
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

  it("leaves the chrome unselectable and the data selectable", () => {
    // A drag across the page paints nothing worth keeping.
    const rule = /user-select: none;/.exec(DASHBOARD_HTML);
    expect(rule).not.toBeNull();
    const chrome = DASHBOARD_HTML.slice(
      DASHBOARD_HTML.lastIndexOf("header, #verdict"),
      DASHBOARD_HTML.indexOf("-webkit-user-select"),
    );
    for (const selector of [
      "header",
      "#verdict",
      "#session_title",
      "#side h2",
      "#side h3",
      "#side dt",
      ".pick",
      ".turn_head",
      "summary",
      ".badge",
      ".key",
    ])
      expect(chrome).toContain(selector);
    // And what is worth copying is still selectable: the conversation and the
    // raw request, the figures, the kinds masked, the alerts.
    for (const selector of ["#viewer", "dd", ".kind", ".alert"]) {
      expect(chrome).not.toContain(selector + ",");
      expect(chrome).not.toContain(selector + " ");
    }
  });

  it("folds each turn on a click of its head, with the keyboard too", () => {
    // A turn is a details element, so it folds without any script of its own.
    expect(DASHBOARD_HTML).toContain("turn = document.createElement('details');");
    // The chevron points the way it will go.
    expect(DASHBOARD_HTML).toContain(".turn:not([open]) .turn_chev::before");
    expect(DASHBOARD_HTML).toMatch(/\.turn \{[^}]*border-left: 1px solid var\(--edge\)/);
  });

  it("leaves Sessions and Numbers open, so both sides read without a click", () => {
    expect(DASHBOARD_HTML).toMatch(/<details class="section" id="fold_sessions" open>/);
    expect(DASHBOARD_HTML).toMatch(/<details class="section" id="fold_numbers" open>/);
  });

  it("says how much of a cut request the page holds", () => {
    // The cap is the proxy's, so the two cannot drift apart.
    expect(DASHBOARD_HTML).toContain(`', cut at ${BODY_BYTES_MAX / 1048576} MiB of '`);
    expect(DASHBOARD_HTML).toContain("function mib(chars)");
    // A body is megabytes, so the page holds a few, not every one it read.
    expect(DASHBOARD_HTML).toContain(`const TEXTS_MAX = ${4};`);
    expect(DASHBOARD_HTML).toContain("while (texts.size > TEXTS_MAX)");
  });

  it("keeps as many events as the proxy does, in a box that scrolls", () => {
    expect(DASHBOARD_HTML).toContain(`const FEED_MAX = ${ENTRIES_MAX};`);
    // The page fills the window and the conversation scrolls in its own box.
    expect(DASHBOARD_HTML).toMatch(/#viewer \{\s+flex: 1; min-height: 0; overflow: auto;/);
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
