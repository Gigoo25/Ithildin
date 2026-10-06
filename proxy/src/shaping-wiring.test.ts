import { describe, expect, it } from "bun:test";
import { createHandler, DEFAULT_ROUTES, shapeOutgoing, type Scanned } from "./server.ts";
import { shapeRequest, shapingOn } from "./shape.ts";
import type { Counts } from "./redact.ts";

// A conversation long enough that the cutoff is live: twenty assistant turns of
// real context, one old tool result among them.
const pad = (): string => `working on it ${"x".repeat(6_000)}`;
const bigResult = (): string =>
  Array.from({ length: 60 }, (_, i) => `line ${i} of output`).join("\n");

function conversation(): Record<string, unknown> {
  const messages: Array<Record<string, unknown>> = [
    { role: "user", content: [{ type: "text", text: "look at this" }] },
    {
      role: "assistant",
      content: [
        { type: "tool_use", id: "t1", name: "Bash", input: { command: "cat /srv/app.log" } },
      ],
    },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: bigResult() }] },
  ];
  for (let i = 0; i < 20; i++) {
    messages.push({ role: "user", content: [{ type: "text", text: `step ${i}` }] });
    messages.push({ role: "assistant", content: [{ type: "text", text: pad() }] });
  }
  return { model: "claude-opus-5", messages };
}

const noCounts: Counts = { masked: 0, files: 0, lines: 0, images: 0 };

// A handler whose upstream records the body it was given.
function recording() {
  const seen: string[] = [];
  const fetchUpstream = (_target: unknown, init: RequestInit) => {
    seen.push(String(init.body ?? ""));
    return Promise.resolve(Response.json({ ok: true }));
  };
  return { seen, fetchUpstream };
}

const post = (body: unknown, session?: string): Request => {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (session) headers["x-claude-code-session-id"] = session;
  return new Request("http://127.0.0.1/anthropic/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
};

// What the upstream was actually sent.
function sentText(seen: string[]): string {
  return seen[seen.length - 1] ?? "";
}

describe("the request path shapes what it forwards", () => {
  it("masks an old result upstream, and keeps the whole one on the dashboard", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);
    await handler(post(conversation(), "w1"));
    const forwarded = sentText(seen);
    expect(forwarded).toContain("[masked to save context:");
    expect(forwarded).not.toContain("line 0 of output");
  });

  it("is pure across requests: the same conversation forwards the same bytes", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);
    await handler(post(conversation(), "w2"));
    const first = sentText(seen);
    await handler(post(conversation(), "w2"));
    expect(sentText(seen)).toBe(first);
  });

  it("sends the body whole when ITHILDIN_SHAPE says no", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);
    const before = process.env.ITHILDIN_SHAPE;
    process.env.ITHILDIN_SHAPE = "off";
    try {
      expect(shapingOn()).toBe(false);
      await handler(post(conversation(), "w3"));
    } finally {
      if (before === undefined) delete process.env.ITHILDIN_SHAPE;
      else process.env.ITHILDIN_SHAPE = before;
    }
    expect(sentText(seen)).toContain("line 0 of output");
    expect(sentText(seen)).not.toContain("[masked to save context:");
  });

  it("sends the body whole for a session that typed [raw], until it types [shape]", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);

    await handler(post(conversation(), "w4"));
    expect(sentText(seen)).toContain("[masked to save context:");

    // The user asks for raw text, in a later prompt of the same conversation.
    const raw = conversation();
    (raw.messages as Array<Record<string, unknown>>).push({
      role: "user",
      content: [{ type: "text", text: "show me it all [raw]" }],
    });
    await handler(post(raw, "w4"));
    expect(sentText(seen)).toContain("line 0 of output");
    expect(sentText(seen)).not.toContain("[masked to save context:");

    // A later prompt that says nothing keeps it raw.
    await handler(post(conversation(), "w4"));
    expect(sentText(seen)).not.toContain("[masked to save context:");

    // And [shape] turns it back on for the rest of that session.
    const again = conversation();
    (again.messages as Array<Record<string, unknown>>).push({
      role: "user",
      content: [{ type: "text", text: "compact it again [shape]" }],
    });
    await handler(post(again, "w4"));
    expect(sentText(seen)).toContain("[masked to save context:");
  });

  it("keeps one session's [raw] out of another's", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);
    const raw = conversation();
    (raw.messages as Array<Record<string, unknown>>).push({
      role: "user",
      content: [{ type: "text", text: "[raw]" }],
    });
    await handler(post(raw, "w5"));
    expect(sentText(seen)).not.toContain("[masked to save context:");
    await handler(post(conversation(), "w6"));
    expect(sentText(seen)).toContain("[masked to save context:");
  });

  it("shapes a client that named no session, since it cannot have opted out", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);
    await handler(post(conversation()));
    expect(sentText(seen)).toContain("[masked to save context:");
  });

  it("leaves a short conversation untouched", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);
    const short = { model: "claude-opus-5", messages: [{ role: "user", content: "hi" }] };
    await handler(post(short, "w7"));
    expect(sentText(seen)).toBe(JSON.stringify(short));
  });

  it("forwards a request it cannot shape, rather than refusing the turn", () => {
    // The worst a body can do to a transformer. Shaping is an optimization,
    // so the answer must be the body redaction produced, not a refusal.
    const hostile = new Proxy({} as Record<string, unknown>, {
      get() {
        throw new TypeError("boom");
      },
    });
    const redacted = JSON.stringify(conversation());
    const scanned: Scanned = {
      body: redacted,
      object: hostile,
      tags: new Set<string>(),
      hits: 0,
      counts: noCounts,
      prompts: 1,
      scanMs: 1,
      label: { untrusted: false, private: false },
      unguarded: [],
      activity: [],
    };
    const forwarded = shapeOutgoing(scanned, "anthropic", "w8");
    expect(forwarded.body).toBe(redacted);
    expect(forwarded.masked).toBe(0);
    expect(forwarded.compacted).toBe(0);
  });

  it("does not touch the counts redaction reported", async () => {
    const { seen, fetchUpstream } = recording();
    const handler = createHandler(DEFAULT_ROUTES, fetchUpstream as never);
    await handler(post(conversation(), "w9"));
    // Shaping never reports a redaction hit: the two are separate counts, and
    // a stub is not a masked value.
    expect(noCounts.masked).toBe(0);
    expect(sentText(seen)).toContain("[masked to save context:");
  });
});

describe("shapeRequest as the path uses it", () => {
  it("reports what it did, so the journal can name it", () => {
    const result = shapeRequest("anthropic", conversation());
    expect(result?.masked).toBe(1);
    expect(result?.savedChars).toBeGreaterThan(0);
    expect(result?.compacted).toBe(0);
  });
});
