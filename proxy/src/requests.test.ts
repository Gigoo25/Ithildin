import { describe, expect, it } from "bun:test";
import {
  BODY_BYTES_MAX,
  KEEP_DEFAULT,
  KEEP_MAX,
  keepFromSettings,
  SentRequests,
} from "./requests.ts";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";

describe("how many requests to keep", () => {
  it("reads a whole number, within a limit, and falls back to the default", () => {
    expect(keepFromSettings(undefined)).toBe(KEEP_DEFAULT);
    expect(keepFromSettings("5")).toBe(5);
    expect(keepFromSettings("0")).toBe(0);
    expect(keepFromSettings("100000")).toBe(KEEP_MAX);
    for (const bad of ["", "-1", "2.5", "many", "1e3"])
      expect(keepFromSettings(bad)).toBe(KEEP_DEFAULT);
  });
});

describe("sent requests", () => {
  it("keeps the newest, newest first, without their text in the list", () => {
    let time = 100;
    const kept = new SentRequests(2, () => time++);
    kept.record({ route: "anthropic", endpoint: "/v1/messages", session: "0123456789abcdef" }, '{"a":1}');
    kept.record({ route: "anthropic", endpoint: "/v1/messages", session: undefined }, '{"a":2}');
    kept.record({ route: "openai-codex", endpoint: "/responses", session: undefined }, '{"a":3}');
    const { requests, keep, enabled } = kept.list();
    expect([keep, enabled]).toEqual([2, true]);
    expect(requests.map((request) => request.id)).toEqual([3, 2]);
    expect(requests[0]).toMatchObject({ route: "openai-codex", endpoint: "/responses", size: 7 });
    expect(requests[0]).not.toHaveProperty("text");
    expect(requests[0]).not.toHaveProperty("session");
    expect(kept.text(1)).toBeUndefined();
  });

  it("shortens a session id, lays out JSON for reading, and passes other text as it is", () => {
    const kept = new SentRequests(5);
    kept.record({ route: "anthropic", endpoint: "/", session: "0123456789abcdef" }, '{"a":[1,2]}');
    kept.record({ route: "anthropic", endpoint: "/", session: undefined }, "not json {");
    expect(kept.list().requests[1]!.session).toBe("01234567");
    expect(kept.text(1)).toBe('{\n "a": [\n  1,\n  2\n ]\n}');
    expect(kept.text(2)).toBe("not json {");
  });

  it("cuts a body over the limit, and says so", () => {
    const kept = new SentRequests(1);
    kept.record({ route: "anthropic", endpoint: "/", session: undefined }, "x".repeat(BODY_BYTES_MAX + 10));
    expect(kept.list().requests[0]).toMatchObject({ size: BODY_BYTES_MAX + 10, cut: true });
    expect(kept.text(1)!.length).toBe(BODY_BYTES_MAX);
  });

  it("keeps nothing when it is off", () => {
    const kept = new SentRequests(0);
    kept.record({ route: "anthropic", endpoint: "/", session: undefined }, "{}");
    expect(kept.list()).toEqual({ enabled: false, keep: 0, requests: [] });
  });
});

describe("the dashboard's request pages", () => {
  const upstream = (() =>
    Promise.resolve(Response.json({ content: [] }))) as unknown as typeof fetch;
  const get = (handler: ReturnType<typeof createHandler>, path: string, host = "127.0.0.1") =>
    handler(new Request(`http://${host}${path}`));

  it("lists what was sent after masking, and shows one request", async () => {
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    await handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-ithildin-session": "request-pages" },
        body: JSON.stringify({
          messages: [{ role: "user", content: "mail jane.doe@acme-corp.com" }],
        }),
      }),
    );
    const list = (await (await get(handler, "/dashboard/requests")).json()) as {
      requests: Array<{ id: number; route: string; endpoint: string; session: string }>;
    };
    expect(list.requests).toHaveLength(1);
    expect(list.requests[0]).toMatchObject({ route: "anthropic", endpoint: "/v1/messages" });
    expect(list.requests[0]!.session).toBe("request-");
    const shown = await get(handler, `/dashboard/request?id=${list.requests[0]!.id}`);
    expect(shown.headers.get("content-type")).toContain("text/plain");
    const text = await shown.text();
    expect(text).toContain('"role": "user"');
    expect(text).not.toContain("jane.doe@acme-corp.com");
  });

  it("answers 404 for a missing request, and 403 for a name that is not local", async () => {
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    expect((await get(handler, "/dashboard/request?id=9")).status).toBe(404);
    expect((await get(handler, "/dashboard/request")).status).toBe(404);
    for (const path of ["/dashboard/requests", "/dashboard/request?id=1"])
      expect((await get(handler, path, "evil.example")).status).toBe(403);
  });
});
