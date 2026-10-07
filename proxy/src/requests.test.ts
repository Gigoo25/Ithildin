import { describe, expect, it } from "bun:test";
import {
  BODY_BYTES_MAX,
  clampToJson,
  KEEP_DEFAULT,
  KEEP_MAX,
  keepFromSettings,
  SentRequests,
} from "./requests.ts";
import { createHandler, DEFAULT_ROUTES, splitVia } from "./server.ts";

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
  it("drops the oldest once the kept text outgrows its budget, keeping the newest", () => {
    const kept = new SentRequests(10, Date.now, 25);
    const context = { route: "anthropic", endpoint: "/v1/messages", session: undefined };
    for (const n of [1, 2, 3]) kept.record(context, `{"n":${n},"pad":"xx"}`);
    // Each is 16 characters: two would be 32, over 25, so only the newest stays.
    expect(kept.list().requests.map((request) => request.id)).toEqual([3]);
    kept.record(context, "x".repeat(40));
    expect(kept.list().requests.map((request) => request.id)).toEqual([4]);
  });

  it("keeps the newest, newest first, without their text in the list", () => {
    let time = 100;
    const kept = new SentRequests(2, () => time++);
    kept.record({ route: "anthropic", endpoint: "/v1/messages", session: undefined }, '{"a":1}');
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
    const at = { route: "anthropic", endpoint: "/", session: undefined };
    kept.record(at, "x".repeat(BODY_BYTES_MAX + 10));
    expect(kept.list().requests[0]).toMatchObject({ size: BODY_BYTES_MAX + 10, cut: true });
    expect(kept.text(1)!.length).toBe(BODY_BYTES_MAX);
  });

  it("keeps a cut body reading as a conversation, and lays it out as JSON", () => {
    const kept = new SentRequests(1);
    // Well past the limit, cut in the middle of the last turn.
    const turn = "x".repeat(BODY_BYTES_MAX);
    const body = JSON.stringify({
      messages: [
        { role: "user", content: "hi" },
        { role: "user", content: turn },
      ],
    });
    kept.record({ route: "anthropic", endpoint: "/", session: undefined }, body + "tail");
    expect(kept.list().requests[0]).toMatchObject({ cut: true });
    // The whole first turn survives, and the text is laid out for reading.
    expect(kept.text(1)).toContain('"role": "user"');
    expect(kept.text(1)).toContain('"content": "hi"');
  });

  it("keeps nothing when it is off", () => {
    const kept = new SentRequests(0);
    kept.record({ route: "anthropic", endpoint: "/", session: undefined }, "{}");
    expect(kept.list()).toEqual({ enabled: false, keep: 0, requests: [] });
  });
});

describe("a body too long to keep whole", () => {
  // Cut `kept`, plus filler that falls away past the cut.
  const at = (kept: string, filler = "XXXX") => clampToJson(kept + filler, kept.length);

  it("closes every bracket the cut left open", () => {
    expect(at('{"a":1,')).toBe('{"a":1}');
    expect(at('{"a":[1,2,')).toBe('{"a":[1,2]}');
    expect(at('{"a":{"b":2}')).toBe('{"a":{"b":2}}');
    expect(at('[{"a":1}')).toBe('[{"a":1}]');
    expect(at('[{"a":1},')).toBe('[{"a":1}]');
    expect(at('{"a":{"b":[1,{"c":2}')).toBe('{"a":{"b":[1,{"c":2}]}}');
  });

  it("keeps the whole values and drops only the partial tail", () => {
    expect(JSON.parse(at('{"messages":[{"role":"user","c":"hi"}],'))).toEqual({
      messages: [{ role: "user", c: "hi" }],
    });
  });

  it("never returns text the view cannot parse", () => {
    for (const kept of [
      '{"a":"unterminated',
      '{"a":"back\\',
      '{"a":12345',
      '{"a":12.5e',
      '{"a":true,"b":fa',
      '{"a":null,"b":[1,[2,[3,',
      '[{"a":{"b":[{"c":1},{"d"',
      '{"a":"escaped \\" quote insid',
      '{"deep":{"deeper":{"deepest":[1,2,',
      '{"a":-12.5e+3 partial',
      '{"a":[[[[[[[[1]]]]]],',
      '{"a":"}]\\" {,"}',
      '{"a":{"b":"c,]}","d":',
    ])
      expect(() => JSON.parse(at(kept))).not.toThrow();
  });

  it("does not read a bracket or comma inside a string as structure", () => {
    expect(JSON.parse(at('{"a":"}]\\" {, ","b"'))).toEqual({ a: '}]" {, ' });
  });

  it("drops a number the cut ran into rather than keeping half of it", () => {
    expect(JSON.parse(at('{"a":12345'))).toEqual({});
    expect(JSON.parse(at('{"a":12.5e'))).toEqual({});
    expect(JSON.parse(at('{"n":1,"a":12345'))).toEqual({ n: 1 });
  });

  it("keeps the text of a string the cut ran into, closed", () => {
    // A long tool output is one string; dropping it whole would lose the turn
    // it is in, so the text read so far is kept and the string closed.
    const long = "A".repeat(1000);
    expect(JSON.parse(at(`{"messages":[{"content":"${long}`))).toEqual({
      messages: [{ content: long }],
    });
    // A backslash at the cut would escape the closing quote, so that one is
    // left out instead.
    expect(JSON.parse(at('{"a":"back\\'))).toEqual({});
    // The text is unchanged: no escape is invented and none is dropped.
    const quoted = at('{"a":"say \\"hi\\" now');
    expect(JSON.parse(quoted).a).toBe('say "hi" now');
  });

  it("cuts plain text and a mismatched prefix as they are", () => {
    expect(clampToJson("xxxxxxxxxxxx", 5)).toBe("xxxxx");
    expect(clampToJson('{"a":[} tail', 7)).toBe('{"a":[}');
  });

  it("leaves a body at or under the limit alone", () => {
    expect(clampToJson('{"a":1}', 100)).toBe('{"a":1}');
    expect(clampToJson('{"a":1}', 7)).toBe('{"a":1}');
  });
});

describe("a route that goes through a proxy in front of the provider", () => {
  const VIA = "http://127.0.0.1:8787";
  const via = (upstream: string, rewrite?: Record<string, string>) => ({
    upstream,
    via: VIA,
    ...(rewrite ? { rewrite } : {}),
  });

  it("splits the target into the endpoint and the upstream behind it", () => {
    expect(splitVia(via("https://api.anthropic.com"), "/v1/messages", "")).toEqual({
      url: VIA + "/v1/messages",
      base: "https://api.anthropic.com",
    });
    // count_tokens is its own endpoint, not a /v1/messages with a tail.
    expect(splitVia(via("https://api.anthropic.com"), "/v1/messages/count_tokens", "")?.url).toBe(
      VIA + "/v1/messages/count_tokens",
    );
    // A base with a path of its own keeps it, and gives up only the endpoint.
    expect(splitVia(via("https://opencode.ai/inference/go/openai"), "/v1/responses", "")).toEqual({
      url: VIA + "/v1/responses",
      base: "https://opencode.ai/inference/go/openai",
    });
    expect(splitVia(via("https://opencode.ai/inference/anthropic"), "/v1/messages", "")?.base).toBe(
      "https://opencode.ai/inference/anthropic",
    );
    expect(splitVia(via("https://api.githubcopilot.com"), "/chat/completions", "")?.url).toBe(
      VIA + "/chat/completions",
    );
    // The query belongs to the request, not to the base.
    expect(splitVia(via("https://api.anthropic.com"), "/v1/messages", "?beta=true")).toEqual({
      url: VIA + "/v1/messages?beta=true",
      base: "https://api.anthropic.com",
    });
    // A trailing slash on the via host does not double up.
    expect(
      splitVia({ upstream: "https://api.anthropic.com", via: VIA + "/" }, "/v1/messages", ""),
    ).toEqual({ url: VIA + "/v1/messages", base: "https://api.anthropic.com" });
  });

  it("rewrites before it splits, so the base is the upstream really meant", () => {
    const route = via("https://opencode.ai/zen/go", {
      "/chat/": "/v1/chat/",
      "/responses": "/v1/responses",
    });
    expect(splitVia(route, "/chat/completions", "")).toEqual({
      url: VIA + "/v1/chat/completions",
      base: "https://opencode.ai/zen/go",
    });
    expect(splitVia(route, "/responses", "")).toEqual({
      url: VIA + "/v1/responses",
      base: "https://opencode.ai/zen/go",
    });
    // Copilot's rewrite leaves /chat/completions, which Headroom serves.
    expect(
      splitVia(
        via("https://api.githubcopilot.com", { "/v1/chat/": "/chat/" }),
        "/v1/chat/completions",
        "",
      ),
    ).toEqual({ url: VIA + "/chat/completions", base: "https://api.githubcopilot.com" });
  });

  it("serves a path a rewrite left unrecognisable, and says which one", () => {
    // Copilot's rewrite leaves /responses, which a via host does not serve. The
    // endpoint for the format goes on the path and the real one rides along.
    const copilot = via("https://api.githubcopilot.com", { "/v1/responses": "/responses" });
    expect(splitVia(copilot, "/v1/responses", "", "responses")).toEqual({
      url: VIA + "/v1/responses",
      base: "https://api.githubcopilot.com",
      original: "/responses",
    });
    // A base with a path of its own keeps it, and the split is at the slash
    // after the host: a trailing one would double the path the host builds.
    expect(
      splitVia(
        via("https://opencode.ai/inference/go/openai", { "/responses": "/responses" }),
        "/responses",
        "",
        "responses",
      ),
    ).toEqual({
      url: VIA + "/v1/responses",
      base: "https://opencode.ai/inference/go/openai",
      original: "/responses",
    });
    // Chat and anthropic fall back the same way.
    expect(
      splitVia(via("https://x.example", { "/c": "/copilot" }), "/c/completions", "", "chat"),
    ).toMatchObject({
      url: VIA + "/v1/chat/completions",
      base: "https://x.example",
      original: "/copilot/completions",
    });
    expect(
      splitVia(via("https://x.example", { "/m": "/m2" }), "/m", "", "anthropic"),
    ).toMatchObject({ url: VIA + "/v1/messages", original: "/m2" });
    // A tail that is itself a known endpoint takes the direct way, with no
    // override: /chat/completions needs none.
    expect(
      splitVia(via("https://x.example", { "/c": "/chat" }), "/c/completions", "", "chat"),
    ).toEqual({ url: VIA + "/chat/completions", base: "https://x.example" });
    // With no format to go on, there is nothing to serve it as: refused.
    expect(splitVia(via("https://x.example", { "/r": "/responses" }), "/r", "")).toBeUndefined();
  });

  it("refuses a path a via host would not recognise, rather than guessing", () => {
    // Gemini is left alone, and anything else the proxy cannot serve.
    expect(splitVia(via("https://generativelanguage.googleapis.com"), "/v1beta/models/x", "")).toBe(
      undefined,
    );
    expect(splitVia(via("https://api.anthropic.com"), "/v1/complete", "")).toBe(undefined);
    // A route with no via is not split at all.
    expect(splitVia({ upstream: "https://api.anthropic.com" }, "/v1/messages", "")).toBe(undefined);
  });

  it("sends the header and refuses the rest, and nothing else changes", async () => {
    const seen: Array<{ url: string; base: string | null; auth: string | null }> = [];
    const handler = createHandler({ anthropic: via("https://api.anthropic.com") }, (async (
      url: string,
      init: RequestInit,
    ) => {
      const headers = new Headers(init.headers);
      seen.push({
        url,
        base: headers.get("x-headroom-base-url"),
        auth: headers.get("x-api-key"),
      });
      return Response.json({ content: [] });
    }) as unknown as typeof fetch);
    const send = (path: string, extra: Record<string, string> = {}) =>
      handler(
        new Request(`http://127.0.0.1/anthropic${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-api-key": "sk-ant-test",
            // A client trying to name its own upstream.
            "x-headroom-base-url": "https://evil.example",
            ...extra,
          },
          body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
        }),
      );
    expect((await send("/v1/messages")).status).toBe(200);
    expect(seen[0]).toEqual({
      url: VIA + "/v1/messages",
      base: "https://api.anthropic.com",
      auth: "sk-ant-test",
    });
    // A path with no endpoint to split is refused, and never sent on.
    const refused = await send("/v1/unknown");
    expect(refused.status).toBe(502);
    expect(await refused.text()).toContain("cannot serve");
    expect(seen).toHaveLength(1);
  });

  it("leaves a route without via exactly as it was", async () => {
    let at = "";
    const handler = createHandler({ anthropic: { upstream: "https://api.anthropic.com" } }, (async (
      url: string,
    ) => {
      at = url;
      return Response.json({ content: [] });
    }) as unknown as typeof fetch);
    const response = await handler(
      new Request("http://127.0.0.1/anthropic/v1/messages?beta=1", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": "sk-ant-test" },
        body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
      }),
    );
    expect(response.status).toBe(200);
    expect(at).toBe("https://api.anthropic.com/v1/messages?beta=1");
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

describe("each session's latest turn", () => {
  it("is kept however busy the others are, and side requests are not", () => {
    const kept = new SentRequests(2);
    const at = (session: string) => ({ route: "anthropic", endpoint: "/", session });
    kept.record(at("quiet-session"), '{"turn":1}');
    kept.record(at("quiet-session"), '{"title":1}', false);
    for (let index = 0; index < 5; index++) kept.record(at("busy-session"), `{"n":${index}}`);
    const list = kept.list().requests;
    expect(list.map((sent) => [sent.session, sent.main])).toEqual([
      ["busy-ses", true],
      ["quiet-se", true],
    ]);
    expect(kept.text(list[1]!.id)).toBe('{\n "turn": 1\n}');
  });
});
