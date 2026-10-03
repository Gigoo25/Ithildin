// The request and reply paths refuse whatever they cannot check: nothing
// unscanned goes out, and no tool call a guard did not see comes back.
import { beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initEngine } from "./redact.ts";
import {
  createHandler,
  DEFAULT_ROUTES,
  formatForPath,
  JSON_DEPTH_MAX,
  jsonDepth,
  loadRoutes,
  readOptions,
  REPLY_BYTES_MAX,
  REQUEST_BYTES_MAX,
  start,
  upstreamUrl,
} from "./server.ts";

beforeAll(() => initEngine());

type Call = { url: string; init: RequestInit };

function upstream(reply: () => Response | Promise<Response>): {
  fetch: typeof fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fn = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return reply();
  }) as unknown as typeof fetch;
  return { fetch: fn, calls };
}

function post(
  path: string,
  body: string,
  headers: Record<string, string> = { "content-type": "application/json" },
): Request {
  return new Request(`http://127.0.0.1/${path}`, { method: "POST", headers, body });
}

const messages = JSON.stringify({ messages: [{ role: "user", content: "hi" }] });

async function refusal(response: Response): Promise<{ status: number; message: string }> {
  const body = (await response.json()) as { error: { type: string; message: string } };
  expect(body.error.type).toBe("ithildin_error");
  return { status: response.status, message: body.error.message };
}

describe("requests the proxy refuses", () => {
  it("refuses unknown routes and never calls upstream", async () => {
    const up = upstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    expect((await refusal(await handler(post("nowhere/v1/messages", messages)))).status).toBe(404);
    expect((await refusal(await handler(new Request("http://127.0.0.1/")))).status).toBe(404);
    expect(up.calls).toHaveLength(0);
  });

  it("refuses bodies it cannot scan", async () => {
    const up = upstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const cases: Array<[Request, number]> = [
      [
        post("anthropic/v1/messages", messages, {
          "content-type": "application/json",
          "content-encoding": "gzip",
        }),
        415,
      ],
      [post("anthropic/v1/messages", "{not json", { "content-type": "application/json" }), 400],
      [post("anthropic/v1/messages", "[1,2]"), 400],
      [post("anthropic/v1/messages", '"a string"'), 400],
      [post("anthropic/v1/messages", "null"), 400],
      [post("anthropic/v1/other", "plain text", { "content-type": "text/plain" }), 415],
      [post("anthropic/v1/other", "plain text", {}), 415],
    ];
    for (const [request, status] of cases)
      expect((await refusal(await handler(request))).status).toBe(status);
    expect(up.calls).toHaveLength(0);
  });

  it("refuses bodies over the size limit, declared or actual", async () => {
    const up = upstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const declared = post("anthropic/v1/messages", messages, {
      "content-type": "application/json",
      "content-length": String(REQUEST_BYTES_MAX + 1),
    });
    expect((await refusal(await handler(declared))).status).toBe(413);
    const big = JSON.stringify({
      messages: [{ role: "user", content: "x".repeat(REQUEST_BYTES_MAX) }],
    });
    expect((await refusal(await handler(post("anthropic/v1/messages", big)))).status).toBe(413);
    // Chunked, with no length declared: it stops reading past the cap.
    let pulled = 0;
    const chunk = new Uint8Array(1024 * 1024).fill(32);
    const chunked = new Request("http://127.0.0.1/anthropic/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: new ReadableStream({
        pull(controller) {
          pulled++;
          controller.enqueue(chunk);
        },
      }),
    });
    expect((await refusal(await handler(chunked))).status).toBe(413);
    expect(pulled * chunk.byteLength).toBeLessThan(REQUEST_BYTES_MAX * 2);
    expect(up.calls).toHaveLength(0);
  });

  it("stops reading a JSON reply past the size limit", async () => {
    let pulled = 0;
    const chunk = new Uint8Array(1024 * 1024).fill(32);
    const endless = () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            pulled++;
            controller.enqueue(chunk);
          },
        }),
        { headers: { "content-type": "application/json" } },
      );
    const handler = createHandler(DEFAULT_ROUTES, upstream(endless).fetch);
    const model = await handler(post("anthropic/v1/messages", messages));
    const unread = await handler(new Request("http://127.0.0.1/anthropic/v1/models"));
    for (const reply of [model, unread]) {
      const refused = await refusal(reply);
      expect(refused.status).toBe(502);
      expect(refused.message).toContain(`over ${REPLY_BYTES_MAX} bytes`);
    }
    expect(pulled * chunk.byteLength).toBeLessThan(REPLY_BYTES_MAX * 3);
  });

  it("refuses nesting past the depth limit before scanning", async () => {
    const up = upstream(() => Response.json({}));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    let deep: unknown = "x";
    for (let i = 0; i < 20_000; i++) deep = [deep];
    const body = JSON.stringify({ messages: [{ role: "user", content: deep }] });
    const { status, message } = await refusal(await handler(post("anthropic/v1/messages", body)));
    expect(status).toBe(400);
    expect(message).toContain(String(JSON_DEPTH_MAX));
    expect(up.calls).toHaveLength(0);
  });

  it("forwards a body with no content type when it is a JSON object on a model path", async () => {
    const up = upstream(() => Response.json({ content: [] }));
    const handler = createHandler(DEFAULT_ROUTES, up.fetch);
    const response = await handler(post("anthropic/v1/messages", messages, {}));
    expect(response.status).toBe(200);
    expect(up.calls).toHaveLength(1);
  });

  it("reports an unreachable upstream as 502", async () => {
    const handler = createHandler(DEFAULT_ROUTES, (async () => {
      throw new Error("connect refused");
    }) as unknown as typeof fetch);
    const { status, message } = await refusal(
      await handler(post("anthropic/v1/messages", messages)),
    );
    expect(status).toBe(502);
    expect(message).toContain("connect refused");
  });
});

describe("replies the proxy refuses", () => {
  const send = async (reply: () => Response) =>
    createHandler(
      DEFAULT_ROUTES,
      upstream(reply).fetch,
    )(post("opencode-go/chat/completions", messages));

  it("refuses a successful reply it cannot parse or rewrite", async () => {
    expect(
      (
        await refusal(
          await send(
            () => new Response("{oops", { headers: { "content-type": "application/json" } }),
          ),
        )
      ).status,
    ).toBe(502);
    expect((await refusal(await send(() => Response.json([1])))).status).toBe(502);
    // The Chat rewriter throws on a null choice: nothing half-rewritten goes out.
    expect((await refusal(await send(() => Response.json({ choices: [null] })))).status).toBe(502);
  });

  it("refuses a successful reply of a type it does not read", async () => {
    const { status, message } = await refusal(
      await send(
        () =>
          new Response("<p>hi</p>", { headers: { "content-type": "text/html; charset=utf-8" } }),
      ),
    );
    expect(status).toBe(502);
    expect(message).toContain("text/html");
    // Newline-delimited JSON takes the JSON path, and fails its parse.
    expect(
      (
        await refusal(
          await send(
            () =>
              new Response('{"a":1}\n{"b":2}\n', {
                headers: { "content-type": "application/x-ndjson" },
              }),
          ),
        )
      ).status,
    ).toBe(502);
    expect((await refusal(await send(() => new Response("data")))).status).toBe(502);
  });

  it("passes provider errors and non-model routes through unchanged", async () => {
    const error = await send(
      () => new Response("overloaded", { status: 529, headers: { "content-type": "text/plain" } }),
    );
    expect(error.status).toBe(529);
    expect(await error.text()).toBe("overloaded");
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => new Response("models", { headers: { "content-type": "text/plain" } })).fetch,
    );
    const models = await handler(new Request("http://127.0.0.1/anthropic/v1/models"));
    expect(await models.text()).toBe("models");
  });

  it("refuses a model reply on a path it does not read, and passes other JSON", async () => {
    const via = (reply: () => Response) =>
      createHandler(DEFAULT_ROUTES, upstream(reply).fetch)(post("anthropic/api/chat", messages));
    const json = (body: unknown) => () => Response.json(body);
    const tool = { message: { tool_calls: [{ function: { name: "bash", arguments: {} } }] } };
    expect((await refusal(await via(json(tool)))).status).toBe(502);
    expect((await refusal(await via(json({ choices: [] })))).status).toBe(502);
    const stream = () =>
      new Response("{}\n", { headers: { "content-type": "application/x-ndjson" } });
    expect((await refusal(await via(stream))).status).toBe(502);
    const list = await via(json({ data: [{ id: "m" }] }));
    expect(await list.json()).toEqual({ data: [{ id: "m" }] });
    expect(
      await (
        await via(
          () => new Response("not json {", { headers: { "content-type": "application/json" } }),
        )
      ).text(),
    ).toBe("not json {");
  });

  it("passes SSE comments and bare lines through a rewritten stream", async () => {
    const text = ': keepalive\n\nevent: ping\ndata: {"type":"ping"}\n\n';
    const handler = createHandler(
      DEFAULT_ROUTES,
      upstream(() => new Response(text, { headers: { "content-type": "text/event-stream" } }))
        .fetch,
    );
    const out = await (await handler(post("anthropic/v1/messages", messages))).text();
    expect(out).toContain(": keepalive");
    expect(out).toContain('"ping"');
  });
});

describe("health and routing", () => {
  it("reports health with the route names", async () => {
    const handler = createHandler(DEFAULT_ROUTES, upstream(() => Response.json({})).fetch);
    const body = (await (
      await handler(new Request("http://127.0.0.1/_ithildin/health"))
    ).json()) as {
      ok: boolean;
      routes: string[];
      badge: string;
    };
    expect(body.ok).toBe(true);
    expect(body.routes).toEqual(Object.keys(DEFAULT_ROUTES));
    expect(body.badge).toBe("ITHILDIN ON");
  });

  it("maps paths to formats", () => {
    expect(formatForPath("/v1/messages")).toBe("anthropic");
    expect(formatForPath("/v1/messages/count_tokens")).toBe("anthropic");
    expect(formatForPath("/v1/chat/completions")).toBe("chat");
    expect(formatForPath("/v1/responses")).toBe("responses");
    expect(formatForPath("/v1/models")).toBeUndefined();
  });

  it("rewrites the first matching prefix only, and trims the upstream's slash", () => {
    expect(upstreamUrl({ upstream: "https://up.example/base/" }, "/v1/x", "?a=1")).toBe(
      "https://up.example/base/v1/x?a=1",
    );
    expect(
      upstreamUrl(
        { upstream: "https://up.example", rewrite: { "/chat/": "/v1/chat/", "/c": "/never" } },
        "/chat/completions",
        "",
      ),
    ).toBe("https://up.example/v1/chat/completions");
  });

  it("loads plain-string and object routes from a file", () => {
    const dir = mkdtempSync(join(tmpdir(), "ithildin-routes-"));
    try {
      const file = join(dir, "routes.json");
      writeFileSync(
        file,
        JSON.stringify({
          local: "http://127.0.0.1:4000",
          other: { upstream: "https://up.example", rewrite: { "/a": "/b" } },
        }),
      );
      const routes = loadRoutes(file);
      expect(routes.local).toEqual({ upstream: "http://127.0.0.1:4000" });
      expect(routes.other!.rewrite).toEqual({ "/a": "/b" });
      expect(routes.anthropic).toEqual(DEFAULT_ROUTES.anthropic!);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("jsonDepth", () => {
  it("counts containers, not scalars, and stops past the limit", () => {
    expect(jsonDepth("x", 10)).toBe(0);
    expect(jsonDepth({}, 10)).toBe(1);
    expect(jsonDepth({ a: [{ b: 1 }] }, 10)).toBe(3);
    let deep: unknown = 1;
    for (let i = 0; i < 1000; i++) deep = [deep];
    expect(jsonDepth(deep, 5)).toBe(6);
  });
});

const REDACTORS_PASSING = {
  request: (_format: unknown, parsed: Record<string, unknown>) => ({
    body: parsed,
    hits: 0,
    counts: { masked: 0, files: 0, lines: 0, images: 0 },
    tags: new Set<string>(),
    label: { untrusted: false, private: false },
    unguarded: [],
  }),
  query: (search: string) => ({ search, hits: 0, values: 0 }),
  path: (path: string) => ({ path, hits: 0, values: 0 }),
};

describe("scan failures", () => {
  it("refuses when any redaction throws, and never calls upstream", async () => {
    const up = upstream(() => Response.json({}));
    const fail = () => {
      throw new TypeError("boom");
    };
    const body = createHandler(DEFAULT_ROUTES, up.fetch, {
      request: fail,
      query: (search) => ({ search, hits: 0, values: 0 }),
      path: (path) => ({ path, hits: 0, values: 0 }),
      headers: () => ({ hits: 0, values: 0 }),
    });
    const first = await refusal(await body(post("anthropic/v1/messages", messages)));
    expect(first.status).toBe(500);
    expect(first.message).toContain("TypeError");
    const query = createHandler(DEFAULT_ROUTES, up.fetch, {
      request: (_format, parsed) => ({
        body: parsed,
        hits: 0,
        counts: { masked: 0, files: 0, lines: 0, images: 0 },
        tags: new Set(),
        label: { untrusted: false, private: false },
        unguarded: [],
      }),
      query: fail,
      path: (path) => ({ path, hits: 0, values: 0 }),
      headers: () => ({ hits: 0, values: 0 }),
    });
    expect(
      (await refusal(await query(new Request("http://127.0.0.1/anthropic/v1/models?q=1")))).status,
    ).toBe(500);
    const path = createHandler(DEFAULT_ROUTES, up.fetch, {
      ...REDACTORS_PASSING,
      headers: () => ({ hits: 0, values: 0 }),
      path: fail,
    });
    expect(
      (await refusal(await path(new Request("http://127.0.0.1/anthropic/v1/models")))).status,
    ).toBe(500);
    const headers = createHandler(DEFAULT_ROUTES, up.fetch, {
      ...REDACTORS_PASSING,
      headers: fail,
    });
    expect(
      (await refusal(await headers(new Request("http://127.0.0.1/anthropic/v1/models")))).status,
    ).toBe(500);
    expect(up.calls).toHaveLength(0);
  });
});

describe("startup", () => {
  const none = () => false;

  it("reads flags before environment before defaults", () => {
    expect(readOptions([], {}, none)).toEqual({ port: 18733, routesFile: undefined });
    expect(readOptions([], { ITHILDIN_PORT: "9000", ITHILDIN_ROUTES: "/r.json" }, none)).toEqual({
      port: 9000,
      routesFile: "/r.json",
    });
    expect(
      readOptions(
        ["bun", "server.ts", "--port", "9100", "--routes", "/f.json"],
        { ITHILDIN_PORT: "9000" },
        none,
      ),
    ).toEqual({ port: 9100, routesFile: "/f.json" });
    const found = readOptions(
      [],
      { HOME: "/home/test", XDG_CONFIG_HOME: "" },
      (file) => file === "/home/test/.config/ithildin/routes.json",
    );
    expect(found.routesFile).toBe("/home/test/.config/ithildin/routes.json");
    expect(
      readOptions([], { XDG_CONFIG_HOME: "/xdg" }, (file) => file.startsWith("/xdg/")).routesFile,
    ).toBe("/xdg/ithildin/routes.json");
  });

  it("stops on a port that is not a whole number in range", () => {
    for (const bad of ["0", "65536", "80a", "", "-1", "1.5"])
      expect(() => readOptions(["--port", bad], {}, none)).toThrow(/invalid port/);
  });

  it("serves health on a free port and drains", async () => {
    const { server, drain } = start(
      { port: 0, routesFile: undefined },
      upstream(() => Response.json({})).fetch,
    );
    try {
      const body = (await (
        await fetch(`http://127.0.0.1:${server.port}/_ithildin/health`)
      ).json()) as { ok: boolean };
      expect(body.ok).toBe(true);
    } finally {
      await drain();
    }
  });
});
