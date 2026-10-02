import { beforeAll, describe, expect, it, spyOn } from "bun:test";
import { initEngine, redactHeaders, redactQuery, redactRequest } from "./redact.ts";
import {
  createHandler,
  DEFAULT_ROUTES,
  formatForPath,
  type Redactors,
  selfTestCli,
  start,
} from "./server.ts";
import { selfTest, syntheticValues, WIRES } from "./selftest.ts";

beforeAll(() => initEngine());

const refuse = (() => Response.json({})) as unknown as typeof fetch;
const post = (body: unknown) =>
  new Request("http://127.0.0.1/anthropic/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
// Scanners that do nothing, and that throw: the self-test must catch both.
const leaking: Redactors = {
  request: (_format, body) => ({
    body,
    hits: 0,
    counts: { masked: 0, files: 0, lines: 0, images: 0 },
    tags: new Set(),
    untrusted: false,
    unguarded: [],
  }),
  query: redactQuery,
  headers: redactHeaders,
};
const broken: Redactors = {
  request: () => {
    throw new TypeError("broken");
  },
  query: redactQuery,
  headers: redactHeaders,
};

describe("self-test", () => {
  it("passes with the real engine, with fresh values each run", async () => {
    const report = await selfTest((upstream) => createHandler(DEFAULT_ROUTES, upstream));
    expect(report).toMatchObject({ ok: true, failures: [] });
    expect(syntheticValues().aws).not.toBe(syntheticValues().aws);
  });

  it("names what leaked when the scanner passes values through, never the value", async () => {
    const report = await selfTest((upstream) => createHandler(DEFAULT_ROUTES, upstream, leaking));
    expect(report.ok).toBe(false);
    expect(report.failures).toEqual(
      expect.arrayContaining([
        "aws reached the provider",
        "token reached the provider",
        "email reached the provider",
        "file reached the provider",
        "image reached the provider",
      ]),
    );
    expect(JSON.stringify(report)).not.toMatch(/AKIA|ghp_|@/);
  });

  it("fails when the scanner throws", async () => {
    const report = await selfTest((upstream) => createHandler(DEFAULT_ROUTES, upstream, broken));
    expect(report.failures).toEqual(
      WIRES.flatMap((wire) => [
        `${wire.name}: request not forwarded (status 500)`,
        `${wire.name} streamed: request not forwarded (status 500)`,
      ]),
    );
  });

  it("names each hold that lets its value through", async () => {
    // Masks the prompt but sends the read file and the image bytes as they were.
    const strings = (value: unknown): string[] =>
      typeof value === "string"
        ? [value]
        : value && typeof value === "object"
          ? Object.values(value).flatMap(strings)
          : [];
    const holed: Redactors = {
      ...leaking,
      request: (format, body, session) => {
        const out = redactRequest(format, body, session);
        const raw = strings(body).filter((text) => /^[a-z]{16,}$/.test(text));
        return { ...out, body: { ...out.body, raw } };
      },
    };
    const report = await selfTest((upstream) => createHandler(DEFAULT_ROUTES, upstream, holed));
    expect(report.failures).toEqual(["file reached the provider", "image reached the provider"]);
  });

  // Masks the request, then hands back the provider's reply with `rewrite`
  // applied to its text: no guard, no stream holding.
  const unguarded =
    (rewrite: (text: string, real: string, standIn: string) => string) =>
    (upstream: typeof fetch) =>
    async (request: Request): Promise<Response> => {
      const format = formatForPath(new URL(request.url).pathname)!;
      const raw = await request.text();
      const sent = JSON.stringify(redactRequest(format, JSON.parse(raw)).body);
      const reply = await upstream("http://upstream", { method: "POST", body: sent });
      const [real, standIn] = [raw, sent].map((text) => /<<([^<>]*)>>/.exec(text)?.[1]);
      // The redirect probe carries no stand-in: its reply goes back as it came.
      if (real === undefined || standIn === undefined) return reply;
      return new Response(rewrite(await reply.text(), real, standIn), reply);
    };
  const labels = WIRES.flatMap((wire) => [wire.name, `${wire.name} streamed`]);
  const UNTRUSTED_SENDS = [
    "anthropic: send after web read not blocked",
    "anthropic streamed: send after web read not blocked",
  ];

  it("names every reply check a proxy that never rewrites replies fails", async () => {
    const report = await selfTest(unguarded((text) => text));
    expect(report.failures).toEqual(
      labels
        .flatMap((label) => [
          `${label}: tool call not swapped back`,
          `${label}: protected change not blocked`,
        ])
        .concat("redirect passed to the client", ...UNTRUSTED_SENDS),
    );
  });

  it("reads a reply that lost a call as unreadable, not as passing", async () => {
    // Drops the egress call from the Anthropic JSON reply.
    const dropped = await selfTest((upstream) =>
      createHandler(DEFAULT_ROUTES, (async (url: string, init?: RequestInit) => {
        const reply = await (await upstream(url, init)).text();
        if (reply.startsWith("{")) {
          const json = JSON.parse(reply) as { content?: unknown[] };
          if (Array.isArray(json.content)) json.content.splice(1, 1);
          return Response.json(json);
        }
        return new Response(reply, { headers: { "content-type": "text/event-stream" } });
      }) as unknown as typeof fetch),
    );
    expect(dropped.failures).toEqual(["anthropic: reply unreadable"]);
  });

  it("names a swap-back that sends the real value to a web host", async () => {
    // Streamed, the stand-in is cut in two, so swapping text as it passes
    // misses it.
    const report = await selfTest(
      unguarded((text, real, standIn) => text.split(standIn).join(real)),
    );
    expect(report.failures).toEqual(
      labels
        .flatMap((label) => [
          label.endsWith("streamed")
            ? `${label}: tool call not swapped back`
            : `${label}: real value sent off the machine`,
          `${label}: protected change not blocked`,
        ])
        .concat("redirect passed to the client", ...UNTRUSTED_SENDS),
    );
  });

  it("reports a handler that throws", async () => {
    const report = await selfTest(() => async () => {
      throw new RangeError("x");
    });
    expect(report.failures).toEqual(["self-test threw RangeError"]);
  });
});

describe("gated handler", () => {
  const request = { messages: [{ role: "user", content: "hi" }] };

  it("refuses model requests until the self-test passes", async () => {
    const handler = createHandler(DEFAULT_ROUTES, refuse, undefined, true);
    const pending = await handler(new Request("http://127.0.0.1/_ithildin/health"));
    expect(pending.status).toBe(503);
    expect(((await pending.json()) as { badge: string }).badge).toBe(
      "ITHILDIN DOWN · self-test pending",
    );
    const before = await handler(post(request));
    expect(before.status).toBe(503);
    expect(((await before.json()) as { error: { message: string } }).error.message).toContain(
      "self-test has not run",
    );
    expect((await handler(new Request("http://127.0.0.1/_ithildin/selftest"))).status).toBe(200);
    expect((await handler(post(request))).status).toBe(200);
    const health = (await (
      await handler(new Request("http://127.0.0.1/_ithildin/health"))
    ).json()) as { selftest: { ok: boolean } };
    expect(health.selftest.ok).toBe(true);
  });

  it("stays closed, and reads as down, after a failed self-test", async () => {
    const handler = createHandler(DEFAULT_ROUTES, refuse, leaking, true);
    expect((await handler(new Request("http://127.0.0.1/_ithildin/selftest"))).status).toBe(503);
    const refused = await handler(post(request));
    expect(refused.status).toBe(503);
    expect(((await refused.json()) as { error: { message: string } }).error.message).toContain(
      "reached the provider",
    );
    const down = await handler(new Request("http://127.0.0.1/_ithildin/health"));
    expect(down.status).toBe(503);
    expect(((await down.json()) as { badge: string }).badge).toMatch(
      /^ITHILDIN DOWN · self-test: anthropic: email got no stand-in \(\+\d+\)$/,
    );
  });

  it("the real engine redacts the same request the gate lets through", () => {
    const { aws } = syntheticValues();
    expect(
      JSON.stringify(
        redactRequest("anthropic", { messages: [{ role: "user", content: aws }] }).body,
      ),
    ).not.toContain(aws);
  });
});

describe("selftest command", () => {
  it("proves the running proxy, and says when none answers", async () => {
    const out: string[] = [];
    const write = spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => {
      out.push(String(chunk));
      return true;
    });
    const { server, drain, proven } = start({ port: 0, routesFile: undefined }, refuse);
    try {
      await proven;
      expect(await selfTestCli(server.port!)).toBe(0);
      expect(out.pop()).toMatch(/^ok: /);
      const failing = (async () =>
        Response.json({
          ok: false,
          at: "",
          ms: 1,
          failures: ["email got no stand-in"],
        })) as unknown as typeof fetch;
      expect(await selfTestCli(1, failing)).toBe(1);
      expect(out.pop()).toBe("FAILED: email got no stand-in\n");
      const down = (async () => {
        throw new Error("connection refused");
      }) as unknown as typeof fetch;
      expect(await selfTestCli(1, down)).toBe(1);
      expect(out.pop()).toContain("not answering on port 1");
    } finally {
      write.mockRestore();
      await drain();
    }
  });
});
