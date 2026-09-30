import { beforeAll, describe, expect, it, spyOn } from "bun:test";
import { initEngine, redactQuery, redactRequest } from "./redact.ts";
import { createHandler, DEFAULT_ROUTES, type Redactors, selfTestCli, start } from "./server.ts";
import { selfTest, syntheticValues } from "./selftest.ts";

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
  }),
  query: redactQuery,
};
const broken: Redactors = {
  request: () => {
    throw new TypeError("broken");
  },
  query: redactQuery,
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
      ]),
    );
    expect(JSON.stringify(report)).not.toMatch(/AKIA|ghp_|@/);
  });

  it("fails when the scanner throws", async () => {
    const report = await selfTest((upstream) => createHandler(DEFAULT_ROUTES, upstream, broken));
    expect(report.failures).toEqual([
      "request not forwarded (status 500)",
      "tool call not swapped back",
    ]);
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
    expect((await handler(new Request("http://127.0.0.1/_ithildin/health"))).status).toBe(503);
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
