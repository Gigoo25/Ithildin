import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setRuntimeInventory } from "../engine/lib/rules.ts";
import { initEngine } from "./redact.ts";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";
import {
  findWatched,
  type KnownValue,
  knownValues,
  MIN_KNOWN_CHARS,
  MIN_TERM_CHARS,
  parseWatchPolicy,
  TERMS_MAX,
  watchPolicy,
} from "./watch.ts";

const saved = process.env.ITHILDIN_CONFIG;
let dir = "";
let config = "";
let tick = 1_000;

// The watch section as the config file holds it. Each write moves the mtime,
// so the policy is read again.
function setWatch(watch: unknown): void {
  writeFileSync(config, JSON.stringify(watch === undefined ? {} : { watch }));
  tick += 10;
  utimesSync(config, tick, tick);
}

beforeAll(() => {
  initEngine();
  dir = mkdtempSync(join(tmpdir(), "ithildin-watch-"));
  config = join(dir, "config.json");
  process.env.ITHILDIN_CONFIG = config;
});

afterAll(() => {
  if (saved === undefined) delete process.env.ITHILDIN_CONFIG;
  else process.env.ITHILDIN_CONFIG = saved;
  rmSync(dir, { recursive: true, force: true });
});

const found = (terms: string[], body: unknown, path = "/", search = "", known: KnownValue[] = []) =>
  findWatched({ terms }, known, { body, path, search });
const messages = (content: unknown) => ({ messages: [{ role: "user", content }] });
const word = (literal: string, caseSensitive = false, token = true): KnownValue => ({
  literal,
  caseSensitive,
  token,
});

describe("parsing the watch section", () => {
  it("reads terms and an action, and defaults to flagging", () => {
    expect(parseWatchPolicy(undefined)).toEqual({
      terms: [],
      action: "flag",
      known: true,
      problems: [],
    });
    expect(parseWatchPolicy({ watch: { terms: ["acme-lab", "Falcon X"] } })).toEqual({
      terms: ["acme-lab", "Falcon X"],
      action: "flag",
      known: true,
      problems: [],
    });
    expect(parseWatchPolicy({ watch: { terms: ["acme-lab"], action: "block" } }).action).toBe(
      "block",
    );
  });

  it("drops bad entries with a reason, and keeps the good ones", () => {
    const parsed = parseWatchPolicy({
      watch: { terms: ["ok-term", "ab", 7, "OK-TERM"], action: "stop", known: "yes", extra: 1 },
    });
    expect(parsed.terms).toEqual(["ok-term"]);
    expect(parsed.action).toBe("flag");
    expect(parsed.problems).toEqual([
      `"watch.extra" is not a watch setting`,
      `"watch.action" must be "flag" or "block"`,
      `"watch.known" must be true or false`,
      `"watch.terms": an entry is under ${MIN_TERM_CHARS} characters`,
      `"watch.terms" must be a string array`,
    ]);
  });

  it("rejects a section or a list of the wrong type, and caps the list", () => {
    expect(parseWatchPolicy({ watch: [] }).problems).toEqual([`"watch" must be an object`]);
    expect(parseWatchPolicy({ watch: "acme" }).problems).toEqual([`"watch" must be an object`]);
    expect(parseWatchPolicy({ watch: { terms: "acme" } }).problems).toEqual([
      `"watch.terms" must be a string array`,
    ]);
    const many = Array.from({ length: TERMS_MAX + 3 }, (_, index) => `term-${index}`);
    const capped = parseWatchPolicy({ watch: { terms: many } });
    expect(capped.terms).toHaveLength(TERMS_MAX);
    expect(capped.problems).toHaveLength(1);
  });
});

describe("finding watched strings", () => {
  it("finds a term whatever its case, and says where in the body", () => {
    const hits = found(["Acme-Lab"], messages([{ type: "text", text: "see the ACME-LAB wiki" }]));
    expect(hits).toEqual([
      { value: "Acme-Lab", source: "watch", where: "messages[0].content[0].text" },
    ]);
  });

  it("finds a term inside a longer word, as plain text", () => {
    expect(found(["acme"], messages("acmeville"))).toHaveLength(1);
  });

  it("reports each place, up to a few per term", () => {
    const body = {
      messages: Array.from({ length: 6 }, () => ({ role: "user", content: "acme-lab" })),
    };
    expect(found(["acme-lab"], body).map((hit) => hit.where)).toEqual([
      "messages[0].content",
      "messages[1].content",
      "messages[2].content",
    ]);
  });

  it("finds a term with quotes or a backslash, in a nested block, and in non-ASCII text", () => {
    expect(found(['say "hi"\\now'], messages('say "hi"\\now'))).toHaveLength(1);
    const system = { system: [{ text: "ship Falcon X today" }], messages: [] };
    expect(found(["falcon x"], system)[0]!.where).toBe("system[0].text");
    expect(found(["café-labs"], messages("at Café-Labs"))).toHaveLength(1);
  });

  it("finds a term in the path and in the query, decoded", () => {
    const hits = found(["acme-lab"], undefined, "/v1/acme-lab/run", "?q=ACME%2DLAB");
    expect(hits.map((hit) => hit.where)).toEqual(["path", "query"]);
    expect(found(["acme-lab"], undefined, "/%E0%A4%A/acme-lab")[0]!.where).toBe("path");
  });

  it("finds nothing in clean text, with no terms, or with no body", () => {
    expect(found(["acme-lab"], messages("nothing here"), "/v1", "?a=1")).toEqual([]);
    expect(found([], messages("acme-lab"))).toEqual([]);
    expect(found(["acme-lab"], undefined)).toEqual([]);
  });

  it("reads a body nested as deep as the proxy forwards one", () => {
    let deep: unknown = "acme-lab";
    for (let level = 0; level < 250; level++) deep = { next: deep };
    expect(found(["acme-lab"], deep)).toHaveLength(1);
    for (let level = 0; level < 100; level++) deep = { next: deep };
    expect(found(["acme-lab"], deep)).toEqual([]);
  });

  it("stops at a limit of hits per request", () => {
    const terms = Array.from({ length: 30 }, (_, index) => `needle-${index}`);
    expect(found(terms, messages(terms.join(" ")))).toHaveLength(20);
  });
});

describe("finding known values", () => {
  it("finds a value only as a whole word, in any case when its entry allows it", () => {
    const known = [word("Zeta-Host")];
    expect(found([], messages("run on zeta-host now"), "/", "", known)).toHaveLength(1);
    expect(found([], messages("run on zeta-hostel now"), "/", "", known)).toEqual([]);
    expect(found([], messages("run on myzeta-host"), "/", "", known)).toEqual([]);
    expect(found([], messages("zeta-host"), "/", "", known)).toHaveLength(1);
  });

  it("keeps case when its entry does", () => {
    const known = [word("QXRT", true)];
    expect(found([], messages("see QXRT here"), "/", "", known)).toHaveLength(1);
    expect(found([], messages("see qxrt here"), "/", "", known)).toEqual([]);
  });

  it("finds a value that starts with punctuation, and one that is not word-bounded", () => {
    const known = [word("/home/zeta"), word("lphabet", false, false)];
    expect(found([], messages("cd /home/zeta/src"), "/", "", known)[0]!.value).toBe("/home/zeta");
    expect(found([], messages("the alphabet"), "/", "", known)[0]!.value).toBe("lphabet");
    expect(found([], messages("cd /root/zeta"), "/", "", known)).toEqual([]);
  });

  it("reports a value once per place, with the first words of two values shared", () => {
    const known = [word("zeta-one"), word("zeta-two")];
    const hits = found([], messages("zeta-one zeta-two zeta-one"), "/", "", known);
    expect(hits.map((hit) => hit.value)).toEqual(["zeta-one", "zeta-two"]);
    expect(hits.every((hit) => hit.source === "known")).toBe(true);
  });

  it("is checked in the path and query as well", () => {
    const known = [word("zeta-host")];
    const hits = found([], undefined, "/v1/Zeta-Host", "?h=zeta-host", known);
    expect(hits.map((hit) => hit.where)).toEqual(["path", "query"]);
  });
});

describe("the known list", () => {
  afterAll(() => setRuntimeInventory([]));

  it("is the engine's inventory, without short or wordless entries and duplicates", () => {
    setRuntimeInventory([
      { id: "one", literal: "zeta-host", match: "token", caseSensitive: false },
      { id: "two", literal: "ZETA-HOST", match: "token", caseSensitive: false },
      { id: "three", literal: "ab", match: "token" },
      { id: "four", literal: "::--::", match: "phrase" },
      { id: "five", literal: "fragment", match: "phrase" },
    ]);
    const values = knownValues();
    expect(values.map((value) => value.literal)).toEqual(["zeta-host", "fragment"]);
    expect(values[0]).toMatchObject({ caseSensitive: false, token: true });
    expect(values[1]).toMatchObject({ caseSensitive: true, token: false });
    expect([...values[0]!.literal].length).toBeGreaterThanOrEqual(MIN_KNOWN_CHARS);
  });
});

describe("the policy file", () => {
  it("is read again when the file changes, and empty when it is absent", () => {
    setWatch({ terms: ["first-term"] });
    expect(watchPolicy().terms).toEqual(["first-term"]);
    setWatch({ terms: ["second-term"], action: "block" });
    expect(watchPolicy()).toMatchObject({ terms: ["second-term"], action: "block" });
    rmSync(config);
    expect(watchPolicy()).toEqual({ terms: [], action: "flag", known: true, problems: [] });
  });
});

describe("the proxy", () => {
  const upstream = (() =>
    Promise.resolve(Response.json({ content: [] }))) as unknown as typeof fetch;
  const send = (handler: ReturnType<typeof createHandler>, content: string, prompt = content) =>
    handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-ithildin-session": "watch-session" },
        body: JSON.stringify({
          messages: [
            { role: "user", content: prompt },
            { role: "assistant", content: "ok" },
            { role: "user", content },
          ],
        }),
      }),
    );
  const activity = async (handler: ReturnType<typeof createHandler>) =>
    (await handler(new Request("http://127.0.0.1/dashboard/activity"))).json() as Promise<{
      entries: Array<Record<string, unknown>>;
      stats: Record<string, unknown>;
      watch: { terms: number; action: string; known: number };
      sessions: Array<{ id: string; name: string; title?: string; guessed?: boolean }>;
    }>;

  it("names a session from a prompt the watch list allows, not from one it rejects", async () => {
    // A name from the conversation reaches the dashboard, so it may hold no
    // real value: a watched string in the prompt means no name at all.
    setWatch({ terms: ["zebra-internal"] });
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    await send(handler, "see zebra-internal");
    const guarded = await activity(handler);
    expect(JSON.stringify(guarded)).not.toContain("zebra-internal");
    expect(guarded.sessions.find((entry) => entry.id === "watch-se")?.title).toBeUndefined();

    // With nothing watched, the same session is named from its first prompt.
    setWatch({ terms: [] });
    const open = createHandler(DEFAULT_ROUTES, upstream);
    await send(open, "fix the login button");
    const free = await activity(open);
    expect(free.sessions.find((entry) => entry.id === "watch-se")).toMatchObject({
      title: "fix the login button",
      guessed: true,
    });
  });

  it("flags a watched string that masking missed, once per place, and still sends", async () => {
    setWatch({ terms: ["zebra-internal"] });
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    expect((await send(handler, "see zebra-internal")).status).toBe(200);
    expect((await send(handler, "see zebra-internal")).status).toBe(200);
    const data = await activity(handler);
    const leaks = data.entries.filter((entry) => entry.type === "leaked");
    expect(leaks).toHaveLength(2);
    expect(leaks[0]).toMatchObject({ kind: "watch", action: "flag", endpoint: "/v1/messages" });
    expect(leaks.map((leak) => leak.where)).toEqual(["messages[0].content", "messages[2].content"]);
    expect(JSON.stringify(data)).not.toContain("zebra-internal");
    expect(data.stats).toMatchObject({ leaked: 2 });
    expect(data.watch).toEqual({ terms: 1, action: "flag", known: 0 });
  });

  it("refuses the request when the list says to block", async () => {
    setWatch({ terms: ["zebra-internal"], action: "block" });
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    const response = await send(handler, "see zebra-internal");
    expect(response.status).toBe(403);
    expect(JSON.stringify(await response.json())).not.toContain("zebra-internal");
    const data = await activity(handler);
    expect(data.entries.map((entry) => entry.type)).toEqual(
      expect.arrayContaining(["leaked", "refused"]),
    );
    expect(data.entries.find((entry) => entry.type === "leaked")).toMatchObject({
      action: "block",
    });
    expect(data.watch).toEqual({ terms: 1, action: "block", known: 0 });
  });

  it("stays quiet for text the proxy masked, a lifted prompt, and an empty list", async () => {
    setWatch({ terms: ["zebra-internal"], action: "block" });
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    expect((await send(handler, "mail jane.doe@acme-corp.com")).status).toBe(200);
    expect((await send(handler, "see zebra-internal [allow-pii]")).status).toBe(200);
    setWatch({ terms: [] });
    expect((await send(handler, "see zebra-internal")).status).toBe(200);
    const data = await activity(handler);
    expect(data.entries.filter((entry) => entry.type === "leaked")).toEqual([]);
    expect(data.watch).toEqual({ terms: 0, action: "flag", known: 0 });
  });

  it("flags a known value in an unscanned thinking block, and never blocks", async () => {
    setRuntimeInventory([
      { id: "zeta", literal: "zeta-host", match: "token", caseSensitive: false },
    ]);
    setWatch({ action: "block" });
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    const thinking = { type: "thinking", thinking: "I will use ZETA-HOST", signature: "sig" };
    const response = await handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          messages: [
            { role: "user", content: "start" },
            { role: "assistant", content: [thinking, { type: "text", text: "ok" }] },
            { role: "user", content: "go on" },
          ],
        }),
      }),
    );
    expect(response.status).toBe(200);
    const data = await activity(handler);
    const leak = data.entries.find((entry) => entry.type === "leaked")!;
    expect(leak).toMatchObject({
      kind: "known",
      action: "flag",
      where: "messages[1].content[0].thinking",
    });
    expect(JSON.stringify(data)).not.toContain("zeta-host");
  });

  it("leaves the known list out when the section turns it off", async () => {
    setRuntimeInventory([
      { id: "zeta", literal: "zeta-host", match: "token", caseSensitive: false },
    ]);
    setWatch({ known: false });
    const handler = createHandler(DEFAULT_ROUTES, upstream);
    const thinking = { type: "thinking", thinking: "I will use zeta-host", signature: "sig" };
    await handler(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          messages: [
            { role: "user", content: "start" },
            { role: "assistant", content: [thinking, { type: "text", text: "ok" }] },
            { role: "user", content: "go on" },
          ],
        }),
      }),
    );
    expect((await activity(handler)).entries.filter((entry) => entry.type === "leaked")).toEqual(
      [],
    );
    setRuntimeInventory([]);
  });
});
