import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { guardPolicy, parseGuardPolicy } from "./policy.ts";
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

  it("ignores a malformed section, keeping the parts that are right", () => {
    expect(parseGuardPolicy(undefined).protect).toEqual([]);
    expect(parseGuardPolicy({ guard: [] }).sendTools).toEqual([]);
    const partial = parseGuardPolicy({ guard: { protect: "~/x", sendTools: ["a*"] } });
    expect(partial.protect).toEqual([]);
    expect(partial.sendTools.map(String)).toEqual(["/^a[^/]*$/"]);
  });
});
