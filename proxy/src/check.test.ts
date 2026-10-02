import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseGuardTest, runCheck, runGuardTest } from "./check.ts";
import { initEngine } from "./redact.ts";

let dir = "";
const saved = { config: process.env.ITHILDIN_CONFIG, xdg: process.env.XDG_CONFIG_HOME };

beforeAll(() => {
  initEngine();
  dir = mkdtempSync(join(tmpdir(), "ithildin-check-"));
});

afterAll(() => {
  for (const [key, value] of [
    ["ITHILDIN_CONFIG", saved.config],
    ["XDG_CONFIG_HOME", saved.xdg],
  ] as const) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(dir, { recursive: true, force: true });
});

const WEB = `# reading the web stops a push, and [allow-send] lets it through
allow WebFetch {"url": "https://example.com/"}
deny  Bash git push origin main
allow Bash git status
prompt [allow-send] push it
allow Bash git push origin main
`;

const steps = (text: string) => {
  const parsed = parseGuardTest(text);
  if (typeof parsed === "string") throw new Error(parsed);
  return parsed;
};

const run = (argv: string[]) => {
  let text = "";
  const status = runCheck(argv, (chunk) => (text += chunk));
  return { status, text };
};

describe("guard tests", () => {
  it("parses calls, prompts and the working directory", () => {
    expect(
      steps('cwd /tmp\nprompt hi\ndeny Bash git push\nallow Read {"file_path":"a"}\nallow X'),
    ).toEqual([
      { line: 1, kind: "cwd", text: "/tmp" },
      { line: 2, kind: "prompt", text: "hi" },
      { line: 3, expect: "deny", tool: "Bash", args: { command: "git push" } },
      { line: 4, expect: "allow", tool: "Read", args: { file_path: "a" } },
      { line: 5, expect: "allow", tool: "X", args: {} },
    ]);
  });

  it("says what is wrong with a line", () => {
    expect(parseGuardTest("expect Bash ls")).toContain("line 1: starts with");
    expect(parseGuardTest("\nallow")).toContain("line 2: names no tool");
    expect(parseGuardTest("deny X {nope")).toContain("not a JSON object");
  });

  it("judges each call by the history before it", () => {
    expect(runGuardTest(steps(WEB))).toEqual([]);
  });

  it("names the calls the guards decided otherwise, and why", () => {
    const failures = runGuardTest(
      steps(
        `cwd ${dir}\nallow WebFetch {"url":"x"}\nallow Bash git push origin main\ndeny Bash ls`,
      ),
    );
    expect(failures).toHaveLength(2);
    expect(failures[0]).toStartWith("line 3: allow Bash git push origin main: blocked: Not run:");
    expect(failures[1]).toBe("line 4: deny Bash ls: allowed");
  });
});

describe("ithildin check", () => {
  it("lists the config's problems, and fails on them", () => {
    const config = join(dir, "config.json");
    writeFileSync(config, JSON.stringify({ guard: { sendTool: ["x"] } }));
    process.env.XDG_CONFIG_HOME = join(dir, "no-config-home");
    const { status, text } = run(["--config", config]);
    expect(status).toBe(1);
    expect(text).toContain(`config: ${config}\n`);
    expect(text).toContain(`problem: "guard.sendTool" is not a guard setting`);
  });

  it("passes with no config and no tests", () => {
    const { status, text } = run(["--config", join(dir, "absent.json")]);
    expect(status).toBe(0);
    expect(text).toContain("absent: the built-in guards alone");
    expect(text).toContain("guard: protect 0, outsideTools 0, sendTools 0");
  });

  it("runs the tests in the default directory and the ones named", () => {
    const tests = join(dir, "home", "ithildin", "guard-tests");
    mkdirSync(join(tests, "nested.guard"), { recursive: true });
    writeFileSync(join(tests, "web.guard"), WEB);
    writeFileSync(join(tests, "notes.txt"), "not a test");
    process.env.XDG_CONFIG_HOME = join(dir, "home");
    const { status, text } = run(["--config", join(dir, "absent.json")]);
    expect(status).toBe(1);
    expect(text).toContain("nested.guard: could not run: could not read it (EISDIR)");
    expect(text).toContain("web.guard: ok (4 calls)");
    expect(text).toContain("2 test files: 1 ok, 1 failed");
    const named = run(["--config", join(dir, "absent.json"), join(tests, "web.guard")]);
    expect(named.status).toBe(0);
    const bad = join(dir, "bad.guard");
    writeFileSync(bad, "maybe Bash ls\n");
    expect(run([bad]).text).toContain("bad.guard: could not run: line 1");
    expect(run([join(dir, "missing")])).toEqual({
      status: 1,
      text: expect.stringContaining("could not read the tests (ENOENT)"),
    });
  });
});
