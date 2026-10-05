// `ithildin check`: the guard and watch sections of the user config, and the decisions
// you expect from the guards, checked without an agent or a provider.
//
//   ithildin check [--config FILE] [TEST.guard | DIR ...]
//
// With no tests named, the *.guard files in ~/.config/ithildin/guard-tests
// run, if there are any. A test file is one conversation, a line a step:
//
//   # reading the web stops a push, and [allow-send] lets it through
//   allow WebFetch {"url": "https://example.com/"}
//   deny  Bash git push origin main
//   prompt [allow-send] push it
//   allow Bash git push origin main
//
// allow and deny name a tool and its arguments: a JSON object, or the rest of
// the line as the command. Each call joins the history with an empty result,
// so later calls are judged by what came before, as in a session. prompt is a
// typed user prompt: its allow tags hold for the calls after it, until the
// next. cwd sets the working directory paths resolve against.
//
// The calls run through the proxy's own request scan and reply guards; no tool
// runs. Exit status 1 when the config has problems or a test fails.

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { configFile } from "../engine/lib/names.ts";
import { guardConfigFile, guardPolicy } from "./policy.ts";
import { watchPolicy } from "./watch.ts";
import { shellCommand } from "./tools.ts";
import { blockedNotice, initEngine, redactRequest, swapToolArguments } from "./redact.ts";

type Call = { line: number; expect: "allow" | "deny"; tool: string; args: unknown };
type Step = Call | { line: number; kind: "prompt" | "cwd"; text: string };

// A test file's steps, or what is wrong with it.
export function parseGuardTest(text: string): Step[] | string {
  const steps: Step[] = [];
  for (const [index, raw] of text.split("\n").entries()) {
    const line = index + 1;
    const content = raw.trim();
    if (content === "" || content.startsWith("#")) continue;
    const [word = "", rest = ""] = content.split(/\s+(.*)/s);
    if (word === "prompt" || word === "cwd") {
      steps.push({ line, kind: word, text: rest });
      continue;
    }
    if (word !== "allow" && word !== "deny")
      return `line ${line}: starts with "${word}", not allow, deny, prompt or cwd`;
    const [tool = "", argText = ""] = rest.split(/\s+(.*)/s);
    if (tool === "") return `line ${line}: names no tool`;
    const args = parseCallArgs(argText.trim());
    if (args === undefined) return `line ${line}: arguments are not a JSON object`;
    steps.push({ line, expect: word, tool, args });
  }
  return steps;
}

function parseCallArgs(text: string): unknown {
  if (text === "") return {};
  if (!text.startsWith("{")) return { command: text };
  try {
    // Text starting with "{" parses as an object or not at all.
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

let conversations = 0;

// The steps as one conversation; a line per call the guards decided otherwise.
export function runGuardTest(steps: Step[]): string[] {
  const conversation = ++conversations;
  const session = `ithildin-check-${process.pid}-${conversation}`;
  const failures: string[] = [];
  const messages: unknown[] = [];
  let cwd = process.cwd();
  for (const step of steps) {
    if ("kind" in step) {
      if (step.kind === "cwd") cwd = path.resolve(cwd, step.text);
      else messages.push({ role: "user", content: step.text });
      continue;
    }
    if (messages.length === 0) messages.push({ role: "user", content: "check" });
    const body = { system: `Primary working directory: ${cwd}`, messages: [...messages] };
    const { tags } = redactRequest("anthropic", body, session);
    // Refusals are remembered by id, so ids stay apart across files.
    const id = `toolu_check_${conversation}_${step.line}`;
    const blocked = swapToolArguments(step.tool, step.args, tags, id).blocked === true;
    const args = shellCommand(step.args) ?? JSON.stringify(step.args);
    const said = `line ${step.line}: ${step.expect} ${step.tool} ${args}`;
    if (blocked && step.expect === "allow") failures.push(`${said}: blocked: ${blockedNotice(id)}`);
    if (!blocked && step.expect === "deny") failures.push(`${said}: allowed`);
    messages.push(
      { role: "assistant", content: [{ type: "tool_use", id, name: step.tool, input: step.args }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: "" }] },
    );
  }
  return failures;
}

// The test files a name stands for: the file, or a directory's *.guard files.
function testFiles(name: string): string[] {
  if (!statSync(name).isDirectory()) return [name];
  return readdirSync(name)
    .filter((file) => file.endsWith(".guard"))
    .sort()
    .map((file) => path.join(name, file));
}

function describeGuard(out: (text: string) => void): number {
  const file = guardConfigFile();
  let present = true;
  try {
    statSync(file);
  } catch {
    present = false;
  }
  const policy = guardPolicy();
  out(`config: ${file}${present ? "" : " (absent: the built-in guards alone)"}\n`);
  const lists = (
    ["outsideTools", "sendTools", "reviewedTools", "trustedReads", "allowedSends"] as const
  )
    .map((key) => `${key} ${policy[key].length}`)
    .join(", ");
  out(`guard: protect ${policy.protect.length}, ${lists}\n`);
  const watch = watchPolicy();
  const known = watch.known ? "on" : "off";
  out(`watch: ${watch.terms.length} string(s), ${watch.action}, known ${known}\n`);
  const problems = [...policy.problems, ...watch.problems];
  for (const problem of problems) out(`problem: ${problem}\n`);
  return problems.length;
}

function runFile(file: string, out: (text: string) => void): boolean {
  let steps: Step[] | string;
  try {
    steps = parseGuardTest(readFileSync(file, "utf8"));
  } catch (error) {
    steps = `could not read it (${(error as NodeJS.ErrnoException).code ?? "error"})`;
  }
  if (typeof steps === "string") {
    out(`${file}: could not run: ${steps}\n`);
    return false;
  }
  const failures = runGuardTest(steps);
  const calls = steps.filter((step) => !("kind" in step)).length;
  out(`${file}: ${failures.length === 0 ? `ok (${calls} calls)` : "FAILED"}\n`);
  for (const failure of failures) out(`  ${failure}\n`);
  return failures.length === 0;
}

// argv: what follows "check". Returns the exit status.
export function runCheck(argv: string[], out: (text: string) => void): number {
  const names: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] !== "--config") names.push(argv[i]!);
    else if (i + 1 < argv.length) process.env.ITHILDIN_CONFIG = argv[++i];
    else {
      out("--config needs a file\n");
      return 1;
    }
  }
  const problems = describeGuard(out);
  const defaults = configFile("guard-tests");
  let files: string[];
  try {
    files = (names.length > 0 ? names : [defaults]).flatMap(testFiles);
  } catch (error) {
    if (names.length === 0) return problems > 0 ? 1 : 0;
    out(`could not read the tests (${(error as NodeJS.ErrnoException).code ?? "error"})\n`);
    return 1;
  }
  // Named tests that turn out to be none would otherwise pass in silence.
  if (names.length > 0 && files.length === 0) {
    out(`no *.guard files in ${names.join(", ")}\n`);
    return 1;
  }
  initEngine();
  const passed = files.filter((file) => runFile(file, out)).length;
  out(`${files.length} test files: ${passed} ok, ${files.length - passed} failed\n`);
  return problems > 0 || passed < files.length ? 1 : 0;
}
