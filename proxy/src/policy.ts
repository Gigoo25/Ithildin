// The guards' part of the user config: what to protect and how to treat tools
// the built-in lists do not name. It lives in config.json beside the
// inventory, under "guard", so the same protection covers it (protect.ts):
//
//   "guard": {
//     "protect": ["~/infra/deploy.yaml", "~/secrets"],
//     "outsideTools": ["mcp__jira__*"],
//     "sendTools": ["mcp__mail__*", "Bash(command:deploy.sh *)"],
//     "reviewedTools": ["mcp__db__run_query"],
//     "trustedReads": ["Bash(command:gh issue view * --repo me/*)"],
//     "allowedSends": ["Bash(command:git push origin *)"]
//   }
//
// protect: paths changed only with [allow-protected], like the agents'
// settings. outsideTools: tools whose results come from outside the machine
// (trust.ts). sendTools: tools that send data off it, blocked once the
// conversation is untrusted or has read secrets. reviewedTools: tools you have
// checked, left out of the badge's unguarded count. trustedReads and
// allowedSends take calls back out of the built-in outside reads and sends.
//
// Entries are a tool name, with * and ? globs, and optionally argument
// patterns: mcp__mail__send(to:*@me.org) matches when every named argument
// matches its pattern whole. In an argument pattern * matches anything, ? one
// character, and \ escapes * ? , ) and \. A shell call's command is matched
// against each command of its line, words joined by single spaces and the
// program named without its directory, so "git push origin *" never covers
// the "curl" after a "&&", and "deploy.sh *" matches "./deploy.sh prod".
//
// Read again whenever the file changes. The engine ignores the section.

import { statSync } from "node:fs";
import { globRegExp } from "../engine/core.ts";
import { readConfigFile } from "../engine/lib/rules.ts";
import { configFile, setting } from "../engine/lib/names.ts";

export interface Selector {
  source: string;
  tool: RegExp;
  args: Array<[key: string, pattern: RegExp]>;
}

export interface GuardPolicy {
  protect: string[];
  outsideTools: Selector[];
  sendTools: Selector[];
  reviewedTools: Selector[];
  trustedReads: Selector[];
  allowedSends: Selector[];
  // What was wrong with the section, already left out.
  problems: string[];
}

const LISTS = [
  "outsideTools",
  "sendTools",
  "reviewedTools",
  "trustedReads",
  "allowedSends",
] as const;

const empty = (problems: string[] = []): GuardPolicy => ({
  protect: [],
  outsideTools: [],
  sendTools: [],
  reviewedTools: [],
  trustedReads: [],
  allowedSends: [],
  problems,
});
let cached: { key: string; policy: GuardPolicy } | undefined;

// An argument pattern as a whole-value RegExp.
function argPattern(text: string): RegExp {
  let source = "";
  for (let i = 0; i < text.length; i++) {
    const char = text[i]!;
    if (char === "\\" && i + 1 < text.length) source += text[++i]!.replace(/[^\w\s]/g, "\\$&");
    else if (char === "*") source += "[\\s\\S]*";
    else if (char === "?") source += "[\\s\\S]";
    else source += char.replace(/[^\w\s]/g, "\\$&");
  }
  return new RegExp(`^${source}$`);
}

// "a:x, b:y\, z" → ["a:x", "b:y\, z"], splitting on commas not escaped.
function splitArgs(text: string): string[] {
  const parts = [""];
  for (let i = 0; i < text.length; i++) {
    const char = text[i]!;
    if (char === "\\" && i + 1 < text.length) parts[parts.length - 1] += char + text[++i];
    else if (char === ",") parts.push("");
    else parts[parts.length - 1] += char;
  }
  return parts;
}

// One entry as a selector, or a string saying what is wrong with it.
export function parseSelector(source: string): Selector | string {
  const match = /^([^()\s]+)(?:\(([\s\S]*)\))?$/.exec(source.trim());
  if (!match) return `"${source}" is not a tool name or name(argument:pattern, ...)`;
  const args: Selector["args"] = [];
  if (match[2] !== undefined) {
    for (const part of splitArgs(match[2])) {
      const colon = part.indexOf(":");
      const key = part.slice(0, colon).trim();
      if (colon < 0 || !/^\w+$/.test(key))
        return `"${source}": "${part.trim()}" is not argument:pattern`;
      args.push([key, argPattern(part.slice(colon + 1).trimStart())]);
    }
  }
  return { source, tool: globRegExp(match[1]!), args };
}

function strings(guard: Record<string, unknown>, key: string, problems: string[]): string[] {
  const value = guard[key];
  if (value === undefined) return [];
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return value;
  problems.push(`"guard.${key}" must be a string array`);
  return [];
}

export function parseGuardPolicy(config: unknown): GuardPolicy {
  const guard = (config as { guard?: unknown } | undefined)?.guard;
  if (guard === undefined) return empty();
  if (!guard || typeof guard !== "object" || Array.isArray(guard))
    return empty([`"guard" must be an object`]);
  const record = guard as Record<string, unknown>;
  const policy = empty();
  for (const key of Object.keys(record))
    if (key !== "protect" && !(LISTS as readonly string[]).includes(key))
      policy.problems.push(`"guard.${key}" is not a guard setting`);
  policy.protect = strings(record, "protect", policy.problems);
  for (const list of LISTS) {
    for (const entry of strings(record, list, policy.problems)) {
      const selector = parseSelector(entry);
      if (typeof selector === "string") policy.problems.push(`guard.${list}: ${selector}`);
      else policy[list].push(selector);
    }
  }
  return policy;
}

export function guardConfigFile(): string {
  return setting("CONFIG") ?? configFile("config.json");
}

// The policy in force: the file's, re-read when its path or mtime moves.
// Problems go to the log once per read; `ithildin check` lists them too.
export function guardPolicy(): GuardPolicy {
  const file = guardConfigFile();
  let mtime = 0;
  try {
    mtime = statSync(file).mtimeMs;
  } catch {
    // Absent: no policy.
  }
  const key = `${file}\0${mtime}`;
  if (cached?.key !== key) {
    const policy = mtime ? parseGuardPolicy(readConfigFile(file, "user config")) : empty();
    for (const problem of policy.problems)
      process.stderr.write(`ithildin: user config: ${problem}, ignoring\n`);
    cached = { key, policy };
  }
  return cached.policy;
}

// A call's argument as text, for a pattern: strings, numbers and booleans.
function argText(args: unknown, key: string): string | undefined {
  if (!args || typeof args !== "object" || Array.isArray(args)) return undefined;
  const value = (args as Record<string, unknown>)[key];
  return ["string", "number", "boolean"].includes(typeof value) ? String(value) : undefined;
}

// Whether a selector matches a call. `command`, when given, stands in for the
// call's command argument: one command of a shell line.
export function selects(
  selector: Selector,
  toolName: string,
  args: unknown,
  command?: string,
): boolean {
  if (!selector.tool.test(toolName)) return false;
  return selector.args.every(([key, pattern]) => {
    const text = key === "command" && command !== undefined ? command : argText(args, key);
    return text !== undefined && pattern.test(text);
  });
}

export function selectsAny(
  selectors: Selector[],
  toolName: string,
  args: unknown,
  command?: string,
): boolean {
  return selectors.some((selector) => selects(selector, toolName, args, command));
}

// Whether a list names a tool at all, whatever arguments it asks for.
export function namesTool(selectors: Selector[], toolName: string): boolean {
  return selectors.some((selector) => selector.tool.test(toolName));
}
