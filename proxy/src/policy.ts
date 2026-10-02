// The guards' part of the user config: what to protect and how to treat tools
// the built-in lists do not name. It lives in config.json beside the
// inventory, under "guard", so the same protection covers it (protect.ts):
//
//   "guard": {
//     "protect": ["~/infra/deploy.yaml", "~/secrets"],
//     "outsideTools": ["mcp__jira__*"],
//     "sendTools": ["mcp__mail__*"],
//     "reviewedTools": ["mcp__db__run_query"]
//   }
//
// protect: paths changed only with [allow-protected], like the agents'
// settings. outsideTools: tools whose results come from outside the machine
// (trust.ts). sendTools: tools that send data off it, blocked once the
// conversation is untrusted. reviewedTools: tools you have checked, left out
// of the badge's unguarded count. Tool names take * and ? globs.
//
// Read again whenever the file changes. The engine ignores the section.

import { statSync } from "node:fs";
import { globRegExp } from "../engine/core.ts";
import { readConfigFile } from "../engine/lib/rules.ts";
import { configFile, setting } from "../engine/lib/names.ts";

export interface GuardPolicy {
  protect: string[];
  outsideTools: RegExp[];
  sendTools: RegExp[];
  reviewedTools: RegExp[];
}

const EMPTY: GuardPolicy = { protect: [], outsideTools: [], sendTools: [], reviewedTools: [] };
let cached: { key: string; policy: GuardPolicy } | undefined;

function strings(guard: Record<string, unknown>, key: string): string[] {
  const value = guard[key];
  if (value === undefined) return [];
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return value;
  process.stderr.write(
    `ithildin: "guard.${key}" in user config must be a string array, ignoring\n`,
  );
  return [];
}

export function parseGuardPolicy(config: unknown): GuardPolicy {
  const guard = (config as { guard?: unknown } | undefined)?.guard;
  if (guard === undefined) return EMPTY;
  if (!guard || typeof guard !== "object" || Array.isArray(guard)) {
    process.stderr.write(`ithildin: "guard" in user config must be an object, ignoring\n`);
    return EMPTY;
  }
  const record = guard as Record<string, unknown>;
  const globs = (key: string) => strings(record, key).map(globRegExp);
  return {
    protect: strings(record, "protect"),
    outsideTools: globs("outsideTools"),
    sendTools: globs("sendTools"),
    reviewedTools: globs("reviewedTools"),
  };
}

// The policy in force: the file's, re-read when its path or mtime moves.
export function guardPolicy(): GuardPolicy {
  const file = setting("CONFIG") ?? configFile("config.json");
  let mtime = 0;
  try {
    mtime = statSync(file).mtimeMs;
  } catch {
    // Absent: no policy.
  }
  const key = `${file}\0${mtime}`;
  if (cached?.key !== key)
    cached = { key, policy: mtime ? parseGuardPolicy(readConfigFile(file, "user config")) : EMPTY };
  return cached.policy;
}

export function matchesAny(name: string, globs: RegExp[]): boolean {
  return globs.some((glob) => glob.test(name));
}
