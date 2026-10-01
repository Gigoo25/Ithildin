// The agents' tool vocabulary, for the guards (protect.ts, the secret reads
// in redact.ts) and swap-back: Claude Code, Pi, and Codex.
//
// Swap-back goes by name alone: real values reach only tools known to run on
// this machine. The guards also go by shape: arguments that look like a shell
// command or a file write are checked whatever the tool is called, so a
// harness whose names are not listed here does not slip past them.

import path from "node:path";
import { candidatePaths } from "../engine/core.ts";

// Codex: shell {command: argv}, exec_command {cmd}.
export const BASH_TOOLS = new Set(["bash", "Bash", "shell", "exec_command"]);
// Codex: apply_patch, freeform (a custom tool) or {input: patch}.
export const WRITE_TOOLS = new Set([
  "write",
  "edit",
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "apply_patch",
]);
export const LOCAL_TOOLS = new Set([
  ...WRITE_TOOLS,
  "read",
  "grep",
  "find",
  "ls",
  "search_files",
  "Read",
  "Glob",
  "Grep",
  "LS",
]);

const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh"]);

function quoteWord(word: string): string {
  return /^[\w@%+=:,./-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`;
}

// ["bash", "-lc", script] runs the script; any other argv is one command.
function argvLine(argv: string[]): string {
  if (argv.length >= 3 && SHELLS.has(path.basename(argv[0]!)) && /^-\w*c$/.test(argv[1]!))
    return argv[2]!;
  return argv.map(quoteWord).join(" ");
}

// A shell call's command line: {command: "…"} (Claude, Pi), {command: argv}
// (Codex shell), {cmd: "…"} (Codex exec_command). Undefined for anything else.
export function shellCommand(args: unknown): string | undefined {
  if (!args || typeof args !== "object" || Array.isArray(args)) return undefined;
  const record = args as Record<string, unknown>;
  for (const key of ["command", "cmd"]) {
    const value = record[key];
    if (typeof value === "string") return value;
    if (Array.isArray(value) && value.length > 0 && value.every((word) => typeof word === "string"))
      return argvLine(value as string[]);
  }
  return undefined;
}

// Files an apply_patch envelope adds, changes, deletes or moves to.
const PATCH_FILE = /^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$/gm;

export function patchPaths(patch: string): string[] {
  return [...patch.matchAll(PATCH_FILE)].map((match) => match[1]!.trim());
}

// Keys only a file write or edit carries.
const WRITE_KEYS = ["content", "new_string", "old_string", "edits", "new_source", "patch"];

// The files a call writes, or undefined when it is not a write. A freeform
// call's arguments are its raw input (an apply_patch envelope).
export function writeTargets(toolName: string, args: unknown): string[] | undefined {
  if (typeof args === "string")
    return args.includes("*** Begin Patch") ? patchPaths(args) : undefined;
  if (!args || typeof args !== "object" || Array.isArray(args)) return undefined;
  const record = args as Record<string, unknown>;
  if (!WRITE_TOOLS.has(toolName) && !WRITE_KEYS.some((key) => key in record)) return undefined;
  const patches = ["input", "patch"].flatMap((key) =>
    typeof record[key] === "string" ? patchPaths(record[key] as string) : [],
  );
  return [
    ...candidatePaths(record),
    ...(typeof record.notebook_path === "string" ? [record.notebook_path] : []),
    ...patches,
  ];
}
