// Changes an agent must not make without the user's say-so.
//
// The secret-read guards withhold what a call printed; the call itself runs.
// So an agent could still rewrite Ithildin's rules blind, point models.json
// or Claude's settings at a route that skips the proxy, or delete .git and the
// history with it. A tool call that would change one of those is dropped
// before the harness runs it, unless the typed prompt behind it carries
// [allow-protected].
//
// Protected:
// - Ithildin's config and state (~/.config/ithildin and its state dir with
//   the stand-in keys, under the old names too) and the repo files those
//   links point at;
// - where agents send requests: Pi's models.json/settings.json, Claude's
//   ~/.claude.json, ~/.claude/settings.json and any .claude/settings*.json
//   (env can set ANTHROPIC_BASE_URL), opencode's opencode.json, Codex's
//   config.toml and auth.json, and the shell startup files an exported
//   base URL would go in;
// - git history: any path inside .git, removing a repo or a directory above
//   one (rm, mv, a deleting find, xargs rm over a find, rsync --delete), and
//   git commands that discard commits or refs.
//
// Like the read guards this is lexical, not a sandbox: paths computed at run
// time ($(...), eval, a script that edits the file) are out of scope, and
// changes to the proxy's own source take a rebuild to matter.

import { existsSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import { canonicalPath, commandPathCandidates, globRegExp } from "../engine/core.ts";
import { NAME, setting } from "../engine/lib/names.ts";
import { shellCommand, writeTargets } from "./tools.ts";

export type ProtectedKind = "config" | "git";

export function protectedBlocked(kind: ProtectedKind): string {
  const what =
    kind === "git" ? "would delete or rewrite git history" : "would change protected configuration";
  return (
    `Not run: this call ${what}, so nothing was changed. If the change is intended, ask the user ` +
    `to include [allow-protected] in their prompt.`
  );
}

function expandHome(filePath: string): string {
  const home = process.env.HOME ?? "";
  if (filePath === "~" || filePath === "$HOME" || filePath === "${HOME}") return home;
  if (filePath.startsWith("~/")) return `${home}${filePath.slice(1)}`;
  if (filePath.startsWith("$HOME/")) return `${home}${filePath.slice(5)}`;
  if (filePath.startsWith("${HOME}/")) return `${home}${filePath.slice(7)}`;
  return filePath;
}

function real(filePath: string): string | undefined {
  try {
    return realpathSync(filePath);
  } catch {
    return undefined;
  }
}

// Recomputed per call: a few stats, and links added since start count.
// Directories: the home-side ones, where they point, and where each file in
// them points (the repo directory Home Manager links config.json from).
function protectedRoots(): { dirs: string[]; files: string[] } {
  const home = process.env.HOME ?? "";
  const config = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  const state = process.env.XDG_STATE_HOME || path.join(home, ".local", "state");
  const dirs = new Set<string>();
  const files = new Set<string>();
  for (const dir of new Set([
    path.join(config, NAME),
    path.join(home, ".config", NAME),
    path.join(state, NAME),
  ])) {
    dirs.add(dir);
    const resolved = real(dir);
    if (!resolved) continue;
    dirs.add(resolved);
    let names: string[] = [];
    try {
      names = readdirSync(resolved);
    } catch {
      continue;
    }
    for (const name of names) {
      const target = real(path.join(resolved, name));
      if (target && target !== path.join(resolved, name)) dirs.add(path.dirname(target));
    }
  }
  const override = setting("CONFIG");
  for (const file of [
    path.join(home, ".pi", "agent", "models.json"),
    path.join(home, ".pi", "agent", "settings.json"),
    path.join(home, ".claude", "settings.json"),
    path.join(home, ".claude.json"),
    path.join(config, "opencode", "opencode.json"),
    path.join(config, "opencode", "opencode.jsonc"),
    path.join(home, ".codex", "config.toml"),
    path.join(home, ".codex", "auth.json"),
    ...[".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv", ".zprofile"].map((name) =>
      path.join(home, name),
    ),
    path.join(config, "fish", "config.fish"),
    ...(override ? [override] : []),
  ]) {
    files.add(file);
    const resolved = real(file);
    if (resolved) files.add(resolved);
  }
  return { dirs: [...dirs], files: [...files] };
}

function within(file: string, root: string): boolean {
  return file === root || file.startsWith(`${root}/`);
}

// The spellings a path can reach: as written, through its links, and through
// its parent's links (a new file in a linked directory has no realpath yet).
function spellings(filePath: string, cwd: string): string[] {
  const lexical = path.resolve(cwd, expandHome(filePath.replace(/^@/, "")));
  const parent = real(path.dirname(lexical));
  return [
    ...new Set([
      lexical,
      canonicalPath(lexical, "/"),
      ...(parent ? [path.join(parent, path.basename(lexical))] : []),
    ]),
  ];
}

const CLAUDE_SETTINGS = /(?:^|\/)\.claude\/settings(?:\.[\w-]+)?\.json$/;

function protectedPath(
  filePath: string,
  cwd: string,
  roots: ReturnType<typeof protectedRoots>,
): ProtectedKind | undefined {
  if (!filePath) return;
  for (const spelling of spellings(filePath, cwd)) {
    if (spelling.split("/").includes(".git")) return "git";
    if (CLAUDE_SETTINGS.test(spelling)) return "config";
    if (roots.files.includes(spelling) || roots.dirs.some((dir) => within(spelling, dir)))
      return "config";
  }
  return undefined;
}

// Removing or moving a directory takes what is below it: a repo (its .git)
// or a protected directory or file.
function holdsProtected(
  filePath: string,
  cwd: string,
  roots: ReturnType<typeof protectedRoots>,
): ProtectedKind | undefined {
  for (const spelling of spellings(filePath, cwd)) {
    if (existsSync(path.join(spelling, ".git"))) return "git";
    if ([...roots.dirs, ...roots.files].some((root) => within(root, spelling))) return "config";
  }
  return undefined;
}

// ── bash ────────────────────────────────────────────────────────────────────

// Quoted text blanked, same length, so splitting and redirect checks do not
// trip on a ; or > inside a string.
function maskQuotes(command: string): string {
  return command.replace(
    /'[^']*'|"(?:[^"\\]|\\.)*"/g,
    (quoted) => quoted[0] + "_".repeat(quoted.length - 2) + quoted[0],
  );
}

// Programs whose heredoc body runs as commands.
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "fish", "ssh", "eval", "source", "."]);
const HEREDOC_OPERATOR = /(?<!<)<<(?!<)(-?)/g;
const HEREDOC_WORD = /^\s*(['"]?)([^\s'"<>;|&()]+)\1/;

// Heredoc bodies taken out: text fed to cat or python is data, and read as
// shell it tripped the guard (a regex's .*? globbed to .git). A body a shell
// on the same line reads stays in, as do the header and everything after.
// Unterminated, the body runs to the end, as in bash.
function heredocsAsData(command: string): string {
  const out: string[] = [];
  const pending: Array<{ word: string; tabs: boolean; keep: boolean }> = [];
  for (const line of command.split("\n")) {
    const body = pending[0];
    if (body) {
      if (body.keep) out.push(line);
      if ((body.tabs ? line.replace(/^\t+/, "") : line) === body.word) pending.shift();
      continue;
    }
    out.push(line);
    const keep = segments(line).some((segment) => SHELLS.has(program(segment)[0] ?? ""));
    for (const match of maskQuotes(line).matchAll(HEREDOC_OPERATOR)) {
      const word = HEREDOC_WORD.exec(line.slice(match.index! + match[0].length))?.[2];
      if (word) pending.push({ word, tabs: match[1] === "-", keep });
    }
  }
  return out.join("\n");
}

function segments(command: string): string[] {
  const masked = maskQuotes(command).replace(/\d*>&\d+|&>/g, (match) => "_".repeat(match.length));
  const out: string[] = [];
  let start = 0;
  for (const match of masked.matchAll(/\|\||&&|[;|&\n()]/g)) {
    out.push(command.slice(start, match.index));
    start = match.index! + match[0].length;
  }
  out.push(command.slice(start));
  return out.map((segment) => segment.trim()).filter(Boolean);
}

function words(segment: string): string[] {
  return (segment.match(/(?:"[^"\n]*"|'[^'\n]*'|[^\s<>"'])+/g) ?? []).map((word) =>
    word.replace(/^(['"])(.*)\1$/, "$2"),
  );
}

// The program and its arguments, past assignments and wrappers.
function program(segment: string): string[] {
  const list = words(segment);
  let i = 0;
  while (
    i < list.length &&
    (/^[A-Za-z_]\w*=/.test(list[i]!) ||
      ["sudo", "env", "command", "exec", "time", "nice", "nohup", "doas", "{", "!"].includes(
        list[i]!,
      ))
  )
    i++;
  return list.slice(i).map((word, j) => (j === 0 ? path.basename(word) : word));
}

function writesRedirect(segment: string): boolean {
  const masked = maskQuotes(segment).replace(/\d*>&\d+|(?:&|\d)?>>?\s*\/dev\/null\b/g, "");
  return />/.test(masked);
}

const READ_ONLY = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "ag",
  "jq",
  "yq",
  "stat",
  "ls",
  "tree",
  "readlink",
  "realpath",
  "file",
  "wc",
  "diff",
  "cmp",
  "test",
  "[",
  "echo",
  "printf",
  "true",
  "pwd",
  "cd",
  "which",
  "type",
  "sha256sum",
  "sha1sum",
  "md5sum",
  "b2sum",
  "du",
  "df",
  "sort",
  "uniq",
  "cut",
  "tr",
  "column",
  "nl",
  "od",
  "xxd",
  "hexdump",
  "basename",
  "dirname",
]);
// add and commit record the file as it is; they do not change it.
const GIT_READ_ONLY = new Set([
  "status",
  "log",
  "show",
  "diff",
  "blame",
  "ls-files",
  "ls-tree",
  "rev-parse",
  "grep",
  "cat-file",
  "shortlog",
  "describe",
  "add",
  "commit",
]);

function gitArgs(argv: string[]): string[] {
  const args = argv.slice(1);
  while (args.length > 0 && /^-(?:C|c)$|^--(?:git-dir|work-tree)$/.test(args[0]!))
    args.splice(0, 2);
  while (args.length > 0 && args[0]!.startsWith("-")) args.shift();
  return args;
}

function readOnly(argv: string[], segment: string): boolean {
  if (writesRedirect(segment)) return false;
  const [name] = argv;
  if (name === undefined) return true;
  if (name === "sed") return !argv.some((arg) => /^(?:-[a-zA-Z]*i|--in-place)/.test(arg));
  if (name === "find") return !argv.some((arg) => /^-(?:delete|exec|execdir|ok|fprint)/.test(arg));
  if (name === "git") return GIT_READ_ONLY.has(gitArgs(argv)[0] ?? "status");
  return READ_ONLY.has(name);
}

// git subcommands that throw away commits, refs or uncommitted work beyond
// what reflog can bring back.
function destroysHistory(argv: string[]): boolean {
  if (argv[0] !== "git") return false;
  const [sub, ...rest] = gitArgs(argv);
  const has = (...flags: string[]) =>
    rest.some((arg) => flags.some((flag) => arg === flag || arg.startsWith(`${flag}=`)));
  switch (sub) {
    case "reset":
      return has("--hard");
    case "clean":
      return rest.some((arg) => arg === "--force" || /^-[a-zA-Z]*f/.test(arg));
    case "push":
      return (
        has("--force", "-f", "--force-with-lease", "--mirror", "--delete", "-d", "--prune") ||
        rest.some((arg) => /^[+:]/.test(arg))
      );
    case "branch":
      return has("-D") || (has("-d", "--delete") && has("-f", "--force"));
    case "filter-branch":
    case "filter-repo":
      return true;
    case "reflog":
      return rest[0] === "expire" || rest[0] === "delete";
    case "update-ref":
      return has("-d");
    case "stash":
      return rest[0] === "drop" || rest[0] === "clear";
    case "gc":
      return has("--prune");
    default:
      return false;
  }
}

const REMOVERS = new Set(["rm", "rmdir", "shred", "unlink", "trash", "trash-put", "mv"]);
const FIND_ACTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
const XARGS_VALUES = new Set(["-I", "-n", "-P", "-d", "-L", "-s", "-a", "-E", "--arg-file"]);

// Names a find -name glob must not match to narrow a deletion: .git and
// files inside it, the protected files, and what the protected dirs hold.
function protectedNames(roots: ReturnType<typeof protectedRoots>): string[] {
  const names = new Set([".git", "HEAD", "config", "index", "packed-refs", "main", "a.pack"]);
  for (const file of roots.files) names.add(path.basename(file));
  for (const dir of roots.dirs) {
    names.add(path.basename(dir));
    try {
      for (const name of readdirSync(dir)) names.add(name);
    } catch {
      continue;
    }
  }
  return [...names];
}

// find deletes, or runs something that may change what it finds.
function findChanges(argv: string[]): boolean {
  return argv.some(
    (arg, i) =>
      arg === "-delete" ||
      (FIND_ACTIONS.has(arg) && !READ_ONLY.has(path.basename(argv[i + 1] ?? ""))),
  );
}

// find's start points, or none when a -name glob keeps it off everything
// protected. A negated or or-ed glob narrows nothing.
function findTargets(argv: string[], roots: ReturnType<typeof protectedRoots>): string[] {
  const args = argv.slice(1);
  while (/^-(?:[HLP]|O\d)$/.test(args[0] ?? "")) args.shift();
  const end = args.findIndex((arg) => /^[-(!]/.test(arg));
  const starts = end < 0 ? args : args.slice(0, end);
  const globs = argv.flatMap((arg, i) =>
    /^-i?name$/.test(arg) && argv[i + 1] && !["!", "-not"].includes(argv[i - 1] ?? "")
      ? [new RegExp(globRegExp(argv[i + 1]!).source, arg === "-iname" ? "i" : "")]
      : [],
  );
  const alternatives = argv.includes("-o") || argv.includes("-or");
  const names = protectedNames(roots);
  if (!alternatives && globs.some((glob) => !names.some((name) => glob.test(name)))) return [];
  return starts.length > 0 ? starts : ["."];
}

// What a segment removes or rewrites wholesale: a remover's operands, a
// changing find's start points, an rsync --delete destination, and a
// remover run by xargs over a find's output (`previous`).
function removedPaths(
  argv: string[],
  previous: string[],
  roots: ReturnType<typeof protectedRoots>,
): string[] {
  const [name = "", ...args] = argv;
  const operands = (list: string[]) => list.filter((arg) => !arg.startsWith("-"));
  // mv's last argument is where things go, not what goes.
  if (REMOVERS.has(name)) return operands(name === "mv" ? args.slice(0, -1) : args);
  if (name === "find") return findChanges(argv) ? findTargets(argv, roots) : [];
  if (name === "rsync") {
    const paths = operands(args);
    return [
      ...(args.some((arg) => arg.startsWith("--delete")) ? paths.slice(-1) : []),
      ...(args.includes("--remove-source-files") ? paths.slice(0, -1) : []),
    ];
  }
  if (name !== "xargs") return [];
  let i = 0;
  while (args[i]?.startsWith("-")) i += XARGS_VALUES.has(args[i]!) ? 2 : 1;
  const inner = args.slice(i).map((word, j) => (j === 0 ? path.basename(word) : word));
  if (!REMOVERS.has(inner[0] ?? "")) return [];
  const piped = previous[0] === "find" ? findTargets(previous, roots) : [];
  return [...removedPaths(inner, [], roots), ...piped];
}

// Directories the command moves into, so a relative name after `cd dir &&`
// or `git -C dir` resolves where it will run.
function commandDirs(command: string, cwd: string): string[] {
  const dirs = [cwd];
  for (const segment of segments(command)) {
    const argv = program(segment);
    const target =
      argv[0] === "cd" || argv[0] === "pushd"
        ? argv[1]
        : argv[0] === "git" && argv[1] === "-C"
          ? argv[2]
          : undefined;
    if (target) dirs.push(path.resolve(cwd, expandHome(target)));
  }
  return dirs;
}

function bashChange(
  raw: string,
  cwd: string,
  roots: ReturnType<typeof protectedRoots>,
): ProtectedKind | undefined {
  const command = heredocsAsData(raw);
  const dirs = commandDirs(command, cwd);
  let previous: string[] = [];
  for (const segment of segments(command)) {
    const argv = program(segment);
    const upstream = previous;
    previous = argv;
    if (destroysHistory(argv)) return "git";
    if (readOnly(argv, segment)) continue;
    const removed = removedPaths(argv, upstream, roots);
    for (const dir of dirs) {
      for (const candidate of commandPathCandidates(segment, dir)) {
        const kind = protectedPath(candidate, dir, roots);
        if (kind) return kind;
      }
      for (const operand of removed) {
        for (const candidate of commandPathCandidates(operand, dir)) {
          const kind = holdsProtected(candidate, dir, roots);
          if (kind) return kind;
        }
      }
    }
  }
  return undefined;
}

// A shell call that may write something: a segment that is not a read.
export function shellWrites(args: unknown): boolean {
  const command = shellCommand(args);
  if (command === undefined) return false;
  return segments(command).some((segment) => !readOnly(program(segment), segment));
}

// What a tool call would change that is protected, or undefined. Shell and
// write calls are known by their arguments as well as their name (tools.ts).
export function protectedChange(
  toolName: string,
  args: unknown,
  cwd: string,
): ProtectedKind | undefined {
  const command = shellCommand(args);
  if (command !== undefined) return bashChange(command, cwd, protectedRoots());
  const targets = writeTargets(toolName, args);
  if (!targets) return;
  const roots = protectedRoots();
  for (const target of targets) {
    const kind = protectedPath(target, cwd, roots);
    if (kind) return kind;
  }
  return undefined;
}
