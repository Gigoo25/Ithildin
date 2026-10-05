// Swap-back: tool calls name stand-ins, tools need real values.
//
// The model only ever sees stand-ins. When it calls a tool with one, the proxy
// replaces the stand-in with the real value in the call's arguments, in the
// reply on its way to the agent (proxy/src/streams.ts). The agent runs the
// tool with the real value and keeps it in its transcript. The tool's output
// is scanned on the way back as usual, and every value swapped in here is
// added to that scan, so the next request carries the stand-in again.
//
// Egress: a real value must not leave the machine for somewhere that is not
// your own infrastructure. The web tools never get swapped values. In Bash,
// a command that talks to the network may carry a stand-in only as the
// destination it connects to (your host); a stand-in anywhere else in such
// a command (a query string, a request body, a pipe into curl) is egress,
// and the caller blocks the call.
// This is a lexical check: a script written to disk and run later is out of
// its reach.

import type { AliasBook, Resolved } from "./aliases.ts";
import { assert } from "./assert.ts";

export interface Swap {
  // Arguments with every stand-in replaced (same shape as the input).
  input: unknown;
  resolved: Resolved[];
  // Stand-ins that could not be resolved (another key, or never seen).
  unresolved: string[];
  // Stand-ins in positions that would send the real value off the machine.
  egress: string[];
}

const WEB_TOOLS = new Set(["web_fetch", "web_search"]);

// Programs that send data over the network, and those among them whose bare
// positional argument is a destination host.
const NETWORK_CLIENTS = new Set([
  "curl",
  "wget",
  "http",
  "https",
  "xh",
  "httpie",
  "aria2c",
  "nc",
  "ncat",
  "netcat",
  "socat",
  "telnet",
  "ftp",
  "lftp",
  "ssh",
  "scp",
  "sftp",
  "rsync",
  "mosh",
  "git",
]);
const GIT_NETWORK = new Set(["push", "fetch", "pull", "clone", "ls-remote"]);
const HOST_ARG_CLIENTS = new Set([
  "nc",
  "ncat",
  "netcat",
  "telnet",
  "ssh",
  "sftp",
  "mosh",
  "ftp",
  "lftp",
]);
// ssh-style options that take a value.
const OPTION_VALUES = new Set([
  "-p",
  "-P",
  "-i",
  "-l",
  "-o",
  "-F",
  "-J",
  "-L",
  "-R",
  "-D",
  "-b",
  "-c",
  "-E",
  "-e",
  "-m",
  "-O",
  "-Q",
  "-S",
  "-W",
  "-w",
  "-B",
]);

type Span = { text: string; start: number; end: number };

// Stand-ins look like real values, so the book finds them by what it
// minted: whole words only (a stand-in glued into a longer word is something
// else), longest first, and names composed from known parts. Exact stand-ins
// keep the value's case: a mixed-case hostname resolved piece by piece came
// back lowercased, and a case-sensitive lookup (a flake attribute) failed.
function standInSpans(text: string, book: AliasBook): Span[] {
  const found = book.matches(text);
  found.sort((left, right) => left.start - right.start || right.end - left.end);
  const spans: Span[] = [];
  for (const span of found)
    if (!spans.length || span.start >= spans[spans.length - 1]!.end) spans.push(span);
  return spans;
}

// Programs that run the command after them, and their options.
const LAUNCHERS = new Set([
  "sudo",
  "doas",
  "env",
  "command",
  "exec",
  "time",
  "nice",
  "nohup",
  "timeout",
  "xargs",
  "stdbuf",
  "ionice",
  "chrt",
  "taskset",
  "setsid",
  "unbuffer",
  "watch",
  "flock",
  "parallel",
  "{",
  "!",
]);

function clientName(word: string): string {
  return (
    word
      .replace(/^[$"'`(]+/, "")
      .split("/")
      .pop() ?? ""
  );
}

// Where a network client sits in a segment's words: the program, the one a
// launcher runs past its options (timeout 5 wget, sudo -u me curl), or the
// first word of a nested script (bash -c "curl …", $(curl …)).
function clientIndex(words: string[]): number | undefined {
  let launched = true;
  let option = false;
  for (const [j, word] of words.entries()) {
    const name = clientName(word);
    if (NETWORK_CLIENTS.has(name) && (launched || /^(?:["'`(]|\$\()/.test(word))) return j;
    if (LAUNCHERS.has(name) || /^[A-Za-z_]\w*=/.test(word)) launched = true;
    else if (launched && (word.startsWith("-") || option || /^\d/.test(word))) {
      option = word.startsWith("-");
      continue;
    } else launched = false;
    option = false;
  }
  return undefined;
}

// Character ranges of network destinations in a Bash command: URL hosts,
// user@host / host:path arguments, and the host argument of ssh-like and
// nc-like clients. Undefined when the command talks to the network at all.
function destinations(command: string): Array<{ start: number; end: number }> | undefined {
  const segments = [...command.matchAll(/[^|;&\n]+/g)];
  let network = false;
  const ranges: Array<{ start: number; end: number }> = [];
  for (const segment of segments) {
    const words = [...segment[0].matchAll(/\S+/g)].map((word) => ({
      text: word[0],
      start: segment.index + word.index,
    }));
    const i = clientIndex(words.map((word) => word.text));
    if (i === undefined) continue;
    const program = clientName(words[i]!.text);
    if (program === "git" && !words.slice(i + 1).some((word) => GIT_NETWORK.has(word.text)))
      continue;
    network = true;
    for (const url of segment[0].matchAll(
      /[a-z][a-z0-9+.-]*:\/\/(?:[^@\s/]*@)?(\[[^\]\s]+\]|[^/:\s?#'"]+)/gi,
    )) {
      const host = url[1] ?? "";
      const start = segment.index + url.index + url[0].length - host.length;
      ranges.push({ start, end: start + host.length });
    }
    let hostTaken = false;
    for (let j = i + 1; j < words.length; j++) {
      const word = words[j]!;
      if (OPTION_VALUES.has(word.text)) {
        j++;
        continue;
      }
      if (word.text.startsWith("-") || word.text.includes("://")) continue;
      // user@host, host:path (scp, rsync, git), or a bare host argument.
      const target = /^(?:[^@\s]+@)?([^:\s/@]+)(?::|$)/.exec(word.text);
      if (!target) continue;
      const scpLike = word.text.includes(":") || word.text.includes("@");
      if (scpLike || (HOST_ARG_CLIENTS.has(program) && !hostTaken)) {
        const host = target[1] ?? "";
        const start = word.start + word.text.indexOf(host, word.text.indexOf("@") + 1);
        ranges.push({ start, end: start + host.length });
        hostTaken = true;
      }
    }
  }
  return network ? ranges : undefined;
}

// Whether a command runs a network client (git only when it talks to a remote).
export function reachesNetwork(command: string): boolean {
  return destinations(command) !== undefined;
}

function swapString(
  text: string,
  book: AliasBook,
  out: Swap,
  egress: (span: Span) => boolean,
): string {
  let result = "";
  let last = 0;
  for (const span of standInSpans(text, book)) {
    // Overlapping spans would copy text twice around the swapped value.
    assert(last <= span.start && span.end <= text.length, "stand-in spans ordered, in text");
    const resolved = book.resolve(span.text);
    if (!resolved) {
      out.unresolved.push(span.text);
      continue;
    }
    if (egress(span)) {
      out.egress.push(span.text);
      continue;
    }
    out.resolved.push(resolved);
    result += text.slice(last, span.start) + resolved.value;
    last = span.end;
  }
  return result + text.slice(last);
}

// `list`/`index`: a string inside an array is visited with the array's key
// and its place in it, so an argv command is checked as one command line.
function walk(
  value: unknown,
  visit: (text: string, key: string | undefined, list?: unknown[], index?: number) => string,
  key?: string,
): unknown {
  if (typeof value === "string") return visit(value, key);
  if (Array.isArray(value))
    return value.map((item, index) =>
      typeof item === "string" ? visit(item, key, value, index) : walk(item, visit),
    );
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, item]) => [childKey, walk(item, visit, childKey)]),
    );
  }
  return value;
}

// The spans of a command line that would leave the machine, or none when
// the command does not talk to the network.
function commandEgress(text: string, book: AliasBook): (span: Span) => boolean {
  const ranges = destinations(text);
  // Every destination a stand-in: the data goes to your own hosts, so
  // stand-ins may appear anywhere (ssh host-… "cat /home/user-…/x").
  const spans = ranges ? standInSpans(text, book) : [];
  const external =
    ranges !== undefined &&
    (ranges.length === 0 ||
      ranges.some(
        (range) => !spans.some((span) => span.start <= range.start && span.end >= range.end),
      ));
  if (!external) return () => false;
  return (span) => !ranges!.some((range) => span.start >= range.start && span.end <= range.end);
}

// One word of an argv command (Codex: ["curl", "-d", …] or ["bash", "-lc",
// script]): egress in the argv read as one command line, or in the word read
// as a command line of its own (a shell's script).
function argvEgress(list: unknown[], index: number, book: AliasBook): (span: Span) => boolean {
  const words = list.map((word) => (typeof word === "string" ? word : ""));
  const offset = words.slice(0, index).reduce((sum, word) => sum + word.length + 1, 0);
  const whole = commandEgress(words.join(" "), book);
  const own = commandEgress(words[index]!, book);
  return (span) =>
    own(span) || whole({ ...span, start: span.start + offset, end: span.end + offset });
}

const COMMAND_KEYS = new Set(["command", "cmd", "script"]);

// `offMachineAllowed`: [allow-pii] lets real values go anywhere.
export function planSwapBack(
  toolName: string,
  input: unknown,
  book: AliasBook,
  offMachineAllowed: boolean,
): Swap {
  const out: Swap = { input, resolved: [], unresolved: [], egress: [] };
  // A shell call with its script under some other key: any string may run.
  const keyed =
    !!input && typeof input === "object" && Object.keys(input).some((k) => COMMAND_KEYS.has(k));
  out.input = walk(input, (text, key, list, index) => {
    let egress: (span: Span) => boolean = () => false;
    if (!offMachineAllowed) {
      if (WEB_TOOLS.has(toolName)) egress = () => true;
      else if (toolName === "bash" && (!keyed || (key !== undefined && COMMAND_KEYS.has(key))))
        egress = list ? argvEgress(list, index!, book) : commandEgress(text, book);
    }
    return swapString(text, book, out, egress);
  });
  return out;
}
