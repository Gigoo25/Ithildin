// Swap-back: tool calls name stand-ins, tools need real values.
//
// The model only ever sees stand-ins. When it calls a tool with one, the
// stand-in is replaced by the real value in the call's arguments just before
// the tool runs (Pi runs the tool with the mutated `event.input`; the
// transcript keeps the model's original arguments). The tool's output is
// scanned on the way back as usual, and every value swapped in here is added
// to that scan, so it returns to the model as its stand-in again.
//
// Egress: a real value must not leave the machine for somewhere that is not
// your own infrastructure. The web tools never get swapped values. In Bash,
// a command that talks to the network may carry a stand-in only as the
// destination it connects to (your host); a stand-in anywhere else in such
// a command (a query string, a request body, a pipe into curl) blocks it.
// This is a lexical check: a script written to disk and run later is out of
// its reach.

import { type AliasBook, aliasMatches, type Resolved } from "./aliases.ts";

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
  "curl", "wget", "http", "https", "xh", "httpie", "aria2c", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "lftp",
  "ssh", "scp", "sftp", "rsync", "mosh", "git",
]);
const GIT_NETWORK = new Set(["push", "fetch", "pull", "clone", "ls-remote"]);
const HOST_ARG_CLIENTS = new Set(["nc", "ncat", "netcat", "telnet", "ssh", "sftp", "mosh", "ftp", "lftp"]);
// ssh-style options that take a value.
const OPTION_VALUES = new Set(["-p", "-P", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-m", "-O", "-Q", "-S", "-W", "-w", "-B"]);

type Span = { text: string; start: number; end: number };

function standInSpans(text: string, book: AliasBook): Span[] {
  const found = aliasMatches(text);
  // IPv6 and MAC stand-ins share their shape with documentation values, so
  // only exact stand-ins this process minted are swapped.
  for (const standIn of book.standIns()) {
    if (!standIn.startsWith("2001:db8:") && !standIn.startsWith("02:") && !standIn.startsWith("02-")) continue;
    for (let at = text.indexOf(standIn); at >= 0; at = text.indexOf(standIn, at + 1)) {
      found.push({ text: standIn, start: at, end: at + standIn.length });
    }
  }
  found.sort((left, right) => left.start - right.start || right.end - left.end);
  const spans: Span[] = [];
  for (const span of found) if (!spans.length || span.start >= spans[spans.length - 1]!.end) spans.push(span);
  return spans;
}

// Character ranges of network destinations in a Bash command: URL hosts,
// user@host / host:path arguments, and the host argument of ssh-like and
// nc-like clients. Undefined when the command talks to the network at all.
function destinations(command: string): Array<{ start: number; end: number }> | undefined {
  const segments = [...command.matchAll(/[^|;&\n]+/g)];
  let network = false;
  const ranges: Array<{ start: number; end: number }> = [];
  for (const segment of segments) {
    const words = [...segment[0].matchAll(/\S+/g)].map((word) => ({ text: word[0], start: segment.index + word.index }));
    let i = 0;
    while (i < words.length && (/^[A-Za-z_]\w*=/.test(words[i]!.text) || ["sudo", "env", "command", "time", "nohup"].includes(words[i]!.text))) i++;
    const program = (words[i]?.text ?? "").split("/").pop() ?? "";
    if (!NETWORK_CLIENTS.has(program)) continue;
    if (program === "git" && !words.slice(i + 1).some((word) => GIT_NETWORK.has(word.text))) continue;
    network = true;
    for (const url of segment[0].matchAll(/[a-z][a-z0-9+.-]*:\/\/(?:[^@\s/]*@)?(\[[^\]\s]+\]|[^/:\s?#'"]+)/gi)) {
      const host = url[1] ?? "";
      const start = segment.index + url.index + url[0].length - host.length;
      ranges.push({ start, end: start + host.length });
    }
    let hostTaken = false;
    for (let j = i + 1; j < words.length; j++) {
      const word = words[j]!;
      if (OPTION_VALUES.has(word.text)) { j++; continue; }
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

function swapString(text: string, book: AliasBook, out: Swap, egress: (span: Span) => boolean): string {
  let result = "";
  let last = 0;
  for (const span of standInSpans(text, book)) {
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

function walk(value: unknown, visit: (text: string, key: string | undefined) => string, key?: string): unknown {
  if (typeof value === "string") return visit(value, key);
  if (Array.isArray(value)) return value.map((item) => walk(item, visit));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, item]) => [childKey, walk(item, visit, childKey)]));
  }
  return value;
}

// `offMachineAllowed`: [allow-pii] lets real values go anywhere.
export function planSwapBack(toolName: string, input: unknown, book: AliasBook, offMachineAllowed: boolean): Swap {
  const out: Swap = { input, resolved: [], unresolved: [], egress: [] };
  out.input = walk(input, (text, key) => {
    let egress: (span: Span) => boolean = () => false;
    if (!offMachineAllowed) {
      if (WEB_TOOLS.has(toolName)) egress = () => true;
      else if (toolName === "bash" && key === "command") {
        const ranges = destinations(text);
        // Every destination a stand-in: the data goes to your own hosts, so
        // stand-ins may appear anywhere (ssh host-… "cat /home/user-…/x").
        const spans = ranges ? standInSpans(text, book) : [];
        const external = ranges !== undefined &&
          (ranges.length === 0 || ranges.some((range) => !spans.some((span) => span.start <= range.start && span.end >= range.end)));
        if (external) egress = (span) => !ranges!.some((range) => span.start >= range.start && span.end <= range.end);
      }
    }
    return swapString(text, book, out, egress);
  });
  return out;
}

// Mutates `target` in place to match `source` (Pi reads the same object).
export function assignInPlace(target: unknown, source: unknown): void {
  if (!target || typeof target !== "object" || !source || typeof source !== "object") return;
  for (const [key, value] of Object.entries(source)) {
    const current = (target as Record<string, unknown>)[key];
    if (current && typeof current === "object" && value && typeof value === "object" && Array.isArray(current) === Array.isArray(value)) {
      if (Array.isArray(current)) current.splice(0, current.length, ...(value as unknown[]));
      else assignInPlace(current, value);
    } else {
      (target as Record<string, unknown>)[key] = value;
    }
  }
}
