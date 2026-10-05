// The leak watch: strings that must never leave this machine. Each outgoing
// request is checked after redaction, so a hit means masking missed the
// string. It tests the masking from outside, which the footer and the
// self-test cannot: they count what was caught, and a miss leaves no trace.
//
// Two lists are watched:
//
//   known   the values the engine promises to mask everywhere: your
//           inventory, and what the proxy reads from this machine (its user
//           name, host name, home directory, git remotes, SSH hosts). It
//           needs no setup. A hit is flagged on the dashboard and never
//           blocks the request.
//   terms   strings you add under "watch" in config.json, beside the
//           inventory:
//
//             "watch": {
//               "terms": ["acme-internal.example", "Project Falcon"],
//               "action": "flag",
//               "known": true
//             }
//
// terms are plain text, matched case-insensitively anywhere in a text, even
// inside a longer word. Each has at least MIN_TERM_CHARS characters, and at
// most TERMS_MAX are read. action is "flag" (the default), which shows the
// hit on the dashboard and sends the request, or "block", which also refuses
// the request. known is true by default; false stops that list.
//
// Checked: every string in the request body, and the path and query. Not
// checked: headers (they carry the user's own credentials), and a value sent
// encoded (base64, hex). A string is a hit wherever it sits, thinking blocks
// included, since those go out unscanned. Skipped for a prompt that carries
// [allow-pii] or [allow-all]: the user lifted masking on purpose.
//
// Read again whenever the file changes. The engine ignores the section.

import { inventoryLiterals, readConfigFile } from "../engine/lib/rules.ts";
import { configKey, guardConfigFile } from "./policy.ts";

export const MIN_TERM_CHARS = 3;
export const MIN_KNOWN_CHARS = 4;
export const TERMS_MAX = 200;
// Places reported per string in one request, and hits reported per request.
const LOCATIONS_PER_TERM = 3;
const HITS_MAX = 20;
// A little past the deepest body the proxy forwards (JSON_DEPTH_MAX in server.ts).
const DEPTH_MAX = 260;
const TOKEN = /[\p{L}\p{N}_]+/gu;
const TOKEN_CHAR = /[\p{L}\p{N}_]/u;

export type WatchAction = "flag" | "block";

export interface WatchPolicy {
  terms: string[];
  action: WatchAction;
  known: boolean;
  // What was wrong with the section, already left out.
  problems: string[];
}

// A value the engine masks, and how: the match rules of its inventory entry.
export interface KnownValue {
  literal: string;
  caseSensitive: boolean;
  token: boolean;
}

export interface WatchHit {
  // The string found. It is only handed on to be cut to a preview.
  value: string;
  source: "watch" | "known";
  // `messages[3].content[0].text`, `path` or `query`.
  where: string;
}

function empty(problems: string[] = []): WatchPolicy {
  return { terms: [], action: "flag", known: true, problems };
}

export function parseWatchPolicy(config: unknown): WatchPolicy {
  const watch = (config as { watch?: unknown } | undefined)?.watch;
  if (watch === undefined) return empty();
  if (!watch || typeof watch !== "object" || Array.isArray(watch))
    return empty([`"watch" must be an object`]);
  const record = watch as Record<string, unknown>;
  const policy = empty();
  for (const key of Object.keys(record))
    if (key !== "terms" && key !== "action" && key !== "known")
      policy.problems.push(`"watch.${key}" is not a watch setting`);
  readAction(record.action, policy);
  readKnown(record.known, policy);
  readTerms(record.terms, policy);
  return policy;
}

function readAction(value: unknown, policy: WatchPolicy): void {
  if (value === undefined) return;
  if (value === "flag" || value === "block") policy.action = value;
  else policy.problems.push(`"watch.action" must be "flag" or "block"`);
}

function readKnown(value: unknown, policy: WatchPolicy): void {
  if (value === undefined) return;
  if (typeof value === "boolean") policy.known = value;
  else policy.problems.push(`"watch.known" must be true or false`);
}

function readTerms(value: unknown, policy: WatchPolicy): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) {
    policy.problems.push(`"watch.terms" must be a string array`);
    return;
  }
  const seen = new Set<string>();
  for (const term of value) {
    if (typeof term !== "string") policy.problems.push(`"watch.terms" must be a string array`);
    else if ([...term].length < MIN_TERM_CHARS)
      policy.problems.push(`"watch.terms": an entry is under ${MIN_TERM_CHARS} characters`);
    else if (!seen.has(term.toLowerCase())) {
      seen.add(term.toLowerCase());
      policy.terms.push(term);
    }
  }
  if (policy.terms.length > TERMS_MAX) {
    policy.problems.push(`"watch.terms" has more than ${TERMS_MAX} entries, keeping the first`);
    policy.terms.length = TERMS_MAX;
  }
}

let cached: { key: string; policy: WatchPolicy } | undefined;

// The policy in force: the file's, re-read when its path, mtime or size moves.
export function watchPolicy(): WatchPolicy {
  const file = guardConfigFile();
  const key = configKey(file);
  if (cached?.key !== key) {
    const policy = key.endsWith("\0absent")
      ? empty()
      : parseWatchPolicy(readConfigFile(file, "user config"));
    for (const problem of policy.problems)
      process.stderr.write(`ithildin: user config: ${problem}, ignoring\n`);
    cached = { key, policy };
  }
  return cached.policy;
}

// The values the engine masks wherever it scans, from its inventory.
export function knownValues(): KnownValue[] {
  const seen = new Set<string>();
  const found: KnownValue[] = [];
  for (const { literal, caseSensitive, token } of inventoryLiterals()) {
    const key = `${caseSensitive}\0${token}\0${caseSensitive ? literal : literal.toLowerCase()}`;
    if ([...literal].length < MIN_KNOWN_CHARS || !TOKEN_CHAR.test(literal) || seen.has(key))
      continue;
    seen.add(key);
    found.push({ literal, caseSensitive, token });
  }
  return found;
}

// Known values by their first word, so one pass over a text finds them all.
// `lead` is how much of a value comes before that word. A value that may match
// inside a longer word has no first word to look up, so those are kept apart.
type Candidate = KnownValue & { text: string; lead: number };
interface KnownIndex {
  byWord: Map<string, Candidate[]>;
  loose: Candidate[];
}

function indexKnown(values: KnownValue[]): KnownIndex {
  const index: KnownIndex = { byWord: new Map(), loose: [] };
  for (const value of values) {
    const first = new RegExp(TOKEN).exec(value.literal)!;
    const text = value.caseSensitive ? value.literal : value.literal.toLowerCase();
    const candidate = { ...value, text, lead: first.index };
    if (!value.token) {
      index.loose.push(candidate);
      continue;
    }
    const word = value.caseSensitive ? first[0] : first[0].toLowerCase();
    index.byWord.set(word, [...(index.byWord.get(word) ?? []), candidate]);
  }
  return index;
}

// Whether a word-bounded value stands at `start` of the text.
function stands(text: string, candidate: Candidate, start: number): boolean {
  if (start < 0 || !text.startsWith(candidate.text, start)) return false;
  const end = start + candidate.text.length;
  return !TOKEN_CHAR.test(text[start - 1] ?? "") && !TOKEN_CHAR.test(text[end] ?? "");
}

function knownIn(text: string, index: KnownIndex): string[] {
  if (index.byWord.size === 0 && index.loose.length === 0) return [];
  const lower = text.toLowerCase();
  const found: string[] = [];
  for (const match of text.matchAll(TOKEN)) {
    const word = match[0];
    const candidates = new Set([
      ...(index.byWord.get(word) ?? []),
      ...(index.byWord.get(word.toLowerCase()) ?? []),
    ]);
    for (const candidate of candidates) {
      const subject = candidate.caseSensitive ? text : lower;
      if (stands(subject, candidate, match.index - candidate.lead)) found.push(candidate.literal);
    }
  }
  for (const candidate of index.loose)
    if ((candidate.caseSensitive ? text : lower).includes(candidate.text))
      found.push(candidate.literal);
  return found;
}

function termsIn(text: string, terms: string[]): string[] {
  const lower = text.toLowerCase();
  return terms.filter((term) => lower.includes(term.toLowerCase()));
}

function decoded(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

interface Scan {
  terms: string[];
  index: KnownIndex;
  hits: WatchHit[];
  counts: Map<string, number>;
}

function note(scan: Scan, source: WatchHit["source"], value: string, where: string): void {
  const key = `${source}\0${value}`;
  const count = scan.counts.get(key) ?? 0;
  if (count >= LOCATIONS_PER_TERM || scan.hits.length >= HITS_MAX) return;
  scan.counts.set(key, count + 1);
  scan.hits.push({ value, source, where });
}

function scanText(scan: Scan, text: string, where: string): void {
  for (const term of termsIn(text, scan.terms)) note(scan, "watch", term, where);
  for (const literal of new Set(knownIn(text, scan.index))) note(scan, "known", literal, where);
}

function walk(scan: Scan, value: unknown, path: string, depth: number): void {
  if (typeof value === "string") scanText(scan, value, path);
  else if (depth < DEPTH_MAX && value && typeof value === "object")
    for (const [key, child] of Object.entries(value))
      walk(
        scan,
        child,
        Array.isArray(value) ? `${path}[${key}]` : path ? `${path}.${key}` : key,
        depth + 1,
      );
}

// Every watched string in the request about to be sent: in its redacted body
// (as parsed JSON), its path and its query. `known` lists the values to hold
// to the engine's promise; leave it empty to watch the terms alone.
export function findWatched(
  policy: Pick<WatchPolicy, "terms">,
  known: KnownValue[],
  target: { body: unknown; path: string; search: string },
): WatchHit[] {
  const scan: Scan = { terms: policy.terms, index: indexKnown(known), hits: [], counts: new Map() };
  walk(scan, target.body, "", 0);
  scanText(scan, decoded(target.path), "path");
  scanText(scan, decoded(target.search), "query");
  return scan.hits;
}
