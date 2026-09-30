// Meaningful, stable stand-ins for PII (not secrets).
//
// A stand-in looks like a real value of the same kind, and keeps the role,
// shape and relationships of the value it replaces, so the model reasons
// about it as it would the real one and never suspects anything was swapped:
//
//   ticket ABC-1234             ->  RUG-8305     (same length, case, digits)
//   handle, username            ->  a pronounceable word of the same shape
//   Mark Smith                  ->  Doris Ellen  (other first names)
//   prod-pg-use1.acme.internal  ->  prod-pg-use1.otvi.internal (role words stay)
//   203.0.113.7 / 203.0.113.9   ->  241.18.5.7 / 241.18.5.9   (same /24 stays together)
//
// Stand-ins that looked like hashes (a label and six hex digits) read as
// corrupted data: a model rewrote a report five times to "repair" them.
//
// Every stand-in is an HMAC of the real value under a local random key, so:
// - the same value maps to the same stand-in for as long as the key lives,
// - nothing but the key and keyed hashes is written to disk (no table of
//   real values),
// - the model cannot reverse a stand-in without the key.
// By default each session has its own key (next to its transcript), so a
// provider cannot join stand-ins across sessions into a profile. Resuming a
// session reuses its key; a fork inherits its parent's.
// Because they look real, stand-ins are found for swap-back by what this
// book minted, never by shape, and a new one is never a common word or a
// word already in the conversation. Network values keep reserved space
// (240.0.0.0/5, 2001:db8::/32, locally administered MACs), which reads as
// ordinary addresses. 240.0.0.0/5 instead of the IPv4 documentation ranges:
// those hold only three /24s, too few to keep one stand-in per subnet.

import { createHmac, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { FIRST_NAMES } from "./first-names.ts";
import { sessionFile as sessionPath, setting, stateDir } from "./names.ts";

export type AliasKind =
  "host" | "user" | "email" | "user-at-host" | "home" | "ipv4" | "ipv6" | "mac" | "label";

// Hostname and email-domain words that describe a role or a place, not an
// owner. They survive aliasing because they carry the meaning.
const ROLE_WORDS = new Set([
  "prod",
  "production",
  "prd",
  "stage",
  "staging",
  "stg",
  "dev",
  "devel",
  "development",
  "test",
  "testing",
  "qa",
  "uat",
  "sandbox",
  "demo",
  "preview",
  "db",
  "pg",
  "postgres",
  "postgresql",
  "mysql",
  "mariadb",
  "redis",
  "mongo",
  "mongodb",
  "elastic",
  "es",
  "kafka",
  "rabbitmq",
  "mq",
  "cache",
  "memcached",
  "web",
  "www",
  "api",
  "app",
  "apps",
  "svc",
  "service",
  "backend",
  "frontend",
  "admin",
  "auth",
  "sso",
  "idp",
  "ldap",
  "vault",
  "secrets",
  "lb",
  "proxy",
  "gw",
  "gateway",
  "ingress",
  "edge",
  "cdn",
  "static",
  "media",
  "files",
  "assets",
  "upload",
  "download",
  "vpn",
  "wg",
  "bastion",
  "jump",
  "ssh",
  "ftp",
  "sftp",
  "mail",
  "smtp",
  "imap",
  "mx",
  "ns",
  "dns",
  "ntp",
  "dhcp",
  "git",
  "ci",
  "cd",
  "build",
  "builder",
  "runner",
  "worker",
  "workers",
  "job",
  "jobs",
  "cron",
  "queue",
  "scheduler",
  "node",
  "nodes",
  "master",
  "primary",
  "secondary",
  "replica",
  "standby",
  "backup",
  "archive",
  "restore",
  "monitor",
  "monitoring",
  "metrics",
  "grafana",
  "prometheus",
  "alert",
  "alerts",
  "log",
  "logs",
  "logging",
  "trace",
  "tracing",
  "nas",
  "san",
  "storage",
  "s3",
  "minio",
  "k8s",
  "kube",
  "kubernetes",
  "cluster",
  "control",
  "docker",
  "registry",
  "vm",
  "host",
  "hv",
  "router",
  "switch",
  "ap",
  "wifi",
  "printer",
  "camera",
  "iot",
  "home",
  "office",
  "lab",
  "desktop",
  "laptop",
  "workstation",
  "server",
  "srv",
  "internal",
  "int",
  "ext",
  "external",
  "corp",
  "lan",
  "local",
  "localdomain",
  "private",
  "public",
  "arpa",
  "intranet",
  "eu",
  "us",
  "uk",
  "de",
  "fr",
  "ca",
  "au",
  "jp",
  "cn",
  "in",
  "br",
  "asia",
  "emea",
  "apac",
  "amer",
  "east",
  "west",
  "north",
  "south",
  "central",
  "use1",
  "use2",
  "usw1",
  "usw2",
  "euw1",
  "euc1",
  "com",
  "net",
  "org",
  "io",
  "co",
  "info",
  "biz",
  "cloud",
  "tech",
  "online",
  "site",
  "gmail",
  "googlemail",
  "outlook",
  "hotmail",
  "live",
  "yahoo",
  "icloud",
  "me",
  "proton",
  "protonmail",
  "pm",
  "fastmail",
  "gmx",
  "aol",
]);

// Built-in rule ids that name a person, an account, a place: the label that
// stands in for them. Anything unlisted falls back to "pii".
const RULE_LABELS: ReadonlyArray<[RegExp, string]> = [
  [/name/, "person"],
  [/ssid/, "ssid"],
  [/phone/, "phone"],
  [/street|address/, "address"],
  [/geo/, "geo"],
  [/postal/, "postal"],
  [/credit-card|card/, "card"],
  [/bank|iban|account/, "account"],
  [/machine-id/, "machine"],
  [/passport|ssn|nir|dni|rrn|brn|mynumber|codice|steuer|resident|11070|customer-id|-wo$/, "id"],
];

export function aliasKind(ruleId: string): AliasKind {
  const id = ruleId.toLowerCase();
  if (/user-at-host/.test(id)) return "user-at-host";
  if (/ipv6/.test(id)) return "ipv6";
  if (/ipv4|tailscale-ip|-ip(?:-\d+)?$/.test(id)) return "ipv4";
  if (/(?:^|-)mac(?:$|-)/.test(id)) return "mac";
  if (/email/.test(id)) return "email";
  if (/runtime-home(?:-\d+)?$/.test(id)) return "home";
  if (/host/.test(id)) return "host";
  if (/user|login|owner/.test(id)) return "user";
  return "label";
}

function labelForRule(ruleId: string, custom: string | undefined): string {
  if (custom !== undefined) return custom;
  const id = ruleId.toLowerCase();
  for (const [pattern, label] of RULE_LABELS) if (pattern.test(id)) return label;
  return "pii";
}

// Recognizes the older hash-like stand-in shapes (a label and six hex
// digits, n-hashed host parts under .example), which transcripts from before
// lookalike stand-ins still hold. Nothing resolves them any more; they are
// recognized so a write naming one can be stopped. Labelled shapes need a
// known label (so branch names like feature-123456 never match), and
// .example must be the final label after a hashed one (so www.example.com
// and .env.example never match).
const BUILTIN_LABELS = [
  "user",
  "host",
  "person",
  "ssid",
  "phone",
  "address",
  "geo",
  "postal",
  "card",
  "account",
  "machine",
  "id",
  "pii",
  "ip",
  "mac",
  "email",
];
const labels = new Set(BUILTIN_LABELS);
let shapes: RegExp[] = [];
let spans = /$^/g;

function compileShapes(): void {
  const labelled = `\\b(?:${[...labels].join("|")})-[0-9a-f]{6}\\b`;
  // Longest shape first, so host-3c9d0e.example is one span, not two.
  const sources = [
    "\\b[a-z0-9.-]*(?<![a-z0-9])(?:n|host-)[0-9a-f]{6}(?![a-z0-9])" +
      "[a-z0-9.-]*\\.example(?![\\w-]|\\.[\\w-])",
    labelled,
    "\\bn[0-9a-f]{6}\\b",
    "\\b24[0-7](?:\\.\\d{1,3}){3}\\b",
  ];
  shapes = sources.map((source) => new RegExp(source));
  spans = new RegExp(sources.join("|"), "g");
}
compileShapes();

export const ALIAS_LABEL = /^[a-z][a-z0-9]{0,15}$/;

// Custom inventory and rule labels join the recognized set.
export function registerAliasLabels(extra: Iterable<string>): void {
  let changed = false;
  for (const label of extra) {
    if (!ALIAS_LABEL.test(label) || labels.has(label)) continue;
    labels.add(label);
    changed = true;
  }
  if (changed) compileShapes();
}

export function looksLikeAlias(text: string): boolean {
  return shapes.some((shape) => shape.test(text));
}

// Every stand-in-shaped span in a tool call's arguments.
export function aliasSpans(text: string): string[] {
  return aliasMatches(text).map((match) => match.text);
}

export function aliasMatches(text: string): Array<{ text: string; start: number; end: number }> {
  return [...text.matchAll(spans)].map((match) => ({
    text: match[0],
    start: match.index,
    end: match.index + match[0].length,
  }));
}

// True when the whole value is stand-ins. An email counts when its local
// part is one: a role-only domain (gmail.com.example) has no hashed label.
export function isAliasValue(text: string): boolean {
  if (text.length === 0) return false;
  if (/^user-[0-9a-f]{6}@[a-z0-9.-]+\.example$/.test(text)) return true;
  return text.replace(spans, "").replace(/@/g, "").trim() === "";
}

export function aliasKeyPath(): string {
  return setting("ALIAS_KEY_FILE") || path.join(stateDir(), "alias-key");
}

// The key is the only persistent state. Without it (unwritable home, bad
// file) stand-ins still work, but only within this process.
export function loadAliasKey(file = aliasKeyPath()): Buffer {
  try {
    const text = readFileSync(file, "utf8").trim();
    if (/^[0-9a-f]{64}$/.test(text)) {
      try {
        if ((statSync(file).mode & 0o077) !== 0) chmodSync(file, 0o600);
      } catch {
        // Best effort. A readable key only weakens stand-in secrecy.
      }
      return Buffer.from(text, "hex");
    }
    process.stderr.write(
      "ithildin: alias key file is malformed; stand-ins will not be stable across " + "sessions\n",
    );
    return randomBytes(32);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      process.stderr.write(
        "ithildin: alias key file is unreadable; stand-ins will not be stable across " +
          "sessions\n",
      );
      return randomBytes(32);
    }
  }
  const key = randomBytes(32);
  try {
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, `${key.toString("hex")}\n`, { mode: 0o600, flag: "wx" });
    return key;
  } catch {
    // Another process may have won the race; prefer its key.
    try {
      const text = readFileSync(file, "utf8").trim();
      if (/^[0-9a-f]{64}$/.test(text)) return Buffer.from(text, "hex");
    } catch {
      //
    }
    process.stderr.write(
      "ithildin: cannot create alias key file; stand-ins will not be stable across " + "sessions\n",
    );
    return key;
  }
}

export interface Resolved {
  value: string;
  // Rule id to re-detect the value with, so it is aliased again on its way
  // back from the tool.
  ruleId: string;
}

export const SESSION_KEY_SUFFIX = ".ithildin-alias-key";
export const LEGACY_SESSION_KEY_SUFFIX = ".canary-alias-key";

// Per-session key file beside the transcript. A fork starts from its
// parent's key, so the stand-ins it inherited keep resolving. No session
// file (ephemeral sessions): a key that lives only in this process.
export function sessionAliasKey(sessionFile: string | undefined, inheritFrom?: string): Buffer {
  if (!sessionFile) return randomBytes(32);
  const file = sessionPath(sessionFile, "alias-key");
  if (inheritFrom && !existsSync(file)) {
    try {
      const parent = readFileSync(sessionPath(inheritFrom, "alias-key"), "utf8").trim();
      if (/^[0-9a-f]{64}$/.test(parent))
        writeFileSync(file, `${parent}\n`, { mode: 0o600, flag: "wx" });
    } catch {
      // No parent key (it predates per-session keys): start a fresh one.
    }
  }
  return loadAliasKey(file);
}

// Letters that keep a stand-in pronounceable: a vowel stays a vowel and a
// consonant a consonant, so a word-like value gets a word-like stand-in.
const VOWELS = "aeiou";
const CONSONANTS = "bcdfghjklmnprstvwz";
// Candidates that read as ordinary words or code are skipped: swap-back would
// turn every later use of the word into the real value.
const COMMON_WORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "but",
  "by",
  "can",
  "do",
  "for",
  "from",
  "go",
  "had",
  "has",
  "have",
  "he",
  "her",
  "him",
  "his",
  "if",
  "in",
  "into",
  "is",
  "it",
  "its",
  "me",
  "my",
  "no",
  "not",
  "of",
  "on",
  "or",
  "our",
  "out",
  "so",
  "the",
  "to",
  "up",
  "us",
  "was",
  "we",
  "who",
  "why",
  "yes",
  "you",
  "all",
  "any",
  "bad",
  "big",
  "bit",
  "box",
  "bug",
  "bus",
  "car",
  "cat",
  "cup",
  "cut",
  "day",
  "dog",
  "end",
  "few",
  "fix",
  "fun",
  "get",
  "got",
  "hit",
  "hot",
  "job",
  "key",
  "kid",
  "let",
  "lot",
  "low",
  "man",
  "map",
  "may",
  "mix",
  "net",
  "new",
  "now",
  "odd",
  "off",
  "old",
  "one",
  "own",
  "pay",
  "pet",
  "put",
  "red",
  "run",
  "sad",
  "saw",
  "say",
  "see",
  "set",
  "she",
  "sit",
  "six",
  "sun",
  "tag",
  "tax",
  "ten",
  "top",
  "try",
  "two",
  "use",
  "var",
  "via",
  "war",
  "way",
  "web",
  "wet",
  "win",
  "yet",
  "zip",
  "base",
  "bash",
  "body",
  "book",
  "call",
  "case",
  "char",
  "code",
  "data",
  "date",
  "done",
  "else",
  "enum",
  "file",
  "find",
  "form",
  "func",
  "game",
  "hash",
  "head",
  "home",
  "item",
  "join",
  "json",
  "kind",
  "last",
  "line",
  "link",
  "list",
  "load",
  "lock",
  "long",
  "loop",
  "main",
  "make",
  "mode",
  "name",
  "next",
  "node",
  "none",
  "note",
  "null",
  "open",
  "page",
  "part",
  "path",
  "pipe",
  "plan",
  "port",
  "post",
  "pull",
  "push",
  "read",
  "rule",
  "safe",
  "save",
  "self",
  "send",
  "show",
  "side",
  "size",
  "some",
  "sort",
  "step",
  "stop",
  "sure",
  "sync",
  "take",
  "task",
  "test",
  "text",
  "that",
  "then",
  "this",
  "time",
  "todo",
  "tool",
  "tree",
  "true",
  "type",
  "unit",
  "user",
  "view",
  "void",
  "wait",
  "want",
  "what",
  "when",
  "with",
  "word",
  "work",
  "yaml",
  "zero",
]);
const MAX_TRIES = 32;
const MAX_COUNTERS = 200_000;

type Bytes = () => number;

// A run of letters or digits with the same length, case and letter classes.
function shaped(run: string, next: Bytes): string {
  let out = "";
  for (const [index, char] of [...run].entries()) {
    if (/[0-9]/.test(char)) {
      // A leading non-zero digit stays non-zero: 0-padding means something.
      out += index === 0 && char !== "0" ? String(1 + (next() % 9)) : String(next() % 10);
      continue;
    }
    const lower = char.toLowerCase();
    const pool = VOWELS.includes(lower) ? VOWELS : CONSONANTS;
    const picked = pool[next() % pool.length]!;
    out += char === lower ? picked : picked.toUpperCase();
  }
  return out;
}

function caseLike(word: string, model: string): string {
  if (model.length > 1 && model === model.toUpperCase()) return word.toUpperCase();
  if (model[0] === model[0]?.toUpperCase()) return word[0]!.toUpperCase() + word.slice(1);
  return word;
}

let NAMES: string[] | undefined;

export class AliasBook {
  // stand-in -> real value, or null when two values share a stand-in.
  private readonly reverse = new Map<string, Resolved | null>();
  // Pieces that composite stand-ins are built from, so a stand-in the model
  // composes itself (another host in a known domain, another address in a
  // known /24) can be resolved too.
  private readonly parts = new Map<string, string | null>();
  private readonly prefixes = new Map<string, string | null>();
  // kind\0value -> stand-in, for values this process has minted.
  private readonly minted = new Map<string, string>();
  // HMAC of kind\0value -> the attempt that minted it. Saved, so a stand-in
  // never moves once chosen, even when its first pick later turns up as
  // real text (the corpus check below only runs on a value's first mint).
  private readonly counters = new Map<string, number>();
  private counterFile: string | undefined;
  private countersDirty = false;
  private corpus: (() => string) | undefined;
  private corpusTokens: Set<string> | undefined;
  private pattern: RegExp | undefined;
  private glued: RegExp | undefined;
  private readonly key: Buffer;

  // No parameter property: Node's type stripping (the node checks) rejects it.
  constructor(key: Buffer) {
    this.key = key;
  }

  private hex(kind: string, value: string, digits = 6): string {
    return createHmac("sha256", this.key)
      .update(`${kind}\0${value}`)
      .digest("hex")
      .slice(0, digits);
  }

  private bits(kind: string, value: string, count: number): number {
    const digest = createHmac("sha256", this.key).update(`${kind}\0${value}`).digest();
    return digest.readUInt32BE(0) >>> (32 - count);
  }

  // Keyed bytes, as many as a stand-in needs.
  private bytes(kind: string, value: string, attempt: number): Bytes {
    let block = 0;
    let buffer = Buffer.alloc(0);
    let at = 0;
    return () => {
      if (at >= buffer.length) {
        buffer = createHmac("sha256", this.key)
          .update(`${kind}\0${value}\0${attempt}\0${block++}`)
          .digest();
        at = 0;
      }
      return buffer[at++]!;
    };
  }

  // Text the request carries, to keep a new stand-in from equalling a word
  // already in the conversation. Read lazily: only a value never minted
  // before needs it.
  setCorpus(corpus: (() => string) | undefined): void {
    this.corpus = corpus;
    this.corpusTokens = undefined;
  }

  private avoided(candidate: string): boolean {
    const tokens = candidate
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
    if (tokens.length === 0) return true;
    if (tokens.length === 1 && COMMON_WORDS.has(tokens[0]!)) return true;
    if (!this.corpus) return false;
    this.corpusTokens ??= new Set(
      this.corpus()
        .toLowerCase()
        .split(/[^a-z0-9]+/),
    );
    return tokens.every((token) => this.corpusTokens!.has(token));
  }

  private taken(candidate: string, value: string): boolean {
    const known = this.reverse.get(candidate);
    if (
      known !== undefined &&
      (known === null || known.value.toLowerCase() !== value.toLowerCase())
    )
      return true;
    const part = this.parts.get(candidate);
    return part !== undefined && part !== value.toLowerCase();
  }

  private mint(
    kind: string,
    value: string,
    make: (attempt: number) => string,
    fallback: () => string,
  ): string {
    const memo = `${kind}\0${value}`;
    const known = this.minted.get(memo);
    if (known !== undefined) return known;
    const id = this.hex(`counter:${kind}`, value, 16);
    let attempt = this.counters.get(id);
    let out: string | undefined;
    if (attempt !== undefined) {
      out = attempt < 0 ? fallback() : make(attempt);
    } else {
      for (attempt = 0; attempt < MAX_TRIES; attempt++) {
        const candidate = make(attempt);
        if (candidate !== value && !this.taken(candidate, value) && !this.avoided(candidate)) {
          out = candidate;
          break;
        }
      }
      // Nothing lookalike fits (a value with no letters or digits).
      if (out === undefined) {
        attempt = -1;
        out = fallback();
      }
      this.counters.set(id, attempt);
      this.countersDirty = true;
    }
    this.minted.set(memo, out);
    return out;
  }

  // Letter runs map on their own, so values sharing a run share its stand-in
  // (one project key across tickets); digit runs map with the whole value.
  private lookalike(kind: string, value: string, attempt: number, names = false): string {
    let index = 0;
    return value.replace(/[A-Za-z]+|[0-9]+/g, (run) => {
      const at = index++;
      if (/[0-9]/.test(run[0]!))
        return shaped(run, this.bytes(`${kind}:digits`, `${value}\0${at}`, attempt));
      if (names && run.length >= 2) return this.name(run, attempt);
      return shaped(run, this.bytes(`${kind}:letters`, run.toLowerCase(), attempt));
    });
  }

  private name(word: string, attempt: number): string {
    NAMES ??= [...FIRST_NAMES];
    const next = this.bytes("name", word.toLowerCase(), attempt);
    let picked = word.toLowerCase();
    while (picked === word.toLowerCase())
      picked = NAMES[((next() << 16) | (next() << 8) | next()) % NAMES.length]!;
    return caseLike(picked, word);
  }

  // `force`: role words too, for a host that is nothing but role words.
  private part(word: string, force = false): string {
    const lower = word.toLowerCase();
    if (!force && (word.length <= 1 || ROLE_WORDS.has(lower) || /^\d+[a-z]?$/.test(lower)))
      return lower;
    // Four letters at least: a two-letter part would be swapped back inside
    // any dotted name that used it (a file extension).
    const out = this.mint(
      "part",
      lower,
      (attempt) => {
        const base = this.lookalike("part", lower, attempt);
        return base.length >= 4
          ? base
          : base + shaped("bab".slice(0, 4 - base.length), this.bytes("part:pad", lower, attempt));
      },
      () => `n${this.hex("part", lower)}`,
    );
    remember(this.parts, out, lower);
    this.pattern = undefined;
    this.glued = undefined;
    return out;
  }

  private dnsLabel(label: string, force = false): string {
    return label
      .split(/([-_])/)
      .map((piece, index) => (index % 2 === 1 ? piece : this.part(piece, force)))
      .join("");
  }

  // Role and public words stay (gmail.com, corp.internal), so a domain that
  // is nothing but those comes back unchanged.
  private domain(domain: string): string {
    return domain
      .split(".")
      .map((label) => this.dnsLabel(label))
      .join(".");
  }

  host(value: string): string {
    const lower = value.toLowerCase().replace(/\.$/, "");
    const aliased = this.domain(lower);
    if (aliased !== lower) return aliased;
    // Only role words (home.lan): the first label hides the name.
    const [first = "", ...rest] = lower.split(".");
    return [this.dnsLabel(first, true), ...rest].join(".");
  }

  user(value: string): string {
    const lower = value.toLowerCase();
    return this.mint(
      "user",
      lower,
      (attempt) => this.lookalike("user", lower, attempt),
      () => `user-${this.hex("user", lower)}`,
    );
  }

  email(value: string): string {
    const at = value.lastIndexOf("@");
    if (at <= 0) return this.label("email", value);
    return `${this.user(value.slice(0, at))}@${this.domain(value.slice(at + 1).toLowerCase())}`;
  }

  ipv4(value: string): string | undefined {
    const octets = value.split(".");
    if (
      octets.length !== 4 ||
      octets.some((octet) => !/^\d{1,3}$/.test(octet) || Number(octet) > 255)
    )
      return;
    // One stand-in /24 per real /24; the host octet carries no identity alone.
    const prefix = octets.slice(0, 3).map(Number).join(".");
    const slot = this.bits("ipv4", prefix, 19);
    const standInPrefix = `${240 + (slot >>> 16)}.${(slot >>> 8) & 255}.${slot & 255}`;
    remember(this.prefixes, standInPrefix, prefix);
    return `${standInPrefix}.${Number(octets[3])}`;
  }

  ipv6(value: string): string | undefined {
    const groups = expandIpv6(value);
    if (!groups) return;
    // One stand-in /64 per real /64. The interface id is hashed too: EUI-64
    // ids embed the MAC address.
    const prefix = this.hex("ipv6-prefix", groups.slice(0, 4).join(":"), 8);
    const iid = this.hex("ipv6-iid", groups.join(":"), 16);
    const hextets = [
      prefix.slice(0, 4),
      prefix.slice(4, 8),
      iid.slice(0, 4),
      iid.slice(4, 8),
      iid.slice(8, 12),
      iid.slice(12, 16),
    ];
    return `2001:db8:${hextets.map((hextet) => hextet.replace(/^0+(?=.)/, "")).join(":")}`;
  }

  mac(value: string): string | undefined {
    const separator = value.includes("-") ? "-" : value.includes(":") ? ":" : undefined;
    if (!separator || value.split(separator).length !== 6) return;
    const upper = value === value.toUpperCase() && /[A-F]/.test(value);
    const tail = this.hex("mac", value.toLowerCase().replace(/[-:]/g, ""), 10).match(/../g) ?? [];
    // 02: locally administered, never a vendor-assigned address.
    const out = ["02", ...tail].join(separator);
    return upper ? out.toUpperCase() : out;
  }

  home(value: string): string {
    const trimmed = value.replace(/[\\/]+$/, "");
    const cut = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
    if (cut < 0) return this.user(trimmed);
    return `${trimmed.slice(0, cut + 1)}${this.user(trimmed.slice(cut + 1))}`;
  }

  // Same length, case, digits and punctuation as the value; person names
  // become other first names.
  label(label: string, value: string): string {
    const kind = `label:${label}`;
    return this.mint(
      kind,
      value,
      (attempt) => this.lookalike(kind, value, attempt, label === "person"),
      () => `${label}-${this.hex(kind, value)}`,
    );
  }

  // The stand-in for one finding. Unparseable network values fall back to a
  // labelled stand-in rather than passing through.
  standIn(ruleId: string, value: string, customLabel?: string): string {
    const kind = aliasKind(ruleId);
    let out: string | undefined;
    switch (kind) {
      case "host":
        out = this.host(value);
        break;
      case "user":
        out = this.user(value);
        break;
      case "email":
        out = this.email(value);
        break;
      case "home":
        out = this.home(value);
        break;
      case "ipv4":
        out = this.ipv4(value) ?? this.label("ip", value);
        break;
      case "ipv6":
        out = this.ipv6(value) ?? this.label("ip", value);
        break;
      case "mac":
        out = this.mac(value) ?? this.label("mac", value);
        break;
      case "user-at-host": {
        const at = value.indexOf("@");
        out =
          at > 0
            ? `${this.user(value.slice(0, at))}@${this.host(value.slice(at + 1))}`
            : this.user(value);
        break;
      }
      default:
        out = this.label(labelForRule(ruleId, customLabel), value);
    }
    this.record(out, value, ruleId);
    // A composite's pieces resolve on their own too (the user of an email).
    if (kind === "email" || kind === "user-at-host") {
      const at = value.lastIndexOf("@");
      if (at > 0)
        this.record(this.user(value.slice(0, at)), value.slice(0, at), "pii-swapback-user");
    }
    return out;
  }

  private record(standIn: string, value: string, ruleId: string): void {
    const known = this.reverse.get(standIn);
    if (known === undefined) {
      this.reverse.set(standIn, { value, ruleId });
      this.pattern = undefined;
      this.glued = undefined;
    } else if (known !== null && known.value.toLowerCase() !== value.toLowerCase()) {
      this.reverse.set(standIn, null);
    }
  }

  // Real value behind a stand-in this process minted, undefined when unknown,
  // null when ambiguous. Used only locally; never sent anywhere.
  valueOf(standIn: string): string | null | undefined {
    const known = this.reverse.get(standIn);
    return known === undefined ? undefined : known === null ? null : known.value;
  }

  // Dotted or dashed name with every known part mapped back; undefined when
  // no part is known.
  private unmapParts(text: string): string | null | undefined {
    let known = false;
    let ambiguous = false;
    const value = text
      .split(/([-_.])/)
      .map((piece, index) => {
        if (index % 2 === 1) return piece;
        const word = this.parts.get(piece.toLowerCase());
        if (word === null) ambiguous = true;
        if (typeof word !== "string") return piece;
        known = true;
        return word;
      })
      .join("");
    if (ambiguous) return null;
    return known ? value : undefined;
  }

  // Exact stand-ins first, then composites: hostnames label by label, emails
  // as user@domain, IPv4 by its /24. undefined: unknown (another key, or
  // never seen); null: ambiguous.
  resolve(standIn: string): Resolved | null | undefined {
    const exact = this.reverse.get(standIn);
    if (exact !== undefined) return exact;
    const at = standIn.lastIndexOf("@");
    if (at > 0) {
      const user = this.resolve(standIn.slice(0, at));
      if (user === null) return null;
      if (!user) return;
      const domain = standIn.slice(at + 1);
      const real = this.unmapParts(domain);
      if (real === null) return null;
      return { value: `${user.value}@${real ?? domain}`, ruleId: "pii-swapback-email" };
    }
    const v4 = /^(24[0-7]\.\d{1,3}\.\d{1,3})\.(\d{1,3})$/.exec(standIn);
    if (v4) {
      const prefix = this.prefixes.get(v4[1] ?? "");
      if (prefix === null) return null;
      return prefix === undefined
        ? undefined
        : { value: `${prefix}.${v4[2]}`, ruleId: "pii-swapback-ipv4" };
    }
    const value = this.unmapParts(standIn);
    if (value === null) return null;
    return value === undefined ? undefined : { value, ruleId: "pii-swapback-host" };
  }

  // Every span of `text` this book can swap back. Stand-ins look like real
  // values, so they are found by what was minted, not by shape: exact
  // stand-ins as whole words, and names or addresses built from known parts.
  matches(text: string): Array<{ text: string; start: number; end: number }> {
    const found: Array<{ text: string; start: number; end: number }> = [];
    this.pattern ??= this.compile();
    for (const match of text.matchAll(this.pattern))
      found.push({ text: match[0], start: match.index, end: match.index + match[0].length });
    const exact = found.filter((span) => this.reverse.has(span.text));
    for (const match of text.matchAll(COMPOSITE)) {
      // An exact stand-in inside keeps its case; the parts map is lowercase.
      const end = match.index + match[0].length;
      if (exact.some((span) => span.start < end && span.end > match.index)) continue;
      if (!/[-_.@]/.test(match[0]) || this.resolve(match[0]) === undefined) continue;
      found.push({ text: match[0], start: match.index, end: match.index + match[0].length });
    }
    for (const match of text.matchAll(/\b24[0-7](?:\.\d{1,3}){3}\b/g)) {
      if (this.resolve(match[0]) !== undefined)
        found.push({ text: match[0], start: match.index, end: match.index + match[0].length });
    }
    // A whole multi-part stand-in glued into a longer word: the model mangled
    // it, so none of its parts is swapped either (a lone last part came back
    // lowercased).
    this.glued ??= this.compile(true);
    const glued: Array<{ start: number; end: number }> = [];
    for (const match of text.matchAll(this.glued)) {
      const end = match.index + match[0].length;
      if (/[A-Za-z0-9]/.test(text[match.index - 1] ?? "") || /[A-Za-z0-9]/.test(text[end] ?? ""))
        glued.push({ start: match.index, end });
    }
    return found.filter(
      (span) => !glued.some((range) => span.start < range.end && span.end > range.start),
    );
  }

  // `glued`: multi-part stand-ins anywhere, to find the mangled ones.
  private compile(glued = false): RegExp {
    const words = (
      glued
        ? [...this.reverse.keys()].filter((word) => /[-_.]/.test(word))
        : [...this.reverse.keys(), ...this.parts.keys()]
    ).sort((left, right) => right.length - left.length);
    if (words.length === 0) return /$^/g;
    const alternatives = words.map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
    // Glued into a longer word, a stand-in is something else.
    return glued
      ? new RegExp(alternatives, "g")
      : new RegExp(`(?<![A-Za-z0-9])(?:${alternatives})(?![A-Za-z0-9])`, "g");
  }

  isStandIn(text: string): boolean {
    return this.reverse.has(text);
  }

  standIns(): string[] {
    return [...this.reverse.keys()];
  }

  // Keeps each stand-in where it was first minted across restarts. The file
  // holds keyed hashes of values and attempt numbers, never a value.
  loadCounters(file: string): void {
    this.counterFile = file;
    try {
      for (const [id, attempt] of JSON.parse(readFileSync(file, "utf8")) as Array<[string, number]>)
        this.counters.set(id, attempt);
    } catch {
      // Absent or unreadable: values mint afresh.
    }
    this.countersDirty = false;
  }

  saveCounters(): void {
    if (!this.counterFile || !this.countersDirty) return;
    for (const id of this.counters.keys()) {
      if (this.counters.size <= MAX_COUNTERS) break;
      this.counters.delete(id);
    }
    try {
      writeFileSync(`${this.counterFile}.tmp`, JSON.stringify([...this.counters]), { mode: 0o600 });
      renameSync(`${this.counterFile}.tmp`, this.counterFile);
      this.countersDirty = false;
    } catch {
      // A lost file costs a stand-in that may move after a restart.
    }
  }

  clear(): void {
    this.reverse.clear();
    this.parts.clear();
    this.prefixes.clear();
    this.minted.clear();
    this.pattern = undefined;
    this.glued = undefined;
  }
}

// A name, an email address, or a dotted/dashed word, taken whole.
const WORD = "[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?";
const COMPOSITE = new RegExp(
  `(?<![A-Za-z0-9_.@-])(?:${WORD}@)?${WORD}(?:\\.${WORD})*(?![A-Za-z0-9_@-]|\\.[A-Za-z0-9])`,
  "g",
);

function remember(map: Map<string, string | null>, standIn: string, value: string): void {
  const known = map.get(standIn);
  if (known === undefined) map.set(standIn, value);
  else if (known !== null && known !== value) map.set(standIn, null);
}

export function expandIpv6(value: string): string[] | undefined {
  const lower = value.toLowerCase().replace(/%.*$/, "");
  if (!/^[0-9a-f:.]+$/.test(lower) || (lower.match(/::/g) ?? []).length > 1) return;
  let text = lower;
  // Embedded IPv4 tail (::ffff:1.2.3.4) becomes two hextets.
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number);
    if ([a, b, c, d].some((octet) => octet === undefined || octet > 255)) return;
    const hextet = (high: number, low: number) => ((high << 8) | low).toString(16);
    text = `${text.slice(0, v4.index)}${hextet(a!, b!)}:${hextet(c!, d!)}`;
  }
  const [head = "", tail] = text.split("::");
  const left = head ? head.split(":") : [];
  const right = tail !== undefined && tail ? tail.split(":") : [];
  const missing = 8 - left.length - right.length;
  if (tail === undefined ? missing !== 0 : missing < 1) return;
  const groups = [...left, ...Array<string>(tail === undefined ? 0 : missing).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return;
  return groups.map((group) => group.replace(/^0+(?=.)/, ""));
}
