// Meaningful, stable stand-ins for PII (not secrets).
//
// A stand-in keeps the role and shape of the value it replaces and the
// relationships between values, so the model can still reason about them:
//
//   prod-pg-use1.acme.internal  ->  prod-pg-n1f2e3.n4a5b6.internal.example
//   bob@acme.internal           ->  user-3c9d0e@n4a5b6.internal.example
//   203.0.113.7 / 203.0.113.9   ->  241.18.5.7 / 241.18.5.9   (same /24 stays together)
//
// Every stand-in is an HMAC of the real value under a local random key, so:
// - the same value maps to the same stand-in for as long as the key lives,
// - nothing but the key is ever written to disk (no table of real values),
// - the model cannot reverse a stand-in without the key.
// By default each session has its own key (next to its transcript), so a
// provider cannot join stand-ins across sessions into a profile. Resuming a
// session reuses its key; a fork inherits its parent's.
// Stand-ins live in namespaces reserved from real use (the .example TLD,
// 240.0.0.0/5, 2001:db8::/32, locally administered MACs), so they never
// collide with a real value. 240.0.0.0/5 instead of the IPv4 documentation
// ranges: those hold only three /24s, too few to keep one stand-in per subnet.

import { createHmac, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export type AliasKind = "host" | "user" | "email" | "user-at-host" | "home" | "ipv4" | "ipv6" | "mac" | "label";

// Hostname and email-domain words that describe a role or a place, not an
// owner. They survive aliasing because they carry the meaning.
const ROLE_WORDS = new Set([
  "prod", "production", "prd", "stage", "staging", "stg", "dev", "devel", "development", "test", "testing", "qa", "uat", "sandbox", "demo", "preview",
  "db", "pg", "postgres", "postgresql", "mysql", "mariadb", "redis", "mongo", "mongodb", "elastic", "es", "kafka", "rabbitmq", "mq", "cache", "memcached",
  "web", "www", "api", "app", "apps", "svc", "service", "backend", "frontend", "admin", "auth", "sso", "idp", "ldap", "vault", "secrets",
  "lb", "proxy", "gw", "gateway", "ingress", "edge", "cdn", "static", "media", "files", "assets", "upload", "download",
  "vpn", "wg", "bastion", "jump", "ssh", "ftp", "sftp", "mail", "smtp", "imap", "mx", "ns", "dns", "ntp", "dhcp",
  "git", "ci", "cd", "build", "builder", "runner", "worker", "workers", "job", "jobs", "cron", "queue", "scheduler",
  "node", "nodes", "master", "primary", "secondary", "replica", "standby", "backup", "archive", "restore",
  "monitor", "monitoring", "metrics", "grafana", "prometheus", "alert", "alerts", "log", "logs", "logging", "trace", "tracing",
  "nas", "san", "storage", "s3", "minio", "k8s", "kube", "kubernetes", "cluster", "control", "docker", "registry", "vm", "host", "hv",
  "router", "switch", "ap", "wifi", "printer", "camera", "iot", "home", "office", "lab", "desktop", "laptop", "workstation", "server", "srv",
  "internal", "int", "ext", "external", "corp", "lan", "local", "localdomain", "private", "public", "arpa", "intranet",
  "eu", "us", "uk", "de", "fr", "ca", "au", "jp", "cn", "in", "br", "asia", "emea", "apac", "amer",
  "east", "west", "north", "south", "central", "use1", "use2", "usw1", "usw2", "euw1", "euc1",
  "com", "net", "org", "io", "co", "info", "biz", "cloud", "tech", "online", "site",
  "gmail", "googlemail", "outlook", "hotmail", "live", "yahoo", "icloud", "me", "proton", "protonmail", "pm", "fastmail", "gmx", "aol",
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

// Recognizes stand-in shapes, including ones minted by an earlier session
// whose value this process has not seen. Labelled stand-ins need a known
// label (so branch names like feature-123456 never match), .example must be
// the final label after a hashed one (so www.example.com and .env.example
// never match), and 240.0.0.0/5 is
// never assigned. IPv6 and MAC stand-ins share their shape with ordinary
// documentation values, so only the session book recognizes those.
const BUILTIN_LABELS = ["user", "host", "person", "ssid", "phone", "address", "geo", "postal", "card", "account", "machine", "id", "pii", "ip", "mac", "email"];
const labels = new Set(BUILTIN_LABELS);
let shapes: RegExp[] = [];
let spans = /$^/g;

function compileShapes(): void {
  const labelled = `\\b(?:${[...labels].join("|")})-[0-9a-f]{6}\\b`;
  // Longest shape first, so host-3c9d0e.example is one span, not two.
  const sources = ["\\b[a-z0-9.-]*(?<![a-z0-9])(?:n|host-)[0-9a-f]{6}(?![a-z0-9])[a-z0-9.-]*\\.example(?![\\w-]|\\.[\\w-])", labelled, "\\bn[0-9a-f]{6}\\b", "\\b24[0-7](?:\\.\\d{1,3}){3}\\b"];
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
  return [...text.matchAll(spans)].map((match) => ({ text: match[0], start: match.index, end: match.index + match[0].length }));
}

// True when the whole value is stand-ins. An email counts when its local
// part is one: a role-only domain (gmail.com.example) has no hashed label.
export function isAliasValue(text: string): boolean {
  if (text.length === 0) return false;
  if (/^user-[0-9a-f]{6}@[a-z0-9.-]+\.example$/.test(text)) return true;
  return text.replace(spans, "").replace(/@/g, "").trim() === "";
}

export function aliasKeyPath(): string {
  if (process.env.SENSITIVE_CANARY_ALIAS_KEY_FILE) return process.env.SENSITIVE_CANARY_ALIAS_KEY_FILE;
  const state = process.env.XDG_STATE_HOME || path.join(process.env.HOME || os.homedir(), ".local", "state");
  return path.join(state, "sensitive-canary", "alias-key");
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
    process.stderr.write("sensitive-canary: alias key file is malformed; stand-ins will not be stable across sessions\n");
    return randomBytes(32);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      process.stderr.write("sensitive-canary: alias key file is unreadable; stand-ins will not be stable across sessions\n");
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
    process.stderr.write("sensitive-canary: cannot create alias key file; stand-ins will not be stable across sessions\n");
    return key;
  }
}

export interface Resolved {
  value: string;
  // Rule id to re-detect the value with, so it is aliased again on its way
  // back from the tool.
  ruleId: string;
}

export const SESSION_KEY_SUFFIX = ".canary-alias-key";

// Per-session key file beside the transcript. A fork starts from its
// parent's key, so the stand-ins it inherited keep resolving. No session
// file (ephemeral sessions): a key that lives only in this process.
export function sessionAliasKey(sessionFile: string | undefined, inheritFrom?: string): Buffer {
  if (!sessionFile) return randomBytes(32);
  const file = `${sessionFile}${SESSION_KEY_SUFFIX}`;
  if (inheritFrom && !existsSync(file)) {
    try {
      const parent = readFileSync(`${inheritFrom}${SESSION_KEY_SUFFIX}`, "utf8").trim();
      if (/^[0-9a-f]{64}$/.test(parent)) writeFileSync(file, `${parent}\n`, { mode: 0o600, flag: "wx" });
    } catch {
      // No parent key (it predates per-session keys): start a fresh one.
    }
  }
  return loadAliasKey(file);
}

export class AliasBook {
  // stand-in -> real value, or null when two values share a stand-in.
  private readonly reverse = new Map<string, Resolved | null>();
  // Pieces that composite stand-ins are built from, so a stand-in the model
  // composes itself (another host in a known domain, another address in a
  // known /24) can be resolved too.
  private readonly parts = new Map<string, string | null>();
  private readonly prefixes = new Map<string, string | null>();
  private readonly key: Buffer;

  // No parameter property: Node's type stripping (the node checks) rejects it.
  constructor(key: Buffer) {
    this.key = key;
  }

  private hex(kind: string, value: string, digits = 6): string {
    return createHmac("sha256", this.key).update(`${kind}\0${value}`).digest("hex").slice(0, digits);
  }

  private bits(kind: string, value: string, count: number): number {
    const digest = createHmac("sha256", this.key).update(`${kind}\0${value}`).digest();
    return digest.readUInt32BE(0) >>> (32 - count);
  }

  private part(word: string): string {
    const lower = word.toLowerCase();
    if (word.length <= 1 || ROLE_WORDS.has(lower) || /^\d+[a-z]?$/.test(lower)) return lower;
    const out = `n${this.hex("part", lower)}`;
    remember(this.parts, out, lower);
    return out;
  }

  private dnsLabel(label: string): string {
    return label.split(/([-_])/).map((piece, index) => (index % 2 === 1 ? piece : this.part(piece))).join("");
  }

  private domain(domain: string): string {
    return `${domain.split(".").map((label) => this.dnsLabel(label)).join(".")}.example`;
  }

  host(value: string): string {
    const lower = value.toLowerCase().replace(/\.$/, "");
    if (!lower.includes(".")) {
      const aliased = this.dnsLabel(lower);
      // Nothing role-like survived: a bare hashed word says less than host-….
      return /^n[0-9a-f]{6}$/.test(aliased) || aliased === lower ? `host-${this.hex("host", lower)}` : aliased;
    }
    const aliased = this.domain(lower);
    return aliased === `${lower}.example` ? `host-${this.hex("host", lower)}.example` : aliased;
  }

  user(value: string): string {
    return `user-${this.hex("user", value.toLowerCase())}`;
  }

  email(value: string): string {
    const at = value.lastIndexOf("@");
    if (at <= 0) return this.label("email", value);
    return `${this.user(value.slice(0, at))}@${this.domain(value.slice(at + 1).toLowerCase())}`;
  }

  ipv4(value: string): string | undefined {
    const octets = value.split(".");
    if (octets.length !== 4 || octets.some((octet) => !/^\d{1,3}$/.test(octet) || Number(octet) > 255)) return;
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
    const hextets = [prefix.slice(0, 4), prefix.slice(4, 8), iid.slice(0, 4), iid.slice(4, 8), iid.slice(8, 12), iid.slice(12, 16)];
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

  label(label: string, value: string): string {
    return `${label}-${this.hex(`label:${label}`, value)}`;
  }

  // The stand-in for one finding. Unparseable network values fall back to a
  // labelled stand-in rather than passing through.
  standIn(ruleId: string, value: string, customLabel?: string): string {
    const kind = aliasKind(ruleId);
    let out: string | undefined;
    switch (kind) {
      case "host": out = this.host(value); break;
      case "user": out = this.user(value); break;
      case "email": out = this.email(value); break;
      case "home": out = this.home(value); break;
      case "ipv4": out = this.ipv4(value) ?? this.label("ip", value); break;
      case "ipv6": out = this.ipv6(value) ?? this.label("ip", value); break;
      case "mac": out = this.mac(value) ?? this.label("mac", value); break;
      case "user-at-host": {
        const at = value.indexOf("@");
        out = at > 0 ? `${this.user(value.slice(0, at))}@${this.host(value.slice(at + 1))}` : this.user(value);
        break;
      }
      default: out = this.label(labelForRule(ruleId, customLabel), value);
    }
    this.record(out, value, ruleId);
    // A composite's pieces resolve on their own too (the user of an email).
    if (kind === "email" || kind === "user-at-host") {
      const at = value.lastIndexOf("@");
      if (at > 0) this.record(this.user(value.slice(0, at)), value.slice(0, at), "pii-swapback-user");
    }
    return out;
  }

  private record(standIn: string, value: string, ruleId: string): void {
    const known = this.reverse.get(standIn);
    if (known === undefined) this.reverse.set(standIn, { value, ruleId });
    else if (known !== null && known.value.toLowerCase() !== value.toLowerCase()) this.reverse.set(standIn, null);
  }

  // Real value behind a stand-in this process minted, undefined when unknown,
  // null when ambiguous. Used only locally; never sent anywhere.
  valueOf(standIn: string): string | null | undefined {
    const known = this.reverse.get(standIn);
    return known === undefined ? undefined : known === null ? null : known.value;
  }

  // Exact stand-ins first, then composites: .example hostnames label by
  // label, emails as user@domain, IPv4 by its /24. undefined: unknown
  // (another key, or never seen); null: ambiguous.
  resolve(standIn: string): Resolved | null | undefined {
    const exact = this.reverse.get(standIn);
    if (exact !== undefined) return exact;
    const at = standIn.indexOf("@");
    if (at > 0) {
      const user = this.resolve(standIn.slice(0, at));
      const domain = this.resolve(standIn.slice(at + 1));
      if (user === null || domain === null) return null;
      if (!user || !domain) return;
      return { value: `${user.value}@${domain.value}`, ruleId: "pii-swapback-email" };
    }
    const v4 = /^(24[0-7]\.\d{1,3}\.\d{1,3})\.(\d{1,3})$/.exec(standIn);
    if (v4) {
      const prefix = this.prefixes.get(v4[1] ?? "");
      if (prefix === null) return null;
      return prefix === undefined ? undefined : { value: `${prefix}.${v4[2]}`, ruleId: "pii-swapback-ipv4" };
    }
    const host = /^(.+)\.example$/.exec(standIn)?.[1] ?? (/^n[0-9a-f]{6}(?:[-_.]|$)/.test(standIn) || /[-_.]n[0-9a-f]{6}(?:[-_.]|$)/.test(standIn) ? standIn : undefined);
    if (host === undefined) return;
    let ambiguous = false;
    let unknown = false;
    const value = host.split(/([-_.])/).map((piece, index) => {
      if (index % 2 === 1 || !/^n[0-9a-f]{6}$/.test(piece)) return piece;
      const word = this.parts.get(piece);
      if (word === null) ambiguous = true;
      if (word === undefined) unknown = true;
      return word ?? piece;
    }).join("");
    if (ambiguous) return null;
    if (unknown || /(?:^|[-_.])host-[0-9a-f]{6}(?:[-_.]|$)/.test(value)) return;
    return { value, ruleId: "pii-swapback-host" };
  }

  isStandIn(text: string): boolean {
    return this.reverse.has(text);
  }

  standIns(): string[] {
    return [...this.reverse.keys()];
  }

  clear(): void {
    this.reverse.clear();
    this.parts.clear();
    this.prefixes.clear();
  }
}

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
    text = `${text.slice(0, v4.index)}${((a! << 8) | b!).toString(16)}:${((c! << 8) | d!).toString(16)}`;
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
