import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import type { InventoryEntry } from "./rules.ts";
import { looksLikeAlias } from "./aliases.ts";
import { assert } from "./assert.ts";

// Single-label names that fire on ordinary prose or distro defaults.
const GENERIC = new Set([
  "localhost",
  "local",
  "linux",
  "darwin",
  "windows",
  "ubuntu",
  "debian",
  "fedora",
  "nixos",
  "host",
  "hostname",
  "user",
  "username",
  "admin",
  "root",
  "nobody",
  "test",
  "testing",
  "dev",
  "devel",
  "docker",
  "container",
  "guest",
  "pi",
  "me",
  "self",
  "owner",
  "home",
  "users",
  "www",
  "api",
  "app",
  "box",
  "pc",
  "mac",
  "srv",
  "nas",
  "lab",
  "node",
  "server",
  // Service accounts in SSH configs and cloud images, not people.
  "git",
  "ec2-user",
  "centos",
  "core",
  "alpine",
  "vagrant",
  "azureuser",
  "opc",
  "bitnami",
  "deploy",
  "runner",
  // Search domains routers and distros hand out.
  "lan",
  "localdomain",
  "home.arpa",
  "internal",
  "intranet",
]);

// Public forges and SSH endpoints: naming them reveals nothing about you.
const PUBLIC_HOSTS = new Set([
  "github.com",
  "ssh.github.com",
  "gist.github.com",
  "gitlab.com",
  "altssh.gitlab.com",
  "bitbucket.org",
  "altssh.bitbucket.org",
  "codeberg.org",
  "gitea.com",
  "sr.ht",
  "git.sr.ht",
  "notabug.org",
  "launchpad.net",
  "git.launchpad.net",
  "ssh.dev.azure.com",
  "vs-ssh.visualstudio.com",
  "dev.azure.com",
  "source.developers.google.com",
  "huggingface.co",
  "hf.co",
  "aur.archlinux.org",
  "salsa.debian.org",
  "gitlab.gnome.org",
  "invent.kde.org",
  "git.kernel.org",
]);

// Upper bound per source, so a huge generated SSH config cannot flood the
// rule list (each entry is one regex on every scan).
const MAX_PER_SOURCE = 100;

// Inert template tokens from user-config.example.json — matching them would
// tokenize documentation, not a person.
const EXAMPLE_LITERALS = new Set([
  "jane",
  "exampleperson",
  "examplehandle",
  "example_handle",
  "examplecorp",
  "homessid",
  "example",
  "jane exampleperson",
  "example team",
]);

export interface RuntimeIdentity {
  username?: string;
  hostname?: string;
  homedir?: string;
  gitName?: string | undefined;
  gitEmail?: string | undefined;
  // From ~/.ssh/config: Host aliases, HostName values, User values.
  sshHosts?: string[];
  sshHostNames?: string[];
  sshUsers?: string[];
  // Hosts of the current repository's git remotes.
  gitHosts?: string[];
  // Wi-Fi networks: saved and in range, from NetworkManager or iwgetid.
  ssids?: string[];
  // resolv.conf search and domain entries.
  searchDomains?: string[];
  // Names and addresses of /etc/hosts entries that are not loopback.
  etcHosts?: string[];
  // Tailscale MagicDNS names: this machine, its peers, the tailnet suffix.
  tailnetNames?: string[];
}

export function identityFromOs(): RuntimeIdentity {
  const out: RuntimeIdentity = {};
  try {
    out.username = os.userInfo().username;
  } catch {
    // Missing passwd entry is not fatal. Skip that field.
  }
  try {
    out.hostname = os.hostname();
  } catch {
    //
  }
  try {
    out.homedir = os.homedir();
  } catch {
    //
  }
  return out;
}

function isEphemeralHome(home: string): boolean {
  const n = home.replace(/\\/g, "/").toLowerCase();
  return (
    n === "/tmp" ||
    n.startsWith("/tmp/") ||
    n.startsWith("/private/tmp/") ||
    n.includes("/var/folders/")
  );
}

function usableLiteral(value: string | undefined): string | undefined {
  const v = value?.trim();
  if (!v || [...v].length < 3) return;
  if (v.includes("\0") || v.includes("\n")) return;
  if (/__ITHILDIN_[A-Z]+_\d+__/.test(v) || looksLikeAlias(v)) return;
  const lower = v.toLowerCase();
  if (GENERIC.has(lower) || EXAMPLE_LITERALS.has(lower)) return;
  return v;
}

// Up to MAX_PER_SOURCE non-public hosts from one source, numbered by kind.
function addInfraHosts(
  prefix: string,
  hosts: string[] | undefined,
  addCaseless: (id: string, literal: string) => void,
): void {
  let n = 0;
  for (const raw of hosts ?? []) {
    if (n >= MAX_PER_SOURCE) break;
    const host = raw.trim().replace(/\.$/, "");
    if (!host || PUBLIC_HOSTS.has(host.toLowerCase()) || !usableLiteral(host)) continue;
    n++;
    const kind = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)
      ? "ip"
      : host.includes(":")
        ? "ipv6"
        : "host";
    addCaseless(`${prefix}-${kind}-${n}`, host);
    if (kind === "host" && host.includes("."))
      addCaseless(`${prefix}-host-short-${n}`, host.slice(0, host.indexOf(".")));
  }
}

export function collectRuntimeIdentity(identity: RuntimeIdentity): InventoryEntry[] {
  const out: InventoryEntry[] = [];
  const seen = new Set<string>();
  const add = (id: string, literal: string | undefined, match: "token" | "phrase" = "token") => {
    const v = usableLiteral(literal);
    if (!v || seen.has(v)) return;
    seen.add(v);
    out.push({ id, literal: v, match, caseSensitive: true });
  };

  add("runtime-user", identity.username);

  const host = usableLiteral(identity.hostname);
  if (host) {
    add("runtime-host", host);
    if (host.includes(".")) add("runtime-host-short", host.slice(0, host.indexOf(".")));
  }

  const home = identity.homedir?.trim();
  if (home && !isEphemeralHome(home)) {
    add("runtime-home", home, "phrase");
    add(
      "runtime-home-user",
      home
        .replace(/[\\/]+$/, "")
        .split(/[\\/]/)
        .pop(),
    );
  }

  const gitName = identity.gitName?.trim();
  if (gitName && gitName.includes(" ")) add("runtime-git-name", gitName, "phrase");
  else add("runtime-git-name", gitName);
  const gitEmail = identity.gitEmail?.trim();
  if (gitEmail && !gitEmail.toLowerCase().endsWith("@example.com"))
    add("runtime-git-email", gitEmail);

  // Infrastructure names. Hostnames match case-insensitively (DNS does).
  const addHosts = (prefix: string, hosts: string[] | undefined) =>
    addInfraHosts(prefix, hosts, addCaseless);
  const addCaseless = (id: string, literal: string) => {
    const v = usableLiteral(literal);
    if (!v || seen.has(v.toLowerCase())) return;
    seen.add(v.toLowerCase());
    out.push({ id, literal: v, match: "token", caseSensitive: false });
  };
  addHosts("runtime-ssh", identity.sshHosts);
  addHosts("runtime-ssh-hostname", identity.sshHostNames);
  addHosts("runtime-git", identity.gitHosts);
  addHosts("runtime-etc-hosts", identity.etcHosts);
  addHosts("runtime-search-domain", identity.searchDomains);
  addHosts("runtime-tailnet", identity.tailnetNames);
  let users = 0;
  for (const user of identity.sshUsers ?? []) {
    if (users >= MAX_PER_SOURCE) break;
    if (!usableLiteral(user)) continue;
    users++;
    add(`runtime-ssh-user-${users}`, user);
  }
  // SSIDs are free text: exact case, and a token only where one starts.
  let ssids = 0;
  for (const ssid of identity.ssids ?? []) {
    if (ssids >= MAX_PER_SOURCE) break;
    if (!usableLiteral(ssid)) continue;
    ssids++;
    add(`runtime-ssid-${ssids}`, ssid);
  }

  return out;
}

export function identityFromGit(
  get: (key: string) => string | undefined = readGitConfig,
): Pick<RuntimeIdentity, "gitName" | "gitEmail"> {
  return { gitName: get("user.name"), gitEmail: get("user.email") };
}

function readGitConfig(key: string): string | undefined {
  const value = runCommand("git", ["config", "--get", key])?.trim();
  return value ? value : undefined;
}

// stdout of a short command, or undefined when it is missing, fails or hangs.
export type RunCommand = (command: string, args: string[], cwd?: string) => string | undefined;

// A command that hangs or floods is treated as missing, never waited out.
const COMMAND_TIMEOUT_MS = 1500;
const COMMAND_OUTPUT_BYTES_MAX = 1 << 20;

function runCommand(command: string, args: string[], cwd?: string): string | undefined {
  try {
    const result = spawnSync(command, args, {
      cwd,
      encoding: "utf8",
      timeout: COMMAND_TIMEOUT_MS,
      maxBuffer: COMMAND_OUTPUT_BYTES_MAX,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return result.status === 0 ? result.stdout : undefined;
  } catch {
    return;
  }
}

// ~/.ssh/config: concrete Host aliases (no wildcards or negations), HostName
// and User values, following Include (relative to ~/.ssh, last-segment
// globs). Token-expanded values (%h) are skipped. Values never leave this
// process: they become in-memory match rules only.
export function identityFromSsh(
  home = os.homedir(),
  read: (file: string) => string | undefined = readTextFile,
  list: (dir: string) => string[] = listDir,
): Pick<RuntimeIdentity, "sshHosts" | "sshHostNames" | "sshUsers"> {
  const sshDir = path.join(home, ".ssh");
  const hosts: string[] = [];
  const hostNames: string[] = [];
  const users: string[] = [];
  const visited = new Set<string>();
  const visit = (file: string, depth: number) => {
    if (depth > 5 || visited.has(file)) return;
    visited.add(file);
    const text = read(file);
    if (text === undefined) return;
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.replace(/(^|\s)#.*$/, "").trim();
      const match = /^(\S+?)(?:\s*=\s*|\s+)(.+)$/.exec(line);
      if (!match) continue;
      const keyword = (match[1] ?? "").toLowerCase();
      const values = (match[2] ?? "")
        .split(/\s+/)
        .map((value) => value.replace(/^"(.*)"$/, "$1"))
        .filter(Boolean);
      if (keyword === "host") {
        for (const value of values) if (!/[*?!%]/.test(value)) hosts.push(value);
      } else if (keyword === "hostname") {
        if (values[0] && !values[0].includes("%")) hostNames.push(values[0]);
      } else if (keyword === "user") {
        if (values[0] && !values[0].includes("%")) users.push(values[0]);
      } else if (keyword === "include") {
        for (const value of values) {
          const target = value.startsWith("~/")
            ? path.join(home, value.slice(2))
            : path.resolve(sshDir, value);
          const base = path.basename(target);
          if (!/[*?]/.test(base)) {
            visit(target, depth + 1);
            continue;
          }
          const pattern = new RegExp(
            `^${base
              .replace(/[.+^${}()|[\]\\]/g, "\\$&")
              .replace(/\*/g, ".*")
              .replace(/\?/g, ".")}$`,
          );
          for (const name of list(path.dirname(target)).sort())
            if (pattern.test(name)) visit(path.join(path.dirname(target), name), depth + 1);
        }
      }
    }
  };
  visit(path.join(sshDir, "config"), 0);
  return { sshHosts: hosts, sshHostNames: hostNames, sshUsers: users };
}

// Host part of each git remote URL: scp-style (user@host:path), ssh://,
// https://, git://. Local paths and file:// have no host.
export function gitRemoteHost(url: string): string | undefined {
  const trimmed = url.trim();
  const scheme = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)/i.exec(trimmed);
  if (scheme) return /^file:/i.test(trimmed) ? undefined : scheme[1]?.replace(/^\[|\]$/g, "");
  const scp = /^(?:[^@/\s]+@)?([^/:\s]+):(?!\/\/)/.exec(trimmed);
  return scp && !/^[a-z]$/i.test(scp[1] ?? "") ? scp[1] : undefined;
}

export function identityFromGitRemotes(
  cwd = process.cwd(),
  urls: () => string[] = () => readGitRemoteUrls(cwd),
): Pick<RuntimeIdentity, "gitHosts"> {
  return {
    gitHosts: urls().flatMap((url) => {
      const host = gitRemoteHost(url);
      return host ? [host] : [];
    }),
  };
}

function readGitRemoteUrls(cwd: string): string[] {
  const out = runCommand("git", ["config", "--get-regexp", "^remote\\..*\\.(push)?url$"], cwd);
  return (out ?? "").split("\n").flatMap((line) => {
    const url = line.split(/\s+/)[1];
    return url ? [url] : [];
  });
}

// Remote hosts of every repository under the roots (default: home), for a
// process like the proxy that serves every project at once. Hidden
// directories and dependency trees are skipped, and a repository is not
// descended into. Depth and directory count are bounded so a huge home
// cannot stall startup.
const REPO_SCAN_DEPTH_MAX = 4;
const REPO_SCAN_DIRS_MAX = 5000;
const SKIP_DIRS = new Set(["node_modules", "vendor", "target", "dist", "build", "result"]);

export function identityFromRepos(
  roots: string[] = [os.homedir()],
  list: (dir: string) => Array<{ name: string; dir: boolean }> = listEntries,
  read: (file: string) => string | undefined = readTextFile,
): Pick<RuntimeIdentity, "gitHosts"> {
  const hosts = new Set<string>();
  assert(roots.length > 0, "repo scan has a root");
  let budget = REPO_SCAN_DIRS_MAX;
  let level = roots.map((root) => path.resolve(root));
  for (let depth = 0; depth <= REPO_SCAN_DEPTH_MAX && level.length > 0; depth++) {
    const next: string[] = [];
    for (const dir of level) {
      if (budget-- <= 0 || hosts.size >= MAX_PER_SOURCE) return { gitHosts: [...hosts] };
      const entries = list(dir);
      if (entries.some((entry) => entry.name === ".git" && entry.dir)) {
        for (const url of remoteUrls(read(path.join(dir, ".git", "config")) ?? "")) {
          const host = gitRemoteHost(url);
          if (host) hosts.add(host);
        }
        continue;
      }
      for (const entry of entries)
        if (entry.dir && !entry.name.startsWith(".") && !SKIP_DIRS.has(entry.name))
          next.push(path.join(dir, entry.name));
    }
    level = next;
  }
  return { gitHosts: [...hosts] };
}

// url and pushurl values of [remote "…"] sections in a git config file.
export function remoteUrls(config: string): string[] {
  const urls: string[] = [];
  let inRemote = false;
  for (const raw of config.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)[#;].*$/, "").trim();
    if (line.startsWith("[")) inRemote = /^\[remote\s+"/i.test(line);
    else if (inRemote) {
      const match = /^(?:push)?url\s*=\s*"?([^"]+?)"?$/i.exec(line);
      if (match?.[1]) urls.push(match[1]);
    }
  }
  return urls;
}

// Wi-Fi networks this machine knows. NetworkManager lists saved connections
// (named for their SSID unless renamed) and networks in range from its
// cache, without a rescan; iwgetid names the one in use elsewhere.
export function identityFromWifi(run: RunCommand = runCommand): Pick<RuntimeIdentity, "ssids"> {
  const ssids = new Set<string>();
  for (const line of (run("nmcli", ["-t", "-f", "NAME,TYPE", "connection", "show"]) ?? "").split(
    "\n",
  )) {
    const [name, type] = nmcliFields(line);
    if (ssids.size >= MAX_PER_SOURCE) break;
    if (name && type === "802-11-wireless") ssids.add(name);
  }
  for (const line of (
    run("nmcli", ["-t", "-f", "IN-USE,SSID", "device", "wifi", "list", "--rescan", "no"]) ?? ""
  ).split("\n")) {
    const [inUse, ssid] = nmcliFields(line);
    if (ssids.size >= MAX_PER_SOURCE) break;
    if (inUse === "*" && ssid) ssids.add(ssid);
  }
  const current = run("iwgetid", ["-r"])?.trim();
  if (current) ssids.add(current);
  return { ssids: [...ssids] };
}

// nmcli -t output: fields joined by ':', with ':' and '\\' in values escaped.
export function nmcliFields(line: string): string[] {
  const fields: string[] = [];
  let field = "";
  for (let i = 0; i < line.length; i++) {
    const char = line[i]!;
    if (char === "\\" && i + 1 < line.length) field += line[++i];
    else if (char === ":") {
      fields.push(field);
      field = "";
    } else field += char;
  }
  fields.push(field);
  assert(fields.length > 0, "an nmcli line has a field");
  return fields;
}

// resolv.conf search domains, and /etc/hosts entries a user added: loopback,
// blocklist (0.0.0.0) and IPv6 multicast lines are the distro's, not yours.
export function identityFromNetworkFiles(
  read: (file: string) => string | undefined = readTextFile,
): Pick<RuntimeIdentity, "searchDomains" | "etcHosts"> {
  const searchDomains: string[] = [];
  for (const raw of (read("/etc/resolv.conf") ?? "").split(/\r?\n/)) {
    const [keyword, ...values] = raw
      .replace(/[#;].*$/, "")
      .trim()
      .split(/\s+/);
    if (searchDomains.length >= MAX_PER_SOURCE) break;
    if (keyword === "search" || keyword === "domain") searchDomains.push(...values);
  }
  const etcHosts: string[] = [];
  for (const raw of (read("/etc/hosts") ?? "").split(/\r?\n/)) {
    if (etcHosts.length >= MAX_PER_SOURCE) break;
    const [address, ...names] = raw.replace(/#.*$/, "").trim().split(/\s+/);
    if (!address || names.length === 0) continue;
    if (/^(?:127\.|0\.0\.0\.0$|::1?$|f[ef][0-9a-f]{2}:)/i.test(address)) continue;
    etcHosts.push(address);
    for (const name of names) if (!/^(?:ip6-|localhost)/i.test(name)) etcHosts.push(name);
  }
  return { searchDomains, etcHosts };
}

// MagicDNS names from `tailscale status --json`: this machine, its peers,
// and the tailnet suffix (tail1234.ts.net), which is as identifying as a host.
export function identityFromTailscale(
  run: RunCommand = runCommand,
): Pick<RuntimeIdentity, "tailnetNames"> {
  const names = new Set<string>();
  let status: {
    MagicDNSSuffix?: unknown;
    Self?: { DNSName?: unknown };
    Peer?: Record<string, { DNSName?: unknown }>;
  };
  try {
    status = JSON.parse(run("tailscale", ["status", "--json"]) ?? "null") ?? {};
  } catch {
    return { tailnetNames: [] };
  }
  const add = (value: unknown) => {
    if (typeof value !== "string") return;
    const name = value.trim().replace(/\.$/, "");
    if (name) names.add(name);
  };
  add(status.MagicDNSSuffix);
  add(status.Self?.DNSName);
  for (const peer of Object.values(status.Peer ?? {})) {
    if (names.size >= MAX_PER_SOURCE) break;
    add(peer?.DNSName);
  }
  return { tailnetNames: [...names] };
}

function readTextFile(file: string): string | undefined {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return;
  }
}

function listEntries(dir: string): Array<{ name: string; dir: boolean }> {
  try {
    return readdirSync(dir, { withFileTypes: true }).map((entry) => ({
      name: entry.name,
      dir: entry.isDirectory(),
    }));
  } catch {
    return [];
  }
}

function listDir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}
