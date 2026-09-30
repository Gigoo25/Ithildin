import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import type { InventoryEntry } from "./rules.ts";
import { looksLikeAlias } from "./aliases.ts";

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
  if (/__CANARY_[A-Z]+_\d+__/.test(v) || looksLikeAlias(v)) return;
  const lower = v.toLowerCase();
  if (GENERIC.has(lower) || EXAMPLE_LITERALS.has(lower)) return;
  return v;
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
  const addHosts = (prefix: string, hosts: string[] | undefined) => {
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
  };
  const addCaseless = (id: string, literal: string) => {
    const v = usableLiteral(literal);
    if (!v || seen.has(v.toLowerCase())) return;
    seen.add(v.toLowerCase());
    out.push({ id, literal: v, match: "token", caseSensitive: false });
  };
  addHosts("runtime-ssh", identity.sshHosts);
  addHosts("runtime-ssh-hostname", identity.sshHostNames);
  addHosts("runtime-git", identity.gitHosts);
  let users = 0;
  for (const user of identity.sshUsers ?? []) {
    if (users >= MAX_PER_SOURCE) break;
    if (!usableLiteral(user)) continue;
    users++;
    add(`runtime-ssh-user-${users}`, user);
  }

  return out;
}

export function identityFromGit(
  get: (key: string) => string | undefined = readGitConfig,
): Pick<RuntimeIdentity, "gitName" | "gitEmail"> {
  return { gitName: get("user.name"), gitEmail: get("user.email") };
}

function readGitConfig(key: string): string | undefined {
  try {
    const result = spawnSync("git", ["config", "--get", key], {
      encoding: "utf8",
      timeout: 1500,
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (result.status !== 0) return;
    const value = result.stdout.trim();
    return value.length > 0 ? value : undefined;
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
  try {
    const result = spawnSync("git", ["config", "--get-regexp", "^remote\\..*\\.(push)?url$"], {
      cwd,
      encoding: "utf8",
      timeout: 1500,
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (result.status !== 0) return [];
    return result.stdout.split("\n").flatMap((line) => {
      const url = line.split(/\s+/)[1];
      return url ? [url] : [];
    });
  } catch {
    return [];
  }
}

function readTextFile(file: string): string | undefined {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return;
  }
}

function listDir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}
