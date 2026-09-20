import os from "node:os";
import { spawnSync } from "node:child_process";
import type { InventoryEntry } from "./rules.ts";

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
]);

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
  gitName?: string;
  gitEmail?: string;
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
  if (/__CANARY_[A-Z]+_\d+__/.test(v)) return;
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
    add("runtime-home-user", home.replace(/[\\/]+$/, "").split(/[\\/]/).pop());
  }

  const gitName = identity.gitName?.trim();
  if (gitName && gitName.includes(" ")) add("runtime-git-name", gitName, "phrase");
  else add("runtime-git-name", gitName);
  const gitEmail = identity.gitEmail?.trim();
  if (gitEmail && !gitEmail.toLowerCase().endsWith("@example.com")) add("runtime-git-email", gitEmail);


  return out;
}

export function identityFromGit(get: (key: string) => string | undefined = readGitConfig): Pick<RuntimeIdentity, "gitName" | "gitEmail"> {
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
