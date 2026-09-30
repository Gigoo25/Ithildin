import { afterAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { identityFromGitRemotes, identityFromSsh } from "./runtime-inventory.ts";

// The default readers, against a made-up home and repo on disk.
const root = mkdtempSync(path.join(tmpdir(), "canary-inventory-io-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("identityFromSsh on disk", () => {
  it("reads hosts from the ssh config and its includes", () => {
    const home = path.join(root, "home");
    const sshDir = path.join(home, ".ssh");
    mkdirSync(path.join(sshDir, "conf.d"), { recursive: true });
    writeFileSync(
      path.join(sshDir, "config"),
      "Include conf.d/*\nHost zzbuildbox\n  HostName zzbuildbox.example.test\n  User zzdeployer\n",
    );
    writeFileSync(path.join(sshDir, "conf.d", "extra"), "Host zzmirror\n");
    const identity = identityFromSsh(home);
    expect(identity.sshHosts).toEqual(expect.arrayContaining(["zzbuildbox", "zzmirror"]));
    expect(identity.sshHostNames).toContain("zzbuildbox.example.test");
    expect(identity.sshUsers).toContain("zzdeployer");
  });

  it("finds nothing in a home without an ssh directory", () => {
    const identity = identityFromSsh(path.join(root, "nowhere"));
    expect(identity.sshHosts ?? []).toEqual([]);
    expect(identity.sshHostNames ?? []).toEqual([]);
  });
});

describe("identityFromGitRemotes on disk", () => {
  const git = (cwd: string, ...args: string[]) =>
    spawnSync("git", args, { cwd, stdio: "ignore", env: { ...process.env, HOME: root } });

  it("reads the hosts of a repo's fetch and push remotes", () => {
    const repo = path.join(root, "repo");
    mkdirSync(repo);
    git(repo, "init", "-q");
    git(repo, "remote", "add", "origin", "git@git.example.test:team/app.git");
    git(repo, "remote", "set-url", "--push", "origin", "https://push.example.test/team/app.git");
    expect(identityFromGitRemotes(repo).gitHosts).toEqual(
      expect.arrayContaining(["git.example.test", "push.example.test"]),
    );
  });

  it("finds nothing outside a repo", () => {
    const plain = path.join(root, "plain");
    mkdirSync(plain);
    expect(identityFromGitRemotes(plain).gitHosts).toEqual([]);
  });
});
