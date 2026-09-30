import { afterEach, describe, expect, it } from "bun:test";
import {
  collectRuntimeIdentity,
  gitRemoteHost,
  identityFromGit,
  identityFromGitRemotes,
  identityFromSsh,
} from "./runtime-inventory.ts";
import { RULES, scan, setRuntimeInventory } from "./rules.ts";
import { aliases, redactText } from "../core.ts";
import { planSwapBack } from "./swap-back.ts";

const UNIQUE_USER = "zzzxquniqueuser";
const UNIQUE_HOST = "zzzxquniquehost";
const UNIQUE_FQDN = "zzzxquniquehost.zzzxq";
const UNIQUE_HOME = "/srv/zzzxquniquedir";

afterEach(() => {
  setRuntimeInventory([]);
});

describe("collectRuntimeIdentity", () => {
  it("emits token rules for user, host, short host, and home", () => {
    const entries = collectRuntimeIdentity({
      username: UNIQUE_USER,
      hostname: UNIQUE_FQDN,
      homedir: UNIQUE_HOME,
    });
    expect(entries.map((e) => e.id).sort()).toEqual([
      "runtime-home",
      "runtime-home-user",
      "runtime-host",
      "runtime-host-short",
      "runtime-user",
    ]);
    expect(entries.find((e) => e.id === "runtime-user")?.literal).toBe(UNIQUE_USER);
    expect(entries.find((e) => e.id === "runtime-host")?.literal).toBe(UNIQUE_FQDN);
    expect(entries.find((e) => e.id === "runtime-host-short")?.literal).toBe(UNIQUE_HOST);
    expect(entries.find((e) => e.id === "runtime-home")?.match).toBe("phrase");
    expect(entries.find((e) => e.id === "runtime-home-user")?.literal).toBe("zzzxquniquedir");
  });

  it("skips short, generic, example, and ephemeral values", () => {
    expect(collectRuntimeIdentity({ username: "ab" })).toEqual([]);
    expect(collectRuntimeIdentity({ username: "root", hostname: "localhost" })).toEqual([]);
    expect(collectRuntimeIdentity({ username: "examplehandle" })).toEqual([]);
    expect(collectRuntimeIdentity({ homedir: "/tmp/nix-build" })).toEqual([]);
  });

  it("adds git name and email when they are distinctive", () => {
    const entries = collectRuntimeIdentity({
      gitName: "Zzzxq Git Person",
      gitEmail: "zzzxqgit@zzzxq.test",
    });
    expect(entries.find((e) => e.id === "runtime-git-name")?.literal).toBe("Zzzxq Git Person");
    expect(entries.find((e) => e.id === "runtime-git-name")?.match).toBe("phrase");
    expect(entries.find((e) => e.id === "runtime-git-email")?.literal).toBe("zzzxqgit@zzzxq.test");
    expect(collectRuntimeIdentity({ gitEmail: "dev@example.com" })).toEqual([]);
  });

  it("does not duplicate the same literal under two ids", () => {
    const entries = collectRuntimeIdentity({
      username: UNIQUE_USER,
      homedir: "/home/" + UNIQUE_USER,
    });
    expect(entries.filter((e) => e.literal === UNIQUE_USER)).toHaveLength(1);
  });
});

describe("setRuntimeInventory", () => {
  it("makes identity literals match as PII and uninstalls cleanly", () => {
    setRuntimeInventory(collectRuntimeIdentity({ username: UNIQUE_USER, hostname: UNIQUE_HOST }));
    const found = scan(`${UNIQUE_USER} on ${UNIQUE_HOST}`);
    expect(found.some((f) => f.secretValue === UNIQUE_USER && f.category === "pii")).toBe(true);
    expect(found.some((f) => f.secretValue === UNIQUE_HOST && f.category === "pii")).toBe(true);
    expect(RULES.some((r) => r.id === "pii-inventory-runtime-user")).toBe(false);
    setRuntimeInventory([]);
    const after = scan(`${UNIQUE_USER} on ${UNIQUE_HOST}`);
    expect(after.some((f) => f.secretValue === UNIQUE_USER)).toBe(false);
    expect(after.some((f) => f.secretValue === UNIQUE_HOST)).toBe(false);
  });
});

describe("identityFromGit", () => {
  it("reads git identity through the injected getter", () => {
    const got = identityFromGit((key) =>
      key === "user.name" ? "Zzzxq Gitname" : "zzzxqgit@zzzxq.test",
    );
    expect(got.gitName).toBe("Zzzxq Gitname");
    expect(got.gitEmail).toBe("zzzxqgit@zzzxq.test");
    expect(identityFromGit(() => undefined)).toEqual({ gitName: undefined, gitEmail: undefined });
  });
});

describe("infrastructure sources", () => {
  const files: Record<string, string> = {
    "/h/.ssh/config": [
      "# personal",
      "Host zqxbox zqxbox-alias *.wild !neg",
      "  HostName zqxbox.zqxcorp.internal",
      "  User zqxadmin",
      "Host gh",
      "  HostName github.com",
      "  User git",
      "Host jump",
      "  HostName=203.0.113.44",
      "  User %u",
      "Include config.d/*",
      "Include ~/.ssh/config", // cycle
    ].join("\n"),
    "/h/.ssh/config.d/work": "Host zqxwork\n  HostName fd00:zq::5\n",
  };
  const read = (file: string) => files[file];
  const list = (dir: string) => (dir === "/h/.ssh/config.d" ? ["work"] : []);

  it("reads concrete hosts, hostnames, users, and includes from SSH config", () => {
    const ssh = identityFromSsh("/h", read, list);
    expect(ssh.sshHosts).toEqual(["zqxbox", "zqxbox-alias", "gh", "jump", "zqxwork"]);
    expect(ssh.sshHostNames).toEqual([
      "zqxbox.zqxcorp.internal",
      "github.com",
      "203.0.113.44",
      "fd00:zq::5",
    ]);
    expect(ssh.sshUsers).toEqual(["zqxadmin", "git"]);
  });

  it("extracts git remote hosts from every URL form", () => {
    expect(gitRemoteHost("git@zqxgit.zqxcorp.internal:team/repo.git")).toBe(
      "zqxgit.zqxcorp.internal",
    );
    expect(gitRemoteHost("ssh://git@zqxgit:2222/team/repo")).toBe("zqxgit");
    expect(gitRemoteHost("https://user@zqxgit.example.org/team/repo")).toBe("zqxgit.example.org");
    expect(gitRemoteHost("file:///srv/repo")).toBeUndefined();
    expect(gitRemoteHost("/srv/repo")).toBeUndefined();
    expect(gitRemoteHost("C:/repo")).toBeUndefined();
    expect(
      identityFromGitRemotes("/x", () => ["git@github.com:o/r.git", "https://zqxgit.internal/r"])
        .gitHosts,
    ).toEqual(["github.com", "zqxgit.internal"]);
  });

  it("makes infrastructure names caseless rules, skipping public forges and service users", () => {
    const entries = collectRuntimeIdentity({
      ...identityFromSsh("/h", read, list),
      gitHosts: ["github.com", "zqxgit.zqxcorp.internal"],
    });
    const literals = entries.map((entry) => entry.literal);
    expect(literals).toContain("zqxbox");
    expect(literals).toContain("zqxbox.zqxcorp.internal");
    expect(literals).toContain("203.0.113.44");
    expect(literals).toContain("zqxadmin");
    expect(literals).toContain("zqxgit.zqxcorp.internal");
    expect(literals).not.toContain("github.com");
    expect(literals).not.toContain("git");
    expect(entries.find((entry) => entry.literal === "zqxbox")?.caseSensitive).toBe(false);
    expect(entries.find((entry) => entry.literal === "203.0.113.44")?.id).toMatch(/-ip-\d+$/);
    setRuntimeInventory(entries);
    expect(
      scan("ssh ZQXBOX then 203.0.113.44")
        .map((finding) => finding.secretValue)
        .sort(),
    ).toEqual(["203.0.113.44", "ZQXBOX"]);
  });
});

// `od -c` layout: a 7-digit octal offset, then 16 bytes per line in
// right-aligned 4-wide columns.
function odC(text: string): string {
  const lines: string[] = [];
  for (let at = 0; at < text.length; at += 16) {
    const columns = [...text.slice(at, at + 16)]
      .map((char) => (char === "\n" ? "\\n" : char).padStart(4))
      .join("");
    lines.push(at.toString(8).padStart(7, "0") + columns);
  }
  return `${lines.join("\n")}\n${text.length.toString(8).padStart(7, "0")}\n`;
}

describe("spaced-out identity literals", () => {
  const MIXED_HOST = "ZQXLAB-KWVRT7";

  it("catches a hostname spelled out by od -c, across its line break", () => {
    setRuntimeInventory(collectRuntimeIdentity({ hostname: MIXED_HOST }));
    // 13 characters of prefix put the name across the 16-byte line boundary.
    const dump = odC(JSON.stringify(["zqxalpha", MIXED_HOST]));
    expect(dump).not.toContain(MIXED_HOST);
    expect(scan(dump).some((f) => f.category === "pii")).toBe(true);
    expect(scan([...MIXED_HOST].join(" ")).some((f) => f.category === "pii")).toBe(true);
  });

  it("leaves spaced text that is not the whole value alone", () => {
    setRuntimeInventory(collectRuntimeIdentity({ hostname: MIXED_HOST }));
    expect(scan("Z Q X L A B").some((f) => f.ruleId.startsWith("pii-inventory-"))).toBe(false);
    expect(scan("Z Q X L A B - K W V R T").some((f) => f.ruleId.startsWith("pii-inventory-"))).toBe(
      false,
    );
  });

  it("gives both spellings one stand-in that swaps back to the exact value", () => {
    const previous = process.env.ITHILDIN_ALIASES;
    process.env.ITHILDIN_ALIASES = "stand-ins";
    try {
      setRuntimeInventory(collectRuntimeIdentity({ hostname: MIXED_HOST }));
      const standIn = redactText(`host ${MIXED_HOST}`).text.slice("host ".length);
      expect(standIn).not.toContain(MIXED_HOST);
      const dump = redactText(odC(MIXED_HOST)).text;
      expect(dump).toContain(standIn);
      expect(dump).not.toMatch(/Z\s+Q\s+X/);
      const swap = planSwapBack(
        "bash",
        { command: `nix eval .#hosts.${standIn}.config` },
        aliases(),
        true,
      );
      expect(swap.input).toEqual({ command: `nix eval .#hosts.${MIXED_HOST}.config` });
    } finally {
      if (previous === undefined) delete process.env.ITHILDIN_ALIASES;
      else process.env.ITHILDIN_ALIASES = previous;
    }
  });
});
