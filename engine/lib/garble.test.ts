// Garbled output, end to end. Two ways the proxy has garbled text an agent
// wrote: masking ordinary text (a commit subject read as a person, a format
// verb learned as a username), and a stand-in the model rewrote slightly
// that swap-back then missed, so the stand-in landed on disk. Add a line to
// a list here whenever a new case turns up.
import { afterEach, describe, expect, it } from "bun:test";
import { aliases, redactText } from "../core.ts";
import { setRuntimeInventory } from "./rules.ts";
import { collectRuntimeIdentity } from "./runtime-inventory.ts";
import { planSwapBack } from "./swap-back.ts";

afterEach(() => setRuntimeInventory([]));

// Built from pieces so that no rule matches the source of this file.
const j = (...parts: string[]) => parts.join("");

describe("ordinary text passes through unchanged", () => {
  const ORDINARY = [
    // commit subjects and headings
    "Add CLAUDE.md",
    "Fix Search Tests",
    "Update README.md",
    "Will Fix Later",
    "Mark Done",
    "Grant Access",
    "Rich Text Editor",
    "Page Title",
    "Chase Bank Export",
    "Rose Pine Theme",
    "Summer Sale Banner",
    "Hunter Mode",
    "Major Release Notes",
    "Ray Tracing Pass",
    "Grace Period Fix",
    "Bill Pay Flow",
    "Hope It Works",
    "Jack Server Setup",
    "Chip Select Pin",
    "Ivy League",
    "Iris Dataset",
    "Jade Plugin",
    "Bell Labs",
    "Del Key",
    "Sky Map",
    "Christmas Eve",
    "Easter Sunday",
    "## Getting Started",
    // code, flags and tooling
    'fmt.Printf("%v %+v %#v\\n", a, b, c)',
    "go test -v -run TestX ./...",
    "for k, v := range m {",
    "ls -la /home/ab",
    "x@example.org",
    "git@github.com:org/repo.git",
    "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
    "Claude Code wrote this",
    "claude-opus-5-5",
    "README.md AGENTS.md CLAUDE.md",
    "Open Main.ts first",
    "SELECT ID,EMAIL FROM USERS",
    "nmcli -f NAME,TYPE con",
    "Press Tab to accept",
    "Notebook tab",
    "New York office",
    "user = await getUser()",
    "owner: root",
    "user: test",
  ];
  for (const text of ORDINARY)
    it(text, () => {
      expect(redactText(text).text).toBe(text);
    });
});

describe("real names are still caught", () => {
  for (const text of [
    "Neil Armstrong",
    "Ward Cunningham",
    "Dean Price",
    "Mark Shelton",
    j("Error: Mark Shel", "ton.jr"),
  ])
    it(text, () => {
      expect(redactText(text).text).not.toBe(text);
    });
});

describe("stand-ins survive the edits a model makes", () => {
  const values = {
    name: j("Bern", "ard ", "Kwa", "sniew"),
    user: j("zq", "xdev"),
    host: j("zq", "xbox-", "lab7"),
    email: j("zq", "x.d", "@kw", "asn.io"),
    gitname: j("Zq", "xa ", "Vel", "marr"),
  };
  const inventory = () =>
    setRuntimeInventory(
      collectRuntimeIdentity({
        username: values.user,
        hostname: values.host,
        gitName: values.gitname,
      }),
    );
  // DNS and mail ignore case, so a host or address may come back lowercased.
  const caseless = new Set(["host", "email"]);
  const forms: Record<string, (s: string) => string> = {
    exact: (s) => s,
    possessive: (s) => `${s}'s`,
    upper: (s) => s.toUpperCase(),
    capitalized: (s) => s[0]!.toUpperCase() + s.slice(1),
    bold: (s) => `**${s}**`,
    json: (s) => JSON.stringify({ v: s }),
    path: (s) => `/srv/${s}/logs`,
    underscored: (s) => `${s}_backup`,
    dotted: (s) => `${s}.conf`,
  };
  const swapped = (text: string) =>
    (planSwapBack("write_file", { content: text }, aliases(), true).input as { content: string })
      .content;

  for (const [kind, real] of Object.entries(values)) {
    for (const [form, edit] of Object.entries(forms)) {
      it(`${kind}, ${form}`, () => {
        inventory();
        const masked = redactText(`x ${real} y`).text.slice(2, -2);
        expect(masked).not.toBe(real);
        const out = swapped(edit(masked));
        if (caseless.has(kind)) expect(out.toLowerCase()).toBe(edit(real).toLowerCase());
        else expect(out).toBe(edit(real));
      });
    }
  }

  // Glued, slugged or re-spaced, a stand-in is something else and stays as
  // written. The write guard refuses a write that carries one.
  it("leaves mangled stand-ins unswapped", () => {
    inventory();
    const masked = redactText(`x ${values.name} y`).text.slice(2, -2);
    for (const mangled of [
      `${masked}s`,
      masked.toLowerCase().replace(/\s+/g, "-"),
      masked.replace(/\s+/g, "  "),
    ])
      expect(swapped(mangled)).toBe(mangled);
  });
});
