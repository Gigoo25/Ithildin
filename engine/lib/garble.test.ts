// Garbled output, end to end. Two ways the proxy has garbled text an agent
// wrote: masking ordinary text (a commit subject read as a person, a format
// verb learned as a username), and a stand-in the model rewrote slightly
// that swap-back then missed, so the stand-in landed on disk. Add a line to
// a list here whenever a new case turns up.
import { afterEach, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
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
    // found by scanning real repos: Go sources, Bun's type docs, git logs
    "return math.Pow((s+0.055)/1.055, 2.4)",
    "Sends an HTTP/1.1 103 Early Hints message",
    'h.add("Early May bank holiday", d)',
    "Copyright (c) Meta Platforms, Inc. and affiliates.",
    "Inline images using the Kitty Graphics Protocol",
    'native functions show up as "Unknown Executable"',
    "Emit ANSI color escape sequences",
    "Emit OSC 8 hyperlinks",
    'data: {user: "John Doe"}',
    "Merge pull request #16 from org/feature-branch",
    // found scanning other personal repos: workflows, Dockerfiles, configs
    "uses: actions/checkout@main",
    "uses: docker/setup-buildx-action@master",
    "uses: dtolnay/rust-toolchain@stable",
    "go install golang.org/x/vuln/cmd/govulncheck@latest",
    "FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b",
    "logs in as demo@example.com / demo1234",
    "- name: Checkout GitHub Action",
    "    name: Bed Exit Confirmation",
    j('<path d="M7.503 0c3.09 0 ', "6.3", "13 5.7", '31 2.841 6.214 0"/>'),
    j("colorful.Color{0.31", "3725, 0.47", "8431, 0.721569}"),
    // an insurance contents list: tab-separated item rows
    "Toy Car Set",
    "Mason Jar Lids",
    "Teddy Bear",
    "General Electric Microwave",
    "Mickey Mouse Clubhouse",
    "King Bed Frame",
    "West Side Story DVD",
    "Little Christmas Tree",
    "Baby Gate",
    "Easter Decoration",
    "Hoover Vacuum",
    "Jack Handle",
    "Clay Bowl",
    "Fanny Pack",
    "03-31-2026\t91020747\tElectric Wire",
    "Waiting For Disposal\t03-30-2026\n91020747\tSt. Patrick's Day Decoration",
  ];
  for (const text of ORDINARY)
    it(text, () => {
      expect(redactText(text).text).toBe(text);
    });
});

// A long document of prose, commands and config. Anything this rewrites is
// a false positive an agent would trip over.
it("passes the README through unchanged", () => {
  const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
  expect(redactText(readme).text).toBe(readme);
});

describe("real names are still caught", () => {
  for (const text of [
    "Neil Armstrong",
    "Ward Cunningham",
    "Dean Price",
    "Mark Shelton",
    j("Error: Mark Shel", "ton.jr"),
    j("name: Neil Arm", "strong"),
    j("author: Bed", "ford Falls"),
    j("ssh ", "deploy", "@build", "box.lan"),
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

// Masking that a change of case or spelling undoes is no masking: an agent
// lowercased its output and read a name the rule only knew capitalized.
describe("respelled copies of a masked name", () => {
  const NAME = j("Bern", "ard ", "Kwa", "sniew");
  const respellings = [
    NAME.toLowerCase(),
    NAME.toUpperCase(),
    NAME.replace(" ", "_").toLowerCase(),
    NAME.replace(" ", "-"),
    NAME.split(" ").reverse().join(" "),
    NAME.split(" ").reverse().join(", "),
  ];

  it("masks them in later text", () => {
    expect(redactText(`signed ${NAME}`).text).not.toContain(NAME);
    for (const spelled of respellings)
      expect({ spelled, out: redactText(`x ${spelled} y`).text.includes(spelled) }).toEqual({
        spelled,
        out: false,
      });
  });

  it("masks them beside the first copy in the same text", () => {
    const out = redactText(`${NAME}\t${NAME.toLowerCase()}`).text;
    expect(out).not.toContain(NAME.toLowerCase());
  });

  it("leaves run-together forms and login-shaped values alone", () => {
    redactText(`signed ${NAME}`);
    const joined = NAME.replace(" ", "").toLowerCase();
    expect(redactText(`const ${joined} = 1`).text).toBe(`const ${joined} = 1`);
    redactText(j("user: ", "first", ".last", "y"));
    expect(redactText("the first lasty idea").text).toBe("the first lasty idea");
  });

  it("takes only capitals and joined forms of a name made of first names", () => {
    const plain = j("Rob", "ert ", "Jam", "es");
    redactText(`signed ${plain}`);
    expect(redactText(`x ${plain.toUpperCase()} y`).text).not.toContain(plain.toUpperCase());
    expect(redactText(`x ${plain.replace(" ", "_").toLowerCase()} y`).text).not.toContain(
      plain.replace(" ", "_").toLowerCase(),
    );
    const prose = `we ${plain.toLowerCase()} it`;
    expect(redactText(prose).text).toBe(prose);
  });

  it("does not join words across a line break", () => {
    redactText(`signed ${NAME}`);
    const [first, last] = NAME.split(" ");
    const text = `${first}\n${last!.toLowerCase()}`;
    expect(redactText(text).text).toContain(last!.toLowerCase());
  });

  it("leaves a lone first name in lowercase alone", () => {
    redactText(`signed ${NAME}`);
    expect(redactText("bernard said hi").text).toBe("bernard said hi");
  });
});
