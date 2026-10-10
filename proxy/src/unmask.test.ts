import { beforeAll, describe, expect, it } from "bun:test";
import { aliases } from "../engine/core.ts";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  blockedNotice,
  initEngine,
  requestAllowTags,
  saveScanCache,
  shapingSwitch,
  swapToolArguments,
  withholdImages,
} from "./redact.ts";
import { SPELLED_BLOCKED, spellsMasked, substitutesLetters, unmasksText } from "./unmask.ts";

beforeAll(() => initEngine());

const unmasks = (command: string) => unmasksText({ command });

describe("letter substitution guard", () => {
  it("refuses rot13 and other letter ciphers", () => {
    for (const command of [
      "tr 'A-Za-z' 'N-ZA-Mn-za-m' < notes.txt",
      "cat notes.txt | tr A-Za-z N-ZA-Mn-za-m",
      "tr a-z b-za <notes.txt",
      "sed 'y/abcdefghijklmnopqrstuvwxyz/nopqrstuvwxyzabcdefghijklm/' f",
      "perl -pe 'tr/A-Za-z/N-ZA-Mn-za-m/' f",
      "rot13 < f",
      "python3 -c \"import codecs,sys; print(codecs.encode(sys.stdin.read(), 'rot13'))\" < f",
      "python3 - <<'EOF'\nimport codecs\nprint(codecs.decode(open('f').read(), 'rot_13'))\nEOF",
    ]) {
      expect({ command, refused: unmasks(command) }).toEqual({ command, refused: true });
    }
  });

  it("lets case changes and other tr jobs through", () => {
    for (const command of [
      "tr a-z A-Z < f",
      "tr '[:lower:]' '[:upper:]' < f",
      "tr -d '\\r' < f",
      "tr -s ' ' < f",
      "tr ',' '\\n' < f",
      "tr -cd 'a-z' < f",
      "grep -rn rot13 engine/",
      "sed 's/foo/bar/' f",
      "git log --format=%s",
      'bun test engine/lib/encoded.test.ts -t "rot13 copies"',
      "grep -rn rot13 engine && python3 tools/report.py",
      "cat > /tmp/p.ts <<'EOF'\nimport { redactRot13 } from './encoded.ts';\nEOF\nbun /tmp/p.ts",
    ]) {
      expect({ command, refused: unmasks(command) }).toEqual({ command, refused: false });
    }
  });

  it("tells a substitution from a case fold", () => {
    expect(substitutesLetters("A-Za-z", "N-ZA-Mn-za-m")).toBe(true);
    expect(substitutesLetters("a-z", "A-Z")).toBe(false);
    expect(substitutesLetters("abc", "abc")).toBe(false);
    expect(substitutesLetters("0-9", "a-j")).toBe(false);
  });

  it("drops the call unless the prompt allows pii or this call", () => {
    const args = { command: "tr 'A-Za-z' 'N-ZA-Mn-za-m' < notes.txt" };
    const refused = swapToolArguments("bash", args, new Set(), "toolu_u1");
    expect(refused.blocked).toBe(true);
    expect(swapToolArguments("bash", args, new Set(["pii"])).blocked).toBeUndefined();
    expect(swapToolArguments("bash", args, new Set(["all"])).blocked).toBeUndefined();
  });
});

describe("spelled value guard", () => {
  // Bytes of NAME, as printf and od write them.
  const NAME = "Quorvel";
  const hex = [...Buffer.from(NAME)].map((b) => "\\x" + b.toString(16)).join("");
  const decimal = [...Buffer.from(NAME)].join(" ");

  it("refuses a call that spells a masked value", () => {
    aliases().standIn("pii-gazetteer-name", NAME);
    for (const command of [
      `printf '${hex}'`,
      `python3 -c 'print(bytes([${decimal.replaceAll(" ", ",")}]))'`,
    ]) {
      expect(spellsMasked({ command }, [NAME])).toBe(true);
      const refused = swapToolArguments("bash", { command }, new Set(), "toolu_s1");
      expect(refused.blocked).toBe(true);
      expect(blockedNotice("toolu_s1")?.startsWith(SPELLED_BLOCKED)).toBe(true);
      expect(swapToolArguments("bash", { command }, new Set(["pii"])).blocked).toBeUndefined();
    }
    // Any tool: an edit that writes the bytes is refused too.
    const edit = { file_path: "/tmp/x.sh", new_string: `name=$(printf '${hex}')` };
    expect(swapToolArguments("Edit", edit, new Set(), "toolu_s2").blocked).toBe(true);
  });

  it("lets ordinary escapes and numbers through", () => {
    for (const command of ["printf '\\x1b[0m'", "seq 1 10", `echo ${decimal.split(" ")[0]}`])
      expect(spellsMasked({ command }, [NAME])).toBe(false);
    expect(spellsMasked({ command: `printf '${hex}'` }, [])).toBe(false);
    expect(spellsMasked(`printf '${hex}'`, [NAME])).toBe(true);
    expect(spellsMasked(undefined, [NAME])).toBe(false);
  });
});

describe("session state across a restart", () => {
  const sessionsFile = () =>
    join(dirname(process.env.ITHILDIN_PROXY_KEY_FILE!), "proxy-sessions.json");
  const typed = (text: string) => ({ messages: [{ role: "user", content: text }] });

  it("writes blocked calls and each session's switches", () => {
    aliases().standIn("pii-gazetteer-name", "Quorvel");
    const hex = [...Buffer.from("Quorvel")].map((b) => "\\x" + b.toString(16)).join("");
    swapToolArguments("bash", { command: `printf '${hex}'` }, new Set(), "toolu_keep");
    shapingSwitch("anthropic", typed("[raw] go"), "s-keep");
    requestAllowTags("anthropic", typed("[allow-pii] go"), "s-keep");
    withholdImages("anthropic", typed("[allow-images:session] go"), "s-keep");
    saveScanCache();
    const state = JSON.parse(readFileSync(sessionsFile(), "utf8"));
    expect(new Map(state.blocked).get("toolu_keep")).toStartWith(SPELLED_BLOCKED);
    expect(state.shapes).toContainEqual(["s-keep", false]);
    expect(state.tags).toContainEqual(["s-keep", ["pii"]]);
    expect(state.images).toContainEqual(["s-keep", true]);
  });

  it("reads them back at start, skipping what does not parse", () => {
    writeFileSync(
      sessionsFile(),
      JSON.stringify({
        blocked: [["toolu_loaded", "Not run: loaded."], ["toolu_bad", 3], "junk"],
        tags: [
          ["s-loaded", ["pii"]],
          ["s-bad", "pii"],
        ],
        shapes: [
          ["s-loaded", false],
          ["s-bad", "no"],
        ],
        images: [
          ["s-loaded", true],
          ["s-bad", 1],
        ],
      }),
    );
    initEngine();
    expect(blockedNotice("toolu_loaded")).toBe("Not run: loaded.");
    expect(blockedNotice("toolu_bad")).toBeUndefined();
    const quiet = typed("go on");
    expect(shapingSwitch("anthropic", quiet, "s-loaded").on).toBe(false);
    expect(shapingSwitch("anthropic", quiet, "s-bad").on).toBeUndefined();
    expect([...requestAllowTags("anthropic", { messages: [] }, "s-loaded")]).toEqual(["pii"]);
    writeFileSync(sessionsFile(), "{not json");
    expect(() => initEngine()).not.toThrow();
  });
});
