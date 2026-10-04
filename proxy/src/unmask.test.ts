import { beforeAll, describe, expect, it } from "bun:test";
import { initEngine, swapToolArguments } from "./redact.ts";
import { substitutesLetters, unmasksText } from "./unmask.ts";

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
