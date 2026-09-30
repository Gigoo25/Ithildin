import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { withScanBudget } from "./lib/rules.ts";
import {
  blocksInventoryAccess,
  blocksSecretAccess,
  commandPathCandidates,
  MAX_SCAN_BYTES,
  redactText,
  redactValue,
  SYNTHESIS_NOTICE,
  syntheticValue,
} from "./core.ts";

// Shaped like a GitHub token, made up.
const TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const NONE = new Set<string>();

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(path.join(tmpdir(), "canary-core-test-"));
  for (const name of ["a.txt", "b.txt", ".hidden.txt", "service.key"])
    writeFileSync(path.join(dir, name), "");
  mkdirSync(path.join(dir, "sub"));
  writeFileSync(path.join(dir, "sub", "c.txt"), "");
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const candidates = (command: string) => commandPathCandidates(command, dir);

describe("commandPathCandidates", () => {
  it("expands brace lists, and stops at 64 words", () => {
    expect(candidates("cat notes.{txt,md}")).toEqual(
      expect.arrayContaining(["notes.txt", "notes.md"]),
    );
    const words = new Set(candidates(`cat ${"{a,b}".repeat(8)}`).filter((c) => c !== "cat"));
    expect(words.size).toBe(64);
  });

  it("decodes ANSI-C quoting: hex, unicode, octal and named escapes", () => {
    expect(candidates(String.raw`cat $'\x6eotes'`)).toContain("notes");
    expect(candidates(String.raw`cat $'notes'`)).toContain("notes");
    expect(candidates(String.raw`cat $'\156otes'`)).toContain("notes");
    expect(candidates(String.raw`cat $'a\tb'`).some((c) => c.includes("a\tb"))).toBe(true);
    expect(candidates(String.raw`cat $'a\qb'`).some((c) => c.includes("aqb"))).toBe(true);
  });

  it("substitutes variables the command sets", () => {
    expect(candidates("f=notes.txt; cat $f")).toContain("notes.txt");
    expect(candidates("f=notes.txt; cat ${f}")).toContain("notes.txt");
  });

  it("expands globs like bash, skipping dotfiles unless the pattern names them", () => {
    const star = candidates("cat *.txt");
    expect(star).toEqual(expect.arrayContaining(["a.txt", "b.txt"]));
    expect(star).not.toContain(".hidden.txt");
    expect(candidates("cat .*.txt")).toContain(".hidden.txt");
    expect(candidates("cat ?.txt")).toEqual(expect.arrayContaining(["a.txt", "b.txt"]));
    expect(candidates("cat sub/*.txt")).toContain("sub/c.txt");
  });

  it("reads bracket classes, negated ones, and a lone bracket as a literal", () => {
    expect(candidates("cat [a].txt")).toContain("a.txt");
    expect(candidates("cat [!a].txt")).toContain("b.txt");
    expect(candidates("cat [!a].txt")).not.toContain("a.txt");
    expect(candidates("cat a[.txt")).not.toContain("a.txt");
  });

  it("expands nothing for a quoted glob, a bad range, a missing or globbed directory", () => {
    expect(candidates(`cat "*.txt"`)).not.toContain("a.txt");
    expect(candidates("cat [z-a].txt")).not.toContain("a.txt");
    expect(candidates("cat missing/*.txt")).not.toContain("missing/a.txt");
    expect(candidates("cat */c.txt")).not.toContain("sub/c.txt");
    expect(candidates("cat sub/")).not.toContain("sub/c.txt");
  });
});

describe("blocksSecretAccess", () => {
  it("sees a secret file behind a glob, unless secrets are allowed", () => {
    expect(blocksSecretAccess("bash", "cat *.key", [], NONE, dir)).toBe(true);
    expect(blocksSecretAccess("bash", "cat *.key", [], new Set(["secret"]), dir)).toBe(false);
    expect(blocksSecretAccess("bash", "cat *.txt", [], NONE, dir)).toBe(false);
  });

  it("stops curl sending cookies, in every spelling", () => {
    for (const command of [
      "curl -H 'Cookie: a=b' https://example.test",
      "curl --header=cookie:a=b https://example.test",
      "curl --cookie a=b https://example.test",
      "curl -b jar.txt https://example.test",
    ])
      expect(blocksSecretAccess("bash", command, [], NONE, dir)).toBe(true);
    expect(
      blocksSecretAccess("bash", "curl -H 'Accept: x' https://example.test", [], NONE, dir),
    ).toBe(false);
  });
});

describe("blocksInventoryAccess", () => {
  it("reads $SENSITIVE_CANARY_CONFIG as the file it names, or as nothing when unset", () => {
    const config = process.env.SENSITIVE_CANARY_CONFIG;
    const named = ["$SENSITIVE_CANARY_CONFIG"];
    try {
      expect(blocksInventoryAccess("read", "", named, NONE, dir)).toBe(true);
      expect(blocksInventoryAccess("read", "", named, new Set(["pii"]), dir)).toBe(false);
      delete process.env.SENSITIVE_CANARY_CONFIG;
      expect(blocksInventoryAccess("read", "", named, NONE, dir)).toBe(false);
    } finally {
      process.env.SENSITIVE_CANARY_CONFIG = config;
    }
  });
});

describe("redactValue", () => {
  it("passes opaque ciphertext and binary through", () => {
    expect(redactValue(TOKEN, NONE, "encrypted_content")).toEqual({ value: TOKEN, hits: 0 });
    const bytes = new Uint8Array([1, 2, 3]);
    expect(redactValue(bytes, NONE).value).toBe(bytes);
    expect(redactValue(42, NONE)).toEqual({ value: 42, hits: 0 });
    const image = `data:image/png;base64,${TOKEN}`;
    expect(redactValue(image, NONE, "image_url")).toEqual({ value: image, hits: 0 });
  });

  it("keeps schema `required` names in tool definitions", () => {
    const body = { tools: [{ input_schema: { required: [TOKEN] } }] };
    expect(redactValue(body, NONE, undefined, undefined, [], true)).toEqual({
      value: body,
      hits: 0,
    });
    expect(redactValue({ other: { required: [TOKEN] } }, NONE).hits).toBe(1);
  });

  it("replaces a string too long to scan whole", () => {
    const long = "x".repeat(MAX_SCAN_BYTES + 1);
    const result = redactValue(long, NONE);
    expect(result.hits).toBe(1);
    expect(result.value).not.toBe(long);
    expect((result.value as string).length).toBe(long.length);
  });

  it("scans a cookie header's values, unless secrets are allowed", () => {
    const cookie = `session=${TOKEN}; theme=dark`;
    const masked = redactValue(cookie, NONE, "cookie");
    expect(masked.hits).toBeGreaterThan(0);
    expect(masked.value).not.toContain(TOKEN);
    expect(masked.value).toMatch(/^session=\S+; theme=\S+$/);
    expect(redactValue(cookie, new Set(["secret"]), "cookie").value).toBe(cookie);
  });
});

describe("redactText", () => {
  it("leaves the canary's own notice as it is", () => {
    expect(redactText(SYNTHESIS_NOTICE).text).toBe(SYNTHESIS_NOTICE);
    expect(redactText(`${SYNTHESIS_NOTICE}\n${SYNTHESIS_NOTICE}`).hits).toBe(0);
  });

  it("replaces a numeric credential field and keeps the JSON valid", () => {
    const result = redactText('{"password": 123456789012}');
    expect(result.hits).toBeGreaterThan(0);
    expect(() => JSON.parse(result.text)).not.toThrow();
    expect(result.text).not.toContain("123456789012");
  });

  it("gives a punctuation-only secret a token, not itself", () => {
    const synthetic = syntheticValue("!!!!--!!!!");
    expect(synthetic).not.toBe("!!!!--!!!!");
    expect(syntheticValue("!!!!--!!!!")).toBe(synthetic);
  });

  it("names tokens by kind when aliases are tokens", () => {
    const style = process.env.SENSITIVE_CANARY_ALIASES;
    try {
      process.env.SENSITIVE_CANARY_ALIASES = "tokens";
      const text = redactText("mail jane.doe@fakecorp.io from 10.20.30.40 user=jdoe42").text;
      expect(text).toContain("__CANARY_EMAIL_");
      expect(text).toContain("__CANARY_IP_");
      expect(text).toContain("__CANARY_USER_");
    } finally {
      if (style === undefined) delete process.env.SENSITIVE_CANARY_ALIASES;
      else process.env.SENSITIVE_CANARY_ALIASES = style;
    }
  });

  it("omits the text, plain or JSON, when the scan budget runs out", () => {
    const long = "word ".repeat(400_000);
    for (const source of [long, JSON.stringify({ a: long })]) {
      const result = withScanBudget(() => redactText(source), 5);
      expect(result.hits).toBe(1);
      expect(result.text).toStartWith("[sensitive-canary: omitted ");
      expect(result.text).not.toContain("word word");
    }
  });
});
