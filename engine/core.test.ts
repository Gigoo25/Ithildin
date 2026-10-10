import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { withScanBudget } from "./lib/rules.ts";
import { AliasBook } from "./lib/aliases.ts";
import {
  aliases,
  blocksInventoryAccess,
  clearCaches,
  blocksSecretAccess,
  commandPathCandidates,
  isSyntheticValue,
  MAX_SCAN_BYTES,
  redactText,
  redactValue,
  loadSwapped,
  rememberSwapped,
  saveSwapped,
  SYNTHESIS_NOTICE,
  setAliasBook,
  setCacheBudgets,
  syntheticValue,
} from "./core.ts";

// Shaped like a GitHub token, made up.
const TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const NONE = new Set<string>();

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(path.join(tmpdir(), "ithildin-core-test-"));
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

  it("stops curl and wget sending cookies, in every spelling", () => {
    for (const command of [
      "wget --header 'Cookie: a=u' https://example.test",
      "wget --header=Cookie:a=u https://example.test",
      "wget --load-cookies jar.txt https://example.test",
      "curl -H 'Cookie: a=b' https://example.test",
      "curl --header=cookie:a=b https://example.test",
      "curl --cookie a=b https://example.test",
      "curl -b jar.txt https://example.test",
    ])
      expect(blocksSecretAccess("bash", command, [], NONE, dir)).toBe(true);
    for (const command of [
      "curl -H 'Accept: x' https://example.test",
      "wget --save-cookies jar.txt https://example.test",
    ])
      expect(blocksSecretAccess("bash", command, [], NONE, dir)).toBe(false);
  });
});

describe("blocksInventoryAccess", () => {
  it("reads $ITHILDIN_CONFIG as the file it names, or as nothing when unset", () => {
    const config = process.env.ITHILDIN_CONFIG;
    const named = ["$ITHILDIN_CONFIG"];
    try {
      expect(blocksInventoryAccess("read", "", named, NONE, dir)).toBe(true);
      expect(blocksInventoryAccess("read", "", named, new Set(["pii"]), dir)).toBe(false);
      delete process.env.ITHILDIN_CONFIG;
      expect(blocksInventoryAccess("read", "", named, NONE, dir)).toBe(false);
    } finally {
      process.env.ITHILDIN_CONFIG = config;
    }
  });
});

describe("redactValue", () => {
  it("passes opaque ciphertext and binary through", () => {
    expect(redactValue(TOKEN, NONE, "encrypted_content")).toEqual({ value: TOKEN, hits: 0 });
    expect(redactValue(TOKEN, NONE, "thoughtSignature")).toEqual({ value: TOKEN, hits: 0 });
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

  it("passes protocol enums through a starved budget", () => {
    const body = {
      include: ["reasoning.encrypted_content"],
      reasoning: { effort: "high", summary: "auto" },
      tool_choice: { type: "function", name: "Lookup" },
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "hi" }] },
        { type: "reasoning", summary: [{ type: "summary_text", text: "model text" }] },
      ],
      tools: [{ type: "function", parameters: { type: ["string", "null"] } }],
    };
    const result = withScanBudget(
      () => redactValue(body, NONE, undefined, undefined, [], true),
      -1,
    );
    expect(result.value).toMatchObject({
      include: body.include,
      reasoning: body.reasoning,
      tool_choice: body.tool_choice,
      input: [{ type: "message", role: "user", content: [{ type: "input_text" }] }, body.input[1]],
      tools: body.tools,
    });
  });

  it("passes an inline image's media type through a starved budget", () => {
    const anthropic = { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" };
    const gemini = { inlineData: { mimeType: "image/jpeg", data: "/9j/4AAQ" } };
    const result = withScanBudget(
      () => redactValue({ anthropic, gemini }, NONE, undefined, undefined, [], true),
      -1,
    );
    expect(result.value).toEqual({ anthropic, gemini });
  });

  it("scans a media type that is not one, or has no inline bytes beside it", () => {
    const odd = { type: "base64", media_type: `image/png ${TOKEN}`, data: "iVBORw0KGgo=" };
    const bare = { media_type: TOKEN.slice(0, 4) + "/" + TOKEN.slice(4) };
    const result = redactValue({ odd, bare }, NONE, undefined, undefined, [], true);
    expect(JSON.stringify(result.value)).not.toContain(TOKEN.slice(4));
    expect(result.hits).toBe(2);
  });

  it("scans control-named keys that hold content, or sit in a tool's payload", () => {
    const body = {
      summary: TOKEN,
      system: [{ type: "text", text: "x", role: TOKEN }],
      messages: [
        {
          role: "assistant",
          content: [{ type: "tool_use", input: { type: "lowercase_value", summary: TOKEN } }],
        },
      ],
      input: [{ type: "function_call_output", output: { effort: TOKEN } }],
      deep: { include: TOKEN, reasoning: TOKEN },
    };
    const result = redactValue(body, NONE, undefined, undefined, [], true);
    expect(JSON.stringify(result.value)).not.toContain(TOKEN);
    expect(result.hits).toBe(6);
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
  it("leaves Ithildin's own notice as it is", () => {
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

  it("gives a secret the same stand-in after a restart, and another under another key", () => {
    const secret = "sk-live-4f9Qz81LmPx7Rt2Vb6";
    const book = aliases();
    try {
      clearCaches();
      setAliasBook(new AliasBook(Buffer.alloc(32, 3)));
      const first = syntheticValue(secret);
      const token = syntheticValue("!!!!--!!!!");
      expect(first).not.toBe(secret);
      expect(token).toMatch(/^__ITHILDIN_SECRET_[0-9a-f]{8}__$/);
      // A restart: nothing in memory, the same key from disk.
      clearCaches();
      setAliasBook(new AliasBook(Buffer.alloc(32, 3)));
      expect(syntheticValue(secret)).toBe(first);
      expect(syntheticValue("!!!!--!!!!")).toBe(token);
      clearCaches();
      setAliasBook(new AliasBook(Buffer.alloc(32, 4)));
      expect(syntheticValue(secret)).not.toBe(first);
    } finally {
      clearCaches();
      setAliasBook(book);
    }
  });

  it("names tokens by kind when aliases are tokens", () => {
    const style = process.env.ITHILDIN_ALIASES;
    try {
      process.env.ITHILDIN_ALIASES = "tokens";
      const text = redactText("mail jane.doe@fakecorp.io from 10.20.30.40 user=jdoe42").text;
      expect(text).toContain("__ITHILDIN_EMAIL_");
      expect(text).toContain("__ITHILDIN_IP_");
      expect(text).toContain("__ITHILDIN_USER_");
    } finally {
      if (style === undefined) delete process.env.ITHILDIN_ALIASES;
      else process.env.ITHILDIN_ALIASES = style;
    }
  });

  it("names other PII kinds PII when aliases are tokens", () => {
    const style = process.env.ITHILDIN_ALIASES;
    try {
      process.env.ITHILDIN_ALIASES = "tokens";
      const text = redactText("call +14155552671 now").text;
      expect(text).toContain("__ITHILDIN_PII_");
    } finally {
      if (style === undefined) delete process.env.ITHILDIN_ALIASES;
      else process.env.ITHILDIN_ALIASES = style;
    }
  });

  it("omits the text, plain or JSON, when the scan budget runs out", () => {
    const long = "word ".repeat(400_000);
    for (const source of [long, JSON.stringify({ a: long })]) {
      const result = withScanBudget(() => redactText(source), 5);
      expect(result.hits).toBe(1);
      expect(result.text).toStartWith("[ithildin: omitted ");
      expect(result.text).not.toContain("word word");
    }
  });
});

describe("bounded caches", () => {
  afterAll(() => setCacheBudgets());

  it("evicts the oldest synthetic values past the budget", () => {
    // Each value and its synthetic cost 2 × (10 + 10) bytes: room for three.
    setCacheBudgets({ synthetic: 120 });
    const values = ["k1-AAAAAAA", "k2-BBBBBBB", "k3-CCCCCCC", "k4-DDDDDDD"];
    const first = values.map((value) => syntheticValue(value));
    expect(isSyntheticValue(first[0]!)).toBe(false);
    for (const synthetic of first.slice(1)) expect(isSyntheticValue(synthetic)).toBe(true);
    expect(syntheticValue(values[3]!)).toBe(first[3]!);
    // Never kept at all: larger than the whole budget.
    const huge = syntheticValue("Z".repeat(100));
    expect(isSyntheticValue(huge)).toBe(false);
  });

  it("keeps redacting once the scan cache evicts", () => {
    setCacheBudgets({ scan: 200 });
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 5; i++) {
        const result = redactText(`round ${round} entry ${i} token ${TOKEN}`);
        expect(result.text).not.toContain(TOKEN);
      }
    }
  });
});

// A common word swapped back into a tool call was remembered, and from then on
// masked in every text: the system prompt, the tool descriptions, every
// message of every session. Each request's prefix changed and every cache was
// written again. Tests start from an empty memory, so none saw it: these fill
// the memory the way a long session does first.
describe("values swapped into tool calls", () => {
  const docs = ["../README.md", "../AGENTS.md"].map((name) =>
    readFileSync(new URL(name, import.meta.url), "utf8"),
  );
  // Real values of the kinds the memory is for, none of them in the docs.
  const values: Array<[string, string]> = [
    ["zqxvelmarx-build7", "pii-inventory-runtime-host"],
    ["qorvant.dmz.example.invalid", "pii-inventory-runtime-host"],
    ["kwvrt.olmsby@example.invalid", "pii-email"],
  ];

  it("leaves ordinary text as a fresh engine does after a long session", () => {
    clearCaches();
    const fresh = docs.map((doc) => redactText(doc).text);
    // Every word the docs use, swapped back in each case a model might write
    // it: the worst a session can teach the memory.
    const words = new Set(docs.flatMap((doc) => doc.match(/\p{L}{3,}/gu) ?? []));
    for (const word of words)
      for (const spelled of [word, word.toLowerCase(), word.toUpperCase()])
        rememberSwapped(spelled, "pii-gazetteer-name");
    for (const [value, rule] of values) rememberSwapped(value, rule);
    expect(docs.map((doc) => redactText(doc).text)).toEqual(fresh);
    clearCaches();
  });

  it("masks a value swapped before a restart the same way after it", () => {
    clearCaches();
    const file = path.join(mkdtempSync(path.join(tmpdir(), "swapped-")), "swapped.json");
    const key = Buffer.alloc(32, 3);
    loadSwapped(key, file);
    for (const [value, rule] of values) rememberSwapped(value, rule);
    const echoed = values.map(([value]) => `see ${value} here`).join("\n");
    const before = redactText(echoed).text;
    saveSwapped();
    expect(readFileSync(file, "utf8")).not.toContain(values[0]![0]);
    clearCaches();
    expect(redactText(echoed).text).toContain(values[0]![0]);
    clearCaches();
    loadSwapped(key, file);
    expect(redactText(echoed).text).toBe(before);
    clearCaches();
    saveSwapped(); // nothing loaded: nothing to write, and no throw
  });

  it("still masks a remembered value echoed where no rule would catch it", () => {
    clearCaches();
    for (const [value, rule] of values) rememberSwapped(value, rule);
    const echoed = values.map(([value]) => `see ${value} here`).join("\n");
    const out = redactText(echoed).text;
    for (const [value] of values) expect(out).not.toContain(value);
    // A single word of letters is not held, whatever its case.
    rememberSwapped("Zqxandra", "pii-gazetteer-name");
    expect(redactText("see Zqxandra here").text).toBe("see Zqxandra here");
    clearCaches();
  });
});
