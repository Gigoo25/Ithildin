import { afterEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { redactText } from "../core.ts";
import { base64Wrapped, hexdumpC, odX, xxd, xxdPlain } from "./encoded-fixtures.ts";
import { encodedBlocks, redactRot13, rot13 } from "./encoded.ts";
import { setRuntimeInventory } from "./rules.ts";
import { collectRuntimeIdentity } from "./runtime-inventory.ts";

const HOST = "ZQXLAB-KWVRT7";
const file = Buffer.from(
  `{"host":"${HOST}","port":22,"note":"enough text for several rows of dump output"}\n`,
);

afterEach(() => setRuntimeInventory([]));

describe("encoded copies of a value", () => {
  for (const [name, dump] of [
    ["xxd", xxd],
    ["hexdump -C", hexdumpC],
    ["od -x", odX],
    ["base64", base64Wrapped],
    ["xxd -p", xxdPlain],
  ] as const) {
    it(`withholds ${name} output that holds an inventory value`, () => {
      setRuntimeInventory(collectRuntimeIdentity({ hostname: HOST }));
      const text = `$ ${name} config.json\n${dump(file)}done\n`;
      const out = redactText(text).text;
      expect(out).toContain("encoded data holding personal data");
      expect(out).not.toContain(dump(file).split("\n")[0]!);
      expect(out.startsWith(`$ ${name} config.json\n`)).toBe(true);
      expect(out.endsWith("done\n")).toBe(true);
    });
  }

  it("passes encoded data through when it holds nothing", () => {
    setRuntimeInventory(collectRuntimeIdentity({ hostname: HOST }));
    const plain = Buffer.from("just an ordinary configuration line, nothing private in it\n");
    for (const dump of [xxd, hexdumpC, odX, base64Wrapped, xxdPlain]) {
      const text = dump(plain);
      expect(redactText(text).text).not.toContain("encoded data holding");
    }
  });

  it("leaves hashes, store paths and identifiers alone", () => {
    const text = [
      createHash("sha256").update("x").digest("hex"),
      createHash("sha1").update("x").digest("hex"),
      `sha256-${createHash("sha256").update("y").digest("base64")}`,
      "/nix/store/xz8sbxyhcnvr9q0v422xq1w5v8qxsd6c-home-manager-files",
      "ITHILDIN_INFRA_INVENTORY",
      "00000000-1111-2222-3333-444444444444",
    ].join("\n");
    expect(encodedBlocks(text)).toEqual([]);
  });

  it("is lifted by [allow-pii]", () => {
    setRuntimeInventory(collectRuntimeIdentity({ hostname: HOST }));
    const text = xxd(file);
    expect(redactText(text, new Set(["pii"])).text).toBe(text);
  });
});

describe("rot13 copies of a masked value", () => {
  it("withholds a rot13 copy of a value already masked", () => {
    setRuntimeInventory(collectRuntimeIdentity({ hostname: HOST }));
    expect(redactText(`ssh ${HOST}`).text).not.toContain(HOST);
    const result = redactText(`decoded: ${rot13(HOST)} done`);
    expect(result.text).not.toContain(rot13(HOST));
    expect(result.text).toContain("(rot13 of a masked value)");
    expect(result.text).toStartWith("decoded: ");
    expect(result.text).toEndWith(" done");
  });

  it("matches whole tokens only, and no short values", () => {
    expect(redactRot13("open the Notebook tab", ["rob"], () => {}).hits).toBe(0);
    const inside = `x${rot13("zqxlab")}y`;
    expect(redactRot13(inside, ["zqxlab"], () => {}).hits).toBe(0);
    expect(redactRot13(`see ${rot13("zqxlab")}.`, ["zqxlab"], () => {}).hits).toBe(1);
  });

  it("leaves rot13 of unmasked text alone", () => {
    const text = `notes ${rot13("ordinary words here")}`;
    expect(redactRot13(text, ["zqxlab"], () => {}).text).toBe(text);
  });

  it("skips values too short or without letters to rotate", () => {
    const text = `ab ${rot13("ab")} 10.0.0.1`;
    expect(redactRot13(text, ["ab", "10.0.0.1"], () => {}).hits).toBe(0);
  });

  it("is lifted by [allow-all]", () => {
    setRuntimeInventory(collectRuntimeIdentity({ hostname: HOST }));
    redactText(`ssh ${HOST}`);
    const text = `decoded: ${rot13(HOST)}`;
    expect(redactText(text, new Set(["all"])).text).toBe(text);
  });
});
