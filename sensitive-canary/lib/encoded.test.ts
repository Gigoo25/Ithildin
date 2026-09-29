import { afterEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { redactText } from "../core.ts";
import { base64Wrapped, hexdumpC, odX, xxd, xxdPlain } from "./encoded-fixtures.ts";
import { encodedBlocks } from "./encoded.ts";
import { setRuntimeInventory } from "./rules.ts";
import { collectRuntimeIdentity } from "./runtime-inventory.ts";

const HOST = "ZQXLAB-KWVRT7";
const file = Buffer.from(`{"host":"${HOST}","port":22,"note":"enough text for several rows of dump output"}\n`);

afterEach(() => setRuntimeInventory([]));

describe("encoded copies of a value", () => {
  for (const [name, dump] of [["xxd", xxd], ["hexdump -C", hexdumpC], ["od -x", odX], ["base64", base64Wrapped], ["xxd -p", xxdPlain]] as const) {
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
      "SENSITIVE_CANARY_INFRA_INVENTORY",
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
