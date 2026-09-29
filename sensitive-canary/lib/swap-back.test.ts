import { expect, it } from "bun:test";
import { AliasBook } from "./aliases.ts";
import { planSwapBack } from "./swap-back.ts";

const book = () => new AliasBook(Buffer.alloc(32, 7));

// A multi-label host stand-in used to resolve piece by piece through the
// lowercased part map, so a mixed-case hostname came back lowercased and a
// case-sensitive lookup (a flake attribute) named a host that did not exist.
it("swaps a multi-label host stand-in back with its exact case", () => {
  const aliasBook = book();
  const standIn = aliasBook.standIn("pii-inventory-runtime-host", "ZQXLAB-KWVRT7");
  expect(standIn).toMatch(/^[a-z]{6}-[a-z]{5}[0-9]$/);
  const swap = planSwapBack("bash", { command: `nix eval .#hosts.${standIn}.config` }, aliasBook, true);
  expect(swap.input).toEqual({ command: "nix eval .#hosts.ZQXLAB-KWVRT7.config" });
  expect(swap.resolved).toHaveLength(1);
});

it("does not take a whole stand-in inside a longer name", () => {
  const aliasBook = book();
  const standIn = aliasBook.standIn("pii-inventory-runtime-host", "ZQXLAB-KWVRT7");
  const swap = planSwapBack("bash", { command: `echo x${standIn}` }, aliasBook, true);
  expect(swap.input).toEqual({ command: `echo x${standIn}` });
  expect(swap.resolved).toHaveLength(0);
});

it("still composes stand-ins the model assembled from known parts", () => {
  const aliasBook = book();
  const standIn = aliasBook.standIn("pii-inventory-runtime-host", "ZQXLAB-KWVRT7");
  const [first] = standIn.split("-");
  const swap = planSwapBack("bash", { command: `ping ${first}-db` }, aliasBook, true);
  expect(swap.input).toEqual({ command: "ping zqxlab-db" });
});
