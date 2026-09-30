import { expect, it } from "bun:test";
import { assert, AssertionFailed } from "./assert.ts";

it("passes a holding invariant and throws on a broken one, naming it", () => {
  expect(() => assert(true, "holds")).not.toThrow();
  expect(() => assert(0, "counts positive")).toThrow(AssertionFailed);
  expect(() => assert(undefined, "counts positive")).toThrow("invariant violated: counts positive");
});
