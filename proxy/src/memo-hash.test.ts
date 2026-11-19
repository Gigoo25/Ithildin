import { describe, expect, it } from "bun:test";
import { memoHash } from "./memo-hash.ts";

describe("memoHash", () => {
  it("is stable within a cache and seeded apart across caches, under Bun", () => {
    const one = memoHash();
    expect(one("abc")).toBe(one("abc"));
    expect(one("abc")).not.toBe(one("abd"));
    expect(memoHash()("abc")).not.toBe(one("abc"));
  });

  it("falls back to a keyed HMAC where Bun is absent (the Node checks)", () => {
    const one = memoHash(null);
    expect(typeof one("abc")).toBe("bigint");
    expect(one("abc")).toBe(one("abc"));
    expect(one("abc")).not.toBe(one("abd"));
    expect(memoHash(null)("abc")).not.toBe(one("abc"));
  });
});
