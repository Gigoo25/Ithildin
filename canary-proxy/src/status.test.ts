import { describe, expect, it } from "bun:test";
import { badgeText, createStatusBook } from "./status.ts";

const none = { masked: 0, files: 0, lines: 0, images: 0 };

describe("badge text", () => {
  it("labels each kind, leaves out zeros, and adds the turn's count", () => {
    expect(badgeText(none, 0)).toBe("CANARY ON · 0");
    expect(badgeText({ masked: 12, files: 1, lines: 3, images: 2 }, 2)).toBe("CANARY ON · 12m 1f 3l 2i (+2)");
    expect(badgeText({ ...none, files: 1 }, 0)).toBe("CANARY ON · 1f");
  });
});

describe("status book", () => {
  it("falls back to the route's latest conversation for an unknown session", () => {
    const book = createStatusBook();
    book.record(undefined, "anthropic", { ...none, masked: 1 }, 1);
    expect(book.lookup("unseen", "anthropic")?.badge).toBe("CANARY ON · 1m (+1)");
    expect(book.lookup("unseen", "opencode-go")).toBeUndefined();
  });

  it("does not count a shrunken conversation as negative", () => {
    const book = createStatusBook();
    book.record("s", "anthropic", { ...none, masked: 5 }, 1);
    book.record("s", "anthropic", { ...none, masked: 1 }, 2);
    expect(book.lookup("s", undefined)?.turn).toBe(0);
  });
});
