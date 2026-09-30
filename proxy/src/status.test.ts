import { describe, expect, it } from "bun:test";
import { allowLabels, badgeText, createStatusBook } from "./status.ts";

const none = { masked: 0, files: 0, lines: 0, images: 0 };

describe("badge text", () => {
  it("labels each kind, leaves out zeros, and adds the turn's count", () => {
    expect(badgeText(none, 0)).toBe("ITHILDIN ON · 0");
    expect(badgeText({ masked: 12, files: 1, lines: 3, images: 2 }, 2)).toBe(
      "ITHILDIN ON · 12m 1f 3l 2i (+2)",
    );
    expect(badgeText({ ...none, files: 1 }, 0)).toBe("ITHILDIN ON · 1f");
    expect(badgeText(none, 0, 3)).toBe("ITHILDIN ON · 0 · 3 req");
    expect(badgeText({ ...none, masked: 2 }, 1, 4)).toBe("ITHILDIN ON · 2m (+1) · 4 req");
  });
});

describe("allow tags", () => {
  it("names what the user typed, [allow-all] as all", () => {
    expect(allowLabels(new Set())).toEqual([]);
    expect(allowLabels(new Set(["secret"]))).toEqual(["secrets"]);
    expect(allowLabels(new Set(["protected", "pii"]))).toEqual(["pii", "protected"]);
    expect(allowLabels(new Set(["all", "secret", "pii"]))).toEqual(["all"]);
    expect(allowLabels(new Set(["all", "secret", "pii", "protected"]))).toEqual([
      "all",
      "protected",
    ]);
  });

  it("go last in the badge", () => {
    expect(badgeText(none, 0, 2, ["pii", "protected"])).toBe(
      "ITHILDIN ON · 0 · 2 req · +pii +protected",
    );
  });

  it("follow the latest prompt: a prompt without one clears it", () => {
    const book = createStatusBook();
    book.record("s", "anthropic", none, 1, new Set(["protected"]));
    expect(book.lookup("s", undefined)?.badge).toBe("ITHILDIN ON · 0 · 1 req · +protected");
    book.record("s", "anthropic", none, 2);
    expect(book.lookup("s", undefined)?.allowed).toEqual([]);
  });
});

describe("status book", () => {
  it("falls back to the route's latest conversation for an unknown session", () => {
    const book = createStatusBook();
    book.record(undefined, "anthropic", { ...none, masked: 1 }, 1);
    expect(book.lookup("unseen", "anthropic")?.badge).toBe("ITHILDIN ON · 1m (+1) · 1 req");
    expect(book.lookup("unseen", "opencode-go")).toBeUndefined();
  });

  it("does not count a shrunken conversation as negative", () => {
    const book = createStatusBook();
    book.record("s", "anthropic", { ...none, masked: 5 }, 1);
    book.record("s", "anthropic", { ...none, masked: 1 }, 2);
    expect(book.lookup("s", undefined)?.turn).toBe(0);
  });

  it("counts requests per conversation, so a quiet session still ticks", () => {
    const book = createStatusBook();
    for (let i = 0; i < 3; i++) book.record("a", "anthropic", none, 1);
    book.record("b", "anthropic", none, 1);
    expect(book.lookup("a", undefined)?.badge).toBe("ITHILDIN ON · 0 · 3 req");
    expect(book.lookup("b", undefined)?.requests).toBe(1);
  });
});
