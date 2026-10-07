import { describe, expect, it } from "bun:test";
import { allowLabels, badgeText, createStatusBook } from "./status.ts";

const none = { masked: 0, files: 0, lines: 0, images: 0 };

describe("badge text", () => {
  it("says what was done in words, and leaves out zeros", () => {
    expect(badgeText(none, 0)).toBe("ITHILDIN ON · nothing masked");
    expect(badgeText(none, 0, 3)).toBe("ITHILDIN ON · nothing masked · 3 req");
    // Withheld files, lines and images read as one count; the new ones once.
    expect(badgeText({ masked: 12, files: 1, lines: 3, images: 2 }, 2, 40)).toBe(
      "ITHILDIN ON · 12 masked (+2) · 6 withheld",
    );
    expect(badgeText({ ...none, files: 1 }, 1, 4)).toBe("ITHILDIN ON · 1 withheld (+1)");
    expect(badgeText({ ...none, masked: 2 }, 0, 4)).toBe("ITHILDIN ON · 2 masked");
  });

  it("flags what blocks or is unguarded, and only shaping that is off", () => {
    const trust = { untrusted: true, private: true, unguarded: 2 };
    expect(badgeText({ ...none, masked: 41 }, 6, 73, ["pii"], trust, false)).toBe(
      "ITHILDIN ON · 41 masked (+6) · \u26a0 untrusted · \u26a0 private · " +
        "\u26a0 2 unguarded tools · +pii · shaping off",
    );
    expect(badgeText({ ...none, masked: 1 }, 0, 1, [], { unguarded: 1 }, true)).toBe(
      "ITHILDIN ON · 1 masked · \u26a0 1 unguarded tool",
    );
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
      "ITHILDIN ON · nothing masked · 2 req · +pii +protected",
    );
  });

  it("follow the latest prompt: a prompt without one clears it", () => {
    const book = createStatusBook();
    book.record("s", "anthropic", none, 1, new Set(["protected"]));
    expect(book.lookup("s", undefined)?.badge).toBe(
      "ITHILDIN ON · nothing masked · 1 req · +protected",
    );
    book.record("s", "anthropic", none, 2);
    expect(book.lookup("s", undefined)?.allowed).toEqual([]);
  });
});

describe("status book", () => {
  it("falls back to the route's latest conversation for an unknown session", () => {
    const book = createStatusBook();
    book.record(undefined, "anthropic", { ...none, masked: 1 }, 1);
    expect(book.lookup("unseen", "anthropic")?.badge).toBe("ITHILDIN ON · 1 masked (+1)");
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
    expect(book.lookup("a", undefined)?.badge).toBe("ITHILDIN ON · nothing masked · 3 req");
    expect(book.lookup("b", undefined)?.requests).toBe(1);
  });
});
