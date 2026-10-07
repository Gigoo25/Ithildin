import { describe, expect, it } from "bun:test";
import { badgeText, createStatusBook } from "./status.ts";
import { shapingOn } from "./shape.ts";
import { requestAllowTags, shapingSwitch } from "./redact.ts";

const counts = { masked: 4, files: 1, lines: 2, images: 0 };

// A conversation: the prompts the user typed, in order.
const conversation = (prompts: string[]): Record<string, unknown> => ({
  messages: prompts.map((text) => ({ role: "user", content: text })),
});

describe("the session switch", () => {
  it("is on until the user says otherwise", () => {
    // A session that has typed neither tag has no answer yet: the proxy's
    // default stands, and the badge leaves shaping unmentioned rather than
    // claiming it is off.
    expect(shapingSwitch("anthropic", conversation(["go on"]), "s1")).toEqual({
      on: undefined,
      session: true,
    });
  });

  it("[raw] turns shaping off for the whole session", () => {
    expect(shapingSwitch("anthropic", conversation(["read it [raw]"]), "s2").on).toBe(false);
    // A later prompt that says nothing does not turn it back on.
    expect(shapingSwitch("anthropic", conversation(["and now this"]), "s2").on).toBe(false);
    expect(shapingSwitch("anthropic", conversation(["more"]), "s2").on).toBe(false);
  });

  it("[shape] turns it back on, and off again", () => {
    shapingSwitch("anthropic", conversation(["go [raw]"]), "s3");
    expect(shapingSwitch("anthropic", conversation(["go [shape]"]), "s3").on).toBe(true);
    expect(shapingSwitch("anthropic", conversation(["go"]), "s3").on).toBe(true);
    expect(shapingSwitch("anthropic", conversation(["go [raw]"]), "s3").on).toBe(false);
  });

  it("reads the last tag in a prompt, as the image switch does", () => {
    expect(shapingSwitch("anthropic", conversation(["[raw] wait [shape]"]), "s4").on).toBe(true);
    expect(shapingSwitch("anthropic", conversation(["[shape] wait [raw]"]), "s5").on).toBe(false);
  });

  it("is per session: one session's switch does not touch another's", () => {
    shapingSwitch("anthropic", conversation(["go [raw]"]), "s6");
    expect(shapingSwitch("anthropic", conversation(["go [raw]"]), "s7").on).toBe(false);
    expect(shapingSwitch("anthropic", conversation(["go"]), "s8").on).toBeUndefined();
  });

  it("does not read a tag out of a tool result or a system reminder", () => {
    const quoted = {
      messages: [
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "t1", content: "the user said [raw]" },
            { type: "text", text: "system-reminder: [raw] is documented" },
          ],
        },
      ],
    };
    expect(shapingSwitch("anthropic", quoted, "s9").on).toBeUndefined();
  });

  it("has no switch for a client the proxy cannot name", () => {
    expect(shapingSwitch("anthropic", conversation(["go [raw]"]), null)).toEqual({
      on: undefined,
      session: false,
    });
  });

  it("reads a Responses request's input, and a malformed one safely", () => {
    expect(
      shapingSwitch("responses", { input: [{ role: "user", content: "go [raw]" }] }, "s10").on,
    ).toBe(false);
    expect(shapingSwitch("anthropic", { messages: "not a list" }, "s11").on).toBeUndefined();
    expect(shapingSwitch("anthropic", {}, "s11").on).toBeUndefined();
  });

  it("leaves the allow tags alone: [raw] is not an allow tag", () => {
    const tags = requestAllowTags("anthropic", conversation(["go [raw]"]), "s12");
    expect(tags.has("raw")).toBe(false);
    expect(tags.size).toBe(0);
  });
});

describe("the badge says when shaping is off", () => {
  it("names shaping only when an answer turned it off", () => {
    expect(badgeText(counts, 0, 1, [], {}, true)).not.toContain("shaping");
    expect(badgeText(counts, 0, 1, [], {}, false)).toContain("· shaping off");
    expect(badgeText(counts, 0, 1)).not.toContain("shaping");
  });

  it("keeps the marker last, so a narrow status line still shows it", () => {
    expect(badgeText(counts, 3, 12, ["pii"], {}, false).endsWith("· shaping off")).toBe(true);
  });

  it("records what the last request in a conversation did", () => {
    const book = createStatusBook();
    book.record("s", "anthropic", counts, 1, new Set(), {}, true);
    expect(book.lookup("s", undefined)?.shaping).toBe(true);
    book.record("s", "anthropic", counts, 2, new Set(), {}, false);
    expect(book.lookup("s", undefined)?.shaping).toBe(false);
    expect(book.lookup("s", undefined)?.badge).toContain("shaping off");
  });

  it("leaves a conversation with no request yet unmentioned", () => {
    const book = createStatusBook();
    book.record("s", "anthropic", counts, 1);
    expect(book.lookup("s", undefined)?.shaping).toBeUndefined();
    expect(book.lookup("s", undefined)?.badge).not.toContain("shaping");
  });
});

describe("both switches, together", () => {
  it("shapes only when the environment allows it and the session has not opted out", () => {
    const on = (env: Record<string, string | undefined>, session: boolean | undefined): boolean =>
      shapingOn(env) && session !== false;
    expect(on({}, undefined)).toBe(true);
    expect(on({}, true)).toBe(true);
    expect(on({}, false)).toBe(false);
    expect(on({ ITHILDIN_SHAPE: "off" }, true)).toBe(false);
    expect(on({ ITHILDIN_SHAPE: "off" }, undefined)).toBe(false);
  });

  it("is off by default in the environment, and every spelling says off", () => {
    expect(shapingOn({})).toBe(true);
    for (const value of ["off", "OFF", " raw ", "false", "0"]) {
      expect(shapingOn({ ITHILDIN_SHAPE: value })).toBe(false);
    }
  });
});
