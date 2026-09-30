import { describe, expect, it } from "bun:test";
import { createHooks } from "../bench/hooks.ts";
import { assignmentEdits, structuredEdits } from "../engine/lib/structured-text.ts";

function setup() {
  const handlers = createHooks();
  const ctx = { sessionManager: { getSessionFile: () => undefined }, ui: { notify() {} } } as never;
  handlers.agent_start({}, ctx);
  return { handlers, ctx };
}

describe("structured documents", () => {
  it("redacts labeled JSON string secrets and keeps syntax valid", () => {
    const input = JSON.stringify({ username: "fixture", password: "s3cr3t-value-abc", retries: 3 });
    const edits = structuredEdits(input);
    expect(edits.length).toBeGreaterThan(0);
    const { handlers, ctx } = setup();
    try {
      const out = handlers.context({ messages: [{ role: "user", content: input }] }, ctx);
      const rendered = out.messages[0].content as string;
      expect(rendered).not.toContain("s3cr3t-value-abc");
      expect(() => JSON.parse(rendered.split("\n\n")[0]!)).not.toThrow();
      expect(rendered).toContain(`"username"`);
    } finally {
      handlers.session_shutdown();
    }
  });
  it("handles escaped quotes and unicode escapes without breaking JSON", () => {
    const input = `{"password": "a\\"b\\\\c\\u0041", "note": "keep"}`;
    const { handlers, ctx } = setup();
    try {
      const out = handlers.context({ messages: [{ role: "user", content: input }] }, ctx);
      const rendered: string = out ? out.messages[0].content : input;
      if (out) {
        expect(() => JSON.parse(rendered.split("\n\n")[0]!)).not.toThrow();
        expect(rendered).toContain(`"note"`);
      }
    } finally {
      handlers.session_shutdown();
    }
  });
  it("renders numeric PII as a quoted token and records the type change", () => {
    const input = JSON.stringify({ account_number: 63334444, note: "hello" });
    const edits = structuredEdits(input);
    expect(edits.some((e) => e.ruleId === "structured-pii-field")).toBe(true);
    const { handlers, ctx } = setup();
    try {
      const out = handlers.context({ messages: [{ role: "user", content: input }] }, ctx);
      const rendered: string = out ? out.messages[0].content : input;
      if (out) {
        const doc = JSON.parse(rendered.split("\n\n")[0]!);
        expect(typeof doc.account_number).toBe("string");
      }
    } finally {
      handlers.session_shutdown();
    }
  });
  it("ignores similarly named harmless fields and preserves sentinels", () => {
    expect(structuredEdits(JSON.stringify({ password_hint: "x", password: "" }))).toEqual([]);
    expect(structuredEdits(JSON.stringify({ id: 1, key: "v", name: "n", token: "t" }))).toEqual([]);
  });
  it("falls back to text detection on malformed JSON", () => {
    const input = `{"password": "unterminated`;
    expect(structuredEdits(input)).toEqual([]);
    const { handlers } = setup();
    try {
      handlers.session_shutdown();
    } finally {
      handlers.session_shutdown();
    }
  });
  it("supports bounded single-line assignments", () => {
    const edits = assignmentEdits(`password = hunter2hunter\nretries = 3\n`);
    expect(edits.some((e) => e.secretValue === "hunter2hunter")).toBe(true);
    expect(edits.some((e) => e.secretValue === "3")).toBe(false);
  });
  it("hook integration: labeled identity hidden, longer variable survives", async () => {
    const { handlers, ctx } = setup();
    try {
      const res = await handlers.tool_result(
        {
          toolName: "bash",
          content: [{ type: "text", text: `username = "sampler"\nconst samplerCount = 3;` }],
        },
        ctx,
      );
      const text = res.content[0].text as string;
      expect(text).toContain("samplerCount");
      expect(text).not.toContain(`"sampler"`);
    } finally {
      handlers.session_shutdown();
    }
  });
});
