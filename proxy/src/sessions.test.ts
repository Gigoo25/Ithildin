import { describe, expect, it } from "bun:test";
import { SessionNames } from "./sessions.ts";

describe("session names", () => {
  it("numbers each agent's sessions in the order seen, and keeps a session's name", () => {
    const names = new SessionNames();
    expect(names.name("claude", "aaa")).toBe("claude 1");
    expect(names.name("pi", "bbb")).toBe("pi 1");
    expect(names.name("claude", "ccc")).toBe("claude 2");
    expect(names.name("claude", "aaa")).toBe("claude 1");
  });
});
