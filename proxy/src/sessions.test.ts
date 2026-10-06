import { describe, expect, it } from "bun:test";
import { AGENT, GUESS, SessionNames, USER } from "./sessions.ts";

describe("session names", () => {
  it("numbers each agent's sessions in the order seen, and keeps a session's name", () => {
    const names = new SessionNames();
    expect(names.name("claude", "aaa")).toBe("claude 1");
    expect(names.name("pi", "bbb")).toBe("pi 1");
    expect(names.name("claude", "ccc")).toBe("claude 2");
    expect(names.name("claude", "aaa")).toBe("claude 1");
  });

  it("keeps the best title a session is given", () => {
    const names = new SessionNames();
    names.name("claude", "aaa");
    // Nothing known: a title for a session never seen is not kept.
    names.title("zzz", "orphan", USER);
    expect(names.list()).toEqual([{ id: "aaa", name: "claude 1" }]);
    // A guess, then an agent's own, then the user's.
    names.title("aaa", "guess", GUESS);
    expect(names.list()[0]).toMatchObject({ title: "guess", guessed: true });
    names.title("aaa", "agent", AGENT);
    expect(names.list()[0]).toMatchObject({ title: "agent" });
    names.title("aaa", "user", USER);
    expect(names.list()[0]).toMatchObject({ title: "user" });
    // A worse one never replaces a better.
    names.title("aaa", "later guess", GUESS);
    expect(names.list()[0]).toMatchObject({ title: "user" });
  });

  it("takes a title with no rank as the agent's own", () => {
    const names = new SessionNames();
    names.name("opencode", "aaa");
    names.title("aaa", "agent title");
    // An agent's title is not marked as a guess: it carries no such flag.
    expect(names.list()[0]).toEqual({ id: "aaa", name: "opencode 1", title: "agent title" });
    // A guess may not stand over it, and the user's name still may.
    names.title("aaa", "later guess", GUESS);
    expect(names.list()[0]).toMatchObject({ title: "agent title" });
    names.title("aaa", "user", USER);
    expect(names.list()[0]).toMatchObject({ title: "user" });
  });

  it("drops the oldest session's name and title once past the bound", () => {
    const names = new SessionNames();
    // NAMES_MAX is 1000; make more than that, so the oldest goes.
    for (let index = 0; index < 1001; index++) names.name("pi", `s${index}`);
    names.title("s1000", "newest", AGENT);
    const list = names.list();
    expect(list).toHaveLength(1000);
    expect(list.map((entry) => entry.id).includes("s0")).toBe(false);
    expect(list.at(-1)).toMatchObject({ id: "s1000", title: "newest" });
  });
});
