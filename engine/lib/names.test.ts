import { afterEach, describe, expect, it } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  configFile,
  configHome,
  LEGACY_ENGINE,
  sessionFile,
  setting,
  stateDir,
  stateHome,
} from "./names.ts";

let dir = "";
const scratch = () => (dir = mkdtempSync(join(tmpdir(), "ithildin-names-")));
afterEach(() => dir && rmSync(dir, { recursive: true, force: true }));

describe("setting", () => {
  it("reads the new name first, then the old one", () => {
    expect(setting("PORT", { ITHILDIN_PORT: "1", SENSITIVE_CANARY_PORT: "2" })).toBe("1");
    expect(setting("PORT", { SENSITIVE_CANARY_PORT: "2" })).toBe("2");
    expect(setting("PORT", {})).toBeUndefined();
  });
});

describe("homes", () => {
  it("follows XDG, else HOME", () => {
    expect(configHome({ XDG_CONFIG_HOME: "/x", HOME: "/h" })).toBe("/x");
    expect(configHome({ HOME: "/h" })).toBe("/h/.config");
    expect(stateHome({ XDG_STATE_HOME: "/s", HOME: "/h" })).toBe("/s");
    expect(stateHome({ HOME: "/h" })).toBe("/h/.local/state");
  });
});

describe("configFile", () => {
  it("reads the old directory only when the new one lacks the file", () => {
    const env = { XDG_CONFIG_HOME: scratch() };
    const current = join(dir, "ithildin", "config.json");
    const legacy = join(dir, LEGACY_ENGINE, "config.json");
    expect(configFile("config.json", LEGACY_ENGINE, env)).toBe(current);
    mkdirSync(join(dir, LEGACY_ENGINE));
    writeFileSync(legacy, "{}");
    expect(configFile("config.json", LEGACY_ENGINE, env)).toBe(legacy);
    mkdirSync(join(dir, "ithildin"));
    writeFileSync(current, "{}");
    expect(configFile("config.json", LEGACY_ENGINE, env)).toBe(current);
    expect(existsSync(legacy)).toBe(true);
  });
});

describe("stateDir", () => {
  it("moves the old state directory once, keeping what it held", () => {
    const env = { XDG_STATE_HOME: scratch() };
    mkdirSync(join(dir, LEGACY_ENGINE));
    writeFileSync(join(dir, LEGACY_ENGINE, "counters"), "kept");
    const current = stateDir(env);
    expect(current).toBe(join(dir, "ithildin"));
    expect(readFileSync(join(current, "counters"), "utf8")).toBe("kept");
    expect(existsSync(join(dir, LEGACY_ENGINE))).toBe(false);
    expect(stateDir(env)).toBe(current);
  });

  it("uses the old directory where it is when the move fails", () => {
    const env = { XDG_STATE_HOME: scratch() };
    mkdirSync(join(dir, LEGACY_ENGINE));
    // A read-only parent: the rename cannot land.
    chmodSync(dir, 0o500);
    try {
      expect(stateDir(env)).toBe(join(dir, LEGACY_ENGINE));
    } finally {
      chmodSync(dir, 0o700);
    }
  });
});

describe("sessionFile", () => {
  it("renames a session's old file to the new suffix once", () => {
    const session = join(scratch(), "a.jsonl");
    expect(sessionFile(session, "alias-key")).toBe(`${session}.ithildin-alias-key`);
    writeFileSync(`${session}.canary-alias-key`, "key");
    expect(sessionFile(session, "alias-key")).toBe(`${session}.ithildin-alias-key`);
    expect(readFileSync(`${session}.ithildin-alias-key`, "utf8")).toBe("key");
    expect(existsSync(`${session}.canary-alias-key`)).toBe(false);
  });

  it("uses the old file where it is when the move fails", () => {
    const session = join(scratch(), "a.jsonl");
    writeFileSync(`${session}.canary-alias-key`, "key");
    chmodSync(dir, 0o500);
    try {
      expect(sessionFile(session, "alias-key")).toBe(`${session}.canary-alias-key`);
    } finally {
      chmodSync(dir, 0o700);
    }
  });
});
