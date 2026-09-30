import { describe, expect, it } from "bun:test";
import { configFile, configHome, sessionFile, setting, stateDir, stateHome } from "./names.ts";

describe("setting", () => {
  it("reads ITHILDIN_<name> only", () => {
    expect(setting("PORT", { ITHILDIN_PORT: "1" })).toBe("1");
    expect(setting("PORT", { SENSITIVE_CANARY_PORT: "2" })).toBeUndefined();
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

describe("paths", () => {
  it("puts config, state and session files under the one name", () => {
    expect(configFile("config.json", { XDG_CONFIG_HOME: "/x" })).toBe("/x/ithildin/config.json");
    expect(stateDir({ XDG_STATE_HOME: "/s" })).toBe("/s/ithildin");
    expect(sessionFile("/t/a.jsonl", "scan-cache.json")).toBe(
      "/t/a.jsonl.ithildin-scan-cache.json",
    );
  });
});
