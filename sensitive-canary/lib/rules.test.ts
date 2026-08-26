import { describe, expect, it } from "bun:test";
import { scan } from "./rules.ts";

describe("generic secret detection", () => {
  it("detects values behind quoted JSON keys", () => {
    const value = "0123456789abcdef".repeat(3).slice(0, 40);
    const findings = scan(JSON.stringify({ apiKey: value }));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "generic-secret",
      secretValue: value,
    });
  });
});
