import { describe, expect, it } from "bun:test";
import { RULES, scan } from "./rules.ts";

describe("upstream detector parity", () => {
  it("loads every detector block from the pinned upstream config", async () => {
    const config = (await Bun.file(`${import.meta.dir}/default-config.json`).json()) as {
      rules: Array<{ id: string }>;
    };
    const loadedIds = new Set(RULES.map((rule) => rule.id));

    expect(config.rules).toHaveLength(76);
    expect(config.rules.every((rule) => loadedIds.has(rule.id))).toBe(true);
  });
});

describe("generic secret detection", () => {
  it("detects values behind quoted JSON keys", () => {
    const value = "0123456789abcdef".repeat(3).slice(0, 40);
    const findings = scan(JSON.stringify({ apiKey: value }));

    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(true);
    expect(findings[0]).toMatchObject({
      ruleId: "generic-secret",
      secretValue: value,
    });
  });

  it("detects LiteLLM master keys", () => {
    const value = "8d941fe70c2a6b35e481f09d72ac463fe905b178";
    const findings = scan(`master_key: "${value}"`);

    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(true);
    expect(findings[0]).toMatchObject({
      ruleId: "generic-secret",
      secretValue: value,
    });
  });
});

describe("local rule additions", () => {
  it("detects provider prefixes added locally", () => {
    for (const [text, id] of [
      [`key: hf_${"aB3xK9mQ2wR7vT5zY8cN1jF4hL6pD0sGq1"}`, "huggingface"],
      [`signing: whsec_a1b2c3d4e5f6g7h8i9j0k1l2m3n4`, "stripe-webhook"],
      [
        `Authorization: Bearer AbCdEf1234567890abcdefGHIJKL`,
        "bearer",
      ],
      [
        `DefaultEndpointsProtocol=https;AccountKey=${"q2Zw8xR5tY3uI9oP1aS6dF7gH0jK4lM9nbV2cX5zB8mQ3wE6rT1yU4iO0pL7kJ9hG+dz/"}==;`,
        "azure-storage",
      ],
    ] as const) {
      const findings = scan(text);
      expect(findings.some((f) => f.ruleId === id)).toBe(true);
    }
  });

  it("anchors entropy to secret-labeled fields", () => {
    const value = "jK4p9vX2mQ8wZ5rT3yB6nC1dF7gH0aS";
    const findings = scan(`client_secret: "${value}"`);
    expect(findings.some((f) => f.ruleId === "anchored-entropy")).toBe(true);
  });

  it("skips hex digests and lowercase words under the entropy rule", () => {
    // 40 hex chars under a secret-ish key: almost always a digest, not a key.
    expect(
      scan(`client_secret: "${"a3f9c1d7e2b8405f".repeat(2)}"`).some(
        (f) => f.ruleId === "anchored-entropy",
      ),
    ).toBe(false);
    // All-lowercase alphabet passes the entropy gate but fails the class check.
    expect(
      scan(`vault_token: "abcdefghijklmnopqrstuvwxyz"`).some(
        (f) => f.ruleId === "anchored-entropy",
      ),
    ).toBe(false);
  });

  it("does not treat ordinary code identifiers as secret fields", () => {
    for (const text of [
      "whichKeyWritable = pkgs.stdenv.hostPlatform.system;",
      "whichKeyMenu = pkgs.writeShellApplication;",
    ]) {
      expect(
        scan(text).some((f) => f.ruleId === "anchored-entropy"),
      ).toBe(false);
    }
  });
});
