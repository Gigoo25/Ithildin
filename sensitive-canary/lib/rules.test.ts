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

  it("synthesizes fleet hostnames and usernames", () => {
    for (const [text, id, secretValue] of [
      ["deploy to FatMan tonight", "pii-fleet-host", "FatMan"],
      ["hostAlias = \"Mini\"", "pii-fleet-host-short", "Mini"],
      ["User rstocchi logs in", "pii-fleet-user", "rstocchi"],
      ["path /home/rob/nix-dotfiles", "pii-home-user", "rob"],
      ['username = "rob"', "pii-fleet-user-context", "rob"],
      ["path /home/newhire/docs", "pii-home-user", "newhire"],
      ["camera at adalina-room.lan:7447", "pii-internal-host", "adalina-room.lan"],
      ["peer 100.96.26.43 up", "pii-tailscale-ip", "100.96.26.43"],
      ["ssh deploy@FatMan", "pii-user-at-host", "deploy"],
      ['owner = "docs-team"', "pii-labeled-user", "docs-team"],
    ] as const) {
      const findings = scan(text);
      expect(findings.some((f) => f.ruleId === id)).toBe(true);
      expect(
        findings.some((f) => f.ruleId === id && f.secretValue === secretValue),
      ).toBe(true);
    }
  });

  it("does not fire fleet inventory on ordinary prose", () => {
    expect(
      scan("they rob banks").some((f) => f.ruleId === "pii-fleet-user-context"),
    ).toBe(false);
    expect(
      scan("mini pc review").some((f) => f.ruleId === "pii-fleet-host-short"),
    ).toBe(false);
  });

  it("does not fire generic PII on public or non-identity text", () => {
    expect(
      scan("see github.com/nixos for docs").some((f) => f.ruleId === "pii-internal-host"),
    ).toBe(false);
    expect(
      scan("localhost is always local").some((f) => f.ruleId === "pii-internal-host"),
    ).toBe(false);
    expect(
      scan("dns 8.8.8.8 without context").some((f) => f.ruleId === "pii-tailscale-ip"),
    ).toBe(false);
    expect(
      scan("price @ 5 is not an address").some((f) => f.ruleId === "pii-user-at-host"),
    ).toBe(false);
    expect(
      scan("login = true").some((f) => f.ruleId === "pii-labeled-user"),
    ).toBe(false);
    expect(
      scan('user = "Display Name"').some((f) => f.ruleId === "pii-labeled-user"),
    ).toBe(false);
  });

  it("synthesizes single-label hostnames in labeled assignments", () => {
    for (const [text, secretValue] of [
      ['hostname = "backupbox"', "backupbox"],
      ['machine = "builder-01"', "builder-01"],
      ["server=prod-02", "prod-02"],
    ] as const) {
      const findings = scan(text);
      expect(findings.some((f) => f.ruleId === "pii-labeled-host")).toBe(true);
      expect(
        findings.some(
          (f) => f.ruleId === "pii-labeled-host" && f.secretValue === secretValue,
        ),
      ).toBe(true);
    }
  });

  it("does not fire labeled-host on public or placeholder names", () => {
    for (const text of [
      "HostName github.com",
      'host = "localhost"',
      'hostname = "server"',
      "8GB host: don't let one flake fetch pin the cache",
      "niriConfigs = lib.mapAttrsToList (host: u: {",
    ]) {
      expect(
        scan(text).some((f) => f.ruleId === "pii-labeled-host"),
      ).toBe(false);
    }
  });

  it("does not mistake Nix attribute paths for internal hostnames", () => {
    for (const text of [
      "u.xdg.configFile",
      "home-manager.users.rstocchi.home",
      "options.local",
      "file = ./.env.local",
    ]) {
      expect(
        scan(text).some((f) => f.ruleId === "pii-internal-host"),
      ).toBe(false);
    }
    const findings = scan("stream at adalina-room.lan:7447, mesh ai.corp");
    expect(
      findings.some((f) => f.ruleId === "pii-internal-host"),
    ).toBe(true);
  });

  it("does not mistake version pins for user@host addresses", () => {
    for (const text of ["depends on repo@v1", "pin lib bar@1.0.0"]) {
      expect(
        scan(text).some((f) => f.ruleId === "pii-user-at-host"),
      ).toBe(false);
    }
  });

  it("detects device identity and network credentials", () => {
    for (const [text, id, secretValue] of [
      ["dev AA:BB:CC:DD:EE:FF up", "pii-mac", "AA:BB:CC:DD:EE:FF"],
      ['machine-id = "a1b2c3d4e5f60718293a4b5c6d7e8f90"', "pii-machine-id", "a1b2c3d4e5f60718293a4b5c6d7e8f90"],
      ['networking.hostId = "deadbeef"', "pii-machine-id", "deadbeef"],
      ['ssid = "HomeNet"', "pii-ssid", "HomeNet"],
      ["key otpauth://totp/svc?secret=JBSWY3DPEHPK3PXP", "totp-uri", "otpauth://totp/svc?secret=JBSWY3DPEHPK3PXP"],
      ["Authorization: Basic dXNlcjpwYXNz", "basic-auth-header", "dXNlcjpwYXNz"],
      ["curl -u admin:s3cret https://x", "curl-basic-auth", "admin:s3cret"],
      ['psk = "sup3rsecretwifi"', "wifi-psk", "sup3rsecretwifi"],
    ] as const) {
      const findings = scan(text);
      expect(findings.some((f) => f.ruleId === id)).toBe(true);
      expect(
        findings.some((f) => f.ruleId === id && f.secretValue === secretValue),
      ).toBe(true);
    }
  });

  it("does not fire device rules on lookalikes", () => {
    for (const [text, id] of [
      ["uuid 123e4567-e89b-12d3-a456-426614174000", "pii-mac"],
      ['version = "1a2b3c4d"', "pii-machine-id"],
      ["mysql -u root db", "curl-basic-auth"],
      ['curl -u "$USER:$PASS" https://x', "curl-basic-auth"],
      ['psk = "x"', "wifi-psk"],
    ] as const) {
      expect(scan(text).some((f) => f.ruleId === id)).toBe(false);
    }
  });

  it("detects Tailscale keys and age secret keys", () => {
    const ageKey = `AGE-SECRET-KEY-1${"qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(2).slice(0, 58)}`;
    for (const [text, id] of [
      [`auth: tskey-auth-${"aB3xK9mQ2wR7vT5zY8cN1jF4hL6pD0sGqW"}`, "tailscale-key"],
      [`token: tskey-api-${"aB3xK9mQ2wR7vT5zY8cN1jF4hL6pD0sGqW"}`, "tailscale-key"],
      [`key = "${ageKey}"`, "age-secret-key"],
    ] as const) {
      expect(scan(text).some((f) => f.ruleId === id)).toBe(true);
    }
  });
});
