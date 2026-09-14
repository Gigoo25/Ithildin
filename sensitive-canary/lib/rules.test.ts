import { describe, expect, it } from "bun:test";
import { beginScanBudget, compileRule, RULES, scan, scanWindows, SCAN_WINDOW_CHARS } from "./rules.ts";

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

describe("personal inventory template", () => {
  it("ships inert rules that all compile", async () => {
    const config = (await Bun.file(`${import.meta.dir}/../user-config.example.json`).json()) as {
      rules: Array<{ id: string; category: string }>;
    };
    expect(config.rules.length).toBeGreaterThan(0);
    for (const rule of config.rules) {
      expect(rule.category).toBe("pii");
      expect(() => compileRule(rule as never)).not.toThrow();
    }
    // Inert: the example values match nothing a user would type.
    expect(scan("deploy tonight").some((f) => f.ruleId.startsWith("pii-personal-"))).toBe(false);
  });
});

describe("upstream PII parity", () => {
  it("detects Luhn-valid card numbers and rejects bad checksums", () => {
    const findings = scan("card 4532015112830366");
    expect(findings.some((f) => f.ruleId === "pii-credit-card")).toBe(true);
    expect(scan("card 4111111111111112").some((f) => f.ruleId === "pii-credit-card")).toBe(false);
  });

  it("exempts published gateway test numbers", () => {
    // Blocking on documentation fixtures trains users to disable the tool.
    expect(scan("card 4111111111111111").some((f) => f.ruleId === "pii-credit-card")).toBe(false);
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

  it("detects bare high-entropy tokens on their own line", () => {
    const token = "K7mQ2vX9pL4sW8eR1tY6uI3oP5aS0dF9gH2jK6";
    const findings = scan(`key is\n${token}\ndeployed`);
    expect(findings.some((f) => f.ruleId === "lone-token-line")).toBe(true);
    expect(
      findings.some((f) => f.ruleId === "lone-token-line" && f.secretValue === token),
    ).toBe(true);
  });

  it("does not fire lone-token on digests, ids, keys, or prose", () => {
    for (const text of [
      "a3f9c1d7e2b8405fa3f9c1d7e2b8405f",
      "123e4567-e89b-12d3-a456-426614174000",
      "zp1x80dxy3sisrxg5a76pa65np98fhss",
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBn0SNDbMs8czytggZLhjLEmjoSSYNV6CUeWphzDU",
      "supercalifragilisticexpialidocious",
      "short-value",
    ]) {
      expect(scan(text).some((f) => f.ruleId === "lone-token-line")).toBe(false);
    }
  });

  it("detects bare public IPs but not versions or private ranges", () => {
    const findings = scan("8.8.8.8");
    expect(findings.some((f) => f.ruleId === "pii-ipv4-lone")).toBe(true);
    expect(
      findings.some((f) => f.ruleId === "pii-ipv4-lone" && f.secretValue === "8.8.8.8"),
    ).toBe(true);
    for (const [text, id] of [
      ["192.168.1.10", "pii-ipv4-lone"],
      ["999.1.1.1", "pii-ipv4-lone"],
      ["2026.09.13.1", "pii-ipv4-lone"],
      ["v1.2.3.4", "pii-ipv4-lone"],
      ["1.2.3", "pii-ipv4-lone"],
    ] as const) {
      expect(scan(text).some((f) => f.ruleId === id)).toBe(false);
    }
    expect(scan("192.168.1.10").some((f) => f.ruleId === "pii-ipv4")).toBe(true);
  });

  it("detects wallet addresses, WIF keys, and valid IBANs", () => {
    for (const [text, id, secretValue] of [
      ["pay 1A2B3C4D5E6F7G8H9J2K3M4N5P6Q7R8", "btc-address", "1A2B3C4D5E6F7G8H9J2K3M4N5P6Q7R8"],
      ["pay bc1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8g", "btc-address", "bc1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8g"],
      ["to 0x1234567890abcdef1234567890abcdef12345678", "eth-address", "0x1234567890abcdef1234567890abcdef12345678"],
      [`key 5${"J".repeat(50)}`, "wif-private-key", `5${"J".repeat(50)}`],
      ["iban DE89370400440532013000", "iban", "DE89370400440532013000"],
    ] as const) {
      const findings = scan(text);
      expect(findings.some((f) => f.ruleId === id)).toBe(true);
      expect(
        findings.some((f) => f.ruleId === id && f.secretValue === secretValue),
      ).toBe(true);
    }
    expect(scan("iban DE00123456789012345678").some((f) => f.ruleId === "iban")).toBe(false);
    expect(scan("0x1234").some((f) => f.ruleId === "eth-address")).toBe(false);
  });

  it("detects context-gated US bank and passport numbers", () => {
    for (const [text, id, secretValue] of [
      ["routing 021000021 account 12345678", "pii-us-bank-account", "12345678"],
      ["passport 123456789", "pii-us-passport", "123456789"],
    ] as const) {
      const findings = scan(text);
      expect(findings.some((f) => f.ruleId === id)).toBe(true);
      expect(
        findings.some((f) => f.ruleId === id && f.secretValue === secretValue),
      ).toBe(true);
    }
    for (const [text, id] of [
      ["order 12345678 shipped", "pii-us-bank-account"],
      ["call 123456789 now", "pii-us-passport"],
    ] as const) {
      expect(scan(text).some((f) => f.ruleId === id)).toBe(false);
    }
  });

  it("detects bank plain", () => {
    const findings = scan('acct 8158123456789012');
    expect(findings.some((f) => f.ruleId === 'pii-bank-account-prefix')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'pii-bank-account-prefix' && f.secretValue === '8158123456789012')).toBe(true);
  });
it("detects bank grouped", () => {
    const findings = scan('acct 8158-1234-5678-9012');
    expect(findings.some((f) => f.ruleId === 'pii-bank-account-prefix')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'pii-bank-account-prefix' && f.secretValue === '8158-1234-5678-9012')).toBe(true);
  });
it("detects labeled name", () => {
    const findings = scan('Name: Jane Exampleperson');
    expect(findings.some((f) => f.ruleId === 'pii-labeled-name')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'pii-labeled-name' && f.secretValue === 'Jane Exampleperson')).toBe(true);
  });
it("detects patient name", () => {
    const findings = scan('patient: Ann Lee');
    expect(findings.some((f) => f.ruleId === 'pii-labeled-name')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'pii-labeled-name' && f.secretValue === 'Ann Lee')).toBe(true);
  });
it("detects street address", () => {
    const findings = scan('ship to 123 Main St');
    expect(findings.some((f) => f.ruleId === 'pii-street-address')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'pii-street-address' && f.secretValue === '123 Main St')).toBe(true);
  });
it("detects avenue address", () => {
    const findings = scan('unit 5 Park Avenue');
    expect(findings.some((f) => f.ruleId === 'pii-street-address')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'pii-street-address' && f.secretValue === '5 Park Avenue')).toBe(true);
  });

it("detects coordinate pairs but not bare number pairs", () => {
  for (const text of [
    "meet at 40.7128, -74.0060",
    "40°42'46\"N 74°00'22\"W",
    "40°N, 74°W",
  ]) {
    expect(scan(text).some((f) => f.ruleId === "pii-geo-decimal" || f.ruleId === "pii-geo-dms")).toBe(true);
  }
  for (const text of ["options 1, 2, 3", "call 5, 6", "v1.2, 3.4", "200, 300"]) {
    expect(scan(text).some((f) => f.ruleId === "pii-geo-decimal" || f.ruleId === "pii-geo-dms")).toBe(false);
  }
});

it("rejects prose lookalikes for inventory rules", () => {
    for (const [text, id] of [
      [" Lake House retreat", "pii-labeled-name"],
      ["username = ordinary_handle", "pii-labeled-name"],
      ["took 2 Road trips", "pii-street-address"],
      ["version 8159 track", "pii-bank-account-prefix"],
    ] as const) {
      expect(scan(text).some((f) => f.ruleId === id)).toBe(false);
    }
  });

  it("detects Tailscale keys and age secret keys", () => {
    const ageKey = `AGE-SECRET-KEY-1${"qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(2).slice(0, 58)}`;
    for (const [text, id] of [
      [`auth: tskey-auth-${"aB3xK9mQ2wR7vT5zY8cN1jF4hL6pD0sGqW"}`, "tailscale-key"],
      [`token: tskey-api-${"aB3xK9mQ2wR7vT5zY8cN1jF4hL6pD0sGqW"}`, "tailscale-key"],
      [`key = ${ageKey}`, "age-secret-key"],
    ] as const) {
      expect(scan(text).some((f) => f.ruleId === id)).toBe(true);
    }
  });
});

describe("bounded scanning", () => {
  it("matches unchunked results on normal texts", () => {
    for (const text of [
      "deploy to fixture.lan tonight",
      `api_key = "${"K7mQ2vX9pL4sW8eR1tY6uI3oP5aS0dF9gH2jK6"}" and host 10.1.2.3 up`,
      "nothing sensitive here, just prose about lunch",
      "contact bob@example.com about it",
    ]) {
      const plain = scan(text).map((f) => `${f.ruleId}=${f.secretValue}`).sort();
      const windowed = scanWindows(text);
      expect(windowed.trips).toEqual([]);
      expect(windowed.findings.map((f) => `${f.ruleId}=${f.secretValue}`).sort()).toEqual(plain);
    }
  });

  it("catches values straddling a window edge", () => {
    const secret = "10.2.3.4";
    const at = SCAN_WINDOW_CHARS - 4;
    const text = `${"x".repeat(at)} ${secret} ${"y".repeat(70_000 - at - secret.length - 2)}`;
    const { findings, trips } = scanWindows(text);
    expect(trips).toEqual([]);
    expect(findings.some((f) => f.secretValue === secret)).toBe(true);
  });

  it("omits the whole span when the budget is already spent", () => {
    beginScanBudget(0);
    try {
      const { findings, trips } = scanWindows("host 10.3.3.3 up");
      expect(findings).toEqual([]);
      expect(trips).toEqual([{ start: 0, end: 16 }]);
    } finally {
      beginScanBudget(null);
    }
  });
});
