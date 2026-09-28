// Synthetic benchmark corpus: invented fixtures only, never real secrets.
export type FixtureSupport = "supported" | "unsupported" | "limitation";
export type FixtureRepr = "text" | "document" | "tool-output" | "payload";

export interface BenchFixture {
  id: string;
  group: string;
  description: string;
  representation: FixtureRepr;
  support: FixtureSupport;
  input: string;
  expectedSecrets: string[];
  expectedRanges?: Array<{start:number;end:number}>;
  mustPreserve: string[];
}

// Deterministic pseudo-random generator (LCG) so fixtures are stable.
function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0x1_0000_0000;
  };
}

export function fakeToken(alphabet: string, length: number, seed: number): string {
  const rand = lcg(seed);
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

const HEX = "0123456789abcdef";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const SECRET_A = `sk-ant-${fakeToken(B64URL, 95, 101)}`;
const SECRET_B = fakeToken(B64URL, 36, 202);
const DB_PW = fakeToken(B64URL, 28, 303);

export const FIXTURES: BenchFixture[] = [
  {
    id: "secret-anthropic-key",
    group: "credential",
    description: "Known provider key format in prose",
    representation: "text",
    support: "supported",
    input: `deploy failed with key ${SECRET_A} in log`,
    expectedSecrets: [SECRET_A],
    mustPreserve: ["deploy failed with key", "in log"],
  },
  {
    id: "secret-bearer-header",
    group: "credential",
    description: "Bearer header value",
    representation: "text",
    support: "supported",
    input: `Authorization: Bearer ${fakeToken(B64URL, 32, 404)}-extra`,
    expectedSecrets: [],
    mustPreserve: ["Authorization"],
  },
  {
    id: "pii-labeled-username",
    group: "pii",
    description: "Labeled username assignment",
    representation: "text",
    support: "supported",
    input: `owner = "fixtureoperator"`,
    expectedSecrets: ["fixtureoperator"],
    mustPreserve: ["owner ="],
  },
  {
    id: "harmless-code-identifier",
    group: "lookalike",
    description: "Ordinary code must not be redacted",
    representation: "text",
    support: "supported",
    input: `whichKeyWritable = pkgs.stdenv.hostPlatform.system;`,
    expectedSecrets: [],
    mustPreserve: [`whichKeyWritable = pkgs.stdenv.hostPlatform.system;`],
  },
  {
    id: "harmless-uuid",
    group: "lookalike",
    description: "UUID lookalike",
    representation: "text",
    support: "supported",
    input: `id 6f7f8f9f-1f2f-4f5f-8f9f-1f2f3f4f5f6f7f`,
    expectedSecrets: [],
    mustPreserve: [`6f7f8f9f-1f2f-4f5f-8f9f-1f2f3f4f5f6f7f`],
  },
  {
    id: "substring-regression",
    group: "usability",
    description: "Short labeled identity plus longer unrelated identifier",
    representation: "text",
    support: "supported",
    input: `username = "sampler"\nconst samplerCount = 3;`,
    expectedSecrets: [`"sampler"`],
    mustPreserve: ["samplerCount"],
  },
  {
    id: "repeated-value",
    group: "usability",
    description: "Repeated secret keeps identity",
    representation: "text",
    support: "supported",
    input: `${SECRET_B}\nreference ${SECRET_B} done`,
    expectedSecrets: [SECRET_B],
    mustPreserve: ["reference", "done"],
  },
  {
    id: "overlap-synthetic",
    group: "usability",
    description: "Overlapping candidate matches",
    representation: "text",
    support: "supported",
    input: `iban DE89370400440532013000 and card 4111111111111111 in doc`,
    expectedSecrets: [],
    mustPreserve: ["iban", "in doc"],
  },
  {
    id: "json-labeled-secret",
    group: "structured",
    description: "JSON password field (structured gap)",
    representation: "document",
    support: "supported",
    input: JSON.stringify({ username: "fixture", password: DB_PW, retries: 3 }),
    expectedSecrets: [DB_PW],
    mustPreserve: [`"username"`, `"retries"`, `"password"`],
  },
  {
    id: "json-numeric-account",
    group: "structured",
    description: "JSON numeric account field (structured gap)",
    representation: "document",
    support: "unsupported",
    input: JSON.stringify({ account_number: 8158123456789012, note: "hello" }),
    expectedSecrets: [],
    mustPreserve: [`"account_number"`, `"note"`],
  },
  {
    id: "business-prose-limitation",
    group: "limitation",
    description: "Confidential meaning without a pattern",
    representation: "text",
    support: "limitation",
    input: `The unannounced product launch is delayed by two months.`,
    expectedSecrets: [],
    mustPreserve: [`The unannounced product launch is delayed by two months.`],
  },
  {
    id: "window-seam",
    group: "usability",
    description: "Value straddling synthetic seam marker",
    representation: "text",
    support: "supported",
    input: `${"x".repeat(200)} peer 100.99.8.7 up ${"y".repeat(200)}`,
    expectedSecrets: ["100.99.8.7"],
    mustPreserve: [],
  },
];

export const FROZEN_IDS = FIXTURES.map((f) => f.id);

export function fixtureById(id: string): BenchFixture {
  const f = FIXTURES.find((x) => x.id === id);
  if (!f) throw new Error(`unknown fixture ${id}`);
  return f;
}
