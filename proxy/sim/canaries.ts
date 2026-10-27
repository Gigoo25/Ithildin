// Invented secrets and personal values, planted in a simulated session so the
// run can tell whether any of them reached the provider. Each has a core, the
// part that must never be sent: a database URL's password, a path's user name,
// a token's body. Every value is random from the seed; none is real.
//
// Whether the engine is expected to catch a value is not decided here. The
// loop asks the engine about each value on its own (calibrate), and holds it
// to catching that value everywhere else: a value caught alone and missed in
// a tool output or a JSON file is a context bug, not a missing rule.

import { Random } from "./random.ts";

export type Kind =
  | "anthropic-key"
  | "github-token"
  | "aws-key"
  | "openai-key"
  | "slack-token"
  | "jwt"
  | "private-key"
  | "email"
  | "ip"
  | "host"
  | "home"
  | "card"
  | "db-url"
  | "password"
  | "bearer";

export const KINDS: Kind[] = [
  "anthropic-key",
  "github-token",
  "aws-key",
  "openai-key",
  "slack-token",
  "jwt",
  "private-key",
  "email",
  "ip",
  "host",
  "home",
  "card",
  "db-url",
  "password",
  "bearer",
];

export interface Canary {
  kind: Kind;
  // As it appears in text.
  value: string;
  // What must not reach the provider.
  core: string;
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64URL = `${ALNUM}-_`;
const NAMES = ["oskar", "wren", "teodora", "malik", "ines", "bayu", "ilse", "dario", "yuki"];
const SURNAMES = ["vantongeren", "okafor", "lindqvist", "mbeki", "ferraro", "halvorsen"];
const ORGS = ["acme", "krell", "zantro", "pelivo", "mardex"];

function chars(random: Random, alphabet: string, n: number): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[random.int(0, alphabet.length - 1)];
  return out;
}

function luhn(random: Random): string {
  const digits = [4, ...Array.from({ length: 14 }, () => random.int(0, 9))];
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    let d = digits[14 - i]!;
    if (i % 2 === 0) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
    sum += d;
  }
  return [...digits, (10 - (sum % 10)) % 10].join("");
}

function pem(random: Random): Canary {
  const body = Array.from({ length: 6 }, () => chars(random, `${ALNUM}+/`, 64));
  const value = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    ...body,
    "-----END OPENSSH PRIVATE KEY-----",
  ].join("\n");
  return { kind: "private-key", value, core: body[2]! };
}

function person(random: Random): { first: string; last: string; org: string } {
  return { first: random.pick(NAMES), last: random.pick(SURNAMES), org: random.pick(ORGS) };
}

function make(kind: Kind, random: Random): Canary {
  const whole = (value: string): Canary => ({ kind, value, core: value });
  const { first, last, org } = person(random);
  switch (kind) {
    case "anthropic-key":
      return whole(`sk-ant-api03-${chars(random, ALNUM, 95)}`);
    case "github-token":
      return whole(`ghp_${chars(random, ALNUM, 36)}`);
    case "aws-key":
      return whole(`AKIA${chars(random, B32, 16)}`);
    case "openai-key":
      return whole(`sk-proj-${chars(random, ALNUM, 48)}`);
    case "slack-token":
      return whole(
        `xoxb-${random.int(1e10, 9e10)}-${random.int(1e10, 9e10)}-${chars(random, ALNUM, 24)}`,
      );
    case "jwt": {
      const head = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
      return whole(`${head}.eyJ${chars(random, B64URL, 60)}.${chars(random, B64URL, 43)}`);
    }
    case "private-key":
      return pem(random);
    case "email":
      return whole(`${first}.${last}@${org}-corp.com`);
    case "ip":
      return whole(`10.${random.int(1, 254)}.${random.int(1, 254)}.${random.int(2, 254)}`);
    case "host":
      return whole(
        `${org}-${random.pick(["db", "ci", "vault", "build"])}${random.int(1, 9)}.internal`,
      );
    case "home": {
      const user = `${first}${last.slice(0, 3)}`;
      return { kind, value: `/home/${user}/src/${org}`, core: `/home/${user}` };
    }
    case "card":
      return whole(luhn(random));
    case "db-url": {
      const password = chars(random, ALNUM, 20);
      return {
        kind,
        value: `postgres://app:${password}@db.${org}.internal:5432/app`,
        core: password,
      };
    }
    case "password": {
      const value = chars(random, `${ALNUM}!#%^*`, 22);
      return { kind, value: `DB_PASSWORD=${value}`, core: value };
    }
    case "bearer": {
      const token = chars(random, ALNUM, 48);
      return { kind, value: `Authorization: Bearer ${token}`, core: token };
    }
  }
}

// How a finding names a canary: enough to tell which, not enough to be one.
export function preview(c: Canary): string {
  return c.core.length > 24 ? `${c.core.slice(0, 12)}…${c.core.slice(-6)}` : c.core;
}

export function canary(random: Random, kind = random.pick(KINDS)): Canary {
  return make(kind, random);
}
