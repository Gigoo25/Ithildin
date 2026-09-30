// New acceptance fixtures, separate from the invalid historical comparison set.
import type { BenchFixture } from "./corpus.ts";
import { fakeToken } from "./corpus.ts";
import { SCAN_WINDOW_CHARS } from "../engine/lib/rules.ts";
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const token = `sk-ant-${fakeToken(alphabet, 95, 918)}`;
const bearer = fakeToken(alphabet, 48, 719);
function fixture(
  id: string,
  input: string,
  expectedSecrets: string[],
  mustPreserve: string[],
  representation: BenchFixture["representation"] = "text",
): BenchFixture {
  return {
    id: `review-${id}`,
    group: id.split("-")[0]!,
    description: "Synthetic review acceptance",
    input,
    expectedSecrets,
    mustPreserve,
    representation,
    support: "supported",
  };
}
const ip = [100, 99, 7, 61].join(".");
const host = ["inventednode", "internal"].join(".");
const home = ["", "home", "inventedoperator", "project"].join("/");
const ibanBody = "123456789012345678";
// Generate an invented GB-shaped, mod-97-valid identifier. Never authenticate.
const ibanAccount = "QWER" + ibanBody.slice(0, 14);
let remainder = 0;
for (const c of ibanAccount + "GB00")
  for (const digit of /[A-Z]/.test(c) ? String(c.charCodeAt(0) - 55) : c)
    remainder = (remainder * 10 + Number(digit)) % 97;
const iban = "GB" + String(98 - remainder).padStart(2, "0") + ibanAccount;
const localId = "11070" + fakeToken("0123456789", 8, 555);
export const REVIEW_FIXTURES: BenchFixture[] = [
  fixture("credential-format", `deploy key ${token} done`, [token], ["deploy key", "done"]),
  fixture("credential-lookalike", "sk-ant-short-example", [], ["sk-ant-short-example"]),
  fixture(
    "bearer-positive",
    `Authorization: Bearer ${bearer}`,
    [bearer],
    ["Authorization: Bearer"],
  ),
  fixture("bearer-negative", "Authorization documentation", [], ["Authorization documentation"]),
  fixture(
    "cookie-positive",
    ["Cookie: session=", bearer, "; mode=", "brief"].join(""),
    [bearer, "brief"],
    ["Cookie: session=", "; mode="],
    "tool-output",
  ),
  fixture(
    "cookie-negative",
    "Cookie documentation has no header value",
    [],
    ["Cookie documentation has no header value"],
  ),
  fixture(
    "identity-positive",
    'username = "inventedoperator"\nconst inventedoperatorCount = 1;',
    ["inventedoperator"],
    ["inventedoperatorCount"],
  ),
  fixture(
    "identity-negative",
    "const inventedoperatorCount = 1;",
    [],
    ["const inventedoperatorCount = 1;"],
  ),
  fixture("home-positive", home, ["inventedoperator"], ["/project"]),
  fixture("home-negative", "homeDirectory = config.home;", [], ["homeDirectory = config.home;"]),
  fixture("host-positive", `hostname = "${host}"`, [host], ["hostname ="]),
  fixture(
    "host-negative",
    "pkgs.stdenv.hostPlatform.system",
    [],
    ["pkgs.stdenv.hostPlatform.system"],
  ),
  fixture("financial-positive", `iban ${iban}`, [iban], ["iban"]),
  fixture("financial-negative", `iban GB00${ibanAccount}`, [], [`GB00${ibanAccount}`]),
  fixture("local-id-positive", `ref ${localId} done`, [localId], ["ref", "done"]),
  fixture("local-id-negative", "version 11070 track", [], ["version 11070 track"]),
  fixture("hash-negative", "sha256 = " + "a1".repeat(32), [], ["a1".repeat(32)]),
  fixture("version-negative", "version = 1.23.45;", [], ["version = 1.23.45;"]),
  fixture(
    "lockfile-negative",
    '{"version":"1.2.3","integrity":"sha512-example-only","resolved":"package"}',
    [],
    ['"integrity":"sha512-example-only"'],
    "document",
  ),
  fixture("unicode-seam", `${"x".repeat(SCAN_WINDOW_CHARS - 9)}peer ${ip} café`, [ip], ["café"]),
  fixture(
    "json-bank",
    '{ "bank_account_number":900719925474099312345, "count":7, "note":"keep" }',
    ["900719925474099312345"],
    ['"count":7, "note":"keep"'],
    "document",
  ),
  fixture(
    "json-escaped",
    '{"password":"weak\\\"phrase","note":"keep"}',
    ['weak\\"phrase'],
    ['"note":"keep"'],
    "document",
  ),
  fixture(
    "json-lookalike",
    '{"password_hint":"keep","password":"","api_key":null}',
    [],
    ['{"password_hint":"keep","password":"","api_key":null}'],
    "document",
  ),
  fixture(
    "assignment-spaces",
    'password = "invented phrase" # retain',
    ["invented phrase"],
    [" # retain"],
  ),
  fixture("assignment-negative", 'password_hint = "retain"', [], ['password_hint = "retain"']),
  fixture(
    "payload-controls",
    '{"account_number":12345,"count":12345,"note":"12345"}',
    ["12345"],
    ['"count":12345,"note":"12345"'],
    "document",
  ),
  fixture(
    "identity-gazetteer",
    "called Marie Dubois yesterday",
    ["Marie Dubois"],
    ["called", "yesterday"],
  ),
  fixture("identity-titled", "Dr. Elena Vasquez on call", ["Elena Vasquez"], ["Dr.", "on call"]),
  fixture("identity-label-from", "From: James Okafor", ["James Okafor"], ["From:"]),
  fixture("identity-place-negative", "Lake House retreat", [], ["Lake House retreat"]),
];
// Label-based numeric classification is occurrence-specific, not every equal
// number. The runner supplies the authored sensitive range for this fixture.
export const EXPECTED_RANGES: Record<string, Array<{ start: number; end: number }>> = {
  "review-identity-positive": [{ start: 12, end: 28 }],
  "review-payload-controls": [{ start: 18, end: 23 }],
};
