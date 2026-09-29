import { expect, it, spyOn } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AliasBook, aliasKind, aliasMatches, aliasSpans, expandIpv6, isAliasValue, loadAliasKey, looksLikeAlias, registerAliasLabels, sessionAliasKey } from "./aliases.ts";

const KEY = Buffer.alloc(32, 7);
const book = () => new AliasBook(KEY);

it("is stable for one key and different under another", () => {
	expect(book().host("zqx-api.zqxcorp.internal")).toBe(book().host("zqx-api.zqxcorp.internal"));
	expect(new AliasBook(Buffer.alloc(32, 8)).host("zqx-api.zqxcorp.internal")).not.toBe(book().host("zqx-api.zqxcorp.internal"));
});

it("keeps role words and shared domains in hostnames", () => {
	const b = book();
	const db = b.host("prod-pg-use1.zqxcorp.internal");
	const web = b.host("web-01.zqxcorp.internal");
	expect(db).toMatch(/^prod-pg-use1\.n[0-9a-f]{6}\.internal\.example$/);
	expect(web).toMatch(/^web-01\.n[0-9a-f]{6}\.internal\.example$/);
	expect(db.split(".")[1]).toBe(web.split(".")[1]);
	expect(db).not.toContain("zqxcorp");
});

it("hashes identifying name parts consistently across hosts", () => {
	const b = book();
	const [a, c] = [b.host("zqxfalcon-web"), b.host("zqxfalcon-db")];
	expect(a).toMatch(/^n[0-9a-f]{6}-web$/);
	expect(a.split("-")[0]).toBe(c.split("-")[0]);
	expect(b.host("zqxfalcon")).toMatch(/^host-[0-9a-f]{6}$/);
});

it("links a user to their email and the email domain to its hosts", () => {
	const b = book();
	const email = b.email("zqxbob@zqxcorp.internal");
	expect(email.startsWith(`${b.user("zqxbob")}@`)).toBe(true);
	expect(email.endsWith(b.host("web.zqxcorp.internal").slice("web.".length))).toBe(true);
	expect(b.home("/home/zqxbob")).toBe(`/home/${b.user("zqxbob")}`);
});

it("keeps subnets together and the host octet in never-assigned space", () => {
	const b = book();
	const [x, y, z] = [b.ipv4("203.0.113.7")!, b.ipv4("203.0.113.9")!, b.ipv4("198.51.100.7")!];
	expect(x).toMatch(/^24[0-7]\.\d+\.\d+\.7$/);
	expect(x.split(".").slice(0, 3)).toEqual(y.split(".").slice(0, 3));
	expect(y.endsWith(".9")).toBe(true);
	expect(z.split(".").slice(0, 3)).not.toEqual(x.split(".").slice(0, 3));
	expect(b.ipv4("300.1.1.1")).toBeUndefined();
});

it("keeps /64s together in the IPv6 documentation prefix", () => {
	const b = book();
	const [x, y] = [b.ipv6("fd12:3456:789a:1::10")!, b.ipv6("fd12:3456:789a:1::20")!];
	expect(x.startsWith("2001:db8:")).toBe(true);
	expect(x.split(":").slice(0, 4)).toEqual(y.split(":").slice(0, 4));
	expect(x).not.toBe(y);
	expect(expandIpv6("::ffff:192.0.2.1")).toEqual(["0", "0", "0", "0", "0", "ffff", "c000", "201"]);
	expect(expandIpv6("1::2::3")).toBeUndefined();
});

it("makes MACs locally administered and keeps their format", () => {
	const b = book();
	expect(b.mac("a4:83:e7:12:34:56")).toMatch(/^02(?::[0-9a-f]{2}){5}$/);
	expect(b.mac("A4-83-E7-12-34-56")).toMatch(/^02(?:-[0-9A-F]{2}){5}$/);
});

it("maps rule ids to kinds and labels", () => {
	const b = book();
	expect(aliasKind("pii-fleet-host-short")).toBe("host");
	expect(aliasKind("pii-inventory-runtime-home")).toBe("home");
	expect(aliasKind("pii-inventory-runtime-home-user")).toBe("user");
	expect(aliasKind("pii-tailscale-ip")).toBe("ipv4");
	expect(aliasKind("pii-customer-mac")).toBe("mac");
	expect(b.standIn("pii-ssid", "ZqxHomeNet")).toMatch(/^ssid-[0-9a-f]{6}$/);
	expect(b.standIn("pii-titled-name", "Dr Zqx Person")).toMatch(/^person-[0-9a-f]{6}$/);
	expect(b.standIn("pii-inventory-employer", "Zqx Corp", "employer")).toMatch(/^employer-[0-9a-f]{6}$/);
	expect(b.standIn("pii-something-new", "value")).toMatch(/^pii-[0-9a-f]{6}$/);
});

it("remembers the value behind each stand-in and flags collisions", () => {
	const b = book();
	const alias = b.standIn("pii-fleet-host", "zqxhost");
	expect(b.valueOf(alias)).toBe("zqxhost");
	expect(b.isStandIn(alias)).toBe(true);
	b.clear();
	expect(b.valueOf(alias)).toBeUndefined();
});

it("recognizes stand-in shapes without matching ordinary names", () => {
	const b = book();
	for (const alias of [b.host("zqxfalcon"), b.host("prod-db.zqxcorp.internal"), b.user("zqx"), b.ipv4("203.0.113.7")!, b.standIn("pii-ssid", "x")]) {
		expect(looksLikeAlias(alias)).toBe(true);
		expect(isAliasValue(alias)).toBe(true);
	}
	expect(isAliasValue(b.email("zqx@gmail.com"))).toBe(true);
	for (const ordinary of [".env.example", "config.example", "www.example.com", "feature-123456", "build-abcdef", "10.0.0.1", "web-01.internal"]) {
		expect(looksLikeAlias(ordinary)).toBe(false);
	}
	expect(aliasSpans(`ssh ${b.user("zqx")}@${b.host("zqxbox")} && cat .env.example`)).toHaveLength(2);
	registerAliasLabels(["employer", "Bad Label"]);
	expect(looksLikeAlias("employer-0a1b2c")).toBe(true);
});

it("creates a private key file once and reuses it", () => {
	const dir = mkdtempSync(join(tmpdir(), "alias-key-"));
	try {
		const file = join(dir, "state", "alias-key");
		const first = loadAliasKey(file);
		expect(statSync(file).mode & 0o777).toBe(0o600);
		expect(loadAliasKey(file).equals(first)).toBe(true);
		expect(readFileSync(file, "utf8").trim()).toMatch(/^[0-9a-f]{64}$/);
		writeFileSync(file, "not a key\n");
		const warn = spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			expect(loadAliasKey(file).equals(first)).toBe(false);
			expect(String(warn.mock.calls[0]?.[0])).toContain("alias key file is malformed");
		} finally {
			warn.mockRestore();
		}
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

it("keeps one key per session, reuses it on resume, and inherits it on fork", () => {
	const dir = mkdtempSync(join(tmpdir(), "session-keys-"));
	try {
		const [a, b, fork] = ["a.jsonl", "b.jsonl", "fork.jsonl"].map((name) => join(dir, name));
		const keyA = sessionAliasKey(a);
		expect(statSync(`${a}.canary-alias-key`).mode & 0o777).toBe(0o600);
		expect(sessionAliasKey(a).equals(keyA)).toBe(true);
		expect(sessionAliasKey(b).equals(keyA)).toBe(false);
		expect(sessionAliasKey(fork, a).equals(keyA)).toBe(true);
		// Different sessions, different stand-ins for the same value.
		expect(new AliasBook(keyA).host("zqxbox")).not.toBe(new AliasBook(sessionAliasKey(b)).host("zqxbox"));
		expect(sessionAliasKey(undefined).equals(sessionAliasKey(undefined))).toBe(false);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

it("takes a .example stand-in whole before sentence punctuation, but not inside a longer name", () => {
  const standIn = ["n3c9d0e", "corp", "example"].join(".");
  for (const text of [`mail ${standIn}.`, `mail ${standIn}. Next`, `(${standIn}).`, `${standIn},`]) {
    expect(aliasMatches(text).map((match) => match.text)).toContain(standIn);
  }
  expect(aliasMatches(`${standIn}.com`).map((match) => match.text)).not.toContain(standIn);
});
