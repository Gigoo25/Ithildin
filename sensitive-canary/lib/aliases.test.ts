import { expect, it, spyOn } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FIRST_NAMES } from "./first-names.ts";
import { AliasBook, aliasKind, aliasMatches, aliasSpans, expandIpv6, loadAliasKey, looksLikeAlias, registerAliasLabels, sessionAliasKey } from "./aliases.ts";

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
	expect(db).toMatch(/^prod-pg-use1\.[a-z]{7}\.internal$/);
	expect(web).toMatch(/^web-01\.[a-z]{7}\.internal$/);
	expect(db.split(".")[1]).toBe(web.split(".")[1]);
	expect(db).not.toContain("zqxcorp");
	// Nothing but role words: the first label is replaced anyway.
	expect(b.host("nas.lan").split(".")).toEqual([expect.not.stringMatching(/^nas$/), "lan"]);
});

it("maps identifying name parts consistently across hosts", () => {
	const b = book();
	const [a, c] = [b.host("zqxfalcon-web"), b.host("zqxfalcon-db")];
	expect(a).toMatch(/^[a-z]{9}-web$/);
	expect(a.split("-")[0]).toBe(c.split("-")[0]);
	expect(b.host("zqxfalcon")).toBe(a.split("-")[0]!);
});

it("mints stand-ins that look like the value: same shape, case and digits", () => {
	const b = book();
	const ticket = b.standIn("pii-custom-ticket", "ZQX-1234", "ticket");
	expect(ticket).toMatch(/^[A-Z]{3}-[1-9]\d{3}$/);
	expect(ticket).not.toBe("ZQX-1234");
	// One project key maps to one stand-in key.
	expect(b.standIn("pii-custom-ticket", "ZQX-77", "ticket").split("-")[0]).toBe(ticket.split("-")[0]);
	expect(b.standIn("pii-custom-handle", "zqk", "handle")).toMatch(/^[a-z]{3}$/);
	const person = b.standIn("pii-titled-name", "Zqxandra");
	expect(person).toMatch(/^[A-Z][a-z]+$/);
	expect(FIRST_NAMES.has(person.toLowerCase())).toBe(true);
	expect(aliasKind("pii-fleet-host-short")).toBe("host");
	expect(aliasKind("pii-inventory-runtime-home")).toBe("home");
	expect(aliasKind("pii-inventory-runtime-home-user")).toBe("user");
	expect(aliasKind("pii-tailscale-ip")).toBe("ipv4");
	expect(aliasKind("pii-customer-mac")).toBe("mac");
});

it("never mints a common word or a word already in the conversation", () => {
	const b = book();
	const first = b.standIn("pii-custom-handle", "zqk", "handle");
	const other = book();
	other.setCorpus(() => `const ${first} = 1`);
	const second = other.standIn("pii-custom-handle", "zqk", "handle");
	expect(second).not.toBe(first);
	expect(second).toMatch(/^[a-z]{3}$/);
});

it("keeps a stand-in where it was first minted across restarts", () => {
	const dir = mkdtempSync(join(tmpdir(), "alias-counters-"));
	try {
		const file = join(dir, "counters.json");
		const first = book();
		first.loadCounters(file);
		const standIn = first.standIn("pii-custom-handle", "zqk", "handle");
		first.saveCounters();
		expect(readFileSync(file, "utf8")).not.toContain("zqk");
		expect(statSync(file).mode & 0o777).toBe(0o600);
		const later = book();
		later.loadCounters(file);
		// Its first pick is in the conversation now, as the stand-in itself.
		later.setCorpus(() => standIn);
		expect(later.standIn("pii-custom-handle", "zqk", "handle")).toBe(standIn);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

it("finds stand-ins by what it minted, as whole words only", () => {
	const b = book();
	const host = b.host("zqxfalcon-web");
	const handle = b.standIn("pii-custom-handle", "zqk", "handle");
	const email = b.standIn("pii-email", "zqk@zqxcorp.io");
	const text = `ssh ${host} && echo ${handle} x${handle}y mail ${email}`;
	const found = b.matches(text);
	expect(found.map((match) => match.text)).toEqual(expect.arrayContaining([email, handle, host]));
	const glued = text.indexOf(`x${handle}y`);
	expect(found.some((match) => match.start > glued && match.start < glued + handle.length + 2)).toBe(false);
	expect(b.resolve(email)?.value).toBe("zqk@zqxcorp.io");
	// A host composed from a known part.
	expect(b.resolve(`${host.split("-")[0]}-db`)?.value).toBe("zqxfalcon-db");
});

it("still recognizes the older hash-like stand-in shapes", () => {
	const hashed = ["host", "0a1b2c"].join("-");
	for (const ordinary of [".env.example", "config.example", "www.example.com", "feature-123456", "build-abcdef", "10.0.0.1"]) {
		expect(looksLikeAlias(ordinary)).toBe(false);
	}
	expect(looksLikeAlias(hashed)).toBe(true);
	expect(aliasSpans(`ssh ${hashed} && cat .env.example`)).toEqual([hashed]);
	registerAliasLabels(["employer", "Bad Label"]);
	expect(looksLikeAlias(["employer", "0a1b2c"].join("-"))).toBe(true);
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


it("remembers the value behind each stand-in and flags collisions", () => {
	const b = book();
	const alias = b.standIn("pii-fleet-host", "zqxhost");
	expect(b.valueOf(alias)).toBe("zqxhost");
	expect(b.isStandIn(alias)).toBe(true);
	b.clear();
	expect(b.valueOf(alias)).toBeUndefined();
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
