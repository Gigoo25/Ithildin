import { expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compileGeneralizeEntry } from "./lib/rules.ts";

it("compiles whole-word, longest-first, case-insensitive term lists", () => {
	const rule = compileGeneralizeEntry({ id: "medical", terms: ["migraine", "chronic migraine", "headache"], replace: "minor neurological condition" });
	expect(rule.id).toBe("pii-generalize-medical");
	expect(rule.generalize).toBe("minor neurological condition");
	const text = "Chronic Migraine and a headache, not headaches";
	expect([...text.matchAll(rule.regex)].map((match) => match[0])).toEqual(["Chronic Migraine", "headache"]);
});

it("rejects malformed entries", () => {
	for (const entry of [
		{ id: "x y", terms: ["a"], replace: "b" },
		{ id: "x", terms: [], replace: "b" },
		{ id: "x", terms: [""], replace: "b" },
		{ id: "x", terms: ["a"], replace: "" },
		{ id: "x", terms: ["a"], replace: "⟦b⟧" },
		{ id: "x", terms: ["a"], replace: "b".repeat(81) },
		{ id: "x", terms: ["a"], replace: "b", caseSensitive: "yes" },
	]) {
		expect(() => compileGeneralizeEntry(entry)).toThrow();
	}
});

it("generalizes wording end to end without nesting, and blocks writing it back", () => {
	// Fresh process: generalize rules load from the user config at import.
	const home = mkdtempSync(join(tmpdir(), "canary-generalize-"));
	try {
		const file = join(home, "config.json");
		writeFileSync(file, JSON.stringify({
			rules: [],
			generalize: [{ id: "medical", terms: ["headache", "migraine", "condition"], replace: "minor neurological condition" }],
		}), { mode: 0o600 });
		const script = [
			"const m = await import(" + JSON.stringify(new URL("./index.ts", import.meta.url).href) + ");",
			"const h = {};",
			"m.default({ on: (n, fn) => { h[n] = fn; }, registerFlag(){}, registerCommand(){}, appendEntry(){}, getFlag: () => false, events: { on(){}, emit(){} } });",
			"const ctx = { cwd: process.cwd(), sessionManager: { getBranch: () => [], getSessionFile: () => undefined }, ui: { notify(){} } };",
			"h.agent_start({}, ctx);",
			"const first = (await h.context({ messages: [{ role: 'user', content: 'I have a Headache today' }] }, ctx)).messages[0].content;",
			"const again = await h.before_provider_request({ payload: { input: first } }, ctx);",
			"const blocked = await h.tool_call({ toolName: 'write', input: { path: 'notes.md', content: first } }, ctx);",
			"await h.context({ messages: [{ role: 'user', content: '[allow-pii] ok' }] }, ctx);",
			"const allowed = await h.tool_call({ toolName: 'write', input: { path: 'notes.md', content: first } }, ctx);",
			"console.log(JSON.stringify({ first, again: again === undefined, blocked: blocked?.reason ?? null, allowed: allowed === undefined }));",
		].join("\n");
		const child = Bun.spawnSync({
			cmd: [process.execPath, "-e", script],
			env: { ...process.env, HOME: home, XDG_CACHE_HOME: join(home, "cache"), SENSITIVE_CANARY_CONFIG: file },
			timeout: 30000,
		});
		expect(child.exitCode).toBe(0);
		const out = JSON.parse(child.stdout.toString());
		expect(out.first).toBe("I have a ⟦minor neurological condition⟧ today");
		// "condition" inside the brackets is never generalized again.
		expect(out.again).toBe(true);
		expect(out.blocked).toContain("generalized wording");
		expect(out.allowed).toBe(true);
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
});

it("loads generalize.json beside the config and honors prompt-only scope", () => {
	const home = mkdtempSync(join(tmpdir(), "canary-generalize-file-"));
	try {
		const file = join(home, "config.json");
		writeFileSync(file, JSON.stringify({ rules: [] }), { mode: 0o600 });
		writeFileSync(join(home, "generalize.json"), JSON.stringify({
			generalize: [
				{ id: "health", terms: ["migraine"], replace: "a neurological condition" },
				{ id: "vendor", terms: ["ZqxShield"], replace: "a security product", scope: "prompts" },
			],
		}), { mode: 0o600 });
		const script = [
			"const m = await import(" + JSON.stringify(new URL("./index.ts", import.meta.url).href) + ");",
			"const h = {};",
			"m.default({ on: (n, fn) => { h[n] = fn; }, registerFlag(){}, registerCommand(){}, appendEntry(){}, getFlag: () => false, events: { on(){}, emit(){} } });",
			"const ctx = { cwd: process.cwd(), sessionManager: { getBranch: () => [], getSessionFile: () => undefined }, ui: { notify(){} } };",
			"h.agent_start({}, ctx);",
			"const prompt = (await h.context({ messages: [{ role: 'user', content: 'ZqxShield flags my migraine app' }] }, ctx)).messages[0].content;",
			"const stored = (await h.message_end({ message: { role: 'user', content: 'ZqxShield config' } }, ctx))?.message.content;",
			"const tool = (await h.tool_result({ toolName: 'bash', content: [{ type: 'text', text: 'ZqxShield: migraine' }] }, ctx))?.content[0].text;",
			`const guarded = await h.tool_call({ toolName: 'bash', input: { command: 'cat ${join(home, "generalize.json")}' } }, ctx);`,
			"console.log(JSON.stringify({ prompt, stored, tool, guarded: guarded?.block === true }));",
		].join("\n");
		const child = Bun.spawnSync({
			cmd: [process.execPath, "-e", script],
			env: { ...process.env, HOME: home, XDG_CACHE_HOME: join(home, "cache"), SENSITIVE_CANARY_CONFIG: file },
			timeout: 30000,
		});
		expect(child.exitCode).toBe(0);
		const out = JSON.parse(child.stdout.toString());
		expect(out.prompt).toBe("⟦a security product⟧ flags my ⟦a neurological condition⟧ app");
		expect(out.stored).toBe("⟦a security product⟧ config");
		// Tool output keeps prompt-only words, so files using them stay editable.
		expect(out.tool).toBe("ZqxShield: ⟦a neurological condition⟧");
		expect(out.guarded).toBe(true);
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
});
