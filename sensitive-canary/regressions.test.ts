import { expect, it } from "bun:test";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import sensitiveCanary from "./index.ts";
import { beginScanBudget, setRuntimeInventory } from "./lib/rules.ts";
import { collectRuntimeIdentity } from "./lib/runtime-inventory.ts";

function harness() {
	const handlers: Record<string, any> = {};
	const commands: Record<string, any> = {};
	const ctx = { cwd: process.cwd(), ui: { notify() {} }, sessionManager: { getSessionFile() {} } };
	sensitiveCanary({
		on: (name: string, fn: any) => { handlers[name] = fn; },
		registerCommand: (name: string, command: any) => { commands[name] = command.handler; },
		registerFlag() {}, getFlag: () => false, appendEntry() {}, events: { on() {}, emit() {} },
	} as any);
	handlers.agent_start({}, ctx);
	return { handlers, commands, ctx };
}

it("does not let boilerplate inside a credential exempt the credential", () => {
	const { handlers, ctx } = harness();
	const key = "AKIA" + "D".repeat(16);
	const seed = handlers.tool_result({ toolName: "read", input: { path: "fixture.txt" }, content: [{ type: "text", text: key }] }, ctx);
	const reminder = handlers.before_agent_start({ prompt: "p", systemPrompt: "base" }, ctx)?.systemPrompt as string;
	const notice = reminder.slice(reminder.indexOf("SENSITIVE-CANARY:"));
	const text = JSON.stringify({ password: "weakcredential " + notice });
	const event = { toolName: "read", input: { path: "fixture.json" }, content: [{ type: "text", text }] };
	const out = handlers.tool_result(event, ctx);
	expect(out).toBeDefined();
	expect(JSON.stringify(out.content)).not.toContain("weakcredential");
	expect(() => JSON.parse(out.content[0].text)).not.toThrow();
});

it("scans routing-named fields in ordinary data rather than exempting whole subtrees", () => {
	const { handlers, ctx } = harness();
	const key = "AKIA" + "E".repeat(16);
	for (const record of [
		{ name: key, arguments: "ordinary data" }, { call_id: key }, { tool_call_id: key },
		{ previous_response_id: key }, { id: key, type: "function_call" },
		{ name: key, call_id: "not a protocol item" },
		{ id: key, encrypted_content: "opaque" },
	]) {
		const payload = { data: record };
		const out = handlers.before_provider_request({ payload }, ctx) ?? payload;
		expect(JSON.stringify(out)).not.toContain(key);
	}
	const payload = { previous_response_id: { password: key } };
	expect(JSON.stringify(handlers.before_provider_request({ payload }, ctx) ?? payload)).not.toContain(key);
});

it("preserves real Responses and Completions routing under normal and exhausted budgets", () => {
	const { handlers, ctx } = harness();
	const reference = "AKIA" + "F".repeat(16);
	const payload = {
		previous_response_id: reference,
		input: [
			{ type: "reasoning", id: reference, encrypted_content: "opaque" },
			{ type: "function_call", id: reference, call_id: reference, name: "bash", arguments: JSON.stringify({ value: reference }) },
			{ type: "function_call_output", call_id: reference, output: reference },
		],
		messages: [
			{ role: "assistant", tool_calls: [{ type: "function", id: reference, function: { name: "bash", arguments: JSON.stringify({ value: reference }) } }] },
			{ role: "tool", tool_call_id: reference, content: reference },
		],
	};
	for (const budget of [null, 0]) {
		beginScanBudget(budget);
		try {
			const out = handlers.before_provider_request({ payload }, ctx) ?? payload;
			expect(out.previous_response_id).toBe(reference);
			expect(out.input[0].id).toBe(reference);
			expect(out.input[1].id).toBe(reference);
			expect(out.input[1].call_id).toBe(reference);
			expect(out.input[1].name).toBe("bash");
			expect(out.input[2].call_id).toBe(reference);
			expect(out.messages[0].tool_calls[0].id).toBe(reference);
			expect(out.messages[0].tool_calls[0].function.name).toBe("bash");
			expect(out.messages[1].tool_call_id).toBe(reference);
			expect(out.input[1].arguments).not.toContain(reference);
			expect(out.input[2].output).not.toContain(reference);
			expect(out.messages[1].content).not.toContain(reference);
		} finally { beginScanBudget(null); }
	}
});

it("scans protocol-named fields in persisted details instead of passing them through", () => {
	const { handlers, ctx } = harness();
	const key = "AKIA" + "H".repeat(16);
	const message = {
		role: "toolResult",
		content: [],
		details: {
			type: key,
			role: key,
			include: [key],
			reasoning: { effort: key },
			service_tier: key,
			record: { type: key },
		},
	};
	const persisted = handlers.message_end({ message }, ctx)?.message ?? message;
	expect(JSON.stringify(persisted.details)).not.toContain(key);
});

it("preserves Completions custom calls and root ciphertext details without exempting nested data", () => {
	const { handlers, ctx } = harness();
	const reference = "AKIA" + "G".repeat(16);
	const payload = { messages: [{ role: "assistant", tool_calls: [{ type: "custom", id: reference, custom: { name: "bash", input: reference } }] }] };
	const out = handlers.before_provider_request({ payload }, ctx) ?? payload;
	expect(out.messages[0].tool_calls[0].id).toBe(reference);
	expect(out.messages[0].tool_calls[0].custom.name).toBe("bash");
	expect(out.messages[0].tool_calls[0].custom.input).not.toContain(reference);
	const message = { role: "toolResult", content: [], details: { id: reference, encrypted_content: "opaque", record: { id: reference, encrypted_content: "opaque" } } };
	const persisted = handlers.message_end({ message }, ctx)?.message ?? message;
	expect(persisted.details.id).toBe(reference);
	expect(persisted.details.record.id).not.toContain(reference);
});

it("normalizes inventory aliases and documented variable spellings without reading the file", async () => {
	const { handlers, ctx } = harness();
	const dir = mkdtempSync(join(tmpdir(), "inventory-guard-"));
	const before = process.env.SENSITIVE_CANARY_CONFIG;
	try {
		const inventory = join(dir, "private inventory.json");
		writeFileSync(inventory, "{}\n");
		const alias = join(dir, "alias.json");
		symlinkSync(inventory, alias);
		process.env.SENSITIVE_CANARY_CONFIG = inventory;
		for (const target of [inventory, join(dir, ".") + "/./private inventory.json", relative(ctx.cwd, inventory), relative(ctx.cwd, alias)]) {
			const out = await handlers.tool_call({ toolName: "read", input: { path: target } }, ctx);
			expect(out?.block).toBe(true);
			expect(out?.reason).toContain("PII inventory");
		}
		for (const command of [
			'cat "$SENSITIVE_CANARY_CONFIG"',
			'cat "${SENSITIVE_CANARY_CONFIG}"',
			`cat "${inventory}"`,
			`cat ${dir}/private*`,
			`cat ${dir}/{alias,other}.json`,
			`p=${dir}/alias.json; cat $p`,
		]) {
			expect((await handlers.tool_call({ toolName: "bash", input: { command } }, ctx))?.reason).toContain("PII inventory");
		}
		await handlers.context({ messages: [{ role: "user", content: "[allow-pii]" }] }, ctx);
		expect(await handlers.tool_call({ toolName: "read", input: { path: relative(ctx.cwd, inventory) } }, ctx)).toBeUndefined();
		expect(await handlers.tool_call({ toolName: "bash", input: { command: 'cat "$SENSITIVE_CANARY_CONFIG"' } }, ctx)).toBeUndefined();
	} finally {
		if (before === undefined) delete process.env.SENSITIVE_CANARY_CONFIG;
		else process.env.SENSITIVE_CANARY_CONFIG = before;
		rmSync(dir, { recursive: true, force: true });
	}
});

it("blocks home and identifying file-tool paths only while canary is on", async () => {
	const { handlers, commands, ctx } = harness();
	const homeFixture = join(process.env.HOME ?? "/home/nobody", "fixture.txt");
	for (const toolName of ["read", "write", "edit", "grep", "find", "ls", "search_files"]) {
		for (const target of [homeFixture, "~/fixture.txt", "$HOME/fixture.txt", "${HOME}/fixture.txt", "C:\\fixture.txt", "\\\\server\\share\\fixture.txt"]) {
			const out = await handlers.tool_call({ toolName, input: { path: target } }, ctx);
			expect(out?.block).toBe(true);
			expect(out?.reason).toContain("relative");
		}
		for (const target of ["fixture.txt", "./src/fixture.txt", "../fixture.txt", "/etc/fixture.txt", "/nix/store/abc-pkg/share/doc.txt"]) {
			expect(await handlers.tool_call({ toolName, input: { path: target } }, ctx)).toBeUndefined();
		}
	}
	for (const field of ["file", "file_path", "filePath"]) {
		expect((await handlers.tool_call({ toolName: "edit", input: { [field]: homeFixture } }, ctx))?.block).toBe(true);
	}
	// Pi strips @ from file paths before resolving them; do not allow it to hide an absolute path.
	expect((await handlers.tool_call({ toolName: "read", input: { path: "@" + homeFixture } }, ctx))?.block).toBe(true);
	expect(await handlers.tool_call({ toolName: "bash", input: { command: 'ls "$HOME"' } }, ctx)).toBeUndefined();
	expect(await handlers.tool_call({ toolName: "web_fetch", input: { url: "https://example.org" } }, ctx)).toBeUndefined();
	await handlers.context({ messages: [{ role: "user", content: "[allow-all]" }] }, ctx);
	expect((await handlers.tool_call({ toolName: "read", input: { path: homeFixture } }, ctx))?.block).toBe(true);
	await commands.canary("off", ctx);
	expect(await handlers.tool_call({ toolName: "read", input: { path: homeFixture } }, ctx)).toBeUndefined();
	await commands.canary("on", ctx);
	expect((await handlers.tool_call({ toolName: "read", input: { path: homeFixture } }, ctx))?.block).toBe(true);
});

it("blocks an absolute path outside home when it contains an identifying name", async () => {
	const { handlers, ctx } = harness();
	setRuntimeInventory(collectRuntimeIdentity({ username: "zzzxquniqueuser" }));
	try {
		const out = await handlers.tool_call({ toolName: "read", input: { path: "/srv/zzzxquniqueuser/notes.txt" } }, ctx);
		expect(out?.block).toBe(true);
		expect(out?.reason).toContain("identifying name");
		expect(await handlers.tool_call({ toolName: "read", input: { path: "/srv/shared/notes.txt" } }, ctx)).toBeUndefined();
	} finally {
		setRuntimeInventory([]);
	}
});
