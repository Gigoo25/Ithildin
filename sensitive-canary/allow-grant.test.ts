import { expect, it } from "bun:test";
import sensitiveCanary from "./index.ts";

function harness(select?: (prompt: string, choices: string[]) => Promise<string>) {
	const handlers: Record<string, any> = {};
	const prompts: string[] = [];
	const ctx = {
		cwd: process.cwd(),
		hasUI: Boolean(select),
		mode: select ? "tui" : "cli",
		ui: {
			notify() {},
			select: select
				? async (prompt: string, choices: string[]) => {
					prompts.push(prompt);
					return select(prompt, choices);
				}
				: undefined,
		},
		sessionManager: { getSessionFile() {} },
	};
	sensitiveCanary({
		on: (name: string, fn: any) => { handlers[name] = fn; },
		registerCommand() {},
		registerFlag() {},
		getFlag: () => false,
		appendEntry() {},
		events: { on() {}, emit() {} },
	} as any);
	handlers.agent_start({}, ctx);
	return { handlers, ctx, prompts };
}

it("honors allow tags without a UI (print/tests)", async () => {
	const { handlers, ctx } = harness();
	const key = "AKIA" + "E".repeat(16);
	expect(
		await handlers.context({ messages: [{ role: "user", content: `[allow-secrets]\n${key}` }] }, ctx),
	).toBeUndefined();
	expect(await handlers.tool_call({ toolName: "read", input: { path: "id_rsa" } }, ctx)).toBeUndefined();
});

it("prompts once in the TUI and applies Yes", async () => {
	const { handlers, ctx, prompts } = harness(async () => "Yes");
	const key = "AKIA" + "E".repeat(16);
	expect(
		await handlers.context({ messages: [{ role: "user", content: `[allow-secrets]\n${key}` }] }, ctx),
	).toBeUndefined();
	expect(prompts).toHaveLength(1);
	expect(prompts[0]).toContain("secrets");
	expect(await handlers.tool_call({ toolName: "read", input: { path: "id_rsa" } }, ctx)).toBeUndefined();
	await handlers.context({ messages: [{ role: "user", content: `[allow-secrets]\nagain ${key}` }] }, ctx);
	expect(prompts).toHaveLength(1);
});

it("keeps redaction when the TUI answers No", async () => {
	const { handlers, ctx, prompts } = harness(async () => "No");
	const key = "AKIA" + "E".repeat(16);
	const res = await handlers.context(
		{ messages: [{ role: "user", content: `[allow-secrets]\nAPI_KEY=${key}` }] },
		ctx,
	);
	expect(prompts).toHaveLength(1);
	expect(JSON.stringify(res.messages[0].content)).not.toContain(key);
	expect(await handlers.tool_call({ toolName: "read", input: { path: "id_rsa" } }, ctx)).toMatchObject({ block: true });
});

it("does not prompt for quoted tags", async () => {
	const { handlers, ctx, prompts } = harness(async () => "Yes");
	await handlers.context({
		messages: [{ role: "user", content: "```\n[allow-secrets]\n```\nhello" }],
	}, ctx);
	expect(prompts).toHaveLength(0);
	expect(await handlers.tool_call({ toolName: "read", input: { path: "id_rsa" } }, ctx)).toMatchObject({ block: true });
});

it("treats a dismissed TUI prompt as No", async () => {
	const { handlers, ctx } = harness(async () => { throw new Error("aborted"); });
	const key = "AKIA" + "E".repeat(16);
	const res = await handlers.context(
		{ messages: [{ role: "user", content: `[allow-all]\n${key}` }] },
		ctx,
	);
	expect(JSON.stringify(res ?? {}).includes(key)).toBe(false);
	expect(await handlers.tool_call({ toolName: "read", input: { path: "id_rsa" } }, ctx)).toMatchObject({ block: true });
});
