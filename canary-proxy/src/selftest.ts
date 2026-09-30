// Proof that masking works, end to end, in the running process.
//
// A badge that reads "0" looks the same whether nothing needed masking or
// masking is broken. So the proxy checks itself: random synthetic values (an
// AWS key, a GitHub token, an email address) go through a real handler to a
// fake upstream that records what it was sent and replies with a tool call
// naming the email's stand-in. It passes when no value reached the "provider"
// and the tool call came back with the real value.
//
// Nothing leaves the process, and the values are new on every run, so none is
// ever a real one. Failures name what failed, never a value.

import { randomInt } from "node:crypto";
import { aliasStyle } from "../engine/lib/rules.ts";

export type SelfTest = { ok: boolean; at: string; ms: number; failures: string[] };
type Handler = (request: Request) => Promise<Response>;

const UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
// Consonants only: a random run cannot spell a word a rule exempts.
const CONSONANTS = "bcdfghjklmnpqrstvwxz";

function pick(alphabet: string, length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[randomInt(alphabet.length)];
  return out;
}

export function syntheticValues(): Record<"aws" | "token" | "email", string> {
  return {
    aws: `AKIA${pick(UPPER32, 16)}`,
    token: `ghp_${pick(ALNUM, 36)}`,
    email: `${pick(CONSONANTS, 8)}@${pick(CONSONANTS, 7)}.net`,
  };
}

// `makeHandler`: a proxy handler over the given upstream, built the way the
// server builds its own.
export async function selfTest(makeHandler: (fetchUpstream: typeof fetch) => Handler): Promise<SelfTest> {
  const started = performance.now();
  const failures: string[] = [];
  const values = syntheticValues();
  let forwarded = "";
  let standIn = "";
  const upstream = (async (_url: string, init?: RequestInit) => {
    forwarded = String(init?.body ?? "");
    standIn = /<<([^<>]*)>>/.exec(forwarded)?.[1] ?? "";
    return Response.json({
      id: "msg_selftest", type: "message", role: "assistant", model: "selftest", stop_reason: "tool_use",
      content: [{ type: "tool_use", id: "toolu_selftest", name: "Bash", input: { command: `echo ${standIn}` } }],
      usage: { input_tokens: 0, output_tokens: 0 },
    });
  }) as unknown as typeof fetch;
  try {
    const body = { model: "selftest", max_tokens: 1, messages: [{ role: "user", content: `self-test ${values.aws} ${values.token} <<${values.email}>>` }] };
    const response = await makeHandler(upstream)(new Request("http://127.0.0.1/anthropic/v1/messages", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    }));
    if (forwarded === "") failures.push(`request not forwarded (status ${response.status})`);
    for (const [name, value] of Object.entries(values)) {
      if (forwarded.includes(value)) failures.push(`${name} reached the provider`);
    }
    if (forwarded !== "" && (standIn === "" || standIn === values.email)) failures.push("email got no stand-in");
    const reply = (await response.json()) as { content?: Array<{ input?: { command?: unknown } }> };
    if (aliasStyle() === "stand-ins" && reply.content?.[0]?.input?.command !== `echo ${values.email}`) {
      failures.push("tool call not swapped back");
    }
  } catch (error) {
    failures.push(`self-test threw ${(error as Error).name}`);
  }
  return { ok: failures.length === 0, at: new Date().toISOString(), ms: Math.round(performance.now() - started), failures };
}
