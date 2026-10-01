// Proof that masking works, end to end, in the running process.
//
// A badge that reads "0" looks the same whether nothing needed masking or
// masking is broken. So the proxy checks itself: random synthetic values (an
// AWS key, a GitHub token, an email address) go through a real handler to a
// fake upstream that records what it was sent and replies with a tool call
// naming the email's stand-in, once as JSON and once streamed. It passes when
// no value reached the "provider" and both tool calls came back with the real
// value.
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

function toolReply(standIn: string): Response {
  return Response.json({
    id: "msg_selftest",
    type: "message",
    role: "assistant",
    model: "selftest",
    stop_reason: "tool_use",
    content: [
      {
        type: "tool_use",
        id: "toolu_selftest",
        name: "Bash",
        input: { command: `echo ${standIn}` },
      },
    ],
    usage: { input_tokens: 0, output_tokens: 0 },
  });
}

// The same tool call streamed, its arguments cut inside the stand-in.
function toolStream(standIn: string): Response {
  const args = JSON.stringify({ command: `echo ${standIn}` });
  const cut = args.indexOf(standIn) + Math.floor(standIn.length / 2);
  const events = [
    {
      type: "content_block_start",
      index: 0,
      content_block: { type: "tool_use", id: "toolu_selftest_stream", name: "Bash", input: {} },
    },
    ...[args.slice(0, cut), args.slice(cut)].map((partial_json) => ({
      type: "content_block_delta",
      index: 0,
      delta: { type: "input_json_delta", partial_json },
    })),
    { type: "content_block_stop", index: 0 },
  ];
  const text = events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join("");
  return new Response(text, { headers: { "content-type": "text/event-stream" } });
}

// The command a streamed reply's tool call carries, reassembled; undefined
// when the reply is not one (a refusal).
function streamedCommand(text: string): unknown {
  let json = "";
  for (const line of text.split("\n")) {
    if (!line.startsWith("data: {")) continue;
    const event = JSON.parse(line.slice(6)) as { delta?: { partial_json?: unknown } };
    if (typeof event.delta?.partial_json === "string") json += event.delta.partial_json;
  }
  try {
    return (JSON.parse(json) as { command?: unknown }).command;
  } catch {
    return undefined;
  }
}

// `makeHandler`: a proxy handler over the given upstream, built the way the
// server builds its own.
export async function selfTest(
  makeHandler: (fetchUpstream: typeof fetch) => Handler,
): Promise<SelfTest> {
  const started = performance.now();
  const failures: string[] = [];
  const values = syntheticValues();
  const forwarded: string[] = [];
  let standIn = "";
  const upstream = (async (_url: string, init?: RequestInit) => {
    const body = String(init?.body ?? "");
    forwarded.push(body);
    standIn = /<<([^<>]*)>>/.exec(body)?.[1] ?? "";
    return (JSON.parse(body) as { stream?: boolean }).stream
      ? toolStream(standIn)
      : toolReply(standIn);
  }) as unknown as typeof fetch;
  const send = (stream: boolean) =>
    makeHandler(upstream)(
      new Request("http://127.0.0.1/anthropic/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "selftest",
          max_tokens: 1,
          stream,
          messages: [
            {
              role: "user",
              content: `self-test ${values.aws} ${values.token} <<${values.email}>>`,
            },
          ],
        }),
      }),
    );
  const swapping = aliasStyle() === "stand-ins";
  try {
    const response = await send(false);
    if (forwarded.length === 0) failures.push(`request not forwarded (status ${response.status})`);
    if (forwarded.length > 0 && (standIn === "" || standIn === values.email))
      failures.push("email got no stand-in");
    const reply = (await response.json()) as { content?: Array<{ input?: { command?: unknown } }> };
    if (swapping && reply.content?.[0]?.input?.command !== `echo ${values.email}`)
      failures.push("tool call not swapped back");
    const streamed = await (await send(true)).text();
    if (swapping && streamedCommand(streamed) !== `echo ${values.email}`)
      failures.push("streamed tool call not swapped back");
    for (const [name, value] of Object.entries(values)) {
      if (forwarded.some((body) => body.includes(value)))
        failures.push(`${name} reached the provider`);
    }
  } catch (error) {
    failures.push(`self-test threw ${(error as Error).name}`);
  }
  return {
    ok: failures.length === 0,
    at: new Date().toISOString(),
    ms: Math.round(performance.now() - started),
    failures,
  };
}
