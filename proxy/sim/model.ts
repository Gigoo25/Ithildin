// The fake model: it reads only what the proxy forwarded, and answers the way
// an agent's model does, by calling tools on what it saw and quoting it back.
// So whatever the proxy put in place of a value (a stand-in path, a stand-in
// address) comes back in the model's calls and text, and the proxy has to
// turn it back into the real value before the harness runs the call.

import { Random } from "./random.ts";

export interface ModelCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface Turn {
  thinking: string;
  text: string;
  calls: ModelCall[];
}

// The signature Gemini gives a turn's thought, as the stream sends it and the
// harness keeps it.
export function geminiSignature(turn: Turn): string {
  return Buffer.from(`sig-${turn.thinking.length}`).toString("base64");
}

const PATH = /\/[\w.-]+(?:\/[\w.-]+)+/g;
const EMAIL = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;

// Opaque bytes the provider signed, which the model never reads as text.
const SIGNED = new Set(["signature", "encrypted_content", "thoughtSignature"]);

function strings(value: unknown, out: string[]): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) strings(item, out);
  else if (value && typeof value === "object")
    for (const [key, inner] of Object.entries(value)) if (!SIGNED.has(key)) strings(inner, out);
  return out;
}

// What the model can see of the latest exchange: the last few items.
function recent(body: Record<string, unknown>): string {
  const list = (body.messages ?? body.input ?? body.contents) as unknown[] | undefined;
  return strings(Array.isArray(list) ? list.slice(-6) : [], []).join("\n");
}

function seen(text: string, pattern: RegExp): string[] {
  return [...new Set(text.match(pattern) ?? [])];
}

function call(random: Random, id: string, paths: string[], emails: string[]): ModelCall {
  const path = paths.length > 0 ? random.pick(paths) : "/";
  const dir = path.split("/").slice(0, 3).join("/");
  const choice = random.int(0, 9);
  if (choice < 4) return { id, name: "Read", input: { file_path: path } };
  if (choice < 6) return { id, name: "Bash", input: { command: `cat ${path}` } };
  if (choice === 6) return { id, name: "Bash", input: { command: `ls ${dir}` } };
  if (choice === 7 && emails.length > 0)
    return { id, name: "Bash", input: { command: `grep -rn ${random.pick(emails)} ${dir}` } };
  if (choice === 8) return { id, name: "Bash", input: { command: "env" } };
  const quoted = [...paths.slice(0, 3), ...emails.slice(0, 3)].join(", ");
  return {
    id,
    name: "Write",
    input: {
      file_path: `${dir}/notes/summary-${random.int(1, 99)}.md`,
      content: `Seen: ${quoted}`,
    },
  };
}

// The model's next turn for a request: calls while the loop goes on, text that
// quotes what it saw when it ends.
export function respond(body: Record<string, unknown>, random: Random, ids: () => string): Turn {
  const text = recent(body);
  const paths = seen(text, PATH);
  const emails = seen(text, EMAIL);
  const mention = [...paths, ...emails];
  const thinking = `Looking at ${mention.slice(0, 2).join(" and ") || "the request"}.`;
  if (random.chance(0.12) || mention.length === 0)
    return {
      thinking,
      text: `Done. I looked at ${mention.slice(0, 4).join(", ") || "nothing"}.`,
      calls: [],
    };
  const count = random.chance(0.15) ? 2 : 1;
  const calls = Array.from({ length: count }, () => call(random, ids(), paths, emails));
  return { thinking, text: random.chance(0.3) ? `Checking ${mention[0]}.` : "", calls };
}
