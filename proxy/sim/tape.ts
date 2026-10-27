// A tape: the requests a harness sent through the proxy, in order, each with
// whether the upstream failed it first or the harness sent it twice. A live
// session records one; a real request body is cut into one; a shrunk failure
// is one. Replaying a tape through a fresh proxy is the same run again, which
// is what makes a failure shrinkable and a shrunk failure a test.
//
// Saved, a tape names its canaries but never holds one: each is stored
// scrambled, and every place a canary, a line of one or its escaped form
// stood in the requests holds a reference instead. A tape of planted keys
// and tokens is then a file a scanner, the proxy or a reviewer can read
// without anything in it looking like a secret.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import type { Format } from "../src/redact.ts";
import { canary, preview, type Canary, type Kind } from "./canaries.ts";
import type { Turn } from "./model.ts";
import { Random } from "./random.ts";

type Fields = Record<string, unknown>;

export interface Sent {
  path: string;
  headers: Record<string, string>;
  body: Fields;
  // The upstream answers this one with an error first, as an overloaded
  // provider does, and the harness sends it again.
  fail?: boolean;
  // The harness sends this one twice.
  retry?: boolean;
  // What the provider answered, in its own form. Replayed, the provider gives
  // the same answer, so the proxy records and swaps back what it did the first
  // time; without it every turn of the model's would be news to the proxy.
  answer?: Turn;
}

// The failure a shrunk tape reproduces: a check, and for a leak which canary.
export interface Target {
  check: string;
  canary?: number;
}

// Whether a finding is the target's failure: the same check, and for a leak
// the same canary.
export function matches(
  tape: Tape,
  target: Target,
  finding: { check: string; detail: string },
): boolean {
  if (finding.check !== target.check) return false;
  const c = target.canary === undefined ? undefined : tape.canaries[target.canary];
  return !c || finding.detail.includes(preview(c));
}

export interface Tape {
  format: Format;
  session: string;
  seed: number;
  canaries: Canary[];
  requests: Sent[];
  target?: Target;
}

export function formatOf(body: Fields): Format {
  if (Array.isArray(body.input)) return "responses";
  return Array.isArray(body.system) || body.system !== undefined ? "anthropic" : "chat";
}

// Where each format's harness sends its requests, and how it names its session.
export function route(format: Format, session: string): Omit<Sent, "body"> {
  const auth = { authorization: "Bearer sim-token", "content-type": "application/json" };
  if (format === "anthropic")
    return {
      path: "anthropic/v1/messages",
      headers: { ...auth, "x-claude-code-session-id": session, "anthropic-version": "2023-06-01" },
    };
  if (format === "responses")
    return { path: "openai-codex/codex/responses", headers: { ...auth, session_id: session } };
  return {
    path: "opencode-go/chat/completions",
    headers: { ...auth, "x-opencode-session": session, "x-opencode-client": "opencode" },
  };
}

// --- Saving and loading -----------------------------------------------------

const SCRAMBLE = 0x5a;
const scramble = (text: string) =>
  Buffer.from(Buffer.from(text).map((byte) => byte ^ SCRAMBLE)).toString("hex");
const unscramble = (hex: string) =>
  Buffer.from(Buffer.from(hex, "hex").map((byte) => byte ^ SCRAMBLE)).toString();

// A string as it reads inside JSON text, and inside a JSON string that is
// itself inside JSON (a call's arguments).
const escaped = (text: string) => JSON.stringify(text).slice(1, -1);

// Every form of a canary that may stand in a saved tape's text, longest first:
// the whole value, its core, each long line, each escaped once and twice.
function forms(c: Canary): string[] {
  const pieces = [c.value, c.core, ...c.value.split("\n").filter((line) => line.length >= 8)];
  const all = pieces.flatMap((piece) => [piece, escaped(piece), escaped(escaped(piece))]);
  return [...new Set(all)].sort((a, b) => b.length - a.length);
}

const reference = (canary: number, form: number) => `@@sim-canary-${canary}-${form}@@`;

export function saveTape(tape: Tape, file: string): void {
  let text = JSON.stringify(tape.requests);
  const all = tape.canaries.flatMap((c, i) =>
    forms(c).map((form, k) => ({ form, at: reference(i, k) })),
  );
  for (const { form, at } of all.sort((a, b) => b.form.length - a.form.length))
    text = text.split(form).join(at);
  // Said, not trusted: a canary in a form not listed above would be written
  // out as it is.
  for (const c of tape.canaries)
    if (forms(c).some((form) => form.length >= 8 && text.includes(form)))
      throw new Error(`a ${c.kind} canary is still in the tape after hiding`);
  const saved = {
    format: tape.format,
    session: tape.session,
    seed: tape.seed,
    ...(tape.target ? { target: tape.target } : {}),
    canaries: tape.canaries.map((c) => ({
      kind: c.kind,
      value: scramble(c.value),
      core: scramble(c.core),
    })),
    requests: "@@requests@@",
  };
  const out = JSON.stringify(saved, null, 1).replace('"@@requests@@"', text);
  writeFileSync(file, `${out}\n`, { mode: 0o600 });
}

export function loadTape(file: string): Tape {
  const raw = readFileSync(file, "utf8");
  const saved = JSON.parse(raw) as Omit<Tape, "canaries"> & {
    canaries: Array<{ kind: Kind; value: string; core: string }>;
  };
  const canaries = saved.canaries.map((c) => ({
    kind: c.kind,
    value: unscramble(c.value),
    core: unscramble(c.core),
  }));
  let text = JSON.stringify(saved.requests);
  canaries.forEach((c, i) =>
    forms(c).forEach((form, k) => {
      text = text.split(reference(i, k)).join(form);
    }),
  );
  return { ...saved, canaries, requests: JSON.parse(text) as Sent[] };
}

// --- Real bodies --------------------------------------------------------------

// A captured body (capture.ts writes an envelope around it) or a bare one.
export function readBody(file: string): Fields {
  const parsed = JSON.parse(readFileSync(file, "utf8")) as Fields;
  return parsed["ithildin-corpus"] !== undefined ? (parsed.body as Fields) : parsed;
}

// Text a canary is planted into, as it reads in each kind of file a session
// shows a model.
function planted(random: Random, c: Canary): string {
  const name = c.kind.toUpperCase().replace(/-/g, "_");
  switch (random.int(0, 3)) {
    case 0:
      return `\n${c.value}\n`;
    case 1:
      return `\nexport ${name}=${JSON.stringify(c.value)}\n`;
    case 2:
      return `\n${JSON.stringify({ [name.toLowerCase()]: c.value })}\n`;
    default:
      return ` (see ${c.value}) `;
  }
}

// The text-bearing places of a list a canary can go: tool output and typed
// text, as each format carries them. Each is a setter on one string.
function places(format: Format, list: Fields[]): Array<(add: string) => void> {
  const out: Array<(add: string) => void> = [];
  list.forEach((item, at) => {
    if (format === "responses") {
      if (item.type === "function_call_output" && typeof item.output === "string")
        out.push((add) => (item.output = `${item.output as string}${add}`));
      return;
    }
    if (typeof item.content === "string" && (item.role === "tool" || item.role === "user"))
      out.push((add) => (item.content = `${item.content as string}${add}`));
    if (format !== "anthropic" || item.role !== "user" || !Array.isArray(item.content)) return;
    for (const block of item.content as Fields[]) {
      if (block.type === "text" && at > 0)
        out.push((add) => (block.text = `${block.text as string}${add}`));
      if (block.type !== "tool_result") continue;
      if (typeof block.content === "string")
        out.push((add) => (block.content = `${block.content as string}${add}`));
      else if (Array.isArray(block.content))
        for (const part of block.content as Fields[])
          if (part.type === "text") out.push((add) => (part.text = `${part.text as string}${add}`));
    }
  });
  return out;
}

// A real body with canaries planted in it, so the leak check has something
// to look for: the body's own values were masked before it was kept.
export function plantedBody(
  file: string,
  seed: number,
  count = 6,
): { format: Format; session: string; body: Fields; canaries: Canary[]; random: Random } {
  const body = structuredClone(readBody(file));
  const format = formatOf(body);
  const digest = createHash("sha256").update(readFileSync(file)).digest("hex");
  const random = new Random(seed ^ Number.parseInt(digest.slice(0, 8), 16));
  const list = (format === "responses" ? body.input : body.messages) as Fields[];
  const spots = places(format, list);
  const canaries: Canary[] = [];
  for (let i = 0; i < count && spots.length > 0; i++) {
    const c = canary(random);
    canaries.push(c);
    random.pick(spots)(planted(random, c));
  }
  return { format, session: `r${digest.slice(0, 7)}`, body, canaries, random };
}

const textOf = (value: unknown): string =>
  typeof value === "string"
    ? value
    : Array.isArray(value)
      ? value.map((part) => textOf((part as Fields).text ?? "")).join("")
      : "";

function argsOf(text: unknown): Record<string, unknown> {
  try {
    const parsed = JSON.parse(String(text)) as unknown;
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : { value: parsed };
  } catch {
    return { raw: String(text) };
  }
}

// The model's items of one turn, as a body holds them, as the turn the
// provider streams: its thinking, its text and its calls.
export function turnOf(format: Format, items: Fields[]): Turn {
  const turn: Turn = { thinking: "", text: "", calls: [] };
  for (const item of items) {
    if (format === "anthropic") {
      for (const block of (Array.isArray(item.content) ? item.content : []) as Fields[]) {
        if (block.type === "thinking") turn.thinking += String(block.thinking ?? "");
        if (block.type === "text") turn.text += String(block.text ?? "");
        if (block.type === "tool_use")
          turn.calls.push({
            id: String(block.id),
            name: String(block.name),
            input: (block.input ?? {}) as Record<string, unknown>,
          });
      }
      if (typeof item.content === "string") turn.text += item.content;
    } else if (format === "responses") {
      if (item.type === "reasoning")
        turn.thinking += ((item.summary ?? []) as Fields[])
          .map((s) => String(s.text ?? ""))
          .join("");
      else if (item.type === "function_call")
        turn.calls.push({
          id: String(item.call_id),
          name: String(item.name),
          input: argsOf(item.arguments),
        });
      else turn.text += textOf(item.content);
    } else {
      turn.thinking += String(item.reasoning_content ?? "");
      turn.text += textOf(item.content);
      for (const call of (item.tool_calls ?? []) as Fields[]) {
        const fn = (call.function ?? {}) as Fields;
        turn.calls.push({
          id: String(call.id),
          name: String(fn.name),
          input: argsOf(fn.arguments),
        });
      }
    }
  }
  return turn;
}
