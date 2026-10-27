// The closed loop: harness → proxy → fake model → proxy → harness, for one
// seeded session, with every check the live proxy cannot afford run on every
// request.
//
//   leak         no canary the engine catches on its own reaches the provider
//                (body, URL or headers), in whatever context it was planted
//   stand-in     nothing the proxy put in place of a value reaches the
//                harness: the model's text and calls get the real values back
//   stream       the response the harness reads parses, and agrees with itself
//   valid        the forwarded body is one the provider would take
//   prefix       each forwarded request extends the one before it, unless the
//                harness cut the conversation, shaping stepped, or a new
//                prompt moved what shaping keeps (shape.ts says why each is)
//   retry        the same request sent again forwards the same bytes
//   status       the proxy answers what the upstream answered, never a 5xx of
//                its own
//   slow         a request takes under SLOW_MS in the proxy

import "./env.ts";
import { initEngine, swapText } from "../src/redact.ts";
import { createHandler, DEFAULT_ROUTES } from "../src/server.ts";
import { redactText } from "../../engine/core.ts";
import { Agent, faultsFor, type Faults } from "./agent.ts";
import { Cache } from "./cache.ts";
import { canary, KINDS, type Canary, type Kind } from "./canaries.ts";
import { firstChange, parts, valid } from "./checks.ts";
import { respond } from "./model.ts";
import { Random } from "./random.ts";
import { readTurn, streamed } from "./wire.ts";
import { makeWorld } from "./world.ts";
import type { Format } from "../src/redact.ts";

type Fields = Record<string, unknown>;

export const SLOW_MS = 5_000;
const FOUND_MAX = 30;

export interface Finding {
  check: string;
  request: number;
  detail: string;
}

export interface LoopReport {
  seed: number;
  format: Format;
  faults: Faults;
  requests: number;
  findings: Finding[];
  // Canaries of a kind the engine does not catch alone that reached the
  // provider, by kind: rule gaps, not bugs in the proxy.
  gaps: Partial<Record<Kind, number>>;
  // Canaries the harness sent through the proxy, by whether the engine is held
  // to catching them: what the leak check covered.
  exposed: { held: number; free: number };
  ms: number[];
  breaks: { step: number; typed: number; cut: number; unexplained: number };
}

// One proxy for every session in this process, as a live one serves every
// agent on the machine: they share its stand-in counters, learned values and
// caches, which is what running sessions side by side tests.
let shared: ((request: Request) => Promise<Response>) | undefined;
// The journal, captured once for the process: requests in flight at once
// write their lines in any order, so each is matched to its session by the
// session= field the proxy writes.
const journal: string[] = [];
const runs = new Map<string, Run>();
const SESSION_HEADERS = ["x-claude-code-session-id", "session_id", "x-opencode-session"];
const caughtKinds = new Map<Kind, boolean>();

// Whether the engine catches a kind on its own, from samples no session uses,
// so asking does not teach it any planted value.
function catches(kind: Kind): boolean {
  let known = caughtKinds.get(kind);
  if (known === undefined) {
    const random = new Random(0xca11 + KINDS.indexOf(kind));
    known = [0, 1, 2].every(() => {
      const sample = canary(random, kind);
      return !redactText(sample.value).text.includes(sample.core);
    });
    caughtKinds.set(kind, known);
  }
  return known;
}

function strings(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) strings(item, out);
  else if (value && typeof value === "object")
    for (const inner of Object.values(value)) strings(inner, out);
  return out;
}

const TOKEN = /\/[\w.-]+(?:\/[\w.-]+)+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|\b[\w-]+(?:\.[\w-]+)+\b/g;

function tokens(text: string): Set<string> {
  return new Set(text.match(TOKEN) ?? []);
}

interface Seen {
  url: string;
  headers: Headers;
  text: string;
  body: Fields;
}

interface Run {
  report: LoopReport;
  agent: Agent;
  random: Random;
  cache: Cache;
  handler: (request: Request) => Promise<Response>;
  forwarded: Seen[];
  // Every path, address and host the harness ever sent, as text.
  sentTokens: Set<string>;
  standIns: Set<string>;
  exposedCores: Set<string>;
  previous?: { raw: Fields; seen: Seen; epoch: number };
  journal: string[];
  failNext: boolean;
}

function find(run: Run, check: string, detail: string): void {
  if (run.report.findings.length < FOUND_MAX)
    run.report.findings.push({ check, request: run.report.requests, detail });
}

function leaks(run: Run, seen: Seen): void {
  const out = [
    seen.url,
    ...[...seen.headers.entries()].map(([k, v]) => `${k}: ${v}`),
    ...strings(seen.body),
  ].join("\n");
  const flagged = new Set<string>();
  for (const c of run.agent.world.canaries) {
    const forms = [c.core, encodeURIComponent(c.core), c.core.replace(/@/g, "\\u0040")];
    if (flagged.has(c.core) || !forms.some((form) => out.includes(form))) continue;
    flagged.add(c.core);
    if (catches(c.kind)) find(run, "leak", `${c.kind} ${preview(c)} reached the provider`);
    else run.report.gaps[c.kind] = (run.report.gaps[c.kind] ?? 0) + 1;
  }
}

function preview(c: Canary): string {
  return c.core.length > 24 ? `${c.core.slice(0, 12)}…${c.core.slice(-6)}` : c.core;
}

function exposure(run: Run, raw: Fields): void {
  const text = strings(raw).join("\n");
  for (const c of run.agent.world.canaries)
    if (!run.exposedCores.has(c.core) && text.includes(c.core)) {
      run.exposedCores.add(c.core);
      run.report.exposed[catches(c.kind) ? "held" : "free"]++;
    }
}

function learnStandIns(run: Run, raw: Fields, seen: Seen): void {
  for (const t of tokens(strings(raw).join("\n"))) run.sentTokens.add(t);
  for (const t of tokens(strings(seen.body).join("\n")))
    if (!run.sentTokens.has(t) && !run.sentTokens.has(t.replace(/[.]+$/, ""))) run.standIns.add(t);
}

export function makeRun(format: Format, seed: number): Run {
  if (!shared) {
    process.stderr.write = ((chunk: unknown) =>
      journal.push(String(chunk)) > 0) as typeof process.stderr.write;
    initEngine();
    shared = createHandler(DEFAULT_ROUTES, upstream);
  }
  const random = new Random(seed);
  const faults = faultsFor(random);
  const world = makeWorld(seed);
  const agent = new Agent(format, world, random, faults, `${format[0]}${seed}`);
  const run: Run = {
    report: {
      seed,
      format,
      faults,
      requests: 0,
      findings: [],
      gaps: {},
      exposed: { held: 0, free: 0 },
      ms: [],
      breaks: { step: 0, typed: 0, cut: 0, unexplained: 0 },
    },
    agent,
    random,
    cache: new Cache(format),
    handler: shared,
    forwarded: [],
    sentTokens: new Set(),
    standIns: new Set(),
    exposedCores: new Set(),
    journal: [],
    failNext: false,
  };
  runs.set(agent.session, run);
  return run;
}

// The fake provider: records what the proxy forwarded and answers with the
// model's turn, or with an error when a fault calls for one.
const upstream = (async (url: string, init: RequestInit) => {
  const headers = new Headers(init.headers);
  const id = SESSION_HEADERS.map((name) => headers.get(name)).find(Boolean);
  const run = runs.get(String(id));
  if (!run) return Response.json({ error: `no session ${String(id)}` }, { status: 400 });
  const text = String(init.body ?? "");
  const body = JSON.parse(text) as Fields;
  run.forwarded.push({ url: String(url), headers, text, body });
  if (run.failNext) {
    run.failNext = false;
    return Response.json({ type: "error", error: { type: "overloaded_error" } }, { status: 529 });
  }
  const usage = run.cache.send(body);
  const turn = respond(body, new Random(run.report.seed * 7919 + run.report.requests), () =>
    run.agent.nextId(),
  );
  return streamed(run.agent.format, turn, usage, run.random);
}) as unknown as typeof fetch;

// The index of the last turn shaping counts as typed: what strip-thinking and
// the reasoning drop key on (lastTyped and lastAsked in shape.ts).
function typedAt(format: Format, body: Fields): number {
  const list = ((format === "responses" ? body.input : body.messages) ?? []) as Fields[];
  return list.findLastIndex((entry) => {
    if (format === "responses") return entry.type === "message" && entry.role === "user";
    if (entry.role !== "user") return false;
    if (format === "chat" || !Array.isArray(entry.content)) return true;
    return (entry.content as Fields[]).some((block) => block.type !== "tool_result");
  });
}

// Where two versions of one part first differ, as a few characters of each.
function where(before: unknown, now: unknown): string {
  const a = JSON.stringify(before) ?? "";
  const b = JSON.stringify(now) ?? "";
  let at = 0;
  while (at < a.length && a[at] === b[at]) at++;
  const cut = (s: string) => JSON.stringify(s.slice(Math.max(0, at - 30), at + 50));
  return `was ${cut(a)}, now ${cut(b)}`;
}

function partValue(format: Format, body: Fields, index: number): unknown {
  const system = format === "responses" ? body.instructions : body.system;
  const list = ((format === "responses" ? body.input : body.messages) ?? []) as unknown[];
  return [body.model, body.tools, system, ...list][index];
}

function prefix(run: Run, raw: Fields, seen: Seen, lines: string[]): void {
  const { format, epoch } = run.agent;
  const before = run.previous;
  run.previous = { raw, seen, epoch };
  if (!before) return;
  const { breaks } = run.report;
  if (before.epoch !== epoch || firstChange(parts(format, before.raw), parts(format, raw)) >= 0) {
    breaks.cut++;
    return;
  }
  const at = firstChange(parts(format, before.seen.body), parts(format, seen.body));
  if (at < 0) return;
  if (lines.some((line) => / step=/.test(line))) breaks.step++;
  else if (typedAt(format, before.raw) !== typedAt(format, raw)) breaks.typed++;
  else {
    breaks.unexplained++;
    const detail = where(partValue(format, before.seen.body, at), partValue(format, seen.body, at));
    find(run, "prefix", `part ${at} changed with no step and no new prompt: ${detail}`);
  }
}

async function send(run: Run, path: string, headers: Record<string, string>, raw: Fields) {
  const from = journal.length;
  const start = performance.now();
  const request = new Request(`http://127.0.0.1/${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(raw),
  });
  const response = await run.handler(request);
  const text = await response.text();
  const ms = performance.now() - start;
  const mine = ` session=${run.agent.session} `;
  const lines = journal.slice(from).filter((line) => line.includes(mine));
  return { status: response.status, text, lines, ms };
}

// One request of the session, its retries, and every check on it.
export async function step(run: Run): Promise<void> {
  const { agent, random, report } = run;
  const { path, headers, body: raw } = agent.outgoing();
  const before = run.forwarded.length;
  if (agent.faults.upstreamErrors && random.chance(0.05)) {
    run.failNext = true;
    const failed = await send(run, path, headers, raw);
    if (failed.status !== 529) find(run, "status", `an upstream 529 came back as ${failed.status}`);
  }
  if (agent.faults.retry && random.chance(0.05)) await send(run, path, headers, raw);
  const sent = await send(run, path, headers, raw);
  report.ms.push(sent.ms);
  if (sent.ms > SLOW_MS) find(run, "slow", `${Math.round(sent.ms)} ms`);
  const copies = run.forwarded.slice(before);
  if (sent.status !== 200 || copies.length === 0) {
    find(run, "status", `${sent.status}: ${sent.text.slice(0, 160)}`);
    agent.take({ thinking: "", text: "", calls: [] });
    return;
  }
  // diagnostics.previous_message_id names the reply before, which a retry
  // has one more of; it is not part of the cached prompt.
  const prompt = (copy: Seen) => JSON.stringify({ ...copy.body, diagnostics: undefined });
  for (const copy of copies) {
    leaks(run, copy);
    if (prompt(copy) !== prompt(copies[0]!))
      find(run, "retry", "the same request forwarded different bytes");
  }
  const seen = copies.at(-1)!;
  for (const v of valid(agent.format, seen.body)) find(run, "valid", v.detail);
  prefix(run, raw, seen, sent.lines);
  learnStandIns(run, raw, seen);
  exposure(run, raw);
  const read = readTurn(agent.format, sent.text);
  for (const problem of read.problems) find(run, "stream", problem);
  const visible = [read.turn.text, ...read.turn.calls.map((c) => JSON.stringify(c.input))].join(
    "\n",
  );
  for (const token of tokens(visible))
    // Only a stand-in the proxy knows how to restore: a secret's replacement is
    // one-way by design.
    if (run.standIns.has(token) && swapText(token, new Set()).text !== token)
      find(run, "stand-in", `the harness got ${token}`);
  agent.take(read.turn);
}

// Which kinds the engine is held to catching, for the report.
export function heldKinds(): Kind[] {
  return KINDS.filter(catches);
}

// Sessions side by side on the one proxy, a request of each in flight at once.
export async function runSessions(
  sessions: Array<{ format: Format; seed: number }>,
  requests: number,
): Promise<LoopReport[]> {
  const all = sessions.map(({ format, seed }) => makeRun(format, seed));
  for (let i = 0; i < requests; i++)
    await Promise.all(
      all.map(async (run) => {
        await step(run);
        run.report.requests++;
      }),
    );
  return all.map((run) => run.report);
}

export async function runSession(
  format: Format,
  seed: number,
  requests: number,
): Promise<LoopReport> {
  const run = makeRun(format, seed);
  for (let i = 0; i < requests; i++) {
    await step(run);
    run.report.requests++;
  }
  return run.report;
}
