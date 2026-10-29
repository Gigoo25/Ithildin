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
//   wide         each command forwarded starts with a word the harness's
//                commands start with: a mask past its value garbles the
//                whole command, and swap-back hides that from every other
//                check
//   prefix       each forwarded request extends the one before it, unless the
//                harness cut the conversation, shaping stepped, or a new
//                prompt moved what shaping keeps (shape.ts says why each is)
//   retry        the same request sent again forwards the same bytes
//   status       the proxy answers what the upstream answered, never a 5xx of
//                its own
//   slow         a request takes under SLOW_MS in the proxy

import "./env.ts";
import { createHash } from "node:crypto";
import { initEngine, swapText } from "../src/redact.ts";
import { currentScanBudgetMs, setScanBudgetMs } from "../../engine/lib/rules.ts";
import { createHandler, DEFAULT_ROUTES } from "../src/server.ts";
import { redactText } from "../../engine/core.ts";
import { Agent, faultsFor, modelItems, type Faults } from "./agent.ts";
import { Cache } from "./cache.ts";
import { canary, KINDS, preview, type Canary, type Kind } from "./canaries.ts";
import { firstChange, parts, valid } from "./checks.ts";
import { respond, type Turn } from "./model.ts";
import { Random } from "./random.ts";
import { plantedBody, route, turnOf, type Sent, type Tape } from "./tape.ts";
import { listKey, listOf, systemOf } from "./workload.ts";
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
  // With a subagent beside a replay: what it sent, and what reached the provider.
  subagent?: { requests: number; sent: number };
  seed: number;
  format: Format;
  // Which faults the session had on; a replayed tape carries its own.
  faults?: Faults;
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
  // A digest of each request's prompt as forwarded, so two runs of one tape
  // (one straight through, one with a restart in it) can be compared.
  sent: string[];
  // The same, with every stand-in swapped back to its value. Which stand-in a
  // value gets depends on what else the proxy saw first (a subagent beside a
  // session takes some), so two runs that both keep their own stand-ins
  // stable can still differ in them; with the values back they cannot.
  real: string[];
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
// By session and model, for a subagent that shares its parent's session.
const routes = new Map<string, Run>();
const routeKey = (session: string, model: unknown) => `${session}\0${String(model)}`;
// The model a request is for: Gemini names it in the path, not the body.
const modelOf = (url: string, body: Fields) => body.model ?? /\/models\/([^/:]+):/.exec(url)?.[1];
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

// Where a session's requests come from: the simulated harness, answering the
// model as it goes, or a tape, which already holds every request.
interface Source {
  format: Format;
  session: string;
  // Live, the world's own list, which grows as the harness pastes.
  canaries: Canary[];
  next(): Sent;
  // The provider's turn for the request just sent; `model` is the fake
  // model's, for a source with none of its own.
  answer(model: () => Turn): Turn;
  take(turn: Turn): void;
  nextId(): string;
}

// The harness, its fault decisions drawn as step drew them before there were
// tapes, so a seed found then still finds the same thing; each request it
// sends is kept, so the session can be replayed.
// Starving scans is opt-in, and drawn from a stream of its own, so turning it
// on leaves every other choice of a seed as it was.
const STARVE = process.env.ITHILDIN_SIM_STARVE === "1";

class Live implements Source {
  readonly tape: Sent[] = [];
  private load: Random;
  constructor(
    readonly agent: Agent,
    private random: Random,
    seed = 0,
  ) {
    this.load = new Random(seed * 977 + 5);
  }
  get format(): Format {
    return this.agent.format;
  }
  get session(): string {
    return this.agent.session;
  }
  get canaries(): Canary[] {
    return this.agent.world.canaries;
  }
  next(): Sent {
    const { faults } = this.agent;
    const fail = faults.upstreamErrors && this.random.chance(0.05);
    const retry = faults.retry && this.random.chance(0.05);
    const starve = STARVE && this.load.chance(0.15) ? this.load.int(1, 40) : 0;
    const sent: Sent = {
      ...this.agent.outgoing(),
      ...(fail ? { fail } : {}),
      ...(retry ? { retry } : {}),
      ...(starve ? { starve } : {}),
    };
    this.tape.push(sent);
    return sent;
  }
  answer(model: () => Turn): Turn {
    const turn = model();
    this.tape.at(-1)!.answer = turn;
    return turn;
  }
  take(turn: Turn): void {
    this.agent.take(turn);
  }
  nextId(): string {
    return this.agent.nextId();
  }
}

// A real session's body driven through the protocol: the harness starts with
// what came before the model's first turn; the provider answers each request
// with the model's next turn as the body has it; the harness keeps what the
// proxy hands back (swapped back), then adds what followed that turn in the
// body (tool results, the next prompt). So the proxy sees the session as it
// did live, its replay store included, not a body it once forwarded.
class Corpus implements Source {
  readonly tape: Sent[] = [];
  private list: Fields[];
  private steps: Array<{ model: Fields[]; then: Fields[] }> = [];
  private at = 0;
  private ids = 0;
  constructor(
    readonly format: Format,
    private body: Fields,
    readonly session: string,
    readonly canaries: Canary[],
    private random: Random,
  ) {
    const items = listOf(format, body) as Fields[];
    const model = (item: Fields) =>
      item.role === "assistant" ||
      item.role === "model" ||
      item.type === "reasoning" ||
      item.type === "function_call";
    let first = items.findIndex(model);
    if (first < 0) first = items.length;
    this.list = items.slice(0, first);
    for (let i = first; i < items.length;) {
      const step = { model: [] as Fields[], then: [] as Fields[] };
      while (i < items.length && model(items[i]!)) step.model.push(items[i++]!);
      while (i < items.length && !model(items[i]!)) step.then.push(items[i++]!);
      this.steps.push(step);
    }
  }
  get left(): number {
    // A request before each of the model's turns, and one after the last
    // when something follows it.
    const last = this.steps.at(-1);
    return this.steps.length + (last && last.then.length > 0 ? 1 : 0) - this.at;
  }
  next(): Sent {
    const sent: Sent = {
      ...route(this.format, this.session),
      body: { ...this.body, [listKey(this.format)]: structuredClone(this.list) },
      ...(this.random.chance(0.03) ? { fail: true } : {}),
      ...(this.random.chance(0.05) ? { retry: true } : {}),
    };
    this.tape.push(sent);
    return sent;
  }
  answer(model: () => Turn): Turn {
    const step = this.steps[this.at];
    const turn = step ? turnOf(this.format, step.model) : model();
    this.tape.at(-1)!.answer = turn;
    return turn;
  }
  take(turn: Turn): void {
    const step = this.steps[this.at++];
    if (!step) return;
    this.list.push(...modelItems(this.format, turn), ...step.then);
  }
  nextId(): string {
    return `call_corpus_${this.ids++}`;
  }
}

class Replay implements Source {
  private ids = 0;
  constructor(
    private tape: Tape,
    private at = 0,
    private upto = tape.requests.length,
  ) {}
  get format(): Format {
    return this.tape.format;
  }
  get session(): string {
    return this.tape.session;
  }
  get canaries(): Canary[] {
    return this.tape.canaries;
  }
  get left(): number {
    return this.upto - this.at;
  }
  next(): Sent {
    return this.tape.requests[this.at++]!;
  }
  answer(model: () => Turn): Turn {
    return this.tape.requests[this.at - 1]?.answer ?? model();
  }
  take(): void {}
  nextId(): string {
    return `call_replay_${this.ids++}`;
  }
}

interface Run {
  report: LoopReport;
  // A subagent beside a replay: its prompts are not the one asked for.
  quiet?: boolean;
  source: Source;
  random: Random;
  cache: Cache;
  handler: (request: Request) => Promise<Response>;
  forwarded: Seen[];
  // Every path, address and host the harness ever sent, as text.
  sentTokens: Set<string>;
  standIns: Set<string>;
  exposedCores: Set<string>;
  previous?: { raw: Fields; seen: Seen };
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
  for (const c of run.source.canaries) {
    const forms = [c.core, encodeURIComponent(c.core), c.core.replace(/@/g, "\\u0040")];
    if (flagged.has(c.core) || !forms.some((form) => out.includes(form))) continue;
    flagged.add(c.core);
    if (catches(c.kind)) find(run, "leak", `${c.kind} ${preview(c)} reached the provider`);
    else run.report.gaps[c.kind] = (run.report.gaps[c.kind] ?? 0) + 1;
  }
}

function exposure(run: Run, raw: Fields): void {
  const text = strings(raw).join("\n");
  for (const c of run.source.canaries)
    if (!run.exposedCores.has(c.core) && text.includes(c.core)) {
      run.exposedCores.add(c.core);
      run.report.exposed[catches(c.kind) ? "held" : "free"]++;
    }
}

// The first word of every command in a body: a call's input, or its
// arguments as a JSON string.
function verbs(value: unknown, out = new Set<string>()): Set<string> {
  if (typeof value === "string" && value.startsWith("{")) {
    try {
      verbs(JSON.parse(value), out);
    } catch {}
  } else if (Array.isArray(value)) for (const item of value) verbs(item, out);
  else if (value && typeof value === "object")
    for (const [key, item] of Object.entries(value))
      if (key === "command" && typeof item === "string") out.add(item.split(" ")[0]!);
      else verbs(item, out);
  return out;
}

function wide(run: Run, raw: Fields, seen: Seen): void {
  const sent = verbs(raw);
  for (const verb of verbs(seen.body))
    if (!sent.has(verb)) find(run, "wide", `a command forwarded as ${JSON.stringify(verb)}`);
}

function learnStandIns(run: Run, raw: Fields, seen: Seen): void {
  for (const t of tokens(strings(raw).join("\n"))) run.sentTokens.add(t);
  for (const t of tokens(strings(seen.body).join("\n")))
    if (!run.sentTokens.has(t) && !run.sentTokens.has(t.replace(/[.]+$/, ""))) run.standIns.add(t);
}

// One request's prompt as forwarded, kept when asked for (trial.ts --dump-at).
// `real`: with its stand-ins swapped back, as LoopReport.real has it.
export const sentPrompts: { keep?: number; text?: string; real?: boolean } = {};

// The proxy as the real one starts: the engine loaded from the state
// directory, then a self-test through the handler before any request.
let booted: Promise<unknown> | undefined;

function proxy(): (request: Request) => Promise<Response> {
  if (!shared) {
    process.stderr.write = ((chunk: unknown) =>
      journal.push(String(chunk)) > 0) as typeof process.stderr.write;
    initEngine();
    shared = createHandler(DEFAULT_ROUTES, upstream);
    booted = shared(new Request("http://127.0.0.1/selftest"));
  }
  return shared;
}

// A subagent shares a parent's session and machine (`session`, `world`) and
// differs in model and system prompt, so it is a thread of its own.
export function makeRun(
  format: Format,
  seed: number,
  options: { session?: string; world?: number; subagent?: boolean } = {},
): Run {
  const random = new Random(seed);
  const faults = faultsFor(random);
  const world = makeWorld(options.world ?? seed);
  const session = options.session ?? `${format[0]}${seed}`;
  const agent = new Agent(format, world, random, faults, session, options.subagent);
  return start(new Live(agent, random, seed), seed, random, faults);
}

function start(source: Source, seed: number, random: Random, faults?: Faults): Run {
  const run: Run = {
    report: {
      seed,
      format: source.format,
      ...(faults ? { faults } : {}),
      requests: 0,
      findings: [],
      gaps: {},
      exposed: { held: 0, free: 0 },
      ms: [],
      breaks: { step: 0, typed: 0, cut: 0, unexplained: 0 },
      sent: [],
      real: [],
    },
    source,
    random,
    cache: new Cache(source.format),
    handler: proxy(),
    forwarded: [],
    sentTokens: new Set(),
    standIns: new Set(),
    exposedCores: new Set(),
    journal: [],
    failNext: false,
  };
  runs.set(source.session, run);
  return run;
}

// The fake provider: records what the proxy forwarded and answers with the
// model's turn, or with an error when a fault calls for one.
const upstream = (async (url: string, init: RequestInit) => {
  const headers = new Headers(init.headers);
  const id = SESSION_HEADERS.map((name) => headers.get(name)).find(Boolean);
  const text = String(init.body ?? "");
  const body = JSON.parse(text) as Fields;
  const run = routes.get(routeKey(String(id), modelOf(String(url), body))) ?? runs.get(String(id));
  if (!run) return Response.json({ error: `no session ${String(id)}` }, { status: 400 });
  run.forwarded.push({ url: String(url), headers, text, body });
  if (run.failNext) {
    run.failNext = false;
    return Response.json({ type: "error", error: { type: "overloaded_error" } }, { status: 529 });
  }
  const usage = run.cache.send(body);
  const turn = run.source.answer(() =>
    respond(body, new Random(run.report.seed * 7919 + run.report.requests), () =>
      run.source.nextId(),
    ),
  );
  return streamed(run.source.format, turn, usage, run.random);
}) as unknown as typeof fetch;

// The index of the last turn shaping counts as typed: what strip-thinking and
// the reasoning drop key on (lastTyped and lastAsked in shape.ts).
function typedAt(format: Format, body: Fields): number {
  const list = listOf(format, body) as Fields[];
  return list.findLastIndex((entry) => {
    if (format === "responses")
      return (entry.type ?? "message") === "message" && entry.role === "user";
    if (entry.role !== "user") return false;
    if (format === "gemini")
      return ((entry.parts ?? []) as Fields[]).some((part) => !part.functionResponse);
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
  return [body.model, body.tools, systemOf(format, body), ...listOf(format, body)][index];
}

function prefix(run: Run, raw: Fields, seen: Seen, lines: string[]): void {
  const { format } = run.source;
  const before = run.previous;
  run.previous = { raw, seen };
  if (!before) return;
  const { breaks } = run.report;
  // The harness changed what it sent (a clear, a compaction, its tools): the
  // provider's cached prefix is gone on purpose, whatever the proxy did.
  if (firstChange(parts(format, before.raw), parts(format, raw)) >= 0) {
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
  await booted;
  routes.set(routeKey(run.source.session, modelOf(path, raw)), run);
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
  const mine = ` session=${run.source.session} `;
  const model = typeof raw.model === "string" ? ` model=${raw.model.replace(/\s/g, "_")}` : "";
  const lines = journal
    .slice(from)
    .filter((line) => line.includes(mine) && (!model || line.includes(`${model} `)));
  return { status: response.status, text, lines, ms };
}

// One request of the session, its retries, and every check on it.
export async function step(run: Run): Promise<void> {
  const next = run.source.next();
  const budget = currentScanBudgetMs();
  if (next.starve) setScanBudgetMs(next.starve);
  try {
    await sendAll(run, next);
  } finally {
    if (next.starve) setScanBudgetMs(budget);
  }
}

async function sendAll(run: Run, { path, headers, body: raw, fail, retry }: Sent): Promise<void> {
  const { source, report } = run;
  const before = run.forwarded.length;
  if (fail) {
    run.failNext = true;
    const failed = await send(run, path, headers, raw);
    if (failed.status !== 529) find(run, "status", `an upstream 529 came back as ${failed.status}`);
  }
  if (retry) await send(run, path, headers, raw);
  const sent = await send(run, path, headers, raw);
  report.ms.push(sent.ms);
  if (sent.ms > SLOW_MS) find(run, "slow", `${Math.round(sent.ms)} ms`);
  const copies = run.forwarded.slice(before);
  if (sent.status !== 200 || copies.length === 0) {
    find(run, "status", `${sent.status}: ${sent.text.slice(0, 160)}`);
    source.take({ thinking: "", text: "", calls: [] });
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
  const text = prompt(seen);
  const real = swapText(text, new Set()).text;
  report.sent.push(createHash("sha1").update(text).digest("base64"));
  report.real.push(createHash("sha1").update(real).digest("base64"));
  if (!run.quiet && sentPrompts.keep === report.requests)
    sentPrompts.text = sentPrompts.real ? real : text;
  for (const v of valid(source.format, seen.body)) find(run, "valid", v.detail);
  prefix(run, raw, seen, sent.lines);
  learnStandIns(run, raw, seen);
  wide(run, raw, seen);
  exposure(run, raw);
  const read = readTurn(source.format, sent.text);
  for (const problem of read.problems) find(run, "stream", problem);
  // Not the thinking: it passes the proxy untouched by design, being signed
  // (streams.ts), so its stand-ins reach the harness as the model wrote them.
  const visible = [read.turn.text, ...read.turn.calls.map((c) => JSON.stringify(c.input))].join(
    "\n",
  );
  for (const token of tokens(visible))
    // Only a stand-in the proxy knows how to restore: a secret's replacement is
    // one-way by design.
    if (run.standIns.has(token) && swapText(token, new Set()).text !== token)
      find(run, "stand-in", `the harness got ${token}`);
  source.take(read.turn);
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
  return (await recordSession(format, seed, requests)).report;
}

// A live session and the tape of what its harness sent, to replay or shrink.
export async function recordSession(
  format: Format,
  seed: number,
  requests: number,
): Promise<{ report: LoopReport; tape: Tape }> {
  const run = makeRun(format, seed);
  for (let i = 0; i < requests; i++) {
    await step(run);
    run.report.requests++;
  }
  const live = run.source as Live;
  const tape = {
    format,
    session: live.session,
    seed,
    canaries: live.canaries,
    requests: live.tape,
  };
  return { report: run.report, tape };
}

// A real body (capture.ts) driven through the proxy, canaries planted in it.
export async function recordCorpus(
  file: string,
  seed: number,
): Promise<{ report: LoopReport; tape: Tape }> {
  const { format, session, body, canaries, random } = plantedBody(file, seed);
  const source = new Corpus(format, body, session, canaries, random);
  const run = start(source, seed, random);
  while (source.left > 0) {
    await step(run);
    run.report.requests++;
  }
  return { report: run.report, tape: { format, session, seed, canaries, requests: source.tape } };
}

// A tape sent through the proxy, every check on every request. The fake
// model still answers each, so what comes back to the harness is checked too;
// the next request is the tape's, not one built from the answer.
// `from` and `upto` replay part of it: the part before a restart, or after.
// Request numbers in findings stay the tape's.
export async function replayTape(
  tape: Tape,
  from = 0,
  upto = tape.requests.length,
  beside?: Subagent,
): Promise<LoopReport> {
  const source = new Replay(tape, from, upto);
  const run = start(source, tape.seed, new Random(tape.seed));
  run.report.requests = from;
  const child = beside
    ? makeRun(tape.format, beside.seed, {
        session: source.session,
        world: tape.seed,
        subagent: true,
      })
    : undefined;
  if (child) child.quiet = true;
  while (source.left > 0) {
    const at = run.report.requests;
    const alongside = child && at >= beside!.at && at < beside!.at + beside!.count;
    await Promise.all([
      step(run).then(() => run.report.requests++),
      alongside ? step(child).then(() => child.report.requests++) : undefined,
    ]);
  }
  if (child)
    run.report.subagent = { requests: child.report.requests, sent: child.forwarded.length };
  if (child)
    for (const f of child.report.findings)
      run.report.findings.push({ ...f, check: `subagent ${f.check}` });
  return run.report;
}

// A subagent stepping beside a replayed session: its seed, the parent's
// request it starts at, and how many requests it sends.
export interface Subagent {
  seed: number;
  at: number;
  count: number;
}
