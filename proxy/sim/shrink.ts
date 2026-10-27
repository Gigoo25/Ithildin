// Shrinks a failing session to the least that still fails: fewest requests,
// fewest messages, shortest texts. Every candidate is replayed through a fresh
// proxy (trial.ts) and kept only if the same check still fails on it.
//
//   bun proxy/sim/shrink.ts --seed 245 --format chat              a live seed
//   bun proxy/sim/shrink.ts --seed 245 --format chat --check prefix
//   bun proxy/sim/shrink.ts --corpus ~/.cache/ithildin-sim/corpus/x.json
//   bun proxy/sim/shrink.ts --tape some-tape.json --check leak
//
// What comes out is a tape (tape.ts) small enough to read, which
// repros.test.ts replays as a test: a seed's goes in proxy/sim/repros/, a real
// body's beside the body, outside the repo.
//
// Delta debugging (Zeller's ddmin) over each kind of piece in turn, the
// candidates of a round tried at once, the first that fails kept: the same
// tape and target shrink to the same result.

import "./env.ts";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import type { Format } from "../src/redact.ts";
import { valid } from "./checks.ts";
import { recordCorpus, recordSession, type Finding } from "./loop.ts";
import { preview } from "./canaries.ts";
import { loadTape, matches, saveTape, type Sent, type Tape, type Target } from "./tape.ts";
import { ddmin } from "./ddmin.ts";
import { listOf } from "./workload.ts";
import { createHash } from "node:crypto";

type Fields = Record<string, unknown>;

const HERE = dirname(new URL(import.meta.url).pathname);
const TRIALS_MAX = Number(process.env.SIM_SHRINK_TRIALS ?? 800);
const AT_ONCE = Math.max(2, Math.floor(availableParallelism() / 2));

// --- Trials -------------------------------------------------------------------

const scratch = mkdtempSync(join(tmpdir(), "ithildin-shrink-"));
process.on("exit", () => rmSync(scratch, { recursive: true, force: true }));
let trials = 0;
let running = 0;
const waiting: Array<() => void> = [];

async function slot<T>(work: () => Promise<T>): Promise<T> {
  if (running >= AT_ONCE) await new Promise<void>((go) => waiting.push(go));
  running++;
  try {
    return await work();
  } finally {
    running--;
    waiting.shift()?.();
  }
}

// The findings of one replay in a fresh process.
export async function trial(tape: Tape): Promise<Finding[]> {
  return slot(async () => {
    const file = join(scratch, `${++trials}.json`);
    saveTape(tape, file);
    const child = Bun.spawn(["bun", join(HERE, "trial.ts"), file], {
      stdout: "pipe",
      stderr: "ignore",
    });
    const out = await new Response(child.stdout).text();
    await child.exited;
    rmSync(file, { force: true });
    const last = out.trim().split("\n").at(-1);
    if (!last) return [{ check: "crash", request: -1, detail: "the replay printed nothing" }];
    return (JSON.parse(last) as { findings: Finding[] }).findings;
  });
}

// A leak's canary must stay as it was planted: cut to one line of a key, a
// candidate fails for a different reason (a bare token with nothing around
// it), and the shrinker slides onto that bug and away from the one it had.
function whole(tape: Tape, target: Target): boolean {
  const c = target.canary === undefined ? undefined : tape.canaries[target.canary];
  if (!c) return true;
  const text = JSON.stringify(tape.requests);
  const once = JSON.stringify(c.value).slice(1, -1);
  return text.includes(once) || text.includes(JSON.stringify(once).slice(1, -1));
}

async function fails(tape: Tape, target: Target): Promise<boolean> {
  if (trials >= TRIALS_MAX || !whole(tape, target)) return false;
  return (await trial(tape)).some((finding) => matches(tape, target, finding));
}

// --- What can be taken away ---------------------------------------------------

const withRequests = (tape: Tape, requests: Sent[]): Tape => ({ ...tape, requests });

function setList(format: Format, body: Fields, list: unknown[]): Fields {
  return { ...body, [format === "responses" ? "input" : "messages"]: list };
}

// A message as itself wherever it stands: its marker moves from request to
// request and is not part of what it is.
function identity(item: unknown): string {
  const text = JSON.stringify(item, (key, value) => (key === "cache_control" ? undefined : value));
  return createHash("sha1").update(text).digest("base64");
}

function messages(tape: Tape): string[] {
  const seen = new Set<string>();
  for (const sent of tape.requests)
    for (const item of listOf(tape.format, sent.body)) seen.add(identity(item));
  return [...seen];
}

// The tape with only the given messages, or undefined when that leaves a
// request no provider would take: such a candidate is not a smaller failure.
function keepMessages(tape: Tape, keep: Set<string>): Tape | undefined {
  const requests = tape.requests.map((sent) => ({
    ...sent,
    body: setList(
      tape.format,
      sent.body,
      listOf(tape.format, sent.body).filter((item) => keep.has(identity(item))),
    ),
  }));
  for (const { body } of requests)
    if (listOf(tape.format, body).length === 0 || valid(tape.format, body).length > 0)
      return undefined;
  return withRequests(tape, requests);
}

function replaceStrings(value: unknown, from: string, to: string): unknown {
  if (typeof value === "string") return value === from ? to : value;
  if (Array.isArray(value)) return value.map((item) => replaceStrings(item, from, to));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, inner]) => [key, replaceStrings(inner, from, to)]),
    );
  return value;
}

function strings(value: unknown, out: Map<string, number>): Map<string, number> {
  if (typeof value === "string") out.set(value, (out.get(value) ?? 0) + 1);
  else if (Array.isArray(value)) for (const item of value) strings(item, out);
  else if (value && typeof value === "object")
    for (const inner of Object.values(value)) strings(inner, out);
  return out;
}

// --- The passes ---------------------------------------------------------------

async function shrinkRequests(tape: Tape, target: Target): Promise<Tape> {
  const last = tape.requests.at(-1)!;
  const earlier = tape.requests.slice(0, -1);
  const kept = await ddmin(earlier, (keep) => fails(withRequests(tape, [...keep, last]), target));
  return withRequests(tape, [...kept, last]);
}

async function shrinkMessages(tape: Tape, target: Target): Promise<Tape> {
  const kept = await ddmin(messages(tape), async (keep) => {
    const candidate = keepMessages(tape, new Set(keep));
    return candidate !== undefined && fails(candidate, target);
  });
  return keepMessages(tape, new Set(kept)) ?? tape;
}

// Each long text cut to the lines (or, on one line, the words) that matter.
async function shrinkTexts(tape: Tape, target: Target): Promise<Tape> {
  const long = [...strings(tape.requests, new Map()).keys()]
    .filter((text) => text.length >= 64)
    .sort((a, b) => b.length - a.length)
    .slice(0, 40);
  for (const text of long) {
    const lines = text.includes("\n");
    const pieces = lines ? text.split("\n") : text.split(" ");
    if (pieces.length < 2) continue;
    const join = (keep: string[]) => keep.join(lines ? "\n" : " ");
    const swap = (keep: string[]) =>
      withRequests(tape, replaceStrings(tape.requests, text, join(keep)) as Sent[]);
    const kept = await ddmin(pieces, (keep) => fails(swap(keep), target));
    if (kept.length < pieces.length) tape = swap(kept);
  }
  return tape;
}

async function shrinkTools(tape: Tape, target: Target): Promise<Tape> {
  const bare = withRequests(
    tape,
    tape.requests.map((sent) => ({ ...sent, body: { ...sent.body, tools: [] } })),
  );
  return (await fails(bare, target)) ? bare : tape;
}

const size = (tape: Tape) =>
  `${tape.requests.length} requests, ${messages(tape).length} messages, ` +
  `${JSON.stringify(tape.requests).length} bytes, ${trials} trials`;

// Every pass again until none takes anything away, or the trials run out.
export async function shrink(tape: Tape, target: Target, say = (_: string) => {}): Promise<Tape> {
  say(`start: ${size(tape)}`);
  for (let round = 1; ; round++) {
    const before = JSON.stringify(tape.requests).length;
    for (const [name, pass] of [
      ["requests", shrinkRequests],
      ["messages", shrinkMessages],
      ["tools", shrinkTools],
      ["texts", shrinkTexts],
    ] as const) {
      tape = await pass(tape, target);
      say(`round ${round} ${name}: ${size(tape)}`);
    }
    if (JSON.stringify(tape.requests).length >= before || trials >= TRIALS_MAX) return tape;
  }
}

// --- Command line -------------------------------------------------------------

function option(name: string): string | undefined {
  const at = process.argv.indexOf(`--${name}`);
  return at < 0 ? undefined : process.argv[at + 1];
}

// The tape to shrink, where its repro goes, and the findings of its run.
async function source(): Promise<{ tape: Tape; out: string; findings: Finding[] }> {
  const seed = Number(option("seed") ?? 1);
  const corpus = option("corpus");
  const file = option("tape");
  if (corpus) {
    const { report, tape } = await recordCorpus(corpus, seed);
    const out = join(dirname(corpus), "repros", `${basename(corpus, ".json")}-${seed}.json`);
    return { tape, out, findings: report.findings };
  }
  if (file)
    return {
      tape: loadTape(file),
      out: file.replace(/\.json$/, "-shrunk.json"),
      findings: await trial(loadTape(file)),
    };
  const format = (option("format") ?? "anthropic") as Format;
  const { report, tape } = await recordSession(format, seed, Number(option("requests") ?? 200));
  return { tape, out: join(HERE, "repros", `${format}-${seed}.json`), findings: report.findings };
}

if (import.meta.main) {
  const { tape, out, findings } = await source();
  const check = option("check");
  const first = findings.find((finding) => !check || finding.check === check);
  if (!first) {
    console.log(`no ${check ?? ""} finding to shrink`.replace("  ", " "));
    process.exit(1);
  }
  const at =
    first.check === "leak" ? tape.canaries.findIndex((c) => first.detail.includes(preview(c))) : -1;
  const target: Target = { check: first.check, ...(at >= 0 ? { canary: at } : {}) };
  const cut = withRequests(tape, tape.requests.slice(0, first.request + 1));
  console.log(`shrinking: request ${first.request} ${first.check}: ${first.detail.slice(0, 120)}`);
  if (!(await fails(cut, target))) {
    console.log("it does not fail again when replayed alone in a fresh proxy: nothing to shrink");
    process.exit(1);
  }
  const small = await shrink(cut, target, (line) => console.log(`  ${line}`));
  mkdirSync(dirname(out), { recursive: true });
  saveTape({ ...small, target }, out);
  console.log(`wrote ${out}`);
  process.exit(0);
}
