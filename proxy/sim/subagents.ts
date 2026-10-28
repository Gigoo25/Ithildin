// Runs a subagent beside sessions and checks that nothing the proxy forwards
// for the parent changes: a subagent shares the parent's session id (Claude
// Code sends one per process), so anything the proxy keeps per session
// (shaping, replay, the break watch, stand-ins) could carry one thread's state
// into the other's bytes, and rewrite the parent's cached prefix.
//
//   bun proxy/sim/subagents.ts                        20 seeds per format
//   bun proxy/sim/subagents.ts --seeds 50 --requests 120 --from 4000
//   bun proxy/sim/subagents.ts --seed 7 --format chat   one, in full
//
// Each session is recorded live, then replayed in fresh processes: straight
// through twice (the two must agree), and with a live subagent sending its own
// requests beside some of the parent's, concurrently, through the same proxy.
// The parent's prompts are compared with their stand-ins swapped back: a
// subagent that is first to a value takes the next stand-in, so the parent's
// may differ, and that is fine while each run keeps its own stable (the
// prefix check in each run says so). Everything else must be the same.
// The subagent runs every check a session does (leaks, prefix, stand-ins) on
// its own requests too. Exits 1 on a difference or a finding.

import "./env.ts";
import { join } from "node:path";
import type { Format } from "../src/redact.ts";
import { recordSession } from "./loop.ts";
import { Random } from "./random.ts";
import { saveTape } from "./tape.ts";
import { option, parting, pool, Trials } from "./trials.ts";

const FORMATS: Format[] = ["anthropic", "responses", "chat", "gemini"];
const trials = new Trials("subagents");

interface Result {
  name: string;
  problems: string[];
}

async function check(format: Format, seed: number, requests: number): Promise<Result> {
  const name = `--seed ${seed} --format ${format}`;
  const { tape } = await recordSession(format, seed, requests);
  const file = join(trials.scratch, `${format}-${seed}.json`);
  saveTape(tape, file);
  const n = tape.requests.length;
  const [one, two] = await Promise.all([
    trials.run(file, trials.dir()),
    trials.run(file, trials.dir()),
  ]);
  if (one.real.some((digest, i) => digest !== two.real[i]))
    return { name, problems: ["not deterministic without a subagent"] };
  const random = new Random(seed * 17 + 3);
  const problems: string[] = [];
  // A short subagent, a long one, and one still running when the parent ends.
  for (const count of [5, 30, n]) {
    const at = random.int(1, Math.max(1, n - 5));
    const spec = `${seed + 50_000}:${at}:${count}`;
    const beside = await trials.run(file, trials.dir(), "--subagent", spec);
    // The subagent's own findings come back as "subagent <check>".
    for (const f of beside.findings) {
      const whose = f.check.startsWith("subagent") ? "" : "parent ";
      problems.push(`beside ${spec}: ${whose}request ${f.request} ${f.check}: ${f.detail}`);
    }
    const parted = beside.real.findIndex((digest, i) => digest !== one.real[i]);
    if (parted < 0) continue;
    const [alone, shared] = await Promise.all([
      trials.dump(file, trials.dir(), parted, ["--real"]),
      trials.dump(file, trials.dir(), parted, ["--real", "--subagent", spec]),
    ]);
    problems.push(
      `subagent ${spec}: parent request ${parted} forwarded differently ${parting(alone, shared)}`,
    );
  }
  return { name, problems };
}

const requests = Number(option("requests") ?? 80);
const one = option("seed");
const jobs: Array<() => Promise<Result>> = [];
if (one !== undefined) {
  const format = (option("format") ?? "anthropic") as Format;
  jobs.push(() => check(format, Number(one), requests));
} else {
  const seeds = Number(option("seeds") ?? 20);
  const from = Number(option("from") ?? 4000);
  for (const format of FORMATS)
    for (let seed = from; seed < from + seeds; seed++)
      jobs.push(() => check(format, seed, requests));
}

const results = await pool(jobs);
let failing = 0;
for (const r of results) {
  if (r.problems.length === 0) continue;
  failing++;
  console.log(r.name);
  for (const p of r.problems.slice(0, 6)) console.log(`    ${p.slice(0, 600)}`);
}
console.log(`${results.length} sessions, ${failing} with a problem beside a subagent`);
process.exit(failing > 0 ? 1 : 0);
