// Restarts the proxy in the middle of sessions and checks that nothing it
// forwards after the restart differs from what it forwards with none: every
// byte the proxy decides is kept across a restart for that reason (losing
// state "rewrote every conversation to the cache", CACHING.md).
//
//   bun proxy/sim/restart.ts                         20 seeds per format
//   bun proxy/sim/restart.ts --seeds 50 --requests 120 --from 2000
//   bun proxy/sim/restart.ts --seed 7 --format chat  one, in full
//
// Each session is recorded live, then replayed three ways in fresh processes:
// straight through twice (the two must agree, or the proxy is not
// deterministic and nothing else can be compared), and stopped and started
// again at a few points, on one state directory. A restart is a clean stop
// (state saved, as server.ts drain does) unless --crash, which stops without
// that save, as a killed proxy does: what decides bytes was saved as it
// changed (saveDecisive), and the scan cache, on a timer, is lost.
// Exits 1 on any difference, naming the seed, the request and where it parts.

import "./env.ts";
import { join } from "node:path";
import type { Format } from "../src/redact.ts";
import { recordSession } from "./loop.ts";
import { Random } from "./random.ts";
import { saveTape } from "./tape.ts";
import { option, parting, pool, Trials } from "./trials.ts";

const FORMATS: Format[] = ["anthropic", "responses", "chat", "gemini"];
const trials = new Trials("restart");
const scratch = trials.scratch;
const trial = trials.run.bind(trials);
const newDir = trials.dir.bind(trials);
const dump = trials.dump.bind(trials);

interface Result {
  name: string;
  problems: string[];
}

// One session: its tape, two straight runs and a restart at each point.
async function check(format: Format, seed: number, requests: number): Promise<Result> {
  const name = `--seed ${seed} --format ${format}`;
  const { tape } = await recordSession(format, seed, requests);
  const file = join(scratch, `${format}-${seed}.json`);
  saveTape(tape, file);
  const n = tape.requests.length;
  const [one, two] = await Promise.all([trial(file, newDir()), trial(file, newDir())]);
  const problems: string[] = [];
  const first = one.sent.findIndex((digest, i) => digest !== two.sent[i]);
  if (first >= 0) {
    const [a, b] = await Promise.all([
      dump(file, newDir(), first, []),
      dump(file, newDir(), first, []),
    ]);
    problems.push(`not deterministic: request ${first} ${parting(a, b)}`);
    return { name, problems };
  }
  const random = new Random(seed * 31 + 7);
  const crash = process.argv.includes("--crash");
  const points = [...new Set(Array.from({ length: 3 }, () => random.int(1, n - 1)))];
  for (const k of points) {
    const dir = newDir();
    const stop = crash ? ["--crash"] : [];
    await trial(file, dir, "--upto", String(k), ...stop);
    const after = await trial(file, dir, "--from", String(k));
    const at = after.sent.findIndex((digest, i) => digest !== one.sent[k + i]);
    if (at < 0) continue;
    const before = await dump(file, newDir(), k + at, []);
    const copy = newDir();
    await trial(file, copy, "--upto", String(k), ...stop);
    const restarted = await dump(file, copy, k + at, ["--from", String(k)]);
    problems.push(
      `${crash ? "crash" : "restart"} before request ${k}: ` +
        `request ${k + at} forwarded differently ` +
        parting(before, restarted),
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
  const from = Number(option("from") ?? 3000);
  for (const format of FORMATS)
    for (let seed = from; seed < from + seeds; seed++)
      jobs.push(() => check(format, seed, requests));
}

// Recording runs in this process, one session at a time (the proxy here is
// shared); the trials it starts run beside it.
const results = await pool(jobs);
let failing = 0;
for (const r of results) {
  if (r.problems.length === 0) continue;
  failing++;
  console.log(r.name);
  for (const p of r.problems) console.log(`    ${p.slice(0, 600)}`);
}
console.log(`${results.length} sessions, ${failing} changed by a restart`);
process.exit(failing > 0 ? 1 : 0);
