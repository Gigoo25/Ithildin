// Many live sessions through the whole proxy, each in a process of its own,
// and every finding of every check, grouped:
//
//   bun proxy/sim/hammer.ts                                20 seeds per format
//   bun proxy/sim/hammer.ts --seeds 50 --requests 150 --from 5000
//   ITHILDIN_SIM_STARVE=1 bun proxy/sim/hammer.ts           scans starved at times
//
// A process each, as a starved scan sets the engine's budget for the whole
// process, and the proxy keeps what it learns in module state. A failing
// session goes to the shrinker the same way: --seed n --format f, with the
// same environment.

import "./env.ts";
import { join } from "node:path";
import type { Format } from "../src/redact.ts";
import { recordSession } from "./loop.ts";
import { option, pool } from "./trials.ts";

const FORMATS: Format[] = ["anthropic", "responses", "chat"];

interface Outcome {
  format: Format;
  seed: number;
  findings: Array<{ check: string; request: number; detail: string }>;
  ms: number[];
}

// In a child: one session, its outcome as a line of JSON.
const only = process.argv.indexOf("--one");
if (only >= 0) {
  const [format, seed, requests] = process.argv.slice(only + 1);
  const { report } = await recordSession(format as Format, Number(seed), Number(requests));
  const outcome = { format, seed: Number(seed), findings: report.findings, ms: report.ms };
  process.stdout.write(`${JSON.stringify(outcome)}\n`);
  process.exit(0);
}

async function one(format: Format, seed: number, requests: number): Promise<Outcome> {
  const child = Bun.spawn(
    ["bun", join(import.meta.dir, "hammer.ts"), "--one", format, String(seed), String(requests)],
    { stdout: "pipe", stderr: "ignore" },
  );
  const out = await new Response(child.stdout).text();
  const code = await child.exited;
  const last = out.trim().split("\n").at(-1);
  if (!last) {
    const crash = { check: "crash", request: -1, detail: `exit ${code}, no outcome` };
    return { format, seed, findings: [crash], ms: [] };
  }
  return JSON.parse(last) as Outcome;
}

const requests = Number(option("requests") ?? 100);
const seeds = Number(option("seeds") ?? 20);
const from = Number(option("from") ?? 5000);
const formats = option("format") ? [option("format") as Format] : FORMATS;
const jobs = formats.flatMap((format) =>
  Array.from({ length: seeds }, (_, i) => () => one(format, from + i, requests)),
);
const outcomes = await pool(jobs, 2);

const byCheck = new Map<string, Array<{ name: string; detail: string }>>();
for (const o of outcomes)
  for (const f of o.findings) {
    const list = byCheck.get(f.check) ?? [];
    list.push({
      name: `--seed ${o.seed} --format ${o.format}`,
      detail: `${f.request}: ${f.detail}`,
    });
    byCheck.set(f.check, list);
  }
for (const [check, list] of [...byCheck].sort((a, b) => b[1].length - a[1].length)) {
  const sessions = new Set(list.map((each) => each.name));
  console.log(`${check}: ${list.length} findings in ${sessions.size} sessions`);
  for (const name of [...sessions].slice(0, 4)) {
    const first = list.find((each) => each.name === name)!;
    console.log(`    ${name}  request ${first.detail.slice(0, 300)}`);
  }
}
const ms = outcomes.flatMap((o) => o.ms).sort((a, b) => a - b);
const at = (q: number) => Math.round(ms[Math.floor(q * (ms.length - 1))] ?? 0);
const failing = outcomes.filter((o) => o.findings.length > 0).length;
console.log(
  `${outcomes.length} sessions, ${ms.length} requests, ` +
    `scan p50 ${at(0.5)} ms p99 ${at(0.99)} ms; ${failing} with findings`,
);
process.exit(failing > 0 ? 1 : 0);
