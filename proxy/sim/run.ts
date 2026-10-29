// Runs the shaping simulator: over seeds, or over real request bodies.
//
//   bun proxy/sim/run.ts                      200 seeds per format
//   bun proxy/sim/run.ts --seeds 2000 --rounds 300
//   bun proxy/sim/run.ts --seed 1234 --format anthropic   one seed, in full
//   bun proxy/sim/run.ts --replay a.json b.json           real bodies
//   bun proxy/sim/run.ts --route opencode-go --replay a.json   priced on a route
//
// A replayed body is a whole session as its last request carried it, such as
// a cache-miss dump (missed.json) or a captured one (capture.ts), which names
// its route. It is read locally and never sent anywhere. Shaping and the cost
// are priced on --route, else the captured route, else at fixed prices.
// Exits 1 when any check fails, naming the seed that reproduces it.

import { readFileSync } from "node:fs";
import type { Format } from "../src/redact.ts";
import { simulate, type Report } from "./sim.ts";
import { formatOf } from "./tape.ts";
import { generated } from "./workload.ts";

type Fields = Record<string, unknown>;

const FORMATS: Format[] = ["anthropic", "responses", "chat", "gemini"];

function option(name: string, fallback: number): number {
  const at = process.argv.indexOf(`--${name}`);
  return at < 0 ? fallback : Number(process.argv[at + 1]);
}

interface Totals {
  runs: number;
  report: Report;
  failing: Array<{ name: string; report: Report }>;
}

function empty(): Totals {
  return {
    runs: 0,
    report: {
      requests: 0,
      steps: 0,
      breaks: { step: 0, typed: 0, note: 0, unexplained: 0 },
      cost: { on: 0, off: 0 },
      largest: { on: 0, off: 0 },
      rewritten: 0,
      violations: [],
    },
    failing: [],
  };
}

function add(totals: Totals, name: string, report: Report): void {
  const t = totals.report;
  totals.runs++;
  t.requests += report.requests;
  t.steps += report.steps;
  t.breaks.step += report.breaks.step;
  t.breaks.typed += report.breaks.typed;
  t.breaks.note += report.breaks.note;
  t.breaks.unexplained += report.breaks.unexplained;
  t.cost.on += report.cost.on;
  t.cost.off += report.cost.off;
  t.largest.on = Math.max(t.largest.on, report.largest.on);
  t.largest.off = Math.max(t.largest.off, report.largest.off);
  t.rewritten += report.rewritten;
  if (report.violations.length > 0) totals.failing.push({ name, report });
}

function print(label: string, totals: Totals): void {
  const { report: r, runs, failing } = totals;
  const ratio = r.cost.off === 0 ? 1 : r.cost.on / r.cost.off;
  console.log(
    `${label}: ${runs} sessions, ${r.requests} requests, ${r.steps} steps; ` +
      `breaks ${r.breaks.step} step / ${r.breaks.typed} typed / ${r.breaks.note} note / ` +
      `${r.breaks.unexplained} unexplained; ` +
      `cost ${Math.round(r.cost.on)} shaped vs ${Math.round(r.cost.off)} raw ` +
      `(${(ratio * 100).toFixed(1)}%); ` +
      `largest prompt ${r.largest.on} shaped vs ${r.largest.off} raw; ` +
      `rewrote ${r.rewritten} tokens; ${failing.length} failing`,
  );
  for (const { name, report } of failing.slice(0, 5)) {
    console.log(`  ${name}`);
    for (const v of report.violations.slice(0, 3))
      console.log(`    request ${v.request}: ${v.check}: ${v.detail}`);
  }
}

function replay(files: string[]): boolean {
  const at = process.argv.indexOf("--route");
  const route = at < 0 ? undefined : process.argv[at + 1];
  let ok = true;
  for (const file of files) {
    const read = JSON.parse(readFileSync(file, "utf8")) as Fields;
    const captured = read["ithildin-corpus"] !== undefined;
    const body = (captured ? read.body : read) as Fields;
    const on = route ?? (captured ? (read.route as string) : undefined);
    const name = on ? `${file} on ${on}` : file;
    const totals = empty();
    add(totals, name, simulate(formatOf(body), body, true, on));
    print(name, totals);
    ok &&= totals.failing.length === 0;
  }
  return ok;
}

function seeds(): boolean {
  const one = process.argv.indexOf("--seed");
  const from = one < 0 ? option("from", 1) : Number(process.argv[one + 1]);
  const count = one < 0 ? option("seeds", 200) : 1;
  const rounds = option("rounds", 150);
  const only = process.argv.indexOf("--format");
  const formats = only < 0 ? FORMATS : [process.argv[only + 1] as Format];
  let ok = true;
  for (const format of formats) {
    const totals = empty();
    for (let seed = from; seed < from + count; seed++)
      add(
        totals,
        `--seed ${seed} --format ${format} --rounds ${rounds}`,
        simulate(format, generated(format, seed, rounds), !process.argv.includes("--no-strip")),
      );
    print(format, totals);
    ok &&= totals.failing.length === 0;
  }
  return ok;
}

if (import.meta.main) {
  const at = process.argv.indexOf("--replay");
  const ok = at >= 0 ? replay(process.argv.slice(at + 1)) : seeds();
  process.exit(ok ? 0 : 1);
}
