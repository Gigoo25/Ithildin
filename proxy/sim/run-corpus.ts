// Replays every captured real body (capture.ts) through a fresh proxy, with
// canaries planted in it, every check on every request:
//
//   bun proxy/sim/run-corpus.ts                 each body, seeds 1 to 3
//   bun proxy/sim/run-corpus.ts --seeds 10
//
// A failure names the body and seed; shrink.ts --corpus <body> --seed <n>
// cuts it to a repro, which it writes beside the body, outside the repo.
// Exits 1 when any check fails.

import { readdirSync } from "node:fs";
import { availableParallelism } from "node:os";
import { join } from "node:path";
import { CORPUS_DIR } from "./capture.ts";
import type { Finding } from "./loop.ts";

const at = process.argv.indexOf("--seeds");
const seeds = at < 0 ? 3 : Number(process.argv[at + 1]);
const HERE = import.meta.dir;

let bodies: string[] = [];
try {
  bodies = readdirSync(CORPUS_DIR).filter((name) => name.endsWith(".json"));
} catch {
  // No corpus yet.
}
if (bodies.length === 0) {
  console.log(`no bodies in ${CORPUS_DIR}: run bun proxy/sim/capture.ts first`);
  process.exit(0);
}

interface Result {
  body: string;
  seed: number;
  requests: number;
  findings: Finding[];
}

async function one(body: string, seed: number): Promise<Result> {
  const file = join(CORPUS_DIR, body);
  const args = ["--corpus", file, "--seed", String(seed)];
  const child = Bun.spawn(["bun", join(HERE, "trial.ts"), ...args], {
    stdout: "pipe",
    stderr: "ignore",
  });
  const out = await new Response(child.stdout).text();
  await child.exited;
  const last = out.trim().split("\n").at(-1);
  if (!last)
    return {
      body,
      seed,
      requests: 0,
      findings: [{ check: "crash", request: -1, detail: "no output" }],
    };
  const parsed = JSON.parse(last) as { requests: number; findings: Finding[] };
  return { body, seed, ...parsed };
}

const jobs = bodies.flatMap((body) =>
  Array.from({ length: seeds }, (_, i) => () => one(body, i + 1)),
);
const results: Result[] = [];
const width = Math.max(1, Math.floor(availableParallelism() / 2));
await Promise.all(
  Array.from({ length: width }, async () => {
    for (let job = jobs.shift(); job; job = jobs.shift()) results.push(await job());
  }),
);

let failing = 0;
for (const r of results.sort((a, b) => a.body.localeCompare(b.body) || a.seed - b.seed)) {
  const checks = [...new Set(r.findings.map((f) => f.check))];
  console.log(
    `${r.body} seed ${r.seed}: ${r.requests} requests, ` +
      (checks.length > 0 ? checks.join(", ") : "clean"),
  );
  for (const f of r.findings.slice(0, 3))
    console.log(`    request ${f.request} ${f.check}: ${f.detail.slice(0, 140)}`);
  if (r.findings.length > 0) failing++;
}
console.log(`${results.length} replays of ${bodies.length} bodies, ${failing} failing`);
process.exit(failing > 0 ? 1 : 0);
