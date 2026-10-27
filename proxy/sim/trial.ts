// One tape replayed through a fresh proxy, in a process of its own:
//
//   bun proxy/sim/trial.ts tape.json
//   bun proxy/sim/trial.ts --corpus body.json --seed 3     a real body
//
// Prints the findings as one line of JSON. A process each, because the proxy
// and the engine keep what they learn (stand-ins, learned values, counters) in
// module state; a replay that shared a process with the last one would not be
// the same run. The shrinker runs many of these at once.

import "./env.ts";
import { recordCorpus, replayTape } from "./loop.ts";
import { loadTape } from "./tape.ts";

const args = process.argv.slice(2);
const corpus = args.indexOf("--corpus");
const file = corpus >= 0 ? args[corpus + 1] : args[0];
if (!file) {
  process.stderr.write(
    "usage: bun proxy/sim/trial.ts <tape.json> | --corpus <body.json> --seed <n>\n",
  );
  process.exit(2);
}
const at = args.indexOf("--seed");
const seed = at < 0 ? 1 : Number(args[at + 1]);
const report =
  corpus >= 0 ? (await recordCorpus(file, seed)).report : await replayTape(loadTape(file));
process.stdout.write(
  `${JSON.stringify({
    requests: report.requests,
    findings: report.findings,
    breaks: report.breaks,
  })}\n`,
);
process.exit(0);
