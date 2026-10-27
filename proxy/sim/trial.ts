// One tape replayed through a fresh proxy, in a process of its own:
//
//   bun proxy/sim/trial.ts tape.json
//   bun proxy/sim/trial.ts tape.json --upto 40       the part before a restart
//   bun proxy/sim/trial.ts tape.json --from 40       and after it
//   bun proxy/sim/trial.ts --corpus body.json --seed 3     a real body
//
// Prints the findings as one line of JSON. A process each, because the proxy
// and the engine keep what they learn (stand-ins, learned values, counters) in
// module state; a replay that shared a process with the last one would not be
// the same run. The shrinker runs many of these at once.
//
// A restart is two of these on one state directory (ITHILDIN_SIM_DIR): the
// first saves what the real proxy saves when it stops, the second loads it as
// the real one does when it starts. `--dump-at <n> <file>` writes request n's
// prompt as forwarded, to see where two runs part.

import "./env.ts";
import { writeFileSync } from "node:fs";
import { saveScanCache } from "../src/redact.ts";
import { recordCorpus, replayTape, sentPrompts } from "./loop.ts";
import { loadTape } from "./tape.ts";

const args = process.argv.slice(2);
const option = (name: string) => {
  const at = args.indexOf(`--${name}`);
  return at < 0 ? undefined : args[at + 1];
};
const corpus = option("corpus");
const file = corpus ?? args[0];
if (!file) {
  process.stderr.write(
    "usage: bun proxy/sim/trial.ts <tape.json> [--from n] [--upto n] | --corpus <body.json>\n",
  );
  process.exit(2);
}
const dumpAt = option("dump-at");
if (dumpAt !== undefined) sentPrompts.keep = Number(dumpAt);
if (args.includes("--real")) sentPrompts.real = true;
let report;
if (corpus) report = (await recordCorpus(file, Number(option("seed") ?? 1))).report;
else {
  const tape = loadTape(file);
  const from = Number(option("from") ?? 0);
  // `--subagent seed:at:count`: a live subagent beside the replay.
  const sub = option("subagent")?.split(":").map(Number);
  const beside = sub ? { seed: sub[0]!, at: sub[1]!, count: sub[2]! } : undefined;
  report = await replayTape(tape, from, Number(option("upto") ?? tape.requests.length), beside);
}
// As the real proxy does when it stops (server.ts drain).
saveScanCache();
if (dumpAt !== undefined)
  writeFileSync(args[args.indexOf("--dump-at") + 2]!, sentPrompts.text ?? "");
process.stdout.write(
  `${JSON.stringify({
    requests: report.requests,
    findings: report.findings,
    breaks: report.breaks,
    sent: report.sent,
    real: report.real,
    ...(report.subagent ? { subagent: report.subagent } : {}),
  })}\n`,
);
process.exit(0);
