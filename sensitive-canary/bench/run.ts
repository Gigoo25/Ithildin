// Explicit Node runner; never discovered as a Bun test. No network calls.
import { FIXTURES } from "./corpus.ts";
import { REVIEW_FIXTURES, EXPECTED_RANGES } from "./review-corpus.ts";
import { runFixture, summarize } from "./harness.ts";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const review=REVIEW_FIXTURES.map(f=>({...f,expectedRanges:EXPECTED_RANGES[f.id]}));
const coldIndex=process.argv.indexOf("--cold-fixture");
if(coldIndex>=0) {
  const f=review.find(f=>f.id===process.argv[coldIndex+1]);
  if(!f) throw new Error("unknown synthetic fixture id");
  const start=performance.now();runFixture(f);
  process.stdout.write(JSON.stringify({ms:performance.now()-start}));
} else {
  const legacy=FIXTURES.map(runFixture), results=review.map(runFixture);
  const summary=summarize(results);
  const fingerprint:Record<string,string>={};
  for(const name of ["corpus.ts","review-corpus.ts","harness.ts","run.ts","../index.ts","../lib/rules.ts","../lib/redaction-spans.ts","../lib/structured-text.ts","../lib/cookies.ts"]) fingerprint[name]=createHash("sha256").update(readFileSync(new URL(name,import.meta.url))).digest("hex");
  const timing:Record<string,unknown>={enabled:false};
  if(process.argv.includes("--timing")) {
    const distribution=(samples:number[])=>{
      const sorted=[...samples].sort((a,b)=>a-b);
      return {samples:sorted.length,minMs:sorted[0],p50Ms:sorted[Math.floor((sorted.length-1)*0.5)],p95Ms:sorted[Math.floor((sorted.length-1)*0.95)],maxMs:sorted.at(-1)};
    };
    timing.enabled=true;
    timing.definition="Cold: first fixture scan in fresh Node, imports excluded. Warm: five scans per fixture in this Node, independent sessions/caches reset; JIT may be warm.";
    timing.fixtures=[];
    for(const f of review) {
      const cold=spawnSync(process.execPath,[new URL(import.meta.url).pathname,"--cold-fixture",f.id],{env:process.env,encoding:"utf8",timeout:10000});
      if(cold.status!==0) throw new Error("cold synthetic benchmark failed");
      const warm:number[]=[];
      for(let n=0;n<5;n++) {const start=performance.now();runFixture(f);warm.push(performance.now()-start);}
      (timing.fixtures as unknown[]).push({id:f.id,cold:distribution([JSON.parse(cold.stdout).ms]),warm:distribution(warm)});
    }
  }
  const safe=(r:ReturnType<typeof runFixture>)=>({id:r.id,support:r.support,misses:r.misses.length,exposedChars:r.exposedChars,falseRedactions:r.falsePreserveViolations.length,omissions:r.trips,omittedChars:r.omittedChars,syntaxFailures:r.syntaxFailures,measurementUnavailable:r.measurementUnavailable});
  process.stdout.write(JSON.stringify({version:2,runtime:process.version,fingerprint,
    historicalBaseline:"baseline.json was captured after implementation and fixture changes; INVALID for before/after claims. Preserved unchanged.",
    metricDefinition:"Misses are uncovered authored sensitive occurrences in direct detections; exposure counts surviving source characters after edits. Omissions are separate, never useful detections. Cookie coordinates are mapped back to source.",
    legacy:{summary:summarize(legacy),fixtures:legacy.map(safe)},review:{summary,fixtures:results.map(safe)},timing},null,2)+"\n");
  if(process.argv.includes("--check") && (summary.misses || summary.exposedChars || summary.falseRedactions || summary.omissions || summary.syntaxFailures || summary.measurementUnavailable)) process.exitCode=1;
}
