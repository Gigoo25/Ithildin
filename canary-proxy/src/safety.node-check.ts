import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectDocument, assignmentEdits } from "../engine/lib/structured-text.ts";
import { planRedaction } from "../engine/lib/redaction-spans.ts";
import { withScanBudget } from "../engine/lib/rules.ts";
import { REVIEW_FIXTURES, EXPECTED_RANGES } from "../bench/review-corpus.ts";
import { runFixture, summarize } from "../bench/harness.ts";

test("production Node review acceptance",()=>{
  const report=summarize(REVIEW_FIXTURES.map(f=>runFixture({...f,expectedRanges:EXPECTED_RANGES[f.id]})));
  for(const key of ["misses","exposedChars","falseRedactions","omissions","syntaxFailures","measurementUnavailable"] as const) assert.equal(report[key],0,key);
});
test("document and renderer deadlines fail explicitly in Node",()=>{
  assert.equal(withScanBudget(()=>inspectDocument('{"password":"weak"}'),0).status,"incomplete");
  assert.throws(()=>withScanBudget(()=>assignmentEdits('password = "weak"'),0));
  const result=planRedaction({text:"abc",findings:[],trips:[],replacementFor:()=>"X",checkBudget:()=>{throw new Error("budget fixture");}});
  assert.ok(result.text.includes("omitted"));
});
test("raw large numeric values and quoted assignments have exact source spans",()=>{
  const text='{"bank_account_number":900719925474099312345}';
  const doc=inspectDocument(text);
  assert.equal(doc.findings.length,1);
  const f=doc.findings[0]!;
  assert.equal(text.slice(f.start,f.end),"900719925474099312345");
  assert.equal(assignmentEdits('password = "invented phrase"')[0]?.secretValue,"invented phrase");
});
