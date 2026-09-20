// Drives real synchronous hooks, with optional controlled transformations for
// metric tests. No networking, session file, or private configuration required.
import sensitiveCanary from "../index.ts";
import { observeRedactions, type RedactionAudit, type Range } from "../lib/redaction-audit.ts";
import type { BenchFixture } from "./corpus.ts";
export interface FixtureResult {
  id: string; support: BenchFixture["support"]; rendered: string;
  misses: Range[]; exposedChars: number; falsePreserveViolations: string[];
  trips: number; hits: number; omittedChars: number;
  syntaxFailures: number; measurementUnavailable: boolean;
}
export function occurrences(text:string, values:string[]): Range[] {
  const found=new Map<string,Range>();
  for(const value of values) {
    if(!value) throw new Error("empty benchmark expectation");
    let at=0;
    while(at<text.length) {
      const start=text.indexOf(value,at); if(start<0) break;
      const end=start+value.length; found.set(`${start}:${end}`,{start,end}); at=start+1;
    }
  }
  return [...found.values()];
}
function mask(length:number,ranges:Range[]): Uint8Array {
  const out=new Uint8Array(length);
  for(const r of ranges) out.fill(1,Math.max(0,r.start),Math.min(length,r.end));
  return out;
}
export function assess(fixture:BenchFixture,rendered:string,audits:RedactionAudit[]): FixtureResult {
  const unavailable=audits.some(a=>a.coordinateSystem!=="original" || a.sourceLength!==fixture.input.length);
  const detections=audits.flatMap(a=>a.detections), replacements=audits.flatMap(a=>a.replacements), omissions=audits.flatMap(a=>a.omissions);
  const expected=fixture.expectedRanges ?? occurrences(fixture.input,fixture.expectedSecrets);
  const detected=mask(fixture.input.length,detections), replaced=mask(fixture.input.length,replacements), omitted=mask(fixture.input.length,omissions);
  const secrets=mask(fixture.input.length,expected);
  // Source-span accounting catches partial leaks and separate equal occurrences.
  // Omission is not detection or useful replacement.
  const misses=expected.filter(r=>Array.from(detected.slice(r.start,r.end)).some(v=>!v));
  let exposedChars=0,omittedChars=0;
  for(let i=0;i<secrets.length;i++) {
    if(secrets[i] && !replaced[i] && !omitted[i]) exposedChars++;
    if(omitted[i]) omittedChars++;
  }
  const harmless=occurrences(fixture.input,fixture.mustPreserve);
  const violations=harmless.filter(r=>Array.from(replaced.slice(r.start,r.end)).some(Boolean) || Array.from(omitted.slice(r.start,r.end)).some(Boolean));
  // Hook-added notices are not part of the document. Provider-payload fixtures
  // avoid notices. Context fixtures append one at the explicit separator.
  let syntaxFailures=0;
  if(fixture.representation==="document") {
    try {JSON.parse(fixture.input);} catch {return finish();}
    try {JSON.parse(rendered.split("\n\n[sensitive-canary]")[0]!);} catch {syntaxFailures=1;}
  }
  return finish();
  function finish():FixtureResult {
    return {id:fixture.id,support:fixture.support,rendered,misses,exposedChars,
      falsePreserveViolations:violations.map(r=>`${r.start}:${r.end}`),trips:omissions.length,hits:detections.length,omittedChars,syntaxFailures,measurementUnavailable:unavailable};
  }
}
export function runFixture(fixture:BenchFixture):FixtureResult {
  const handlers:Record<string,(event:any,ctx?:any)=>any>={};
  sensitiveCanary({on:(name:string,fn:any)=>{handlers[name]=fn;},registerFlag(){},registerCommand(){},appendEntry(){},getFlag:()=>false,events:{on(){},emit(){}}} as never);
  const ctx={sessionManager:{getSessionFile:()=>undefined},ui:{notify(){}}};
  const audits:RedactionAudit[]=[];
  handlers.agent_start({},ctx);
  try {
    const rendered=observeRedactions(a=>audits.push(a),()=>{
      if(fixture.representation==="payload" || fixture.representation==="document") {
        const out=handlers.before_provider_request({payload:{prompt:fixture.input}},ctx);
        return out?.prompt ?? fixture.input;
      }
      if(fixture.representation==="tool-output") {
        const out=handlers.tool_result({toolName:"bash",content:[{type:"text",text:fixture.input}]},ctx);
        return out?.content[0]?.text ?? fixture.input;
      }
      const out=handlers.context({messages:[{role:"user",content:fixture.input}]},ctx);
      return out?.messages?.[0]?.content ?? fixture.input;
    });
    return assess(fixture,rendered,audits);
  } finally {handlers.session_shutdown();}
}
export interface BenchSummary {
  fixtures:number;misses:number;exposedChars:number;falseRedactions:number;omissions:number;
  unsupported:number;limitations:number;omittedChars:number;syntaxFailures:number;measurementUnavailable:number;
}
export function summarize(results:FixtureResult[]):BenchSummary {
  const out:BenchSummary={fixtures:results.length,misses:0,exposedChars:0,falseRedactions:0,omissions:0,unsupported:0,limitations:0,omittedChars:0,syntaxFailures:0,measurementUnavailable:0};
  for(const r of results) {
    if(r.support==="unsupported") {out.unsupported++;continue;}
    if(r.support==="limitation") {out.limitations++;continue;}
    if(r.measurementUnavailable) {out.measurementUnavailable++;continue;}
    out.misses+=r.misses.length;out.exposedChars+=r.exposedChars;out.falseRedactions+=r.falsePreserveViolations.length;
    out.omissions+=r.trips;out.omittedChars+=r.omittedChars;out.syntaxFailures+=r.syntaxFailures;
  }
  return out;
}
