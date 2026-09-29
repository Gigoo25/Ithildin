import { describe, expect, it } from "bun:test";
import { planRedaction } from "../engine/lib/redaction-spans.ts";
import { inspectDocument, assignmentEdits, STRUCTURED_MAX_CHARS } from "../engine/lib/structured-text.ts";
import { withScanBudget, type LocatedFinding } from "../engine/lib/rules.ts";
import { createHooks } from "../bench/hooks.ts";
const finding = (secretValue: string, start: number, category: "pii" | "secret" = "secret"): LocatedFinding => ({ ruleId:"fixture", description:"fixture", category, secretValue, start, end:start+secretValue.length, score:1, matchRedacted:"" });
function sanitize(text: string, tag = "", repeat = false) {
  const handlers=createHooks();
  const ctx={sessionManager:{getSessionFile:()=>undefined},ui:{notify(){}}};
  handlers.agent_start({},ctx);
  try {
    if(tag) handlers.context({messages:[{role:"user",content:tag}]},ctx);
    const result=handlers.before_provider_request({payload:{prompt:text,limit:12345}},ctx);
    const first=result ?? {prompt:text,limit:12345};
    if(repeat) {
      const second=handlers.before_provider_request({payload:first},ctx) ?? first;
      expect(second).toEqual(first);
    }
    return first;
  } finally {handlers.session_shutdown();}
}
describe("review safety regressions",()=>{
  it("unions propagated partial overlaps and self overlaps",()=>{
    const out=planRedaction({text:"abc bcd abcd",findings:[finding("abc",0),finding("bcd",4)],trips:[],replacementFor:()=>"X"});
    expect(out.text).toBe("X X X");
    expect(planRedaction({text:"aaa aaaaa",findings:[finding("aaa",0)],trips:[],replacementFor:()=>"X"}).text).toBe("X X");
  });
  it("propagated values and overlapping omissions form one union",()=>{
    const out=planRedaction({text:"abc bcd abcd",findings:[finding("abc",0),finding("bcd",4)],trips:[{start:9,end:10},{start:10,end:11}],replacementFor:()=>"X",omissionLabel:()=>"O"});
    expect(out.text).toBe("X X O");
  });
  it("secret wins even when PII was encountered first",()=>{
    expect(planRedaction({text:"abc abc xabc",findings:[finding("abc",0,"pii"),finding("abc",4)],trips:[],replacementFor:f=>f.category === "secret" ? "S":"P"}).text).toBe("S S xS");
  });
  it("keeps adjacent identities distinct and handles astral identifier boundaries",()=>{
    expect(planRedaction({text:"abcxyz",findings:[finding("abc",0),finding("xyz",3)],trips:[],replacementFor:f=>f.secretValue === "abc"?"A":"B"}).text).toBe("AB");
    const text="abc 𐐀abc abc𐐀 abc-count /abc/file abc.example";
    const out=planRedaction({text,findings:[finding("abc",0,"pii")],trips:[],replacementFor:()=>"P"}).text;
    expect(out).toBe("P 𐐀abc abc𐐀 P-count /P/file P.example");
  });
  it("uses the full original union slice for replacement",()=>{
    const values:string[]=[];
    planRedaction({text:"abcdef",findings:[finding("abcd",0),finding("cdef",2)],trips:[],replacementFor:f=>{values.push(f.secretValue);return "X";}});
    expect(values).toEqual(["abcdef"]);
  });
  it("retains direct equal PII captures inside longer identifiers",()=>{
    const text='username = "inventedreader"\nusername = "inventedreader"; const inventedreaderCount=2;';
    const result=sanitize(text).prompt;
    expect(result).not.toContain('"inventedreader"');
    expect(result).toContain("inventedreaderCount");
  });
  it("recognizes all approved JSON labels including bank accounts",()=>{
    for(const key of ["bank_account_number","bankAccountNumber","passport_number","accountNumber","password","clientSecret","api_key","access_token","refreshToken","private_key"]) {
      const input=JSON.stringify({[key]:"invented phrase"});
      expect(inspectDocument(input).findings).toHaveLength(1);
      expect(sanitize(input).prompt).not.toContain("invented phrase");
    }
  });
  it("preserves numeric values not classified by a sensitive field",()=>{
    const result=sanitize('{"account_number":12345,"count":12345,"note":"12345"}');
    const doc=JSON.parse(result.prompt);
    expect(typeof doc.account_number).toBe("string");
    expect(doc.count).toBe(12345); expect(doc.note).toBe("12345");
    expect(result.limit).toBe(12345);
  });
  it("preserves syntax, nesting, duplicate keys, escapes and raw large integers",()=>{
    const input='{ "rows": [{"password":"tiny\\\"\\\\\\u0041","password":"changeme"}], "bank_account_number":900719925474099312345, "keep" : [true,null,7] }';
    const result=sanitize(input).prompt;
    expect(()=>JSON.parse(result)).not.toThrow();
    expect(result).not.toContain("changeme");
    expect(result).not.toContain("900719925474099312345");
    expect(result).toContain('"keep" : [true,null,7]');
  });
  it("preserves empty/null/boolean sentinels and harmless longer keys",()=>{
    const input='{"password":"","client_secret":null,"api_key":false,"password_hint":"retain","id":1}';
    expect(inspectDocument(input).findings).toHaveLength(0);
    expect(sanitize(input).prompt).toBe(input);
  });
  it("handles quoted/unquoted assignments, spaces, comments and exact spans",()=>{
    for(const input of ['password = "invented phrase" # comment',"client_secret='invented phrase'",'access_token = changeme; comment']) {
      const matches=assignmentEdits(input);
      expect(matches).toHaveLength(1);
      expect(input.slice(matches[0]!.start,matches[0]!.end)).toBe(matches[0]!.secretValue);
      expect(sanitize(input).prompt).not.toContain(matches[0]!.secretValue);
    }
    expect(assignmentEdits('password_hint = retain')).toHaveLength(0);
  });
  it("reports malformed input and falls back to assignment/text scanning",()=>{
    const input='{ broken\npassword = "invented phrase"';
    expect(inspectDocument(input).status).toBe("malformed");
    expect(sanitize(input).prompt).not.toContain("invented phrase");
  });
  it("omits oversized documents and expired-budget/resource failures",()=>{
    const input=JSON.stringify({password:"x".repeat(STRUCTURED_MAX_CHARS)});
    expect(inspectDocument(input).status).toBe("incomplete");
    expect(sanitize(input).prompt).toContain("omitted");
    expect(inspectDocument('{"password":"weak"}',()=>{throw new Error("fixture");}).status).toBe("incomplete");
    expect(withScanBudget(()=>inspectDocument('{"password":"weak"}'),0).status).toBe("incomplete");
  });
  it("walks deeply nested documents without recursive stack overflow",()=>{
    const input='['.repeat(2000)+'{"password":"weak"}'+']'.repeat(2000);
    expect(inspectDocument(input).findings).toHaveLength(1);
  });
  it("does not pass punctuation-only explicit credentials through unchanged",()=>{
    const result=JSON.parse(sanitize('{"password":"!!!"}').prompt);
    expect(result.password).not.toBe("!!!");
  });
  it("reprocessing sanitized JSON preserves tokens",()=>{
    sanitize('{"account_number":12345,"password":"invented phrase"}', "", true);
  });
});
