// Structured DOCUMENT text only; never traverses provider numeric fields.
import { assertScanBudget, type LocatedFinding } from "./rules.ts";
import type { ScalarEnvelope } from "./redaction-spans.ts";
const SECRET_LABELS = new Set(["password", "clientsecret", "apikey", "accesstoken", "refreshtoken", "privatekey"]);
const PII_LABELS = new Set(["accountnumber", "bankaccountnumber", "passportnumber"]);
const normLabel = (key: string) => key.toLowerCase();
const normalize = (key: string) => normLabel(key).replace(/_/g, "");
// Retain the existing document ceiling; exceeding it is now explicit omission,
// not an unreported structured-detection miss. No threshold was increased.
export const STRUCTURED_MAX_CHARS = 65536;
export interface DocumentScan {
  status: "text" | "json" | "malformed" | "incomplete";
  findings: LocatedFinding[];
  scalars: ScalarEnvelope[];
  numericTypeChanges: number;
}
export function inspectDocument(text: string, check = assertScanBudget): DocumentScan {
  const result: DocumentScan = { status: "text", findings: [], scalars: [], numericTypeChanges: 0 };
  try {
    check();
    const trimmed = text.trimStart();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return result;
    if (text.length > STRUCTURED_MAX_CHARS) return { ...result, status: "incomplete" };
    try { JSON.parse(text); } catch { return { ...result, status: "malformed" }; }
    check();
    result.status = "json";
    type Frame = { kind: "object" | "array"; key: string | null; expectKey: boolean };
    const stack: Frame[] = [];
    let i = 0;
    while (i < text.length) {
      check();
      const ch = text[i]!;
      const frame = stack.at(-1);
      if (/\s/.test(ch)) { i++; continue; }
      if (ch === "{" || ch === "[") {
        if (frame) frame.key = null;
        stack.push({ kind: ch === "{" ? "object" : "array", key: null, expectKey: ch === "{" });
        i++; continue;
      }
      if (ch === "}" || ch === "]") { stack.pop(); i++; continue; }
      if (ch === ",") { if (frame) { frame.key=null; frame.expectKey=frame.kind === "object"; } i++; continue; }
      if (ch === ":") { i++; continue; }
      const start = i;
      let decoded: string;
      let jsonKind: ScalarEnvelope["jsonKind"];
      if (ch === '"') {
        i++;
        while (i < text.length) {
          check();
          if (text[i] === "\\") { i += 2; continue; }
          if (text[i++] === '"') break;
        }
        decoded = JSON.parse(text.slice(start,i));
        jsonKind = "json-string";
      } else {
        while (i < text.length && !/[\s,\]}]/.test(text[i]!)) { check(); i++; }
        decoded = text.slice(start,i);
        if (["null", "true", "false"].includes(decoded)) { if(frame) frame.key=null; continue; }
        jsonKind = "json-number";
      }
      result.scalars.push({start,end:i,jsonKind});
      if (frame?.expectKey) { frame.key=decoded; frame.expectKey=false; continue; }
      const key = frame?.key;
      if(frame) frame.key=null;
      if (!key || decoded.length === 0) continue;
      const label=normalize(key);
      const category=SECRET_LABELS.has(label) ? "secret" : PII_LABELS.has(label) ? "pii" : null;
      if (!category) continue;
      // Boolean/null/empty sentinels are handled above. Nonempty explicit
      // credential values are not exempted merely because they look weak.
      const finding = { ruleId: `structured-${category}-field`, description: "Sensitive document scalar", category, matchRedacted:"****", secretValue:text.slice(start,i), score:1, start, end:i, jsonKind };
      result.findings.push(finding);
      if (jsonKind === "json-number") result.numericTypeChanges++;
    }
    check();
    return result;
  } catch { return { status:"incomplete", findings:[], scalars:[], numericTypeChanges:0 }; }
}
export function structuredEdits(text: string): LocatedFinding[] { return inspectDocument(text).findings; }

// Single-line assignments only. Quoted values may contain spaces and escaped
// quotes; multiline YAML/TOML and interpolation semantics remain unsupported.
export function assignmentEdits(text: string, check = assertScanBudget): LocatedFinding[] {
  const findings: LocatedFinding[] = [];
  const re = /^\s*([A-Za-z][A-Za-z0-9_]*)\s*[:=]\s*(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^\s"'`#;]+))\s*(?:[#;].*)?$/d;
  let offset=0;
  while(offset < text.length) {
    check();
    const nl=text.indexOf("\n",offset), end=nl < 0 ? text.length : nl;
    if(end-offset > STRUCTURED_MAX_CHARS) {
      const prefix=/^\s*([A-Za-z][A-Za-z0-9_]*)\s*[:=]/.exec(text.slice(offset,end));
      check();
      if(prefix && (SECRET_LABELS.has(normalize(prefix[1]!)) || PII_LABELS.has(normalize(prefix[1]!)))) throw new Error("incomplete assignment scan");
      offset=end+1;
      continue;
    }
    const m=re.exec(text.slice(offset,end));
    check();
    if(m) {
      const label=normalize(m[1]!);
      const category=SECRET_LABELS.has(label) ? "secret" : PII_LABELS.has(label) ? "pii" : null;
      const group=m[2] !== undefined ? 2 : m[3] !== undefined ? 3 : 4;
      const val=m[group]!;
      if(category && val.length && !(group === 4 && /^(?:null|true|false)$/.test(val))) {
        const [start,stop]=m.indices![group]!;
        findings.push({ruleId:`structured-${category}-field`,description:"Sensitive assignment",category,matchRedacted:"****",secretValue:val,score:1,start:offset+start,end:offset+stop});
      }
    }
    offset=end+1;
  }
  return findings;
}
