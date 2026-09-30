// Structured DOCUMENT text only. It never traverses provider numeric fields.
import { assertScanBudget, type Category, type LocatedFinding } from "./rules.ts";
import type { ScalarEnvelope } from "./redaction-spans.ts";
const SECRET_LABELS = new Set([
  "password",
  "clientsecret",
  "apikey",
  "accesstoken",
  "refreshtoken",
  "privatekey",
]);
const PII_LABELS = new Set(["accountnumber", "bankaccountnumber", "passportnumber"]);
const normLabel = (key: string) => key.toLowerCase();
const normalize = (key: string) => normLabel(key).replace(/_/g, "");
// Retain the existing document ceiling. Exceeding it is now explicit omission,
// not an unreported structured-detection miss. The change increases no threshold.
export const STRUCTURED_MAX_CHARS = 65536;
export interface DocumentScan {
  status: "text" | "json" | "malformed" | "incomplete";
  findings: LocatedFinding[];
  scalars: ScalarEnvelope[];
  numericTypeChanges: number;
}
type Frame = { kind: "object" | "array"; key: string | null; expectKey: boolean };

// Applies one structural character to the frame stack; false for the start
// of a scalar.
function structural(ch: string, stack: Frame[]): boolean {
  const frame = stack.at(-1);
  if (/\s/.test(ch) || ch === ":") return true;
  if (ch === "{" || ch === "[") {
    if (frame) frame.key = null;
    stack.push({ kind: ch === "{" ? "object" : "array", key: null, expectKey: ch === "{" });
    return true;
  }
  if (ch === "}" || ch === "]") {
    stack.pop();
    return true;
  }
  if (ch === ",") {
    if (frame) {
      frame.key = null;
      frame.expectKey = frame.kind === "object";
    }
    return true;
  }
  return false;
}

// The scalar starting at `start`: its end, its decoded text, and its kind
// (undefined for null, true and false).
function readScalar(
  text: string,
  start: number,
  check: () => void,
): { end: number; decoded: string; jsonKind: ScalarEnvelope["jsonKind"] | undefined } {
  let i = start;
  if (text[i] === '"') {
    i++;
    while (i < text.length) {
      check();
      if (text[i] === "\\") {
        i += 2;
        continue;
      }
      if (text[i++] === '"') break;
    }
    return { end: i, decoded: JSON.parse(text.slice(start, i)), jsonKind: "json-string" };
  }
  while (i < text.length && !/[\s,\]}]/.test(text[i]!)) {
    check();
    i++;
  }
  const decoded = text.slice(start, i);
  const literal = ["null", "true", "false"].includes(decoded);
  return { end: i, decoded, jsonKind: literal ? undefined : "json-number" };
}

function fieldFinding(
  key: string,
  text: string,
  start: number,
  end: number,
  jsonKind: ScalarEnvelope["jsonKind"],
) {
  const label = normalize(key);
  const category: Category | null = SECRET_LABELS.has(label)
    ? "secret"
    : PII_LABELS.has(label)
      ? "pii"
      : null;
  if (!category) return undefined;
  // Boolean/null/empty sentinels are handled above. Nonempty explicit
  // credential values are not exempted merely because they look weak.
  return {
    ruleId: `structured-${category}-field`,
    description: "Sensitive document scalar",
    category,
    matchRedacted: "****",
    secretValue: text.slice(start, end),
    score: 1,
    start,
    end,
    jsonKind,
  };
}

// Walks parsed-valid JSON text once, recording every scalar's envelope and a
// finding for each value under a sensitive key.
function walkJson(text: string, result: DocumentScan, check: () => void): void {
  const stack: Frame[] = [];
  let i = 0;
  while (i < text.length) {
    check();
    if (structural(text[i]!, stack)) {
      i++;
      continue;
    }
    const frame = stack.at(-1);
    const start = i;
    const { end, decoded, jsonKind } = readScalar(text, start, check);
    i = end;
    if (!jsonKind) {
      if (frame) frame.key = null;
      continue;
    }
    result.scalars.push({ start, end, jsonKind });
    if (frame?.expectKey) {
      frame.key = decoded;
      frame.expectKey = false;
      continue;
    }
    const key = frame?.key;
    if (frame) frame.key = null;
    if (!key || decoded.length === 0) continue;
    const finding = fieldFinding(key, text, start, end, jsonKind);
    if (!finding) continue;
    result.findings.push(finding);
    if (jsonKind === "json-number") result.numericTypeChanges++;
  }
}

export function inspectDocument(text: string, check = assertScanBudget): DocumentScan {
  const result: DocumentScan = { status: "text", findings: [], scalars: [], numericTypeChanges: 0 };
  try {
    check();
    const trimmed = text.trimStart();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return result;
    if (text.length > STRUCTURED_MAX_CHARS) return { ...result, status: "incomplete" };
    try {
      JSON.parse(text);
    } catch {
      return { ...result, status: "malformed" };
    }
    check();
    result.status = "json";
    walkJson(text, result, check);
    check();
    return result;
  } catch {
    return { status: "incomplete", findings: [], scalars: [], numericTypeChanges: 0 };
  }
}
export function structuredEdits(text: string): LocatedFinding[] {
  return inspectDocument(text).findings;
}

// Single-line assignments only. Quoted values may contain spaces and escaped
// quotes. Multiline YAML/TOML and interpolation semantics remain unsupported.
export function assignmentEdits(text: string, check = assertScanBudget): LocatedFinding[] {
  const findings: LocatedFinding[] = [];
  const re = new RegExp(
    String.raw`^\s*([A-Za-z][A-Za-z0-9_]*)\s*[:=]\s*(?:"((?:\\.|[^"\\])*)"|'((?:\\.|` +
      "[^'\\\\])*)'|([^\\s\"'`#;]+))\\s*(?:[#;].*)?$",
    "d",
  );
  let offset = 0;
  while (offset < text.length) {
    check();
    const nl = text.indexOf("\n", offset),
      end = nl < 0 ? text.length : nl;
    if (end - offset > STRUCTURED_MAX_CHARS) {
      const prefix = /^\s*([A-Za-z][A-Za-z0-9_]*)\s*[:=]/.exec(text.slice(offset, end));
      check();
      if (
        prefix &&
        (SECRET_LABELS.has(normalize(prefix[1]!)) || PII_LABELS.has(normalize(prefix[1]!)))
      )
        throw new Error("incomplete assignment scan");
      offset = end + 1;
      continue;
    }
    const m = re.exec(text.slice(offset, end));
    check();
    if (m) {
      const label = normalize(m[1]!);
      const category: Category | null = SECRET_LABELS.has(label)
        ? "secret"
        : PII_LABELS.has(label)
          ? "pii"
          : null;
      const group = m[2] !== undefined ? 2 : m[3] !== undefined ? 3 : 4;
      const val = m[group]!;
      if (category && val.length && !(group === 4 && /^(?:null|true|false)$/.test(val))) {
        const [start, stop] = m.indices![group]!;
        findings.push({
          ruleId: `structured-${category}-field`,
          description: "Sensitive assignment",
          category,
          matchRedacted: "****",
          secretValue: val,
          score: 1,
          start: offset + start,
          end: offset + stop,
        });
      }
    }
    offset = end + 1;
  }
  return findings;
}
