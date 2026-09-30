// All direct and propagated occurrences share one coordinate system and union.
import type { LocatedFinding } from "./rules.ts";

export interface SpanEdit {
  start: number;
  end: number;
  replacement: string;
  secret: boolean;
}
export interface ScalarEnvelope {
  start: number;
  end: number;
  jsonKind: "json-string" | "json-number";
}
export interface PlanInput {
  text: string;
  findings: LocatedFinding[];
  trips: Array<{ start: number; end: number }>;
  replacementFor: (finding: LocatedFinding) => string;
  omissionLabel?: (start: number, end: number) => string;
  scalars?: ScalarEnvelope[];
  checkBudget?: () => void;
}
export function isIdentifierChar(ch: string): boolean {
  return /[\p{L}\p{N}_]/u.test(ch);
}
function before(text: string, at: number): string {
  const last = text.charCodeAt(at - 1);
  return text.slice(at - (last >= 0xdc00 && last <= 0xdfff ? 2 : 1), at);
}
type PlanRange = { start: number; end: number; members: LocatedFinding[]; omission: boolean };

function jsonKind(f: LocatedFinding): string | undefined {
  return (f as LocatedFinding & { jsonKind?: string }).jsonKind;
}

// Every finding and trip is a whole-integer span inside the text, and each
// finding's value is the text it spans.
function offsetsValid(input: PlanInput): boolean {
  const { text } = input;
  const valid = (f: { start: number; end: number }) =>
    Number.isInteger(f.start) &&
    Number.isInteger(f.end) &&
    f.start >= 0 &&
    f.end <= text.length &&
    f.start < f.end;
  return (
    input.findings.every((f) => valid(f) && text.slice(f.start, f.end) === f.secretValue) &&
    input.trips.every(valid)
  );
}

// Each finding's own span, then every other occurrence of its value.
function collectRanges(input: PlanInput, check: () => void): PlanRange[] {
  const { text, findings } = input;
  const ranges: PlanRange[] = [];
  const add = (f: LocatedFinding, start: number, end: number) => {
    check();
    // Promote edits inside JSON scalars to the raw scalar envelope, including
    // propagated matches inside quoted strings. Final JSON validation is still
    // necessary for unions crossing property/container boundaries.
    for (const scalar of input.scalars ?? []) {
      if (scalar.start < end && start < scalar.end) {
        start = Math.min(start, scalar.start);
        end = Math.max(end, scalar.end);
      }
    }
    ranges.push({ start, end, members: [f], omission: false });
  };
  for (const f of findings) add(f, f.start, f.end);
  for (const [value, f] of propagatedValues(findings)) {
    // A captured fragment can be much shorter than the full sensitive value (for
    // example, a one-character local part of user@host). Propagating such a
    // fragment replaces unrelated text. The exact finding is already covered by
    // the direct range above, so only propagate specific values.
    if (value.length < 2) continue;
    let at = 0;
    while (at < text.length) {
      check();
      const idx = text.indexOf(value, at);
      if (idx < 0) break;
      at = idx + 1; // overlapping equal occurrences must also participate
      const end = idx + value.length;
      if (
        f.category === "pii" &&
        (isIdentifierChar(before(text, idx)) ||
          isIdentifierChar(String.fromCodePoint(text.codePointAt(end) ?? 0)))
      )
        continue;
      add(f, idx, end);
    }
  }
  for (const t of input.trips) ranges.push({ ...t, members: [], omission: true });
  return ranges;
}

// Values to find again elsewhere in the text, each with the finding that
// names it (a secret wins over PII).
function propagatedValues(findings: LocatedFinding[]): Map<string, LocatedFinding> {
  const values = new Map<string, LocatedFinding>();
  for (const f of findings) {
    // Numeric document fields are classified by their label, not by numeric
    // equality with unrelated counters or protocol-looking document fields.
    if (jsonKind(f) === "json-number") continue;
    const keys = [f.secretValue];
    if (jsonKind(f) === "json-string") {
      keys.push(JSON.parse(f.secretValue) as string, f.secretValue.slice(1, -1));
    }
    for (const value of keys) {
      if (!value) continue;
      const prior = values.get(value);
      if (!prior || f.category === "secret") values.set(value, f);
    }
  }
  return values;
}

function unionRanges(ranges: PlanRange[], check: () => void): PlanRange[] {
  ranges.sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: PlanRange[] = [];
  for (const r of ranges) {
    check();
    const last = merged.at(-1);
    if (last && r.start < last.end) {
      last.end = Math.max(last.end, r.end);
      last.omission ||= r.omission;
      last.members.push(...r.members);
    } else merged.push({ ...r, members: [...r.members] });
  }
  return merged;
}

function editFor(input: PlanInput, r: PlanRange): SpanEdit {
  if (r.omission)
    return {
      start: r.start,
      end: r.end,
      secret: true,
      replacement:
        input.omissionLabel?.(r.start, r.end) ??
        `[sensitive-canary: omitted ${r.end - r.start} chars (scan budget exceeded)]`,
    };
  const secret = r.members.some((f) => f.category === "secret");
  const rep = [...r.members].sort((a, b) =>
    a.category === b.category ? a.ruleId.localeCompare(b.ruleId) : a.category === "secret" ? -1 : 1,
  )[0]!;
  const scalar = input.scalars?.find((s) => s.start === r.start && s.end === r.end);
  const finding = {
    ...rep,
    start: r.start,
    end: r.end,
    secretValue: input.text.slice(r.start, r.end),
    category: secret ? ("secret" as const) : ("pii" as const),
    jsonKind: scalar?.jsonKind,
  };
  return { start: r.start, end: r.end, secret, replacement: input.replacementFor(finding) };
}

export function planRedaction(input: PlanInput): { text: string; edits: SpanEdit[] } {
  const { text } = input;
  const omit = () => {
    const replacement = `[sensitive-canary: omitted ${text.length} chars (invalid scan offsets)]`;
    return {
      text: replacement,
      edits: [{ start: 0, end: text.length, replacement, secret: true }],
    };
  };
  if (!offsetsValid(input)) return omit();
  try {
    const check = () => input.checkBudget?.();
    check();
    const merged = unionRanges(collectRanges(input, check), check);
    const edits = merged.map((r) => {
      check();
      return editFor(input, r);
    });
    let out = "",
      cursor = 0;
    for (const e of edits) {
      check();
      out += text.slice(cursor, e.start) + e.replacement;
      cursor = e.end;
    }
    return { text: out + text.slice(cursor), edits };
  } catch {
    return omit();
  }
}
