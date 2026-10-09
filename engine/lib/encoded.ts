// Encoded copies of text: base64 runs and hex dumps (xxd, hexdump, od -x,
// xxd -p). Rules match literal text, so `base64 file` or `xxd file` carried
// a value through whole. Each block is decoded and scanned; a block that
// holds a finding is withheld whole. `od -c` needs no decoding: its spaced
// characters are matched by the inventory rules directly.

import { type Category, escapeRegExp, type LocatedFinding } from "./rules.ts";

export interface EncodedBlock {
  start: number;
  end: number;
  // Decodings to scan. A dump of 16-bit words (od -x, plain hexdump) prints
  // each pair of bytes swapped, so both byte orders are tried.
  decoded: string[];
}

// Below this, a run is an identifier or a hash fragment, not an encoded file.
const MIN_BASE64 = 16;
const MIN_HEX_BYTES = 6;
// Budget: a megabyte of dump is 3 MB of text; decoding stops there.
const MAX_BLOCK_CHARS = 3_000_000;

// Decoded bytes that are valid UTF-8 and mostly printable. Random bytes (a
// key, a hash, an image) are not text, and their decodings cannot carry a
// value the rules would match.
const UTF8 = new TextDecoder("utf-8", { fatal: true });

function asText(bytes: Buffer): string | undefined {
  if (bytes.length < MIN_HEX_BYTES) return;
  let text: string;
  try {
    text = UTF8.decode(bytes);
  } catch {
    return;
  }
  const control = text.match(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g)?.length ?? 0;
  return control <= text.length * 0.05 ? text : undefined;
}

function swapPairs(bytes: Buffer): Buffer {
  const out = Buffer.from(bytes);
  for (let i = 0; i + 1 < out.length; i += 2) [out[i], out[i + 1]] = [out[i + 1]!, out[i]!];
  return out;
}

// One dump line: an offset, then hex groups of one width. The ASCII column
// (xxd, hexdump -C) follows and is covered by the block, not decoded.
const DUMP_LINE = /^[ \t]*(?:[0-9A-Fa-f]{6,16}:?)?((?:[ \t]{1,3}[0-9A-Fa-f]{2,8}(?=[ \t|]|$))+)/;

function dumpBlocks(text: string): EncodedBlock[] {
  const blocks: EncodedBlock[] = [];
  let open: { start: number; end: number; hex: string; words: boolean } | undefined;
  const close = () => {
    if (!open) return;
    const bytes = Buffer.from(open.hex.slice(0, open.hex.length & ~1), "hex");
    const decoded = [asText(bytes), open.words ? asText(swapPairs(bytes)) : undefined].filter(
      (d): d is string => d !== undefined,
    );
    if (decoded.length) blocks.push({ start: open.start, end: open.end, decoded });
    open = undefined;
  };
  let at = 0;
  for (const line of text.split("\n")) {
    const end = at + line.length;
    const groups =
      DUMP_LINE.exec(line)?.[1]
        ?.trim()
        .split(/[ \t]+/) ?? [];
    const width = groups[0]?.length ?? 0;
    // Groups of one even width; the last line of a dump may end short.
    const same = groups.filter(
      (group, i) =>
        group.length === width ||
        (i === groups.length - 1 && group.length < width && group.length % 2 === 0),
    );
    if (
      width % 2 === 0 &&
      same.length >= 4 &&
      same.length === groups.length &&
      end - (open?.start ?? at) <= MAX_BLOCK_CHARS
    ) {
      open ??= { start: at, end, hex: "", words: width === 4 };
      open.hex += same.join("");
      open.end = end;
    } else {
      close();
    }
    at = end + 1;
  }
  close();
  return blocks;
}

// Base64 (standard or URL alphabet) and plain hex runs, wrapped lines joined.
const RUN = new RegExp(
  String.raw`(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}(?:\r?\n[A-Za-z0-9+/_-]{4,})*={0,2}(?!` +
    String.raw`[A-Za-z0-9+/_=-])`,
  "g",
);

function runBlocks(text: string): EncodedBlock[] {
  const blocks: EncodedBlock[] = [];
  for (const match of text.matchAll(RUN)) {
    const run = match[0];
    if (run.length > MAX_BLOCK_CHARS) continue;
    // The run regex also takes the next short word ("done") as a wrapped
    // line. Wrapped hex is hex on every line; wrapped base64 has every line
    // but the last at the wrap width.
    const pieces = run.split(/(\r?\n)/);
    const lines = pieces.filter((_, i) => i % 2 === 0);
    const hexLines = lines.findIndex((line) => !/^[0-9A-Fa-f]+$/.test(line));
    const hexCount = hexLines < 0 ? lines.length : hexLines;
    let b64Count = 1;
    while (b64Count < lines.length && lines[b64Count - 1]!.length === lines[0]!.length) b64Count++;
    const found: Array<{ count: number; text: string }> = [];
    const hex = lines.slice(0, hexCount).join("");
    if (hex.length % 2 === 0 && hex.length >= MIN_HEX_BYTES * 2) {
      const decoded = asText(Buffer.from(hex, "hex"));
      if (decoded !== undefined) found.push({ count: hexCount, text: decoded });
    }
    const b64 = lines.slice(0, b64Count).join("");
    if (b64.replace(/=+$/, "").length >= MIN_BASE64) {
      const decoded = asText(Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
      if (decoded !== undefined) found.push({ count: b64Count, text: decoded });
    }
    if (!found.length) continue;
    const count = Math.max(...found.map((f) => f.count));
    const length = pieces.slice(0, count * 2 - 1).join("").length;
    blocks.push({
      start: match.index,
      end: match.index + length,
      decoded: found.map((f) => f.text),
    });
  }
  return blocks;
}

export function encodedBlocks(text: string): EncodedBlock[] {
  if (text.length < MIN_BASE64) return [];
  return [...dumpBlocks(text), ...runBlocks(text)].sort(
    (a, b) => a.start - b.start || b.end - a.end,
  );
}

export function rot13(text: string): string {
  return text.replace(/[A-Za-z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

// Below this, a rotated value turns up inside ordinary words: a three-letter
// username rotated is a piece of "Notebook".
const MIN_ROT13_LETTERS = 5;
// A spelled copy carries its own shape (escapes, a run of byte numbers), so a
// three-letter name is specific enough; below that, byte runs are noise.
const MIN_SPELLED_BYTES = 3;

// The forms a value is spelled in byte by byte: the ones a shell, od or
// an interpreter print or accept. `od -tu1` printed a username as
// "114 111 98", which no rule matches; an agent then wrote it back as
// printf '\x72\x6f\x62'. Escapes anchor themselves; a bare run of numbers
// must stand alone. Unprefixed hex pairs are left to dump blocks above:
// "68 75 74" is too often just numbers.
//
// Each form is found by its shape alone, in one pass, and each run is read
// back into bytes and looked up among the values. Matching the values
// themselves, one regex alternative per value and form, cost time for every
// value at every position: with 1,600 values masked in a long session a
// request took over 30 seconds and the rest of it was omitted.
interface SpelledForm {
  // A run of the form. Global, so it is stateful: reset before each use.
  run: RegExp;
  // One unit inside a run.
  unit: RegExp;
  // The byte (or UTF-16 unit, for \u) one unit spells; -1 if no value can
  // hold it.
  read: (unit: string) => number;
  // Whether a value spelled up to `end` may stop there.
  ends?: (text: string, end: number) => boolean;
  utf16?: boolean;
}

const hexUnit = (unit: string): number => parseInt(unit.slice(-2), 16);
// A number that stands alone: no word character, and not the integer part
// of a decimal.
const standsAlone = (text: string, end: number): boolean =>
  !/\w/.test(text[end] ?? "") && !(text[end] === "." && /\d/.test(text[end + 1] ?? ""));

const SPELLED_FORMS: SpelledForm[] = [
  { run: /(?:\\x[0-9a-fA-F]{2})+/g, unit: /\\x[0-9a-fA-F]{2}/g, read: hexUnit },
  { run: /(?:%[0-9a-fA-F]{2})+/g, unit: /%[0-9a-fA-F]{2}/g, read: hexUnit },
  // A byte is at most \377, so a fourth digit after \0 belongs to the text.
  {
    run: /(?:\\0?[0-3][0-7]{2})+/g,
    unit: /\\0?[0-3][0-7]{2}/g,
    read: (unit) => parseInt(unit.slice(-3), 8),
  },
  {
    run: /(?<![\w.])\d+(?:[\s,]+\d+)*/g,
    unit: /\d+/g,
    // Written the way od and a byte list print it: no leading zeros.
    read: (unit) => (/^(?:0|[1-9]\d{0,2})$/.test(unit) && +unit < 256 ? +unit : -1),
    ends: standsAlone,
  },
  {
    run: /0[xX][0-9a-fA-F]{2}(?:[\s,]+0[xX][0-9a-fA-F]{2})*/g,
    unit: /0[xX][0-9a-fA-F]{2}/g,
    read: hexUnit,
    ends: (text, end) => !/\w/.test(text[end] ?? ""),
  },
  {
    run: /(?:\\u[0-9a-fA-F]{4})+/g,
    unit: /\\u[0-9a-fA-F]{4}/g,
    read: (unit) => parseInt(unit.slice(-4), 16),
    utf16: true,
  },
];

// Values by their first three units, longest first. Three is the shortest
// spelled value, and units are below 2^16, so the key is exact.
type UnitIndex = Map<number, number[][]>;
const unitKey = (units: ArrayLike<number>, at: number): number =>
  (units[at]! * 65536 + units[at + 1]!) * 65536 + units[at + 2]!;

function indexUnits(all: number[][]): UnitIndex {
  const index: UnitIndex = new Map();
  for (const units of all) {
    if (units.length < MIN_SPELLED_BYTES) continue;
    const key = unitKey(units, 0);
    const list = index.get(key) ?? [];
    list.push(units);
    index.set(key, list);
  }
  for (const list of index.values()) list.sort((a, b) => b.length - a.length);
  return index;
}

interface CopyIndex {
  values: readonly string[];
  bytes: UnitIndex;
  utf16: UnitIndex;
  // Rotated values by their leading word; `oddRotated` for the rare one
  // that starts with punctuation, which has no leading word.
  rotated: Map<string, string[]>;
  oddRotated?: RegExp;
}

const WORD = /[\p{L}\p{N}_]+/gu;
const WORD_CHAR = /^[\p{L}\p{N}_]/u;

function rotatedTargets(values: readonly string[]): Pick<CopyIndex, "rotated" | "oddRotated"> {
  const rotated = new Map<string, string[]>();
  const odd: string[] = [];
  for (const value of new Set(values)) {
    if ((value.match(/[A-Za-z]/g)?.length ?? 0) < MIN_ROT13_LETTERS) continue;
    const target = rot13(value);
    if (target === value) continue;
    const lead = /^[\p{L}\p{N}_]*/u.exec(target)![0];
    if (!lead) odd.push(target);
    else rotated.set(lead, [...(rotated.get(lead) ?? []), target]);
  }
  for (const list of rotated.values()) list.sort((a, b) => b.length - a.length);
  if (!odd.length) return { rotated };
  const alternatives = odd.sort((a, b) => b.length - a.length).map(escapeRegExp);
  const source = `(?<![\\p{L}\\p{N}_])(?:${alternatives.join("|")})(?![\\p{L}\\p{N}_])`;
  return { rotated, oddRotated: new RegExp(source, "gu") };
}

// Built once per set of values. AliasBook.values() hands back the same array
// until a value is added, so the check is one comparison per string.
let copiesFor: CopyIndex | undefined;
function copyIndex(values: readonly string[]): CopyIndex {
  if (copiesFor?.values === values) return copiesFor;
  const points = (value: string) => [...value].map((c) => c.codePointAt(0)!);
  copiesFor = {
    values,
    bytes: indexUnits(values.map((value) => [...Buffer.from(value, "utf8")])),
    utf16: indexUnits(values.map(points).filter((p) => p.every((point) => point <= 0xffff))),
    ...rotatedTargets(values),
  };
  return copiesFor;
}

type Copy = Range & { rot13?: true };
type Range = { start: number; end: number };

// The longest value spelled at each unit of one run, left to right.
function valuesInRun(text: string, at: number, run: string, form: SpelledForm, index: UnitIndex) {
  const found: Range[] = [];
  const units: number[] = [];
  const starts: number[] = [];
  const ends: number[] = [];
  form.unit.lastIndex = 0;
  for (const unit of run.matchAll(form.unit)) {
    units.push(form.read(unit[0]));
    starts.push(at + unit.index);
    ends.push(at + unit.index + unit[0].length);
  }
  for (let i = 0; i + MIN_SPELLED_BYTES <= units.length; i++) {
    const candidates = index.get(unitKey(units, i));
    const hit = candidates?.find(
      (value) =>
        i + value.length <= units.length &&
        value.every((unit, k) => units[i + k] === unit) &&
        (form.ends?.(text, ends[i + value.length - 1]!) ?? true),
    );
    if (!hit) continue;
    found.push({ start: starts[i]!, end: ends[i + hit.length - 1]! });
    i += hit.length - 1;
  }
  return found;
}

function spelledCopies(text: string, index: CopyIndex): Copy[] {
  const found: Copy[] = [];
  for (const form of SPELLED_FORMS) {
    const units = form.utf16 ? index.utf16 : index.bytes;
    if (!units.size) continue;
    form.run.lastIndex = 0;
    for (const run of text.matchAll(form.run))
      found.push(...valuesInRun(text, run.index, run[0], form, units));
  }
  return found;
}

// Whole tokens only: a rotated value is never part of a longer word.
function rotatedCopies(text: string, index: CopyIndex): Copy[] {
  const found: Copy[] = [];
  if (index.rotated.size) {
    let last = 0;
    WORD.lastIndex = 0;
    for (const word of text.matchAll(WORD)) {
      if (word.index < last) continue;
      const hit = index.rotated
        .get(word[0])
        ?.find(
          (target) =>
            text.startsWith(target, word.index) &&
            !WORD_CHAR.test(text.slice(word.index + target.length, word.index + target.length + 2)),
        );
      if (!hit) continue;
      last = word.index + hit.length;
      found.push({ start: word.index, end: last, rot13: true });
    }
  }
  if (index.oddRotated) {
    index.oddRotated.lastIndex = 0;
    for (const match of text.matchAll(index.oddRotated))
      found.push({ start: match.index, end: match.index + match[0].length, rot13: true });
  }
  return found;
}

// Leftmost first, the longer of two at one place, and none overlapping.
function disjoint(copies: Copy[]): Copy[] {
  const sorted = copies.sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Copy[] = [];
  for (const copy of sorted)
    if (!out.length || copy.start >= out[out.length - 1]!.end) out.push(copy);
  return out;
}

// Whether text spells a masked value byte by byte: a shell call that would
// put the real value back together where no rule sees it.
export function spellsValue(text: string, values: readonly string[]): boolean {
  return values.length > 0 && spelledCopies(text, copyIndex(values)).length > 0;
}

// Withholds rot13 and spelled copies of values already masked. Neither has
// a shape the rules know, so this matches known values exactly rather than
// scanning a decoding with the shape rules, which would fire on gibberish.
// One pass, so both share one list of edits.
export function redactCopies(
  text: string,
  values: readonly string[],
  onEdit: (start: number, end: number, replacementLength: number) => void,
): { text: string; hits: number } {
  if (!values.length) return { text, hits: 0 };
  const index = copyIndex(values);
  const copies = disjoint([...rotatedCopies(text, index), ...spelledCopies(text, index)]);
  let out = "";
  let last = 0;
  for (const copy of copies) {
    const kind = copy.rot13 ? "rot13" : "an encoded copy";
    const marker = `[ithildin: omitted ${copy.end - copy.start} chars (${kind} of a masked value)]`;
    out += text.slice(last, copy.start);
    onEdit(copy.start, copy.end, marker.length);
    out += marker;
    last = copy.end;
  }
  return copies.length ? { text: out + text.slice(last), hits: copies.length } : { text, hits: 0 };
}

// Withholds every block whose decoding holds a finding in a category not
// allowed. `onEdit` receives edits in the coordinates of the input text,
// the same contract as redactCookieHeaders.
export function redactEncoded(
  text: string,
  scan: (decoded: string) => LocatedFinding[],
  allowed: (category: Category) => boolean,
  onEdit: (start: number, end: number, replacementLength: number) => void,
): { text: string; hits: number } {
  let out = "";
  let last = 0;
  let hits = 0;
  for (const block of encodedBlocks(text)) {
    if (block.start < last) continue;
    const categories = new Set(
      block.decoded.flatMap((decoded) => scan(decoded).map((finding) => finding.category)),
    );
    const held = [...categories].filter((category) => !allowed(category));
    if (!held.length) continue;
    const what = held.includes("secret") ? "a secret" : "personal data";
    const marker =
      `[ithildin: omitted ${block.end - block.start} chars (encoded data holding ` + `${what})]`;
    out += text.slice(last, block.start);
    onEdit(block.start, block.end, marker.length);
    out += marker;
    last = block.end;
    hits++;
  }
  return hits ? { text: out + text.slice(last), hits } : { text, hits: 0 };
}
