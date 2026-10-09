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

// A hex digit in either case, as a regex.
function hexDigits(byte: number): string {
  return [...byte.toString(16).padStart(2, "0")]
    .map((d) => (/[a-f]/.test(d) ? `[${d}${d.toUpperCase()}]` : d))
    .join("");
}

// Regex sources for a value spelled byte by byte: the forms a shell, od or
// an interpreter print or accept. `od -tu1` printed a username as
// "114 111 98", which no rule matches; an agent then wrote it back as
// printf '\x72\x6f\x62'. Escapes anchor themselves; a bare run of numbers
// must stand alone. Unprefixed hex pairs are left to dump blocks above:
// "68 75 74" is too often just numbers.
export function spelledSources(value: string): string[] {
  const bytes = [...Buffer.from(value, "utf8")];
  if (bytes.length < MIN_SPELLED_BYTES) return [];
  const hex = bytes.map(hexDigits);
  const sources = [
    hex.map((h) => String.raw`\\x${h}`).join(""),
    hex.map((h) => `%${h}`).join(""),
    bytes.map((b) => "\\\\0?" + b.toString(8).padStart(3, "0")).join(""),
    String.raw`(?<![\w.])` + bytes.join(String.raw`[\s,]+`) + String.raw`(?!\w|\.\d)`,
    hex.map((h) => `0[xX]${h}`).join(String.raw`[\s,]+`) + String.raw`(?!\w)`,
  ];
  const points = [...value].map((c) => c.codePointAt(0)!);
  if (points.every((p) => p <= 0xffff))
    sources.push(
      points.map((p) => String.raw`\\u` + hexDigits(p >> 8) + hexDigits(p & 0xff)).join(""),
    );
  return sources;
}

function spelledPattern(values: string[]): RegExp | undefined {
  const sources = values.flatMap(spelledSources);
  return sources.length ? new RegExp(sources.map((s) => `(?:${s})`).join("|"), "g") : undefined;
}

// Whether text spells a masked value byte by byte: a shell call that would
// put the real value back together where no rule sees it.
export function spellsValue(text: string, values: string[]): boolean {
  const pattern = spelledPattern(values);
  return pattern ? pattern.test(text) : false;
}

// The pattern for one set of values, built once: it holds several
// alternatives per value, and every string of every request is scanned with
// it, so rebuilding it per string would cost more than the scan.
let copiesFor: { key: string; pattern?: RegExp; targets: Set<string> } | undefined;
function copiesPattern(values: string[]): { pattern?: RegExp; targets: Set<string> } {
  const key = values.join("\0");
  if (copiesFor?.key === key) return copiesFor;
  const targets = new Set<string>();
  for (const value of values) {
    if ((value.match(/[A-Za-z]/g)?.length ?? 0) < MIN_ROT13_LETTERS) continue;
    const rotated = rot13(value);
    if (rotated !== value) targets.add(rotated);
  }
  const alternatives = [...targets]
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp)
    .join("|");
  const rotatedSource = alternatives
    ? `(?<![\\p{L}\\p{N}_])(?:${alternatives})(?![\\p{L}\\p{N}_])`
    : undefined;
  const spelled = spelledPattern(values)?.source;
  const sources = [rotatedSource, spelled].filter((s): s is string => s !== undefined);
  const pattern = sources.length ? new RegExp(sources.join("|"), "gu") : undefined;
  copiesFor = { key, ...(pattern ? { pattern } : {}), targets };
  return copiesFor;
}

// Withholds rot13 and spelled copies of values already masked. Neither has
// a shape the rules know, so this matches known values exactly rather than
// scanning a decoding with the shape rules, which would fire on gibberish.
// One pass, so both share one list of edits.
export function redactCopies(
  text: string,
  values: string[],
  onEdit: (start: number, end: number, replacementLength: number) => void,
): { text: string; hits: number } {
  const { pattern, targets } = copiesPattern(values);
  if (!pattern) return { text, hits: 0 };
  let out = "";
  let last = 0;
  let hits = 0;
  for (const match of text.matchAll(pattern)) {
    const kind = targets.has(match[0]) ? "rot13" : "an encoded copy";
    const marker = `[ithildin: omitted ${match[0].length} chars (${kind} of a masked value)]`;
    out += text.slice(last, match.index);
    onEdit(match.index, match.index + match[0].length, marker.length);
    out += marker;
    last = match.index + match[0].length;
    hits++;
  }
  return hits ? { text: out + text.slice(last), hits } : { text, hits: 0 };
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
