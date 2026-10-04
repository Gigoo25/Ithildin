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

// Below this, a rot13 value is too short to tell from ordinary text.
const MIN_ROT13_LETTERS = 3;

// Withholds rot13 copies of values already masked (`tr 'A-Za-z'
// 'N-ZA-Mn-za-m'`, Python's codecs). rot13 has no shape of its own, so this
// matches known values exactly rather than scanning a decoding with the
// shape rules, which would fire on gibberish.
export function redactRot13(
  text: string,
  values: string[],
  onEdit: (start: number, end: number, replacementLength: number) => void,
): { text: string; hits: number } {
  const targets = new Set<string>();
  for (const value of values) {
    if ((value.match(/[A-Za-z]/g)?.length ?? 0) < MIN_ROT13_LETTERS) continue;
    const rotated = rot13(value);
    if (rotated !== value) targets.add(rotated);
  }
  if (!targets.size) return { text, hits: 0 };
  const pattern = new RegExp(
    [...targets]
      .sort((a, b) => b.length - a.length)
      .map(escapeRegExp)
      .join("|"),
    "g",
  );
  let out = "";
  let last = 0;
  let hits = 0;
  for (const match of text.matchAll(pattern)) {
    const marker = `[ithildin: omitted ${match[0].length} chars (rot13 of a masked value)]`;
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
