// Command-agnostic compaction: the passes that clean up output without
// knowing which command produced it. Ported from Pi's output-shaping
// extension (compact.ts), which could only run them inside Pi.
//
// The command-aware scorers next door in that file — git diff, bun/go/cargo
// test output, ripgrep, nix — are deliberately not here. rtk condenses those
// at the source for every agent, before the text ever reaches the proxy, so
// doing it again on the wire would be the same work twice. What arrives
// uncondensed is what rtk does not recognise: MCP results, a direct grep, a
// WebFetch, anything an agent ran that is not a dev command. That is the gap
// these five close, so they and rtk divide the work rather than overlap.
//
// Every pass is near-lossless and returns undefined when it would change
// nothing, so a request whose output is already tidy is forwarded untouched —
// and forwarded identically on every retry, which is what keeps the provider's
// prompt cache intact.

// JSON with its indentation removed. Only when the text is one JSON document
// that parses: a log line that happens to start with a brace is left alone.
export function minifyJsonOutput(text: string): string | undefined {
  const trimmed = text.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return undefined;
  try {
    JSON.parse(trimmed);
  } catch {
    return undefined;
  }
  const minified = trimmed.replace(/"(?:[^"\\]|\\[\s\S])*"|[\t\n\r ]+/g, (part) =>
    part.startsWith('"') ? part : "",
  );
  if (minified.length >= text.length) return undefined;
  return minified;
}

// A progress row: a percentage, a done/total count, or a size or rate.
const PROGRESS_ROW =
  /\d+(?:\.\d+)?\s?%|\b\d+\/\d+\b|\b\d+(?:\.\d+)?\s?(?:[KMGT]i?B|[kMG]B|B)(?:\/s)?\b/;
const COLOR = /\x1b\[[0-?]*[ -/]*[@-~]/g;

// The row with its numbers blanked, so rows that differ only in a number look
// alike. Test names and data rows differ by more than a number and are kept.
function progressShape(line: string): string | undefined {
  if (!PROGRESS_ROW.test(line)) return undefined;
  return line.replace(/\d+(?:\.\d+)?/g, "#");
}

// Runs of 10+ identical lines collapse to the first plus a count; blank runs
// of 4+ collapse to one, so paragraph structure survives and scrollback does
// not. Runs of 10+ progress rows keep the first and the last.
export function collapseRepeatedLines(text: string, minRun = 10): string | undefined {
  const lines = text.split("\n");
  const output: string[] = [];
  let changed = false;
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";
    let run = 1;
    while (lines[i + run] === line && i + run < lines.length) run++;
    const shape = run < minRun ? progressShape(line.replace(COLOR, "")) : undefined;
    let similar = 1;
    if (shape !== undefined)
      while (similarRun(lines, i + similar, shape) && i + similar < lines.length) similar++;
    if (shape !== undefined && similar >= minRun) {
      output.push(line, `[${similar - 2} similar progress lines]`, lines[i + similar - 1] ?? line);
      changed = true;
      i += similar;
    } else if (run >= minRun && line.replace(COLOR, "").trim() !== "") {
      output.push(line, `[${run - 1} more identical lines]`);
      changed = true;
      i += run;
    } else if (run >= 4 && line.trim() === "") {
      output.push("");
      changed = true;
      i += run;
    } else {
      output.push(line);
      i++;
    }
  }
  if (!changed) return undefined;
  return output.join("\n") || "\n";
}

// Whether the line at `from` is another progress row of the same shape.
function similarRun(lines: string[], from: number, shape: string): boolean {
  return progressShape((lines[from] ?? "").replace(COLOR, "")) === shape;
}

// ISO-8601 and syslog prefixes cost ~25 characters a line and carry no
// ordering that line order does not already carry. Values mid-line are left
// alone, and it needs 10+ stamped lines, so a stray date-like line survives.
const ISO_TS_PREFIX = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+/;
const SYSLOG_TS_PREFIX =
  /^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+/;
const TS_MIN_LINES = 10;

export function stripLogTimestamps(text: string): string | undefined {
  let stripped = 0;
  const output = text.split("\n").map((line) => {
    const match = ISO_TS_PREFIX.exec(line) ?? SYSLOG_TS_PREFIX.exec(line);
    if (!match || line.slice(match[0].length).trim() === "") return line;
    stripped++;
    return line.slice(match[0].length);
  });
  if (stripped < TS_MIN_LINES) return undefined;
  return output.join("\n");
}

// Display noise with no model value: cursor moves, line erases, and
// carriage-return progress rewrites. A \r that is not followed by \n becomes
// a real line break, so the repeat-collapsing pass above can see the run. SGR
// colour codes are kept: retained lines keep their colour by contract.
export function stripControlSequences(text: string): string | undefined {
  const stripped = text
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, (sequence) => (sequence.endsWith("m") ? sequence : ""))
    .replace(/\r(?!\n)/g, "\n")
    .replace(/\x00/g, "");
  return stripped === text ? undefined : stripped;
}

// Encoded data with no model value: a run of base64 or hex long enough that no
// model reads it, inline in a page, a log, or a JSON field. It becomes its
// length and first characters, which are enough to tell two blobs apart and
// too few to decode. Secrets were redacted before this ever runs, so a key
// cannot survive as a prefix here.
export const BLOB_MIN_CHARS = 1_000;
const BLOB_HEAD = 12;
const BLOB = new RegExp(`[A-Za-z0-9+/_-]{${BLOB_MIN_CHARS},}={0,2}`, "g");

export function collapseBlobs(text: string): string | undefined {
  let changed = false;
  const output = text.replace(BLOB, (blob) => {
    // A run of one character is a ruler or padding, already handled by the
    // repeat pass when it spans lines, and not encoded data.
    if (new Set(blob.slice(0, 64)).size < 8) return blob;
    changed = true;
    return `[encoded blob, ${blob.length} chars, starting ${blob.slice(0, BLOB_HEAD)}]`;
  });
  return changed ? output : undefined;
}

// What SHAPE_THRESHOLD_CHARS guards in Pi: small output is not worth the risk
// or the bytes, and a stub's worth of text is left whole.
export const PASS_THRESHOLD_CHARS = 2_000;

// Every pass, in the order that lets the next one see less: control noise
// first, so the repeats it exposes are visible, then the text-level passes.
const PASSES = [
  stripControlSequences,
  collapseRepeatedLines,
  stripLogTimestamps,
  collapseBlobs,
  minifyJsonOutput,
];

// The text as the passes leave it, or undefined when none of them
// changed anything.
export function compact(text: string): string | undefined {
  if (text.length < PASS_THRESHOLD_CHARS) return undefined;
  let working = text;
  let changed = false;
  for (const pass of PASSES) {
    const next = pass(working);
    if (next === undefined || next.length >= working.length) continue;
    working = next;
    changed = true;
  }
  return changed ? working : undefined;
}
