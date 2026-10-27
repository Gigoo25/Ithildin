// Text the model reads and a person does not see.
//
// A skill, a pasted prompt or a file can carry instructions in characters
// that render as nothing: Unicode tag characters spell ASCII invisibly ("ASCII
// smuggling"), a run of variation selectors or zero-width characters encodes
// bytes, and direction overrides show a reviewer one order of the text while
// the model reads another (Trojan Source). The user who checked the skill
// never saw what it asks for, and the rules never saw a secret spelled that
// way, since they match letters.
//
// So before anything else reads a request, each such run in what came in
// (the system prompt, tools, typed prompts, tool results) is made visible:
// tag characters and variation selectors are decoded to the text they spell,
// inside a marker the model can read as a warning, and other runs become a
// marker that counts them. Redaction then scans the decoded text like any
// other. A conversation that carried one is untrusted (trust.ts).
//
// The model's own turns are left as they are: the replay and the prompt cache
// read them by their bytes, and what is in them came from input revealed
// before. The rewrite is a pure function of the text, so a revealed message
// is the same bytes on every request and the cache holds.
//
// Uses that are not hiding pass: an emoji's single variation selector or
// joiner, a flag's tag sequence, and direction marks in right-to-left text.

import type { Format } from "./redact.ts";

// Tag characters, U+E0000–U+E007F: each one is an ASCII character offset.
const TAGS = "\\u{E0000}-\\u{E007F}";
// Variation selectors: one byte each in the usual smuggling encoding.
const SELECTORS = "\\uFE00-\\uFE0F\\u{E0100}-\\u{E01EF}";
// Zero-width spaces, joiners, invisible operators, the mid-text BOM.
const ZERO_WIDTH = "\\u200B-\\u200D\\u2060-\\u2064\\uFEFF\\u180E";
// Embeddings, overrides and isolates; plain LRM/RLM reorder nothing.
const DIRECTION = "\\u202A-\\u202E\\u2066-\\u2069";

const ANY = new RegExp(`[${TAGS}${SELECTORS}${ZERO_WIDTH}${DIRECTION}]`, "u");
// Alternatives in order: a flag's tag sequence (kept), a tag run, a run of
// three or more invisible characters, two of them that are not an emoji's
// selector-then-joiner, and one direction control.
const RUN = new RegExp(
  `(\\u{1F3F4}[\\u{E0020}-\\u{E007E}]{1,8}\\u{E007F})` +
    `|[${TAGS}]+` +
    `|[${SELECTORS}${ZERO_WIDTH}]{3,}` +
    `|(?![\\uFE0E\\uFE0F]\\u200D)[${SELECTORS}${ZERO_WIDTH}]{2}` +
    `|([${DIRECTION}])`,
  "gu",
);
// Letters of the right-to-left scripts, where direction controls are ordinary.
const RTL = /[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFC]/;
const ONLY_SELECTORS = new RegExp(`^[${SELECTORS}]+$`, "u");

export const HIDDEN_PREFIX = "[ithildin: hidden";

// The text a run of tag characters spells, or of variation selectors read as
// bytes (U+FE00 + b below 16, U+E0100 + b - 16 above); undefined when the
// bytes are not readable text.
function decodeRun(run: string): string | undefined {
  const points = [...run].map((char) => char.codePointAt(0)!);
  if (points[0]! >= 0xe0000 && points[0]! <= 0xe007f)
    return String.fromCharCode(...points.map((point) => point - 0xe0000));
  if (!ONLY_SELECTORS.test(run)) return undefined;
  const bytes = points.map((point) => (point < 0xe0100 ? point - 0xfe00 : point - 0xe0100 + 16));
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
  } catch {
    return undefined;
  }
}

function marker(run: string): string {
  const text = decodeRun(run);
  if (text !== undefined && !/[\0-\x08\x0E-\x1F\x7F]/.test(text))
    return `${HIDDEN_PREFIX} text: ${JSON.stringify(text)}]`;
  return `${HIDDEN_PREFIX}: ${[...run].length} invisible characters]`;
}

// One text with its hidden runs made visible, and how many there were.
export function revealText(text: string): { text: string; runs: number } {
  if (!ANY.test(text)) return { text, runs: 0 };
  const rtl = RTL.test(text);
  let runs = 0;
  const out = text.replace(RUN, (run: string, flag?: string, direction?: string) => {
    if (flag !== undefined || (direction !== undefined && rtl)) return run;
    runs++;
    return direction !== undefined ? "" : marker(run);
  });
  return { text: out, runs };
}

// Where hidden text was found, for the journal: a top-level field, or a turn.
export interface HiddenAt {
  where: string;
  runs: number;
}

function revealValue(value: unknown, count: { runs: number }): unknown {
  if (typeof value === "string") {
    const result = revealText(value);
    count.runs += result.runs;
    return result.text;
  }
  if (Array.isArray(value)) {
    let changed = false;
    const out = value.map((item) => {
      const next = revealValue(item, count);
      changed ||= next !== item;
      return next;
    });
    return changed ? out : value;
  }
  if (!value || typeof value !== "object") return value;
  let changed = false;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    out[key] = revealValue(item, count);
    changed ||= out[key] !== item;
  }
  return changed ? out : value;
}

// The model's own turns: replies, reasoning, and its tool calls (not their
// outputs, which are input).
function modelAuthored(item: unknown): boolean {
  if (!item || typeof item !== "object") return false;
  const { role, type } = item as { role?: unknown; type?: unknown };
  if (role === "assistant" || role === "model") return true;
  return typeof type === "string" && (type === "reasoning" || type.endsWith("_call"));
}

// The request with every input's hidden runs revealed, unchanged (the same
// object) when it has none, and where they were.
export function revealHidden(
  format: Format,
  body: Record<string, unknown>,
): { body: Record<string, unknown>; found: HiddenAt[] } {
  const list = format === "responses" ? "input" : format === "gemini" ? "contents" : "messages";
  const found: HiddenAt[] = [];
  let changed = false;
  const out: Record<string, unknown> = {};
  const reveal = (value: unknown, where: string) => {
    const count = { runs: 0 };
    const next = revealValue(value, count);
    if (count.runs > 0) found.push({ where, runs: count.runs });
    changed ||= next !== value;
    return next;
  };
  for (const [key, value] of Object.entries(body)) {
    out[key] =
      key === list && Array.isArray(value)
        ? value.map((item, i) => (modelAuthored(item) ? item : reveal(item, `${key}[${i}]`)))
        : reveal(value, key);
  }
  return { body: changed ? out : body, found };
}
