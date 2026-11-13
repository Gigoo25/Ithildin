// The note an old call's long input becomes (shape.ts), and the guard that
// refuses a new call written with it (redact.ts). One module, so the wording
// and the pattern that reads it back cannot drift apart.
//
// The wording says the call ran with the full text and that a new one needs
// it, because a model that reads its own history as having written
// placeholders will write them. Some still do: across 156 Pi sessions, 46 new
// calls had the note as their input, from every model family in use. As a
// shell command it fails on the apostrophe ("unexpected EOF while looking for
// matching `'`"), which the model takes for its own quoting and retries; as a
// Write's content or an Edit's new text it does not fail at all, and the note
// is written into the file.

// A long input used to become the note alone. A model then read its history as
// calls whose whole input was a note, and wrote the same: in one 925-call
// qwen4-max-preview session 84 calls were refused for it, and the model took a
// refused `git commit` for a commit that later vanished. So the start of the
// real input stays, and the note only closes it: the history still reads as
// real commands, and what a model copies from it starts as one.
export const HEAD_CHARS = 200;

export function inputNote(size: number): string {
  return (
    `[${size} more chars of this earlier call's input removed from the history to save ` +
    "context. The call ran with the full text; a new call needs its full text written out.]"
  );
}

// The input as the history keeps it: its start, then the note for the rest.
export function notedInput(value: string): string {
  let end = HEAD_CHARS;
  // Not through the middle of a surrogate pair: half of one is not valid JSON
  // text to every upstream.
  const last = value.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return `${value.slice(0, end)}\n${inputNote(value.length - end)}`;
}

// A string that is the note or ends in it, not one that mentions it: a grep
// for the wording, or a file about this proxy, is ordinary input. The start
// form is what proxies before HEAD_CHARS wrote, and what a model writes when
// it copies the note without the text above it.
const WORDING = "\\[\\d+ (?:more )?chars of this earlier call's input removed from the history\\b";
const NOTE_FIRST = new RegExp(`^\\s*${WORDING}`);
const NOTE_LAST = new RegExp(`${WORDING}[^\\]]*\\]\\s*$`);
// As deep as shaping masks (INPUT_DEPTH_MAX in shape.ts): an edit list inside
// an input.
const DEPTH_MAX = 4;

export function holdsInputNote(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return NOTE_FIRST.test(value) || NOTE_LAST.test(value);
  if (!value || typeof value !== "object" || depth >= DEPTH_MAX) return false;
  return Object.values(value).some((inner) => holdsInputNote(inner, depth + 1));
}

// No tag lifts this one: there is no reading of the call in which the note is
// what the model meant to run or write.
export const NOTE_AS_INPUT =
  "Not run, and nothing changed: this call's input is, or ends in, the note that stands in for " +
  "an earlier call's input in the history, not real input. The text it replaced is no longer " +
  "in the conversation. Write the full input for this call yourself, and read the file again " +
  "first if you need its content.";
