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

export function inputNote(size: number): string {
  return (
    `[${size} chars of this earlier call's input removed from the history to save context. ` +
    "The call ran with the full text; a new call needs its full text written out.]"
  );
}

// A whole string that is the note, not one that mentions it: a grep for the
// wording, or a file about this proxy, is ordinary input.
const NOTE = /^\s*\[\d+ chars of this earlier call's input removed from the history\b/;
// As deep as shaping masks (INPUT_DEPTH_MAX in shape.ts): an edit list inside
// an input.
const DEPTH_MAX = 4;

export function holdsInputNote(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return NOTE.test(value);
  if (!value || typeof value !== "object" || depth >= DEPTH_MAX) return false;
  return Object.values(value).some((inner) => holdsInputNote(inner, depth + 1));
}

// No tag lifts this one: there is no reading of the call in which the note is
// what the model meant to run or write.
export const NOTE_AS_INPUT =
  "Not run: this call's input is the note that stands in for an earlier call's input in the " +
  "history, not real input. The text it replaced is no longer in the conversation. Write the " +
  "full input for this call yourself, and read the file again first if you need its content.";
