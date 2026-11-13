// The guard that refuses a new call written with the note an old call's long
// input used to become (redact.ts).
//
// Shaping cut a long string in an old input to a note, and later to its first
// 200 characters and the note: "[N more chars of this earlier call's input
// removed from the history to save context. ...]". A model that reads its own
// history as having written placeholders writes them: 46 new calls across 156
// Pi sessions had the note as their input, from every model family in use,
// and keeping the start only halved it (shape.ts, "old calls"), so inputs are
// no longer cut. As a shell command the note fails on its apostrophe
// ("unexpected EOF while looking for matching `'`"), which the model takes for
// its own quoting and retries; as a Write's content or an Edit's new text it
// does not fail at all, and the note is written into the file. The guard
// stays for a note that outlived the cut: one a summary quoted, or a
// conversation carried on from a client that kept the shaped history.

// A string that is the note or ends in it, not one that mentions it: a grep
// for the wording, or a file about this proxy, is ordinary input. The start
// form is the note alone, the end form the note closing an input's start.
const WORDING = "\\[\\d+ (?:more )?chars of this earlier call's input removed from the history\\b";
const NOTE_FIRST = new RegExp(`^\\s*${WORDING}`);
const NOTE_LAST = new RegExp(`${WORDING}[^\\]]*\\]\\s*$`);
// As deep as shaping cut: an edit list inside an input.
const DEPTH_MAX = 4;

export function holdsInputNote(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return NOTE_FIRST.test(value) || NOTE_LAST.test(value);
  if (!value || typeof value !== "object" || depth >= DEPTH_MAX) return false;
  return Object.values(value).some((inner) => holdsInputNote(inner, depth + 1));
}

// No tag lifts this one: there is no reading of the call in which the note is
// what the model meant to run or write.
export const NOTE_AS_INPUT =
  "Not run, and nothing changed: this call's input is, or ends in, a note that stood in for " +
  "an earlier call's input, not real input. Write the full input for this call yourself, and " +
  "read the file again first if you need its content.";
