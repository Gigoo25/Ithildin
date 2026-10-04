// Shell calls that rotate letters: `tr 'A-Za-z' 'N-ZA-Mn-za-m'`, `sed y///`,
// perl's tr///, a rot13 program, Python's rot_13 codec. Run over a file, the
// output carries real values that no rule matches, so the model reads past
// its stand-ins. The call is refused before it runs; [allow-pii] lifts it.
//
// Lexical like the other guards: a script file that rotates, or a mapping
// built at run time, is out of scope. encoded.ts withholds rot13 copies of
// masked values from tool output as the second line.

import { shellCommand } from "./tools.ts";
import { shellPrograms } from "./protect.ts";

export const UNMASK_BLOCKED =
  "Not run: this command substitutes letters (rot13 or a similar cipher), which would read " +
  "past masked values. Work with the text as shown, or ask the user to include [allow-pii] " +
  "in their prompt.";

const INTERPRETERS = new Set([
  "python",
  "python2",
  "python3",
  "perl",
  "ruby",
  "node",
  "bun",
  "deno",
  "php",
  "awk",
  "gawk",
]);
const ROTATORS = new Set(["rot13", "rot-13", "caesar", "rot"]);
const ROT_CODEC = /\brot[-_]?13\b/i;

// A tr set expanded to its characters. Undefined when it holds anything but
// letters and ranges of them: digits, escapes and classes are other jobs.
function expandSet(set: string): string | undefined {
  if (/^\[:(upper|lower|alpha):\]$/.test(set)) return undefined;
  let out = "";
  for (let i = 0; i < set.length; i++) {
    const c = set[i]!;
    if (!/[A-Za-z]/.test(c)) return undefined;
    const end = set[i + 2];
    if (set[i + 1] === "-" && end && /[A-Za-z]/.test(end) && end >= c) {
      for (let code = c.charCodeAt(0); code <= end.charCodeAt(0); code++)
        out += String.fromCharCode(code);
      i += 2;
    } else {
      out += c;
    }
  }
  return out;
}

function swapCase(c: string): string {
  return c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase();
}

// Two letter sets that map some letter to a different letter, not merely
// to the other case (`tr a-z A-Z` stays allowed).
export function substitutesLetters(from: string, to: string): boolean {
  const a = expandSet(from);
  const b = expandSet(to);
  if (!a || !b) return false;
  for (let i = 0; i < a.length; i++) {
    // tr pads a short second set with its last character.
    const c = a[i]!;
    const mapped = b[Math.min(i, b.length - 1)]!;
    if (mapped !== c && mapped !== swapCase(c)) return true;
  }
  return false;
}

// tr/../../ and y/../../ in sed or perl code, any delimiter.
const TRANSLITERATION = /(?:^|[^\w])(?:tr|y)([^\w\s])((?:(?!\1).)+)\1((?:(?!\1).)*)\1/g;

function codeSubstitutes(code: string): boolean {
  for (const match of code.matchAll(TRANSLITERATION))
    if (substitutesLetters(match[2]!, match[3]!)) return true;
  return false;
}

function trSubstitutes(argv: string[]): boolean {
  const sets = argv.slice(1).filter((word) => !/^-/.test(word));
  if (argv.slice(1).some((word) => /^-[a-z]*[ds]/.test(word))) return false;
  return sets.length >= 2 && substitutesLetters(sets[0]!, sets[1]!);
}

// Whether a shell call would rotate or substitute letters.
export function unmasksText(args: unknown): boolean {
  const command = shellCommand(args);
  if (command === undefined) return false;
  for (const argv of shellPrograms(command)) {
    const name = argv[0] ?? "";
    if (ROTATORS.has(name)) return true;
    if (name === "tr" && trSubstitutes(argv)) return true;
    if ((name === "sed" || name === "perl") && codeSubstitutes(argv.slice(1).join(" ")))
      return true;
    // Heredoc bodies are dropped from the parsed programs, so an
    // interpreter's code is read from the whole command line.
    if (INTERPRETERS.has(name) && (ROT_CODEC.test(command) || codeSubstitutes(command)))
      return true;
  }
  return false;
}
