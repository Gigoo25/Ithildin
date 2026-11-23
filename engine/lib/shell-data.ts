// Parts of a bash command that are data, not file names: the pattern rg or
// grep searches for, jq's filter, and a heredoc body cat or tee only copies.
// The path guards read every word as a possible file, so `jq -r '.a | .key'`
// and `rg 'x\.pem' src` read as a private key, and `cat > notes.md <<'EOF'`
// with prose naming .env read as a dotenv read. Each such call had its whole
// output withheld though it opened no secret.
//
// Only what is certainly data is blanked; anything unsure stays checked:
// - a pattern only when every option before it is known, so an option's
//   value (`rg -g '*.key' foo`) is never taken for the pattern; an unknown
//   option gives up, and -e/-f/--regexp/--file/--files anywhere (every
//   operand is then a file) does too;
// - nothing holding `$(` or a backtick, which the shell runs;
// - a heredoc body only when its command is cat or tee and nothing in the
//   whole command could run text (a shell, an interpreter, a script by path);
// - awk and sed programs never, since they open files themselves
//   (`getline < ".env"`, `r .env`).

interface Options {
  // Short flags that take no value, and those that take one.
  flags: string;
  values: string;
  // Long options and how many values follow each (0 for a flag).
  long: Record<string, number>;
}

function long(spec: string, values: number): Record<string, number> {
  return Object.fromEntries(spec.split(" ").map((name) => [name, values]));
}

const RG: Options = {
  flags: "zsFiSvxUPawLubhnN0opqHIcl",
  values: "ABCdEgjmMrtT",
  long: {
    ...long(
      "search-zip case-sensitive fixed-strings ignore-case smart-case invert-match " +
        "line-regexp multiline pcre2 text word-regexp follow unrestricted byte-offset " +
        "line-number no-line-number null only-matching pretty quiet with-filename " +
        "no-filename count files-with-matches files-without-match count-matches hidden " +
        "no-ignore no-ignore-vcs no-ignore-dot no-ignore-parent no-ignore-global " +
        "no-messages column heading no-heading vimgrep json trim crlf multiline-dotall " +
        "no-config sort-files no-require-git one-file-system binary include-zero " +
        "passthru stats max-columns-preview",
      0,
    ),
    ...long(
      "after-context before-context context max-depth encoding glob iglob threads " +
        "max-count max-columns replace type type-not sort sortr color colors " +
        "max-filesize path-separator context-separator",
      1,
    ),
  },
};

const GREP: Options = {
  flags: "EFGPiwxzsvcLloqHhnbrRaIUZT",
  values: "ABCmdD",
  long: {
    ...long(
      "extended-regexp fixed-strings basic-regexp perl-regexp ignore-case no-ignore-case " +
        "word-regexp line-regexp null-data no-messages invert-match count " +
        "files-with-matches files-without-match only-matching quiet silent with-filename " +
        "no-filename line-number byte-offset recursive dereference-recursive text " +
        "null initial-tab",
      0,
    ),
    ...long(
      "after-context before-context context max-count include exclude exclude-dir " +
        "label binary-files directories devices color colour group-separator",
      1,
    ),
  },
};

const JQ: Options = {
  flags: "nRscrjaSCM",
  values: "L",
  long: {
    ...long(
      "null-input raw-input slurp compact-output raw-output raw-output0 join-output " +
        "ascii-output sort-keys color-output monochrome-output tab seq stream stream-errors",
      0,
    ),
    ...long("indent library-path", 1),
    // The file each of these reads stays checked: only the filter is blanked.
    ...long("arg argjson slurpfile rawfile", 2),
  },
};

const PROGRAMS: Record<string, Options> = { rg: RG, grep: GREP, egrep: GREP, fgrep: GREP, jq: JQ };

// Anywhere in the options, these make every operand a file (or list files),
// so there is no pattern operand to blank. jq's -e is a flag, but giving up on
// it costs nothing.
const NO_PATTERN = /^-(?:[A-Za-z0-9]*[ef]|-(?:regexp|file|files|from-file|type-list)(?:=|$))/;
const WRAPPERS = new Set(["sudo", "env", "command", "exec", "time", "nice", "nohup", "doas"]);
const DATA_SINKS = new Set(["cat", "tee"]);
const RUNNERS = new Set(
  (
    "bash sh zsh dash ksh fish ssh eval source . python python3 node bun deno perl " +
    "ruby php lua xargs"
  ).split(" "),
);
const RUNS_TEXT = /\$\(|`/;

const TOKEN = /\d*(?:<<-?|<>|>>|<&|>&|&>>?|<|>)|(?:"[^"\n]*"|'[^'\n]*'|[^\s|;&<>()"'])+/g;
const HEREDOC_WORD = /^<<(-?)\s*(['"]?)([^\s'"<>;|&()]+)\2/;

type Range = [number, number];
interface Token {
  text: string;
  at: number;
}
interface Segment {
  range: Range;
  words: Token[];
}

export function maskQuotes(text: string): string {
  return text.replace(/'[^']*'|"(?:[^"\\]|\\.)*"/g, (q) => q[0] + "_".repeat(q.length - 2) + q[0]);
}

function unquote(word: string): string {
  return word.replace(/^(['"])(.*)\1$/s, "$2");
}

function baseName(word: string | undefined): string {
  return unquote(word ?? "")
    .split("/")
    .pop()!;
}

// A simple command's words, redirections and their targets dropped.
function wordsIn(command: string, [start, end]: Range): Token[] {
  const words: Token[] = [];
  let target = false;
  for (const m of command.slice(start, end).matchAll(TOKEN)) {
    const at = start + m.index;
    if (/^\d*[<>&]/.test(m[0]) && !/^\d+$/.test(m[0])) target = !m[0].startsWith("<<");
    else if (target) target = false;
    else words.push({ text: m[0], at });
  }
  return words;
}

// Called with heredoc bodies already blanked, so a stray quote in prose
// cannot swallow the separators after it.
function segments(command: string): Segment[] {
  const out: Segment[] = [];
  let start = 0;
  for (const m of maskQuotes(command).matchAll(/\|\||&&|[;|&\n()]/g)) {
    // `2>&1`, `&>file` and `>&2` are redirections, not separators.
    if (m[0] === "&" && (/[<>]$/.test(command.slice(0, m.index)) || command[m.index + 1] === ">"))
      continue;
    out.push({ range: [start, m.index], words: wordsIn(command, [start, m.index]) });
    start = m.index + m[0].length;
  }
  out.push({ range: [start, command.length], words: wordsIn(command, [start, command.length]) });
  return out;
}

function programAt(words: Token[]): number {
  let i = 0;
  while (
    i < words.length &&
    (/^[A-Za-z_]\w*=/.test(words[i]!.text) || WRAPPERS.has(words[i]!.text))
  )
    i++;
  return i;
}

// How many words an option uses after itself, or undefined if unknown.
function optionValues(word: string, options: Options): number | undefined {
  if (word.startsWith("--")) {
    const [name, attached] = word.slice(2).split(/=(.*)/s);
    const count = options.long[name!];
    if (count === undefined || (attached !== undefined && count !== 1)) return undefined;
    return attached === undefined ? count : 0;
  }
  for (const [i, c] of [...word.slice(1)].entries()) {
    if (options.values.includes(c)) return i === word.length - 2 ? 1 : 0;
    if (!options.flags.includes(c)) return undefined;
  }
  return 0;
}

// The pattern or filter word, when it is certainly not a file.
export function patternWord(words: Token[]): Token | undefined {
  const at = programAt(words);
  const options = PROGRAMS[baseName(words[at]?.text)];
  if (!options) return undefined;
  const args = words.slice(at + 1).map((w) => ({ ...w, plain: unquote(w.text) }));
  for (let i = 0; i < args.length; i++) {
    const { plain } = args[i]!;
    if (plain === "--") return args[i + 1];
    if (plain === "-" || !plain.startsWith("-")) {
      const rest = args.slice(i + 1).findIndex((w) => w.plain === "--");
      const later = rest === -1 ? args.slice(i + 1) : args.slice(i + 1, i + 1 + rest);
      // grep and rg take options after operands too: -e/-f there still applies.
      return later.some((w) => NO_PATTERN.test(w.plain)) ? undefined : args[i];
    }
    if (NO_PATTERN.test(plain)) return undefined;
    const values = optionValues(plain, options);
    if (values === undefined) return undefined;
    i += values;
  }
  return undefined;
}

interface Heredoc {
  op: number;
  body: Range;
  quoted: boolean;
}

// Heredoc bodies, each with the offset of its operator. Unterminated, a body
// runs to the end, as in bash.
export function heredocBodies(command: string): Heredoc[] {
  const out: Heredoc[] = [];
  const pending: { op: number; word: string; tabs: boolean; quoted: boolean }[] = [];
  let from = 0;
  let offset = 0;
  for (const line of command.split("\n")) {
    const next = offset + line.length + 1;
    const open = pending[0];
    if (open) {
      if ((open.tabs ? line.replace(/^\t+/, "") : line) === open.word) {
        out.push({ op: open.op, body: [from, offset], quoted: open.quoted });
        pending.shift();
        from = next;
      }
    } else {
      for (const m of maskQuotes(line).matchAll(/<<(?!<)/g)) {
        const word = HEREDOC_WORD.exec(line.slice(m.index));
        if (!word) continue;
        pending.push({
          op: offset + m.index,
          word: word[3]!,
          tabs: word[1] === "-",
          quoted: word[2] !== "",
        });
      }
      from = next;
    }
    offset = next;
  }
  for (const open of pending)
    out.push({ op: open.op, body: [from, command.length], quoted: open.quoted });
  return out.filter(({ body }) => body[0] <= body[1]);
}

export function blank(command: string, ranges: Range[]): string {
  if (ranges.length === 0) return command;
  const chars = command.split("");
  for (const [start, end] of ranges)
    for (let i = start; i < end && i < chars.length; i++) if (chars[i] !== "\n") chars[i] = " ";
  return chars.join("");
}

function heredocData(command: string, bodies: Heredoc[], parsed: Segment[]): Range[] {
  const runs = parsed.some(({ words }) => {
    const name = words[programAt(words)]?.text ?? "";
    return unquote(name).includes("/") || RUNNERS.has(baseName(name));
  });
  if (runs) return [];
  const out: Range[] = [];
  for (const { op, body, quoted } of bodies) {
    // Unquoted, the shell expands $(...) and backticks in the body.
    if (!quoted && RUNS_TEXT.test(command.slice(...body))) continue;
    const owner = parsed.find(({ range }) => op >= range[0] && op < range[1]);
    if (owner && DATA_SINKS.has(baseName(owner.words[programAt(owner.words)]?.text)))
      out.push(body);
  }
  return out;
}

// The command with its data blanked to spaces, same length and lines, so
// every other word keeps its place.
export function withoutShellData(command: string): string {
  const bodies = heredocBodies(command);
  const parsed = segments(
    blank(
      command,
      bodies.map(({ body }) => body),
    ),
  );
  const ranges = heredocData(command, bodies, parsed);
  for (const { words } of parsed) {
    const word = patternWord(words);
    if (word && !RUNS_TEXT.test(word.text)) ranges.push([word.at, word.at + word.text.length]);
  }
  return blank(command, ranges);
}
