// The top-level lists of a bash command: the parts `;`, `&&`, `||`, `&` and
// newlines separate. A pipeline stays one part (`echo x | nc host 80` sends
// its input), and so does a compound command with all of its body (a loop,
// an if, a group or a subshell). The egress check reads each part on its own:
// a home path in a `cd` before a curl was withheld as if curl sent it.
//
// Undefined when the command is outside the grammar this follows closely
// enough to trust the split (backticks, a function definition, unbalanced
// keywords or parentheses); the caller then reads it as one part.
// Expects quotes masked and heredoc bodies blanked, same length as the
// command, so offsets carry over.

export type Range = [number, number];

// `&>f`, `2>&1` and `>&2` are redirections inside a word, not separators.
const TOKEN = /\$\(|\|\||&&|;;|\|&|(?:&>>?|[<>]&|[^\s;|&()`])+|[;|&\n()`]/g;
const SEPARATORS = new Set([";", "&&", "||", "&", "\n"]);
const PIPES = new Set(["|", "|&", ";;"]);
// Reserved words count only where a command starts (`echo done` is a word).
const OPENERS = new Set(["if", "case", "for", "while", "until", "select", "{"]);
const CLOSERS = new Set(["fi", "esac", "done", "}"]);
// After these the next word is again a command.
const COMMAND_NEXT = new Set(["do", "then", "else", "elif", "!", "if", "while", "until", "{"]);

export function topLevelParts(skeleton: string): Range[] | undefined {
  if (skeleton.includes("`") || /\(\s*\)|(?:^|\s)function\s/.test(skeleton)) return undefined;
  const parts: Range[] = [];
  let depth = 0;
  let start = 0;
  let command = true;
  for (const m of skeleton.matchAll(TOKEN)) {
    const token = m[0];
    if (SEPARATORS.has(token) || PIPES.has(token)) {
      if (depth === 0 && SEPARATORS.has(token)) {
        parts.push([start, m.index]);
        start = m.index + token.length;
      }
      command = true;
    } else if (token === "(" || token === "$(") {
      depth++;
      command = true;
    } else if (token === ")") {
      if (--depth < 0) return undefined;
      command = false;
    } else if (command) {
      if (OPENERS.has(token)) depth++;
      else if (CLOSERS.has(token) && --depth < 0) return undefined;
      command = COMMAND_NEXT.has(token) || /^[A-Za-z_]\w*\+?=/.test(token);
    }
  }
  if (depth !== 0) return undefined;
  parts.push([start, skeleton.length]);
  return parts.filter(([from, to]) => skeleton.slice(from, to).trim() !== "");
}

// The text outside `ranges`, as ranges of a text `length` long.
export function gaps(ranges: Range[], length: number): Range[] {
  const out: Range[] = [];
  let at = 0;
  for (const [from, to] of [...ranges].sort((a, b) => a[0] - b[0])) {
    if (from > at) out.push([at, from]);
    at = Math.max(at, to);
  }
  if (at < length) out.push([at, length]);
  return out;
}
