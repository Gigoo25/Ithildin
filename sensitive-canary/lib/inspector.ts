import type { Finding } from "./rules.ts";

export type { Finding };

type TextBlock = { type: "text"; text: string };
type ToolResultBlock = {
  type: "tool_result";
  content: string | ContentBlock[];
};
type ToolUseBlock = { type: "tool_use"; input: Record<string, unknown> };
type ContentBlock = TextBlock | ToolResultBlock | ToolUseBlock;

export interface Message {
  role: string;
  content: string | ContentBlock[];
}

// What the user actually typed, as opposed to what the runtime wrote around it
// or what the user quoted. Both hooks read tags out of this: they answered the
// question separately once, and the prompt hook read the raw text, so a pasted
// log containing `[allow-secrets]` lifted the guard on the same message's key.
//
// Claude Code writes things the user did not type into the transcript as user
// messages with plain string content: the output of a `!` command, the name and
// arguments of a slash command, system reminders, and a background task
// reporting back. A tag in any of those switches the protection off —
// `grep -r allow-all` is enough, and so is a subagent whose report quotes the
// documentation for these tags.
//
// A list of names is a list, and the runtime is free to add to it. The
// transcript reader asks `origin.kind` instead, which answers the question
// directly. This is what covers the same lines when the field is not there.
export const SYNTHETIC_ELEMENT_NAMES = [
  "local-command-stdout",
  "local-command-stderr",
  "command-name",
  "command-message",
  "command-args",
  "bash-input",
  "bash-output",
  "bash-stdout",
  "bash-stderr",
  "system-reminder",
  "task-notification",
].join("|");

const SYNTHETIC_USER_ELEMENTS = new RegExp(`<(${SYNTHETIC_ELEMENT_NAMES})>[\\s\\S]*?<\\/\\1>`, "g");

// An opening tag with nothing closing it takes the rest of the message with it.
// Pairs alone would have left an unclosed one — a truncated capture, or output
// that happens to contain the tag — reading as the user speaking.
const UNCLOSED_SYNTHETIC_ELEMENT = new RegExp(`<(?:${SYNTHETIC_ELEMENT_NAMES})>[\\s\\S]*$`, "g");

// Text inside a fence is being quoted, not issued: a pasted log or diff that
// happens to contain the tag is not the user asking for it.
//
// Backticks around a single word are not the same thing. The documentation here
// writes the tags that way — `[allow-secrets]` — so stripping them refused the
// form the project itself teaches, and refused it silently: the block that
// followed advised adding the tag it had just ignored.
//
// From the first marker to the last, rather than marker one to marker two and
// marker three to marker four. Pairing them off leaves the span between the
// second and third readable as typed, and a pasted markdown document with a
// code block inside it puts a quoted tag in exactly that span. Which markers
// open and which close cannot be told apart here — a document quoting a fence
// is the same characters as two documents — so the whole run counts as quoted.
// A tag before the first fence or after the last still reads as typed.
const FENCED_CODE = /(?:```|~~~)[\s\S]*(?:```|~~~)/g;

// A fence that never closes takes the rest of the message with it, the way an
// unclosed synthetic element does. Pairs alone let a truncated paste through:
// the quoting is what the fence marks, and a paste cut short is still a paste.
const UNCLOSED_FENCE = /(?:```|~~~)[\s\S]*$/g;

// What the user actually typed, with the above taken out.
export function userTypedText(msg: Message): string {
  const blocks =
    typeof msg.content === "string"
      ? [msg.content]
      : msg.content.filter((b) => b.type === "text").map((b) => b.text ?? "");
  return blocks
    .join("\n")
    .replace(SYNTHETIC_USER_ELEMENTS, " ")
    .replace(UNCLOSED_SYNTHETIC_ELEMENT, " ")
    .replace(FENCED_CODE, " ")
    .replace(UNCLOSED_FENCE, " ");
}

// The last tag in the text is the one that applies. Earlier ones are discarded
// whole, not merged with it.
//
//   "[allow-all] … [allow-secrets]"  → secrets only. PII is blocked again
//   "[allow-secrets] … [allow-all]"  → both
//   "[mask-secret] … [allow-secrets]" → allow
//
// Merging per category would keep the wider grant of the two, so a writer who
// started with `[allow-all]` and narrowed to `[allow-secrets]` would still be
// allowing PII — the opposite of what narrowing means. Writing two tags to
// combine categories does not work either. `[allow-all]` is how both are asked
// for.
export function resolveTagPriority(prompt: string): {
  effectiveAllow: Set<string>;
  effectiveMask: Set<string>;
} {
  const pattern = /\[(allow|mask)-(all|secrets?|pii)\]/gi;
  const effectiveAllow = new Set<string>();
  const effectiveMask = new Set<string>();

  const tags = [...prompt.matchAll(pattern)];
  const last = tags[tags.length - 1];
  if (!last) return { effectiveAllow, effectiveMask };

  const kind = last[1]?.toLowerCase();
  const category = last[2]?.toLowerCase().replace("secrets", "secret");
  if (!kind || !category) return { effectiveAllow, effectiveMask };

  const target = kind === "allow" ? effectiveAllow : effectiveMask;
  if (category === "all") {
    target.add("secret");
    target.add("pii");
    target.add("all");
  } else {
    target.add(category);
  }

  return { effectiveAllow, effectiveMask };
}

export function applyAllowTags(findings: Finding[], allowTags: Set<string>): Finding[] {
  if (allowTags.size === 0) return findings;
  if (allowTags.has("all")) return [];
  return findings.filter((f) => !allowTags.has(f.category));
}

// The same value found twice is one finding. Keyed by category as well as by
// value, because one value can be both: an address in an assignment matches a
// PII rule and a secret rule, and collapsing on the value alone reported
// whichever came first and said nothing about the other. Which tag lifts the
// block then reads as arbitrary, since the message names one category and the
// other is what is holding it.
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.category}\u0000${f.secretValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
