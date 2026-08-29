import type { Finding } from "./rules.ts";

const BIRD_EMOJIS = ["🐦", "🐧", "🐤", "🐔"];

export function randomBird(): string {
  return BIRD_EMOJIS[Math.floor(Math.random() * BIRD_EMOJIS.length)] ?? "🐦";
}

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

function parseTagsOfType(prefix: string, messages: Message[]): Set<string> {
  const tags = new Set<string>();
  const pattern = new RegExp(`\\[${prefix}-([^\\]]+)\\]`, "gi");

  for (const msg of messages) {
    if (msg.role !== "user") continue;
    const texts =
      typeof msg.content === "string"
        ? [msg.content]
        : msg.content
            .filter((b): b is TextBlock => b.type === "text")
            .map((b) => b.text);

    for (const text of texts) {
      for (const [, tag] of text.matchAll(pattern)) {
        if (tag) tags.add(tag.toLowerCase());
      }
    }
  }
  return tags;
}

export function parseAllowTags(messages: Message[]): Set<string> {
  return parseTagsOfType("allow", messages);
}

export function applyAllowTags(
  findings: Finding[],
  allowTags: Set<string>,
): Finding[] {
  if (allowTags.size === 0) return findings;
  if (allowTags.has("all")) return [];
  return findings.filter((f) => !allowTags.has(f.category));
}

export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.secretValue)) return false;
    seen.add(f.secretValue);
    return true;
  });
}

export function findingsToLines(findings: Finding[]): string[] {
  return findings.map((f) => {
    const tag = f.category === "pii" ? "PII" : "Secret";
    return `  [${tag}] ${f.description} (${f.ruleId}): ${f.matchRedacted}`;
  });
}
