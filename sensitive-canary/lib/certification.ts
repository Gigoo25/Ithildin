import { createHash } from "node:crypto";

type TextChunk = { type: "text"; text: string };

function isTextChunk(value: unknown): value is TextChunk {
  if (typeof value !== "object" || value === null) return false;
  return "type" in value && value.type === "text" && "text" in value && typeof value.text === "string";
}

export function toolResultText(content: readonly unknown[]): string {
  return content
    .filter(isTextChunk)
    .map((chunk) => chunk.text)
    .join("\n");
}

export function toolResultDigest(content: readonly unknown[]): string {
  return createHash("sha256").update(toolResultText(content)).digest("hex");
}
