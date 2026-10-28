// What must hold of every shaped request, alone and against the one before.
// The properties shape.ts promises in its header (pure, stepped, never moving
// back), and what a provider would refuse: a result with no call, an empty
// turn, a marker on thinking, more markers than allowed.

import { createHash } from "node:crypto";
import { MARKERS_MAX } from "../src/mark.ts";
import type { Format } from "../src/redact.ts";
import { listOf, systemOf } from "./workload.ts";

type Fields = Record<string, unknown>;

export interface Violation {
  check: string;
  detail: string;
}

function record(value: unknown): Fields | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Fields)
    : undefined;
}

function blocks(item: unknown): Fields[] {
  const content = record(item)?.content;
  return Array.isArray(content) ? (content as Fields[]) : [];
}

function anthropicPairs(list: unknown[]): Violation[] {
  const out: Violation[] = [];
  list.forEach((item, at) => {
    const entry = record(item)!;
    if (Array.isArray(entry.content) && entry.content.length === 0)
      out.push({ check: "valid", detail: `message ${at} is empty` });
    if (at > 0 && record(list[at - 1])?.role === entry.role)
      out.push({ check: "valid", detail: `messages ${at - 1} and ${at} share a role` });
    const asked = new Set(
      blocks(list[at - 1])
        .filter((block) => block.type === "tool_use")
        .map((block) => block.id),
    );
    for (const block of blocks(item))
      if (block.type === "tool_result" && !asked.has(block.tool_use_id))
        out.push({ check: "valid", detail: `message ${at} answers a call not just made` });
  });
  return out;
}

function markerChecks(body: Fields): Violation[] {
  const text = JSON.stringify(body);
  const count = text.split('"cache_control"').length - 1;
  const out: Violation[] = [];
  if (count > MARKERS_MAX) out.push({ check: "valid", detail: `${count} cache markers` });
  for (const item of listOf("anthropic", body))
    for (const block of blocks(item))
      if (block.type === "thinking" && block.cache_control)
        out.push({ check: "valid", detail: "a marker on a thinking block" });
  return out;
}

function callPairs(format: Format, list: unknown[]): Violation[] {
  const made = new Set<unknown>();
  const out: Violation[] = [];
  for (const item of list) {
    const entry = record(item)!;
    if (format === "responses") {
      if (entry.type === "function_call") made.add(entry.call_id);
      if (entry.type === "function_call_output" && !made.has(entry.call_id))
        out.push({ check: "valid", detail: `output for unknown call ${String(entry.call_id)}` });
    } else {
      for (const call of (entry.tool_calls as Fields[] | undefined) ?? []) made.add(call.id);
      if (entry.role === "tool" && !made.has(entry.tool_call_id))
        out.push({ check: "valid", detail: `tool message for unknown call` });
    }
  }
  return out;
}

function partsOf(item: unknown): Fields[] {
  const parts = record(item)?.parts;
  return Array.isArray(parts) ? (parts as Fields[]) : [];
}

// What Gemini refuses: a turn with no parts or a role it does not know, and a
// turn of results that does not answer the calls of the model turn just
// before it, one result per call by name (calls carry no id).
function geminiPairs(list: unknown[]): Violation[] {
  const out: Violation[] = [];
  list.forEach((item, at) => {
    const role = record(item)?.role;
    if (role !== "user" && role !== "model")
      out.push({ check: "valid", detail: `turn ${at} has role ${String(role)}` });
    const parts = partsOf(item);
    if (parts.length === 0) out.push({ check: "valid", detail: `turn ${at} has no parts` });
    const results = parts.filter((part) => record(part.functionResponse));
    if (results.length === 0) return;
    const before = list[at - 1];
    const calls = partsOf(before).filter((part) => record(part.functionCall));
    const names = (list: Fields[], key: string) =>
      list
        .map((part) => String(record(part[key])?.name))
        .sort()
        .join(",");
    if (
      record(before)?.role !== "model" ||
      names(calls, "functionCall") !== names(results, "functionResponse")
    )
      out.push({ check: "valid", detail: `turn ${at} answers calls not just made` });
  });
  return out;
}

// What a provider would refuse.
export function valid(format: Format, body: Fields): Violation[] {
  const list = listOf(format, body);
  if (format === "anthropic") return [...anthropicPairs(list), ...markerChecks(body)];
  if (format === "gemini") return geminiPairs(list);
  return callPairs(format, list);
}

// The last message is what the model answers, so shaping may compact a result
// in it but never take a turn away.
export function keepsTail(format: Format, before: Fields, after: Fields): Violation[] {
  const a = listOf(format, before);
  const b = listOf(format, after);
  const role = (item: unknown) => record(item)?.role ?? record(item)?.type;
  if (b.length === 0 || role(a.at(-1)) !== role(b.at(-1)))
    return [{ check: "tail", detail: "the last message changed kind" }];
  return [];
}

// A digest per part, in the order the provider caches them, without markers.
export function parts(format: Format, body: Fields): string[] {
  const digest = (value: unknown) =>
    createHash("sha1")
      .update(
        JSON.stringify(value ?? null, (key, inner) =>
          key === "cache_control" ? undefined : inner,
        ),
      )
      .digest("base64");
  return [body.model, body.tools, systemOf(format, body), ...listOf(format, body)].map(digest);
}

// The first part where `now` stops extending `before`, or -1 when it only
// appended.
export function firstChange(before: string[], now: string[]): number {
  for (let at = 0; at < before.length; at++) if (before[at] !== now[at]) return at;
  return -1;
}
