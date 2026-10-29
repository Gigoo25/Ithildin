// Replays a conversation through shaping one request at a time, as the agent
// sent it, checks every shaped request, and prices the run against a model of
// the provider's cache with shaping on and off.
//
// The checks are the ones a live proxy cannot afford: shaping each request
// twice to prove it pure, and comparing every request with the one before it
// to find each place the cached prefix broke and say why.

import { createHash } from "node:crypto";
import { cachePrices, type CachePrices } from "../src/prices.ts";
import { shapeRequest, type Retrieval } from "../src/shape.ts";
import type { Format } from "../src/redact.ts";
import { Cache, cost, type Usage } from "./cache.ts";
import { firstChange, keepsTail, parts, valid, type Violation } from "./checks.ts";
import { listOf, requestsOf } from "./workload.ts";

type Fields = Record<string, unknown>;

export interface Found extends Violation {
  request: number;
}

export interface Report {
  requests: number;
  steps: number;
  // Requests whose shaped prefix broke where the agent's did not: on a step,
  // where the last typed turn moved (the thinking strip and Responses and chat
  // reasoning follow it), where only a harness note beside a result moved it,
  // or for no reason shaping gives.
  breaks: { step: number; typed: number; note: number; unexplained: number };
  // What the run cost against the cache model, in uncached-input tokens.
  cost: { on: number; off: number };
  // The largest prompt sent, in tokens, with shaping on and off.
  largest: { on: number; off: number };
  // Tokens written to the cache by requests whose shaped prefix broke.
  rewritten: number;
  violations: Found[];
}

const VIOLATIONS_MAX = 20;

function retrieval(kept: Map<string, string>): Retrieval {
  return {
    tool: "ithildin_retrieve",
    keep: (text) => {
      const id = createHash("sha1").update(text).digest("hex").slice(0, 12);
      kept.set(id, text);
      return id;
    },
  };
}

// The index of the last turn a person typed: what the thinking strip and the
// reasoning drop follow. Mirrors lastTyped and lastAsked in shape.ts.
// With `person`, notes a harness adds (a block that is one tag) do not count.
const NOTE = /^\s*<([a-z][\w-]*)>[\s\S]*<\/\1>\s*$/;

function typedAt(format: Format, list: unknown[], person = false): number {
  return list.findLastIndex((item) => {
    const entry = item as Fields;
    if (format === "responses")
      return (entry.type ?? "message") === "message" && entry.role === "user";
    if (entry.role !== "user") return false;
    // Gemini is read as its Anthropic view: a result part is a tool_result.
    if (format === "gemini")
      return ((entry.parts ?? []) as Fields[]).some(
        (part) => !part.functionResponse && !(person && NOTE.test(String(part.text ?? ""))),
      );
    if (format === "chat" || !Array.isArray(entry.content)) return true;
    return (entry.content as Fields[]).some(
      (block) => block.type !== "tool_result" && !(person && NOTE.test(String(block.text ?? ""))),
    );
  });
}

function unknownIds(body: Fields, kept: Map<string, string>): Violation[] {
  const ids = [...JSON.stringify(body).matchAll(/with id \\"([0-9a-f]+)\\"/g)].map((m) => m[1]!);
  return ids
    .filter((id) => !kept.has(id))
    .map((id) => ({ check: "retrieve", detail: `stub names ${id}, which was never kept` }));
}

interface State {
  report: Report;
  kept: Map<string, string>;
  cutoff: number;
  // The previous request's digests (checks.ts parts), kept so each request
  // is digested once rather than again as the next one's `before`.
  previous?: { raw: Fields; parts: { raw: string[]; shaped: string[] } };
  on: Cache;
  off: Cache;
  strip: boolean;
  route: string | undefined;
}

function shapeOnce(format: Format, raw: Fields, state: State, at: number) {
  const add = (found: Violation[]) => {
    for (const v of found)
      if (state.report.violations.length < VIOLATIONS_MAX)
        state.report.violations.push({ ...v, request: at });
  };
  const shape = () =>
    shapeRequest(format, structuredClone(raw), retrieval(state.kept), state.strip, state.route);
  const result = shape();
  const again = shape();
  if (JSON.stringify(result?.body) !== JSON.stringify(again?.body))
    add([{ check: "pure", detail: "the same request shaped two ways" }]);
  const shaped = result?.body ?? raw;
  add(valid(format, shaped));
  add(keepsTail(format, raw, shaped));
  add(unknownIds(shaped, state.kept));
  if (result?.step) {
    const { from, to } = result.step;
    if (from !== state.cutoff || to <= from)
      add([{ check: "stepped", detail: `step ${from}→${to} after a cutoff of ${state.cutoff}` }]);
    state.cutoff = to;
  }
  return { shaped, step: result?.step !== undefined, add };
}

function moved(format: Format, before: Fields, now: Fields, person: boolean): boolean {
  return (
    typedAt(format, listOf(format, before), person) !== typedAt(format, listOf(format, now), person)
  );
}

function compare(format: Format, raw: Fields, shaped: Fields, step: boolean, state: State) {
  const before = state.previous;
  const now = { raw: parts(format, raw), shaped: parts(format, shaped) };
  state.previous = { raw, parts: now };
  if (!before) return false;
  if (firstChange(before.parts.raw, now.raw) >= 0) return false;
  const at = firstChange(before.parts.shaped, now.shaped);
  if (at < 0) return false;
  const { breaks } = state.report;
  if (step) breaks.step++;
  else if (moved(format, before.raw, raw, true)) breaks.typed++;
  else if (moved(format, before.raw, raw, false)) breaks.note++;
  else {
    breaks.unexplained++;
    return "unexplained";
  }
  return true;
}

// Priced as shape.ts prices a step on `route`: the route's prices, with every
// Anthropic write at the hour's. With no route, the fixed prices in cache.ts.
function routePrices(format: Format, body: Fields, route?: string): CachePrices | undefined {
  if (route === undefined) return undefined;
  const prices = cachePrices(body.model, route);
  return format === "anthropic" ? { ...prices, write: 2 } : prices;
}

const sent = (usage: Usage) => usage.read + usage.write + usage.uncached;

export function simulate(format: Format, body: Fields, strip = true, route?: string): Report {
  const report: Report = {
    requests: 0,
    steps: 0,
    breaks: { step: 0, typed: 0, note: 0, unexplained: 0 },
    cost: { on: 0, off: 0 },
    largest: { on: 0, off: 0 },
    rewritten: 0,
    violations: [],
  };
  const state: State = {
    report,
    kept: new Map(),
    cutoff: 0,
    on: new Cache(format),
    off: new Cache(format),
    strip,
    route,
  };
  const prices = routePrices(format, body, route);
  requestsOf(format, body).forEach((raw, at) => {
    report.requests++;
    const { shaped, step, add } = shapeOnce(format, raw, state, at);
    if (step) report.steps++;
    const broke = compare(format, raw, shaped, step, state);
    if (broke === "unexplained")
      add([
        { check: "prefix", detail: "the shaped prefix changed with no step and no new prompt" },
      ]);
    const on = state.on.send(shaped);
    const off = state.off.send(raw);
    report.cost.on += cost(format, on, prices);
    report.cost.off += cost(format, off, prices);
    report.largest.on = Math.max(report.largest.on, sent(on));
    report.largest.off = Math.max(report.largest.off, sent(off));
    if (broke) report.rewritten += on.write + on.uncached;
  });
  return report;
}
