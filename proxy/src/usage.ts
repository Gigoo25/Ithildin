// What a reply says it cost, read from the provider's own usage figures.
//
// Shaping's saved characters are an upper bound on what it saves, not a
// measurement: an old result the provider already holds in its prompt cache
// costs a tenth of a fresh one, and every step of the cutoff makes the
// provider write everything after it into the cache again. Only the reply
// knows which of those happened, so this reads it, and the dashboard shows the
// cache's share beside what shaping took off the wire.
//
// The three formats spell it differently:
//
//   anthropic  usage.{input_tokens, cache_read_input_tokens,
//              cache_creation_input_tokens, output_tokens}; a stream splits it
//              between message_start (input) and message_delta (output)
//   chat       usage.{prompt_tokens, completion_tokens,
//              prompt_tokens_details.cached_tokens}; prompt_tokens includes
//              the cached ones
//   responses  usage.{input_tokens, output_tokens,
//              input_tokens_details.cached_tokens}; a stream carries it in
//              response.completed, and input_tokens includes the cached ones
//
// Everything is normalised to Anthropic's split, where `input` is only what
// was neither read from nor written to the cache.

import type { Format } from "./redact.ts";

export interface Usage {
  input: number;
  cacheRead: number;
  cacheWrite: number;
  output: number;
}

type Fields = Record<string, unknown>;

function fields(value: unknown): Fields | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Fields)
    : undefined;
}

function tokens(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

// The usage object a reply or a stream event carries, wherever it sits.
function usageObject(format: Format, value: Fields): Fields | undefined {
  if (format === "anthropic") return fields(value.usage) ?? fields(fields(value.message)?.usage);
  if (format === "responses") return fields(value.usage) ?? fields(fields(value.response)?.usage);
  return fields(value.usage);
}

// The usage in one reply body or one parsed stream event, or undefined when it
// carries none. A stream's figures arrive in parts; `merge` adds them up.
export function usageOf(format: Format, value: unknown): Usage | undefined {
  const outer = fields(value);
  const usage = outer && usageObject(format, outer);
  if (!usage) return;
  if (format === "anthropic")
    return {
      input: tokens(usage.input_tokens),
      cacheRead: tokens(usage.cache_read_input_tokens),
      cacheWrite: tokens(usage.cache_creation_input_tokens),
      output: tokens(usage.output_tokens),
    };
  const chat = format === "chat";
  const total = tokens(chat ? usage.prompt_tokens : usage.input_tokens);
  const details = fields(chat ? usage.prompt_tokens_details : usage.input_tokens_details);
  const cached = Math.min(tokens(details?.cached_tokens), total);
  return {
    input: total - cached,
    cacheRead: cached,
    cacheWrite: 0,
    output: tokens(chat ? usage.completion_tokens : usage.output_tokens),
  };
}

// Parts of one reply's usage, combined. Field by field the larger wins: an
// Anthropic message_delta repeats the running totals rather than adding to
// them, and a field a part leaves out reads as zero.
export function merge(into: Usage | undefined, part: Usage): Usage {
  if (!into) return { ...part };
  return {
    input: Math.max(into.input, part.input),
    cacheRead: Math.max(into.cacheRead, part.cacheRead),
    cacheWrite: Math.max(into.cacheWrite, part.cacheWrite),
    output: Math.max(into.output, part.output),
  };
}

// The usage in one stream event's data. Most events are text deltas, so the
// data is parsed only when it names usage at all.
export function usageOfEvent(format: Format, data: string): Usage | undefined {
  if (!data.includes('"usage"')) return;
  try {
    return usageOf(format, JSON.parse(data));
  } catch {
    return undefined;
  }
}

// How the journal names it: in/read/write/out.
export function usageText(usage: Usage): string {
  return `${usage.input}/${usage.cacheRead}/${usage.cacheWrite}/${usage.output}`;
}
