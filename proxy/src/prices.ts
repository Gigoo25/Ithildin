// What a cache read costs on each model, relative to uncached input, for the
// step gate in shape.ts. Neither the Models API nor a reply's usage says what
// a model charges, so this is a table, and a table goes stale on a release.
//
// A model the table does not name gets the lowest price in it, and the proxy
// says so once. A lower read price makes a step look worth less, so the gate
// takes fewer of them: a wrong guess costs a saving missed, never a rewrite
// that did not pay (the mistake this table exists to stop, on 2026-10-09).
//
// The user config overrides or adds to the table, under "cacheReadPrices",
// keyed by model name with * and ? globs:
//
//   "cacheReadPrices": { "claude-opus-6*": 0.05 }

import { globRegExp } from "../engine/core.ts";
import { readConfigFile } from "../engine/lib/rules.ts";
import { configKey, guardConfigFile } from "./policy.ts";

// Read price over input price, from Anthropic's pricing page, model by model:
// a family glob would let next year's model pass as known.
const TENTH = [
  "claude-sonnet-5-5",
  "claude-sonnet-5",
  "claude-sonnet-4-6",
  "claude-haiku-5-5",
  "claude-haiku-4-5",
  "claude-opus-5",
  "claude-opus-4-8",
  "claude-opus-4-7",
  "claude-opus-4-6",
  "claude-fable-5",
];
export const BUILT_IN: ReadonlyArray<[string, number]> = [
  ["claude-opus-5-5", 0.2 / 4],
  ["claude-fable-5-1", 0.25 / 10],
  ["claude-mythos-5-1", 0.25 / 10],
  ...TENTH.map((model): [string, number] => [model, 0.1]),
];

// A request with no model names nothing to price; the common price stands.
export const DEFAULT_READ = 0.1;

interface Prices {
  entries: Array<[RegExp, number]>;
  lowest: number;
}

let cached: { key: string; prices: Prices } | undefined;
const warned = new Set<string>();

// The config's entries, checked; problems go to the log and are left out.
export function parseReadPrices(config: unknown): {
  entries: Array<[string, number]>;
  problems: string[];
} {
  const section = (config as { cacheReadPrices?: unknown } | undefined)?.cacheReadPrices;
  if (section === undefined) return { entries: [], problems: [] };
  if (!section || typeof section !== "object" || Array.isArray(section))
    return { entries: [], problems: [`"cacheReadPrices" must be an object`] };
  const entries: Array<[string, number]> = [];
  const problems: string[] = [];
  for (const [model, price] of Object.entries(section)) {
    if (typeof price === "number" && price > 0 && price <= 1) entries.push([model, price]);
    else problems.push(`cacheReadPrices: "${model}" must be a number above 0, at most 1`);
  }
  return { entries, problems };
}

function prices(): Prices {
  const file = guardConfigFile();
  const key = configKey(file);
  if (cached?.key !== key) {
    const parsed = key.endsWith("\0absent")
      ? { entries: [], problems: [] }
      : parseReadPrices(readConfigFile(file, "user config"));
    for (const problem of parsed.problems)
      process.stderr.write(`ithildin: user config: ${problem}, ignoring\n`);
    // The user's entries first, so they win over the built-in ones.
    const all = [...parsed.entries, ...BUILT_IN];
    const entries = all.map(([model, price]): [RegExp, number] => [globRegExp(model), price]);
    cached = { key, prices: { entries, lowest: Math.min(...all.map(([, price]) => price)) } };
  }
  return cached.prices;
}

// A model is matched whole, and also with a date or a variant after it
// (claude-opus-5-5-20260401, claude-opus-5-5[1m]), but claude-opus-5 does not
// match claude-opus-5-5.
function modelBase(model: string): string {
  return model.replace(/\[.*\]$/, "").replace(/-\d{8}$/, "");
}

export function cacheReadPrice(model: unknown): number {
  if (typeof model !== "string" || model === "") return DEFAULT_READ;
  const { entries, lowest } = prices();
  const base = modelBase(model);
  const known = entries.find(([pattern]) => pattern.test(model) || pattern.test(base));
  if (known) return known[1];
  // Only a Claude name is a release the table missed. Anything else on this
  // format (the proxy's own self-test, a model behind a gateway) still gets
  // the cautious price, without a warning nobody can act on.
  if (/^claude-/.test(model) && !warned.has(model)) {
    warned.add(model);
    process.stderr.write(
      `ithildin: cache read price unknown for ${model}; assuming ${lowest}x, ` +
        `add it under "cacheReadPrices" in config.json\n`,
    );
  }
  return lowest;
}
