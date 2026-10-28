// What a cache read and a cache write cost on each model, relative to
// uncached input, for the step gate in shape.ts. Neither the Models API nor a
// reply's usage says what a model charges, so this is a table
// (prices.data.ts, built from models.dev by prices-update.ts), and a table
// goes stale on a release.
//
// A route is priced from its provider's list: OpenCode Go resells a model at
// its own price, and that price is what its allowance counts. A route the
// table does not know (a LAN server, a provider added in routes.json) takes a
// model's price from its maker's list, and the common price for anything else.
//
// A model its route's list does not name gets the lowest read and the highest
// write in it, and the proxy says so once. Both make a step look worth less,
// so the gate takes fewer of them: a wrong guess costs a saving missed, never a
// rewrite that did not pay (the mistake this table exists to stop, on
// 2026-10-09).
//
// The user config overrides a read price, under "cacheReadPrices", keyed by
// model name with * and ? globs:
//
//   "cacheReadPrices": { "claude-opus-6*": 0.05 }

import { globRegExp } from "../engine/core.ts";
import { readConfigFile } from "../engine/lib/rules.ts";
import { configKey, guardConfigFile } from "./policy.ts";
import { CACHE_PRICES } from "./prices.data.ts";
import type { Ratios } from "./prices-update.ts";

// The models.dev provider each built-in route pays.
export const ROUTE_PROVIDERS: Readonly<Record<string, string>> = {
  anthropic: "anthropic",
  "openai-codex": "openai",
  "opencode-go": "opencode-go",
};
const MAKERS = ["anthropic", "openai", "google"];

export interface CachePrices {
  read: number;
  write: number;
}

// A request with no model names nothing to price, and a model no list knows
// on a route none prices gets this: a tenth to read, no write premium.
export const COMMON: CachePrices = { read: 0.1, write: 1 };

let cached: { key: string; entries: Array<[RegExp, number]> } | undefined;
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

function overrides(): Array<[RegExp, number]> {
  const file = guardConfigFile();
  const key = configKey(file);
  if (cached?.key !== key) {
    const parsed = key.endsWith("\0absent")
      ? { entries: [], problems: [] }
      : parseReadPrices(readConfigFile(file, "user config"));
    for (const problem of parsed.problems)
      process.stderr.write(`ithildin: user config: ${problem}, ignoring\n`);
    const entries = parsed.entries.map(([model, price]): [RegExp, number] => [
      globRegExp(model),
      price,
    ]);
    cached = { key, entries };
  }
  return cached.entries;
}

// A model is matched whole, and also with a date or a variant after it
// (claude-opus-5-5-20260401, claude-opus-5-5[1m]), but claude-opus-5 does not
// match claude-opus-5-5.
function modelBase(model: string): string {
  return model.replace(/\[.*\]$/, "").replace(/-\d{8}$/, "");
}

function listed(provider: string, model: string): Ratios | undefined {
  const table = CACHE_PRICES[provider];
  return table?.[model] ?? table?.[modelBase(model)];
}

// The cautious price for a model the route's list does not name.
function cautious(provider: string): CachePrices {
  const all = Object.values(CACHE_PRICES[provider] ?? {});
  return {
    read: Math.min(...all.map(([read]) => read)),
    write: Math.max(...all.map(([, write]) => write)),
  };
}

function fromTables(model: string, route: string | undefined, warn: boolean): CachePrices {
  const provider = route === undefined ? undefined : ROUTE_PROVIDERS[route];
  for (const name of provider ? [provider] : MAKERS) {
    const known = listed(name, model);
    if (known) return { read: known[0], write: known[1] };
  }
  if (!provider) return COMMON;
  const price = cautious(provider);
  // The proxy's own self-test names no real model: nothing to act on.
  if (model === "selftest") return price;
  const said = `${route}\0${model}`;
  if (warn && !warned.has(said)) {
    warned.add(said);
    process.stderr.write(
      `ithildin: cache price unknown for ${model} on ${route}; assuming ${price.read}x to ` +
        `read and ${price.write}x to write, run proxy/src/prices-update.ts or add it ` +
        `under "cacheReadPrices" in config.json\n`,
    );
  }
  return price;
}

export function cachePrices(model: unknown, route?: string): CachePrices {
  if (typeof model !== "string" || model === "") return COMMON;
  const base = modelBase(model);
  const override = overrides().find(([pattern]) => pattern.test(model) || pattern.test(base));
  const price = fromTables(model, route, override === undefined);
  return override ? { ...price, read: override[1] } : price;
}
