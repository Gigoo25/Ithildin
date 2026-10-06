// Long JSON arrays of similar objects, cut down to the items that say
// something. Headroom's SmartCrusher is the model: an MCP result listing 200
// issues, pods or rows mostly repeats one shape, and the model needs the
// first few to see that shape, the last to see where it ends, and the ones
// that differ from the rest.
//
// What differs is read from the values, not from a list of words like
// "error": a field that takes few values across the array marks the items
// holding its rare ones, and a number far from its field's mean marks an
// outlier. A field unique to every item (an id, a title) says nothing about
// which items matter and is ignored.
//
// It is lossy, unlike every pass in compact.ts, so it never runs on its own:
// shape.ts uses it only when the agent has the proxy's retrieve tool, and adds
// the id that brings the whole output back.

export const CRUSH_MIN_ITEMS = 30;
const KEEP_HEAD = 3;
const KEEP_TAIL = 2;
// Rare items kept, beyond the head and tail. The rest are still retrievable.
const KEEP_RARE = 20;
// A value is rare when at most this share of the items hold it.
const RARE_SHARE = 0.1;
// A field with more distinct values than this share of the items is an id.
const CATEGORY_SHARE = 0.5;
const OUTLIER_SIGMAS = 3;
const OUTLIER_MIN_VALUES = 10;
const DEPTH_MAX = 32;
// Not worth the lost items unless the text shrinks at least this much.
const SHRINK_MAX = 0.8;

type Item = Record<string, unknown>;

function isItem(value: unknown): value is Item {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

// How a primitive value is counted; objects and arrays are not categories.
function category(value: unknown): string | undefined {
  if (value === undefined) return "absent";
  if (value === null || ["string", "number", "boolean"].includes(typeof value))
    return JSON.stringify(value);
  return undefined;
}

// The items holding a rare value of one field.
function rareByCategory(items: Item[], key: string, into: Set<number>): void {
  const counts = new Map<string, number>();
  const seen: Array<string | undefined> = items.map((item) => category(item[key]));
  for (const value of seen)
    if (value !== undefined) counts.set(value, (counts.get(value) ?? 0) + 1);
  if (counts.size < 2 || counts.size > items.length * CATEGORY_SHARE) return;
  const rare = Math.max(1, Math.floor(items.length * RARE_SHARE));
  const marked = seen.flatMap((value, index) =>
    value !== undefined && (counts.get(value) ?? 0) <= rare ? [index] : [],
  );
  // A field where most items are rare spreads evenly, like an id, and marks
  // nothing out.
  if (marked.length > items.length / 2) return;
  for (const index of marked) into.add(index);
}

// The items whose number in one field is far from the field's mean.
function rareByNumber(items: Item[], key: string, into: Set<number>): void {
  const values = items.map((item) => item[key]);
  const numbers = values.filter((value): value is number => typeof value === "number");
  if (numbers.length < OUTLIER_MIN_VALUES) return;
  const mean = numbers.reduce((sum, value) => sum + value, 0) / numbers.length;
  const spread = Math.sqrt(
    numbers.reduce((sum, value) => sum + (value - mean) ** 2, 0) / numbers.length,
  );
  if (spread === 0) return;
  values.forEach((value, index) => {
    if (typeof value === "number" && Math.abs(value - mean) > OUTLIER_SIGMAS * spread)
      into.add(index);
  });
}

// Which items of an array to keep, by index.
function chosen(items: Item[]): Set<number> {
  const keep = new Set<number>();
  for (let index = 0; index < Math.min(KEEP_HEAD, items.length); index++) keep.add(index);
  for (let index = Math.max(0, items.length - KEEP_TAIL); index < items.length; index++)
    keep.add(index);
  const keys = new Set(items.flatMap((item) => Object.keys(item)));
  const rare = new Set<number>();
  for (const key of keys) {
    rareByCategory(items, key, rare);
    rareByNumber(items, key, rare);
  }
  let added = 0;
  for (const index of [...rare].sort((a, b) => a - b)) {
    if (added >= KEEP_RARE) break;
    if (!keep.has(index)) added++;
    keep.add(index);
  }
  return keep;
}

function marker(count: number): string {
  return `[${count} similar item${count === 1 ? "" : "s"} omitted]`;
}

// The array with its unremarkable items replaced by a marker per gap.
function crushArray(items: unknown[], tally: { omitted: number }): unknown[] {
  if (items.length < CRUSH_MIN_ITEMS || !items.every(isItem)) return items;
  const keep = chosen(items as Item[]);
  if (keep.size >= items.length) return items;
  const out: unknown[] = [];
  let gap = 0;
  items.forEach((item, index) => {
    if (!keep.has(index)) return void gap++;
    if (gap > 0) out.push(marker(gap));
    gap = 0;
    out.push(item);
  });
  if (gap > 0) out.push(marker(gap));
  tally.omitted += items.length - keep.size;
  return out;
}

function walk(node: unknown, depth: number, tally: { omitted: number }): unknown {
  if (depth > DEPTH_MAX) return node;
  if (Array.isArray(node))
    return crushArray(
      node.map((item) => walk(item, depth + 1, tally)),
      tally,
    );
  if (!isItem(node)) return node;
  const out: Item = {};
  for (const [key, value] of Object.entries(node)) out[key] = walk(value, depth + 1, tally);
  return out;
}

// One JSON document with its long arrays crushed and its whitespace gone, and
// how many items went; undefined when it is not JSON or nothing was worth it.
export function crushJson(text: string): { text: string; omitted: number } | undefined {
  const trimmed = text.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return;
  let value: unknown;
  try {
    value = JSON.parse(trimmed);
  } catch {
    return;
  }
  const tally = { omitted: 0 };
  const crushed = JSON.stringify(walk(value, 0, tally));
  if (tally.omitted === 0 || crushed.length > text.length * SHRINK_MAX) return;
  return { text: crushed, omitted: tally.omitted };
}
