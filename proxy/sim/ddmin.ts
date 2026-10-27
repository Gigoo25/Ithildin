// Delta debugging (Zeller and Hildebrandt's ddmin): the smallest subset of a
// failing input that still fails, by trying to take away ever smaller parts.
// The candidates of a round are tried at once and the first (in order) that
// fails is kept, so the same input and test always give the same result.

function chunks<T>(items: T[], n: number): T[][] {
  const out: T[][] = [];
  const size = Math.ceil(items.length / n);
  for (let at = 0; at < items.length; at += size) out.push(items.slice(at, at + size));
  return out;
}

// The smallest subset of items (1-minimal, as far as the trials allow) that
// still fails. `fails` must be true of all of them.
export async function ddmin<T>(items: T[], fails: (keep: T[]) => Promise<boolean>): Promise<T[]> {
  if (items.length > 0 && (await fails([]))) return [];
  let n = 2;
  while (items.length >= 2) {
    const parts = chunks(items, n);
    const without = parts.map((_, i) => parts.filter((_, j) => j !== i).flat());
    const first = (await Promise.all(without.map(fails))).indexOf(true);
    if (first >= 0) {
      items = without[first]!;
      n = Math.max(n - 1, 2);
      continue;
    }
    const alone = (await Promise.all(parts.map(fails))).indexOf(true);
    if (alone >= 0) {
      items = parts[alone]!;
      n = 2;
      continue;
    }
    if (n >= items.length) break;
    n = Math.min(items.length, n * 2);
  }
  return items;
}
