// Line and function coverage floors over an lcov report, for source files only:
// tests, Node-only gates and the bench (test infrastructure) are not measured.
//
//   bun checks/coverage.ts <lcov.info>
//
// The floors sit just under what the suite reaches, so a change that lands
// untested code fails here instead of eroding the number a file at a time.
import { readFileSync } from "node:fs";

const TOTAL_LINES_MIN = 99;
const FILE_LINES_MIN = 97;
const FILE_FUNCTIONS_MIN = 90;
const EXCLUDED = /\.(test|node-check)\.ts$|(^|\/)bench\//;

type Counts = { lines: number; linesHit: number; functions: number; functionsHit: number };

export function parseLcov(text: string): Map<string, Counts> {
  const files = new Map<string, Counts>();
  let current: Counts | undefined;
  for (const line of text.split("\n")) {
    const [tag, value = ""] = line.trim().split(":", 2) as [string, string?];
    if (tag === "SF") {
      current = { lines: 0, linesHit: 0, functions: 0, functionsHit: 0 };
      files.set(value, current);
    } else if (current && tag === "LF") current.lines = Number(value);
    else if (current && tag === "LH") current.linesHit = Number(value);
    else if (current && tag === "FNF") current.functions = Number(value);
    else if (current && tag === "FNH") current.functionsHit = Number(value);
  }
  return files;
}

const percent = (hit: number, total: number) => (total === 0 ? 100 : (100 * hit) / total);

export function belowFloor(files: Map<string, Counts>): string[] {
  const found: string[] = [];
  let lines = 0;
  let linesHit = 0;
  for (const [file, counts] of files) {
    if (EXCLUDED.test(file)) continue;
    lines += counts.lines;
    linesHit += counts.linesHit;
    const linePct = percent(counts.linesHit, counts.lines);
    const fnPct = percent(counts.functionsHit, counts.functions);
    if (linePct < FILE_LINES_MIN)
      found.push(`${file}: lines ${linePct.toFixed(2)}% < ${FILE_LINES_MIN}%`);
    if (fnPct < FILE_FUNCTIONS_MIN)
      found.push(`${file}: functions ${fnPct.toFixed(2)}% < ${FILE_FUNCTIONS_MIN}%`);
  }
  if (lines === 0) found.push("no source files in the report");
  const total = percent(linesHit, lines);
  if (total < TOTAL_LINES_MIN)
    found.push(`total: lines ${total.toFixed(2)}% < ${TOTAL_LINES_MIN}%`);
  console.error(`source lines ${linesHit}/${lines} = ${total.toFixed(2)}%`);
  return found;
}

if (import.meta.main) {
  const report = process.argv[2];
  if (!report) throw new Error("usage: bun checks/coverage.ts <lcov.info>");
  const found = belowFloor(parseLcov(readFileSync(report, "utf8")));
  for (const line of found) console.error(line);
  process.exit(found.length === 0 ? 0 : 1);
}
