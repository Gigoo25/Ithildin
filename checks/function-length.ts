// Every function outside the tests is at most FUNCTION_LINES_MAX lines, from
// its first line to its closing brace (TigerStyle's hard limit). Tests are
// exempt: their describe blocks group cases, they are not logic.
//
//   bun checks/function-length.ts <repo root>
//
// TYPESCRIPT names a TypeScript 5 package directory (its JS parser API).
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import type * as TS from "typescript";

const FUNCTION_LINES_MAX = 70;
const SKIPPED_DIRS = new Set(["node_modules", "coverage", ".git"]);
// The proxy's engine is a symlink to the engine directory, checked there.
const SKIPPED_PATHS = new Set(["proxy/engine"]);

const ts = createRequire(import.meta.url)(process.env.TYPESCRIPT ?? "typescript") as typeof TS;

function sourceFiles(root: string, dir = ""): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(path.join(root, dir), { withFileTypes: true })) {
    const rel = path.join(dir, entry.name);
    if (SKIPPED_DIRS.has(entry.name) || SKIPPED_PATHS.has(rel)) continue;
    if (entry.isDirectory()) out.push(...sourceFiles(root, rel));
    else if (/\.ts$/.test(rel) && !/\.(test|node-check)\.ts$/.test(rel)) out.push(rel);
  }
  return out;
}

function nameOf(node: TS.Node): string {
  const named = (node as { name?: TS.Node }).name;
  if (named) return named.getText();
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent))
    return parent.name.getText();
  return "<anonymous>";
}

export function overLimit(file: string, text: string, limit = FUNCTION_LINES_MAX): string[] {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const found: string[] = [];
  const visit = (node: TS.Node): void => {
    if (ts.isFunctionLike(node) && (node as { body?: TS.Node }).body) {
      const first = source.getLineAndCharacterOfPosition(node.getStart()).line;
      const last = source.getLineAndCharacterOfPosition(node.end).line;
      const lines = last - first + 1;
      if (lines > limit) found.push(`${file}:${first + 1}: ${nameOf(node)} is ${lines} lines`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

if (import.meta.main) {
  const root = process.argv[2] ?? ".";
  const files = sourceFiles(root);
  if (files.length === 0) throw new Error(`no source files under ${root}`);
  const found = files.flatMap((file) =>
    overLimit(file, readFileSync(path.join(root, file), "utf8")),
  );
  for (const line of found) console.error(line);
  console.error(
    `${files.length} files, ${found.length} functions over ${FUNCTION_LINES_MAX} lines`,
  );
  process.exit(found.length === 0 ? 0 : 1);
}
