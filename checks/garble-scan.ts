// Finds text the engine would rewrite in real repositories: candidates for
// false positives that garble what an agent reads. Prints counts per rule
// and a few samples per rule, each matched value shown only as its shape
// (Aaaa 99), so real personal data in a scanned repo is not printed.
//
//   bun checks/garble-scan.ts [--samples N] <repo>...
//
// Tracked text files only (git ls-files), each under 1 MB.

import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { scan } from "../engine/lib/rules.ts";

const CHUNK = 20_000;
const MAX_FILE = 1_000_000;
const BINARY = new RegExp(
  String.raw`\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|xz|zst|wasm|woff2?|ttf|otf|mp[34]|db|` +
    String.raw`sqlite|lock|bin|exe|so|dylib|a|o)$`,
  "i",
);

const args = process.argv.slice(2);
let samples = 5;
const repos: string[] = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--samples") samples = Number(args[++i]);
  else repos.push(args[i]!);
}

const shape = (value: string) =>
  value.replace(/[A-Z]/g, "A").replace(/[a-z]/g, "a").replace(/[0-9]/g, "9");
const oneLine = (text: string) => text.replace(/\s+/g, " ");

function trackedFiles(repo: string): string[] {
  try {
    return execFileSync("git", ["-C", repo, "ls-files", "-z"], { encoding: "utf8" })
      .split("\0")
      .filter((file) => file && !BINARY.test(file))
      .map((file) => path.join(repo, file));
  } catch {
    return [];
  }
}

for (const repo of repos) {
  const counts = new Map<string, number>();
  const shown = new Map<string, string[]>();
  let chars = 0;
  for (const file of trackedFiles(repo)) {
    let text: string;
    try {
      if (statSync(file).size > MAX_FILE) continue;
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (text.includes("\0")) continue;
    chars += text.length;
    for (let at = 0; at < text.length; at += CHUNK) {
      const chunk = text.slice(at, at + CHUNK);
      for (const finding of scan(chunk)) {
        if (finding.category !== "pii") continue;
        const id = finding.ruleId;
        counts.set(id, (counts.get(id) ?? 0) + 1);
        const list = shown.get(id) ?? [];
        if (list.length >= samples) continue;
        const start = finding.start;
        const end = finding.end;
        const before = oneLine(chunk.slice(Math.max(0, start - 40), start));
        const after = oneLine(chunk.slice(end, end + 30));
        list.push(`${path.relative(repo, file)}: ${before}⟨${shape(finding.secretValue)}⟩${after}`);
        shown.set(id, list);
      }
    }
  }
  console.log(`== ${path.basename(repo)} (${Math.round(chars / 1000)}k chars)`);
  for (const [id, count] of [...counts].sort((a, b) => b[1] - a[1])) {
    console.log(`${count}\t${id}`);
    for (const line of shown.get(id) ?? []) console.log(`\t${line}`);
  }
}
