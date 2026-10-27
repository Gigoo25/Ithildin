// What the drivers that compare runs share (restart.ts, subagents.ts): trials
// of a tape in fresh processes, each on a state directory of its own, and
// where two forwarded prompts part.

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { join } from "node:path";

const HERE = import.meta.dir;

export function option(name: string): string | undefined {
  const at = process.argv.indexOf(`--${name}`);
  return at < 0 ? undefined : process.argv[at + 1];
}

export interface Trial {
  sent: string[];
  real: string[];
  findings: Array<{ check: string; request: number; detail: string }>;
}

export class Trials {
  readonly scratch: string;
  private fresh = 0;

  constructor(prefix: string) {
    this.scratch = mkdtempSync(join(tmpdir(), `ithildin-${prefix}-`));
    process.on("exit", () => rmSync(this.scratch, { recursive: true, force: true }));
  }

  // The tape replayed in a process of its own, on state directory `dir`.
  async run(tape: string, dir: string, ...args: string[]): Promise<Trial> {
    const child = Bun.spawn(["bun", join(HERE, "trial.ts"), tape, ...args], {
      stdout: "pipe",
      stderr: "ignore",
      env: { ...process.env, ITHILDIN_SIM_DIR: dir },
    });
    const out = await new Response(child.stdout).text();
    await child.exited;
    const last = out.trim().split("\n").at(-1);
    return last ? (JSON.parse(last) as Trial) : { sent: [], real: [], findings: [] };
  }

  dir(): string {
    return mkdtempSync(join(this.scratch, `state-${++this.fresh}-`));
  }

  // Request `at`'s prompt as a trial forwarded it.
  async dump(tape: string, dir: string, at: number, args: string[]): Promise<string> {
    const file = join(this.scratch, `dump-${++this.fresh}`);
    await this.run(tape, dir, ...args, "--dump-at", String(at), file);
    return readFileSync(file, "utf8");
  }
}

// Where two prompts part, with a little of each.
export function parting(a: string, b: string): string {
  let at = 0;
  while (at < a.length && a[at] === b[at]) at++;
  const show = (text: string) => JSON.stringify(text.slice(Math.max(0, at - 60), at + 100));
  return `at character ${at}: was ${show(a)}, now ${show(b)}`;
}

// Jobs a few at a time: each records in this process and starts trials of
// its own, so the width is well under the cores.
export async function pool<T>(jobs: Array<() => Promise<T>>, per = 6): Promise<T[]> {
  const results: T[] = [];
  const width = Math.max(1, Math.floor(availableParallelism() / per));
  await Promise.all(
    Array.from({ length: width }, async () => {
      for (let job = jobs.shift(); job; job = jobs.shift()) results.push(await job());
    }),
  );
  return results;
}
