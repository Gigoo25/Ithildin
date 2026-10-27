// Every shrunk failure in repros/ replayed through a fresh proxy: each was a
// bug the simulator found (shrink.ts made the tape), and each must stay fixed.
// A process a tape, as trial.ts says why.

import { describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "./loop.ts";
import { loadTape, matches } from "./tape.ts";

const DIR = join(import.meta.dir, "repros");
const tapes = readdirSync(DIR).filter((name) => name.endsWith(".json"));

describe("simulator repros", () => {
  test("there are some", () => expect(tapes.length).toBeGreaterThan(0));
  for (const name of tapes)
    test(
      name,
      () => {
        const file = join(DIR, name);
        const tape = loadTape(file);
        const run = Bun.spawnSync(["bun", join(import.meta.dir, "trial.ts"), file]);
        const last = run.stdout.toString().trim().split("\n").at(-1) ?? "";
        const findings = (JSON.parse(last) as { findings: Finding[] }).findings;
        expect(findings.filter((finding) => matches(tape, tape.target!, finding))).toEqual([]);
      },
      60_000,
    );
});
