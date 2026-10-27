// The machine the simulated agent works on: a small project under a home
// directory whose files are full of canaries, and the tools that read it. The
// agent side runs here with the real values, as a harness does; only the
// proxy stands between this and the fake model.

import { canary, type Canary, type Kind } from "./canaries.ts";
import { Random } from "./random.ts";
import { SCAN_WINDOW_CHARS } from "../../engine/lib/rules.ts";

const PLANTED_IN_LOGS = ["github-token", "aws-key", "email"] as const;

export interface World {
  root: string;
  files: Map<string, string>;
  canaries: Canary[];
  // The values a secret file holds: the proxy must withhold the file.
  secrets: string[];
  // Project instructions the harness puts in its system prompt (CLAUDE.md,
  // AGENTS.md), with values in them.
  memory: string;
}

function plant(world: World, random: Random, kind?: Kind): Canary {
  const made = canary(random, kind);
  world.canaries.push(made);
  return made;
}

function readme(world: World, random: Random): string {
  const lines = [`# ${random.text(30)}`, random.text(300)];
  for (let i = 0; i < 4; i++) {
    const c = plant(world, random, random.pick(["email", "host", "ip"] as const));
    lines.push(`Contact or reach ${c.value} for ${random.text(60)}`);
  }
  return lines.join("\n\n");
}

function code(world: World, random: Random): string {
  const db = plant(world, random, "db-url");
  const key = plant(
    world,
    random,
    random.pick(["anthropic-key", "openai-key", "github-token"] as const),
  );
  return [
    `import { connect } from "./db";`,
    `const url = process.env.DATABASE_URL ?? "${db.value}";`,
    `const apiKey = "${key.value}";`,
    random.text(800),
    `export const client = connect(url, apiKey);`,
  ].join("\n");
}

function config(world: World, random: Random): string {
  const jwt = plant(world, random, "jwt");
  const aws = plant(world, random, "aws-key");
  const email = plant(world, random, "email");
  const rows = Array.from({ length: random.int(5, 40) }, (_, i) => ({
    id: i,
    note: random.text(30),
  }));
  return JSON.stringify(
    { service: { token: jwt.value, aws: { accessKeyId: aws.value } }, owner: email.value, rows },
    null,
    2,
  );
}

function dotenv(world: World, random: Random): string {
  const values = [plant(world, random, "password"), plant(world, random, "slack-token")];
  const pemKey = plant(world, random, "private-key");
  world.secrets.push(...values.map((v) => v.core), pemKey.core);
  return [...values.map((v) => v.value), `SLACK=${values[1]!.value}`, `KEY="${pemKey.value}"`].join(
    "\n",
  );
}

// A log long enough to be scanned in windows, with a canary placed across the
// seam between two of them when the seed says so.
function log(world: World, random: Random): string {
  const lines: string[] = [];
  let size = 0;
  const target = random.pick([4_000, 30_000, SCAN_WINDOW_CHARS + 20_000]);
  const seam = random.chance(0.5) ? SCAN_WINDOW_CHARS : -1;
  while (size < target) {
    let line = `${random.int(0, 23)}:${random.int(10, 59)} ${random.text(60).split("\n")[0]}`;
    if (random.chance(0.05))
      line += ` from ${plant(world, random, random.pick(["ip", "host", "bearer"] as const)).value}`;
    if (seam > 0 && size < seam && size + line.length + 1 >= seam - 20) {
      const c = plant(world, random, random.pick(["github-token", "email", "card"] as const));
      line = `${" ".repeat(Math.max(0, seam - size - 10))}${c.value} seam`;
    }
    lines.push(line);
    size += line.length + 1;
  }
  return lines.join("\n");
}

function people(world: World, random: Random): string {
  return Array.from({ length: 5 }, () => {
    const email = plant(world, random, "email");
    const card = plant(world, random, "card");
    return `- ${email.value}, card ${card.value}, ${random.text(40)}`;
  }).join("\n");
}

// Build output: long, repetitive, a canary now and then. Sometimes past the
// size the engine scans at all (MAX_SCAN_BYTES), where it withholds the whole
// output instead.
function buildLog(world: World, random: Random): string {
  const size = random.chance(0.1) ? random.int(1_500_000, 2_500_000) : random.int(40_000, 200_000);
  const line = random.text(100).split("\n")[0];
  const lines: string[] = [];
  let length = 0;
  for (let i = 0; length < size; i++) {
    const next = random.chance(0.002)
      ? `step ${i}: token ${plant(world, random, random.pick(PLANTED_IN_LOGS)).value}`
      : `step ${i}: ${line}`;
    lines.push(next);
    length += next.length + 1;
  }
  return lines.join("\n");
}

// A script with a value in a URL's query and one in a heredoc.
function script(world: World, random: Random): string {
  const token = plant(world, random, random.pick(["github-token", "openai-key", "jwt"] as const));
  const email = plant(world, random, "email");
  const host = plant(world, random, "host");
  return [
    "#!/bin/sh",
    `curl -s "https://${host.value}/api/v1/deploy` +
      `?token=${token.value}&notify=${encodeURIComponent(email.value)}"`,
    "cat <<EOF > notify.txt",
    `owner: ${email.value}`,
    "EOF",
  ].join("\n");
}

function memory(world: World, random: Random): string {
  const email = plant(world, random, "email");
  const host = plant(world, random, "host");
  const key = plant(world, random, random.pick(["aws-key", "anthropic-key"] as const));
  return [
    "# Project notes",
    `Owner: ${email.value}. Staging runs on ${host.value}.`,
    "```sh",
    `export AWS_ACCESS_KEY_ID=${key.value}`,
    "```",
  ].join("\n");
}

export function makeWorld(seed: number): World {
  const random = new Random(seed ^ 0x5eed);
  const world: World = { root: "", files: new Map(), canaries: [], secrets: [], memory: "" };
  world.root = plant(world, random, "home").value;
  const at = (name: string) => `${world.root}/${name}`;
  world.files.set(at("README.md"), readme(world, random));
  world.files.set(at("src/app.ts"), code(world, random));
  world.files.set(at("config.json"), config(world, random));
  world.files.set(at(".env"), dotenv(world, random));
  world.files.set(at("logs/server.log"), log(world, random));
  world.files.set(at("notes/people.md"), people(world, random));
  world.files.set(at("logs/build.log"), buildLog(world, random));
  world.files.set(at("scripts/deploy.sh"), script(world, random));
  world.memory = memory(world, random);
  for (let i = 0; i < 8; i++)
    world.files.set(at(`src/mod${i}.ts`), random.text(random.int(2_000, 12_000)));
  return world;
}

// What a tool call returns, run against the world with the real values.
export function runTool(world: World, name: string, input: Record<string, unknown>): string {
  const path = String(input.file_path ?? input.path ?? "");
  if (name === "Read") return world.files.get(path) ?? `Error: ${path}: no such file`;
  if (name === "Write") {
    world.files.set(path, String(input.content ?? ""));
    return `Wrote ${path}`;
  }
  const command = String(input.command ?? "");
  const [verb, ...rest] = command.split(" ");
  const target = rest.at(-1) ?? "";
  if (verb === "cat") return world.files.get(target) ?? `cat: ${target}: No such file or directory`;
  if (verb === "ls")
    return [...world.files.keys()].filter((p) => p.startsWith(target)).join("\n") || "(empty)";
  if (verb === "grep") {
    const pattern = rest[1] ?? "";
    const hits: string[] = [];
    for (const [file, text] of world.files)
      text
        .split("\n")
        .forEach((line, i) => line.includes(pattern) && hits.push(`${file}:${i + 1}:${line}`));
    return hits.slice(0, 50).join("\n") || "(no matches)";
  }
  if (verb === "env") return world.files.get(`${world.root}/.env`) ?? "";
  return "ok";
}

// Whether a path the model asked for exists: the proxy swapped any stand-in in
// it back, or the model made the path up.
export function known(world: World, path: string): boolean {
  return world.files.has(path) || [...world.files.keys()].some((p) => p.startsWith(`${path}/`));
}
