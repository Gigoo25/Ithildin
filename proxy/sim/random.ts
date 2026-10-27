// A seeded generator, so a run is a function of its seed: the same seed builds
// the same conversations and finds the same failure, every time, anywhere.
// mulberry32: small, fast, and good enough to pick lengths and branches.

export class Random {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  // An integer in [min, max].
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }

  chance(p: number): boolean {
    return this.next() < p;
  }

  pick<T>(items: readonly T[]): T {
    return items[Math.floor(this.next() * items.length)]!;
  }

  // Text of about `size` characters, in lines, from a small vocabulary: real
  // tool output repeats itself, and compaction should get to see that.
  text(size: number): string {
    const lines: string[] = [];
    let length = 0;
    while (length < size) {
      const words = Array.from({ length: this.int(3, 12) }, () => this.pick(WORDS));
      const line = `${this.pick(PREFIXES)}${words.join(" ")}`;
      lines.push(line);
      length += line.length + 1;
    }
    return lines.join("\n");
  }
}

const WORDS = [
  "return",
  "const",
  "value",
  "request",
  "session",
  "await",
  "error",
  "result",
  "string",
  "index",
  "proxy",
  "turn",
  "cache",
  "list",
  "item",
  "true",
  "false",
  "42",
  "1024",
  "src/server.ts",
];

const PREFIXES = ["", "  ", "    ", "// ", "+ ", "- ", "ok ", "PASS ", "error: "];
