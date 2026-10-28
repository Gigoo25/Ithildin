// A provider's prompt cache, modelled well enough to price a run of requests:
// what each one reads, writes and sends uncached. Tokens are characters over
// four, as shaping itself counts them.
//
// Anthropic (docs, and what CACHING.md measured): a request is read as blocks
// in order, tools, system, then each message's content blocks. An entry is
// written only at a cache_control marker, for the prefix that ends there, and
// a marker finds an earlier entry only within 20 blocks before it. Whatever
// follows the last marker is sent uncached.
//
// OpenAI and Gemini cache implicitly: the longest prefix any earlier request
// sent is read back, from 1024 tokens, and the rest is uncached. There is no
// write premium and no marker to place.

import { createHash } from "node:crypto";
import type { Format } from "../src/redact.ts";
import { listOf, systemOf } from "./workload.ts";

type Fields = Record<string, unknown>;

export const LOOKBACK_BLOCKS = 20;
const MIN_PREFIX_TOKENS = 1024;

// Prices relative to uncached input, as shape.ts reckons them.
export const PRICE = { read: 0.1, write: 2, openaiWrite: 1 };

export interface Usage {
  read: number;
  write: number;
  uncached: number;
}

interface Block {
  hash: string;
  tokens: number;
  marked: boolean;
}

function tokensOf(value: unknown): number {
  return Math.ceil(JSON.stringify(value ?? null).length / 4);
}

function strip(value: unknown): unknown {
  return JSON.parse(
    JSON.stringify(value ?? null, (key, inner) => (key === "cache_control" ? undefined : inner)),
  );
}

// The request as the blocks the provider reads, each with a digest of the
// whole prefix up to and including it.
function blocksOf(format: Format, body: Fields): Block[] {
  const raw: Array<{ value: unknown; marked: boolean }> = [];
  const add = (value: unknown) =>
    raw.push({ value, marked: JSON.stringify(value ?? null).includes('"cache_control"') });
  const each = (list: unknown) =>
    Array.isArray(list) ? list.forEach(add) : list !== undefined && add(list);
  add({ model: body.model, thinking: body.thinking ?? body.reasoning });
  each(body.tools);
  each(systemOf(format, body));
  for (const item of listOf(format, body)) {
    const entry = item as Fields;
    // A message's role is part of its first block, so two messages with the
    // same blocks but different roles do not share a prefix. A Gemini turn's
    // blocks are its parts.
    const content = format === "gemini" ? entry.parts : entry.content;
    if (Array.isArray(content) && content.length > 0)
      content.forEach((block, i) => add(i === 0 ? { role: entry.role, block } : block));
    else add(item);
  }
  const hash = createHash("sha1");
  return raw.map(({ value, marked }) => {
    hash.update(JSON.stringify(strip(value)));
    return { hash: hash.copy().digest("base64"), tokens: tokensOf(value), marked };
  });
}

export class Cache {
  private readonly entries = new Set<string>();

  constructor(private readonly format: Format) {}

  send(body: Fields): Usage {
    const blocks = blocksOf(this.format, body);
    return this.format === "anthropic" ? this.marked(blocks) : this.implicit(blocks);
  }

  private marked(blocks: Block[]): Usage {
    const usage: Usage = { read: 0, write: 0, uncached: 0 };
    let covered = -1;
    const sum = (from: number, to: number) =>
      blocks.slice(from + 1, to + 1).reduce((total, block) => total + block.tokens, 0);
    blocks.forEach((block, at) => {
      if (!block.marked) return;
      let hit = -1;
      for (let back = at; back >= Math.max(0, at - LOOKBACK_BLOCKS); back--)
        if (this.entries.has(blocks[back]!.hash)) {
          hit = back;
          break;
        }
      if (hit > covered) {
        usage.read += sum(covered, hit);
        covered = hit;
      }
      if (at > covered) {
        usage.write += sum(covered, at);
        covered = at;
      }
      this.entries.add(block.hash);
    });
    usage.uncached += sum(covered, blocks.length - 1);
    return usage;
  }

  private implicit(blocks: Block[]): Usage {
    let hit = -1;
    blocks.forEach((block, at) => {
      if (this.entries.has(block.hash) && hit === at - 1) hit = at;
    });
    const total = blocks.reduce((sum, block) => sum + block.tokens, 0);
    const read = blocks.slice(0, hit + 1).reduce((sum, block) => sum + block.tokens, 0);
    for (const block of blocks) this.entries.add(block.hash);
    if (read < MIN_PREFIX_TOKENS) return { read: 0, write: 0, uncached: total };
    return { read, write: 0, uncached: total - read };
  }
}

// What a usage costs, in uncached-input tokens.
export function cost(format: Format, usage: Usage): number {
  const write = format === "anthropic" ? PRICE.write : PRICE.openaiWrite;
  return usage.read * PRICE.read + usage.write * write + usage.uncached;
}
