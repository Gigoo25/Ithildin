import { createHmac, randomBytes } from "node:crypto";

// A seeded hash for the memo caches that skip text a request carries again.
// Bun.hash where the proxy runs; the Node checks load the same code, so they
// get a keyed HMAC instead. A seed per cache keeps an attacker who controls
// the text from choosing collisions.
export type MemoHash = (text: string) => number | bigint;

type BunHash = (text: string, seed: bigint) => number | bigint;

const bunHash = (globalThis as { Bun?: { hash: BunHash } }).Bun?.hash ?? null;

// `hash` is for the tests: null takes the HMAC path the Node checks take.
export function memoHash(hash: BunHash | null = bunHash): MemoHash {
  if (!hash) {
    const key = randomBytes(32);
    return (text) => createHmac("sha256", key).update(text).digest().readBigUInt64LE(0);
  }
  const seed = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
  return (text) => hash(text, seed);
}
