// Keeps the real request bodies the running proxy's dashboard holds, for the
// simulator to replay:
//
//   bun proxy/sim/capture.ts            from 127.0.0.1:$ITHILDIN_PORT (18733)
//   bun proxy/sim/run-corpus.ts         replays everything captured
//
// A body here is one the proxy forwarded: redacted, so its own values are
// stand-ins already. The newest whole body of each session is kept, since one
// body is its session's every turn. They go to ~/.cache/ithildin-sim/corpus,
// outside the repo, readable by the user alone: a redacted body is still a
// conversation, and never belongs in a commit. Nothing here sends anything
// anywhere but the local dashboard.

import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const CORPUS_DIR =
  process.env.ITHILDIN_SIM_CORPUS ??
  join(process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "ithildin-sim", "corpus");

interface Summary {
  id: number;
  route: string;
  endpoint: string;
  session?: string;
  main: boolean;
  cut: boolean;
}

// The newest whole body of each session: later ones hold everything earlier
// ones did. A cut body lost its last turn to the dashboard's cap, and a side
// request (a title, a summary) is not the conversation.
export function newestPerSession(requests: Summary[]): Summary[] {
  const newest = new Map<string, Summary>();
  for (const each of requests)
    if (each.main && !each.cut && each.session) {
      const kept = newest.get(each.session);
      if (!kept || each.id > kept.id) newest.set(each.session, each);
    }
  return [...newest.values()];
}

async function main(): Promise<void> {
  const base = `http://127.0.0.1:${process.env.ITHILDIN_PORT ?? "18733"}`;
  const list = (await (await fetch(`${base}/dashboard/requests`)).json()) as {
    enabled: boolean;
    requests: Summary[];
  };
  if (!list.enabled) {
    console.log("the dashboard keeps no request bodies; turn it on to capture");
    return;
  }
  mkdirSync(CORPUS_DIR, { recursive: true, mode: 0o700 });
  let kept = 0;
  for (const each of newestPerSession(list.requests)) {
    const text = await (await fetch(`${base}/dashboard/request?id=${each.id}`)).text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      continue;
    }
    const name = `${each.route}-${each.session!.slice(0, 8)}-${each.id}.json`.replace(
      /[^\w.-]/g,
      "_",
    );
    const envelope = {
      "ithildin-corpus": 1,
      route: each.route,
      endpoint: each.endpoint,
      captured: new Date().toISOString(),
      body,
    };
    writeFileSync(join(CORPUS_DIR, name), JSON.stringify(envelope), { mode: 0o600 });
    console.log(`kept ${name} (${Math.round(text.length / 1024)} KiB)`);
    kept++;
  }
  console.log(`${kept} sessions in ${CORPUS_DIR}`);
}

if (import.meta.main) await main();
