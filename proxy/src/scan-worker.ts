// A scan thread's entry (scan-pool.ts). Like cli.ts, it only wires up what
// is tested elsewhere: it runs in its own thread, which coverage does not see.
import { parentPort } from "node:worker_threads";
import { answer, type ScanAsk } from "./scan-pool.ts";

parentPort?.on("message", (ask: ScanAsk) => {
  const reply = answer(ask);
  if (reply) parentPort?.postMessage(reply);
});
