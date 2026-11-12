import { describe, expect, it } from "bun:test";
import { supervise, workerArgs } from "./supervise.ts";

type Fake = {
  signals: string[];
  end: (code: number) => Promise<void>;
  becomeReady: () => Promise<void>;
  kill: (signal: "SIGTERM" | "SIGKILL") => void;
  ready: Promise<void>;
  exited: Promise<number>;
};

function harness() {
  const workers: Fake[] = [];
  const exits: number[] = [];
  const logs: string[] = [];
  let timer: (() => void) | undefined;
  const spawn = (): Fake => {
    const exited = Promise.withResolvers<number>();
    const ready = Promise.withResolvers<void>();
    const settle = async () => {
      await Promise.resolve();
      await Promise.resolve();
    };
    const worker: Fake = {
      signals: [],
      kill: (signal) => void worker.signals.push(signal),
      ready: ready.promise,
      exited: exited.promise,
      becomeReady: async () => {
        ready.resolve();
        await settle();
      },
      end: async (code) => {
        exited.resolve(code);
        await settle();
      },
    };
    workers.push(worker);
    return worker;
  };
  const control = supervise({
    spawn,
    exit: (code) => void exits.push(code),
    log: (line) => void logs.push(line),
    stopMs: 30_000,
    later: (run) => void (timer = run),
  });
  return { workers, exits, logs, control, fire: () => timer?.() };
}

describe("the supervisor", () => {
  it("keeps the old worker serving until the next one is ready, then drains it", async () => {
    const { workers, exits, logs, control } = harness();
    expect(workers).toHaveLength(1);
    control.reload();
    expect(workers).toHaveLength(2);
    expect(workers[0]!.signals).toEqual([]);
    await workers[1]!.becomeReady();
    expect(workers[0]!.signals).toEqual(["SIGTERM"]);
    expect(workers[1]!.signals).toEqual([]);
    expect(logs).toEqual(["ithildin: reloaded, 1 draining"]);
    // The old worker finishing its replies ends nothing.
    await workers[0]!.end(0);
    expect(exits).toEqual([]);
    // The new one is the serving one now: its end is the service's.
    await workers[1]!.end(0);
    expect(exits).toEqual([1]);
  });

  it("keeps serving the old rules when the next worker ends before it is ready", async () => {
    const { workers, exits, logs, control } = harness();
    control.reload();
    await workers[1]!.end(1);
    expect(exits).toEqual([]);
    expect(workers[0]!.signals).toEqual([]);
    expect(logs).toEqual([
      "ithildin: reload failed (exit 1), still serving the rules from before it",
    ]);
    // And the edit that fixes the file reloads as usual.
    control.reload();
    await workers[2]!.becomeReady();
    expect(workers[0]!.signals).toEqual(["SIGTERM"]);
  });

  it("drops a worker that a second edit overtook before it was ready", async () => {
    const { workers, exits, logs, control } = harness();
    control.reload();
    control.reload();
    expect(workers[1]!.signals).toEqual(["SIGTERM"]);
    // Ready too late: it read the rules from before the second edit.
    await workers[1]!.becomeReady();
    expect(workers[0]!.signals).toEqual([]);
    await workers[1]!.end(0);
    expect(logs).toEqual([]);
    await workers[2]!.becomeReady();
    expect(workers[0]!.signals).toEqual(["SIGTERM"]);
    expect(exits).toEqual([]);
  });

  it("exits with the serving worker when it ends unasked", async () => {
    const { workers, exits } = harness();
    await workers[0]!.end(3);
    expect(exits).toEqual([3]);
  });

  it("stops every worker, and exits when the last has drained", async () => {
    const { workers, exits, control } = harness();
    control.reload();
    control.stop();
    control.stop();
    expect(workers.map((worker) => worker.signals)).toEqual([["SIGTERM"], ["SIGTERM"]]);
    // Neither a reload nor a worker that is ready only now changes a stop.
    control.reload();
    await workers[1]!.becomeReady();
    expect(workers).toHaveLength(2);
    expect(workers[0]!.signals).toEqual(["SIGTERM"]);
    await workers[1]!.end(0);
    expect(exits).toEqual([]);
    await workers[0]!.end(0);
    expect(exits).toEqual([0]);
  });

  it("kills what is still draining when a stop has waited long enough", async () => {
    const { workers, exits, control, fire } = harness();
    control.reload();
    await workers[1]!.becomeReady();
    control.stop();
    await workers[1]!.end(0);
    fire();
    expect(workers[0]!.signals).toEqual(["SIGTERM", "SIGTERM", "SIGKILL"]);
    expect(workers[1]!.signals).toEqual(["SIGTERM"]);
    expect(exits).toEqual([0]);
  });

  it("hands the worker this command line, sharing the port and not supervising", () => {
    expect(workerArgs(["--supervise", "--port", "18733"])).toEqual([
      "--port",
      "18733",
      "--handover",
    ]);
  });
});
