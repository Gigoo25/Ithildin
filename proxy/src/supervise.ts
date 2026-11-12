// `ithildin --supervise`: one small parent that owns the proxy process, so
// new rules take over without waiting for old replies.
//
// The rules, the inventory and the routes are compiled once, as a process
// starts, in the main thread and in every scan thread; new ones need a new
// process. A stop drains first, so a streaming reply is not cut off mid-turn,
// and under systemd the next process starts only when the old one is gone:
// over 21 days, 23 of 78 restarts on a rules edit waited more than a second
// for someone's reply to finish, 8 more than ten, one 279s, and every agent
// was refused for that long. The proxy itself was listening 0.2 to 1.2s after
// it started, every time.
//
// On SIGHUP the parent starts the next worker beside the serving one. Both
// bind the port (SO_REUSEPORT, which only the same user can share). When the
// new one says it is ready (listening, self-test run), the old one is told to
// stop listening and drain: its replies finish under the rules they began
// with, and no agent is refused. A worker that ends before it is ready (a
// routes file that does not parse) changes nothing: the old one keeps serving
// on the old rules, where a restart would have left no proxy at all.
//
// This file imports nothing of the engine: the parent stays a few megabytes
// and has no rules of its own to go stale.

export type Worker = {
  kill(signal: "SIGTERM" | "SIGKILL"): void;
  // Settles when the worker is listening and has run its self-test; never,
  // if it ends first.
  ready: Promise<void>;
  exited: Promise<number>;
};

export type Deps = {
  spawn: () => Worker;
  exit: (code: number) => void;
  log: (line: string) => void;
  // Longest a full stop waits for the workers to drain.
  stopMs: number;
  later: (run: () => void, ms: number) => void;
};

// A full stop holds every agent off until it ends, where a handover holds
// none, so it waits less than a worker's own drain: a reply still streaming
// after this is cut, and its agent retries. modules/ithildin.nix sets
// TimeoutStopSec above it.
export const STOP_DRAIN_MS = 30_000;

export function supervise(deps: Deps): { reload: () => void; stop: () => void } {
  const live = new Set<Worker>();
  let stopping = false;
  let serving: Worker;
  // Started by a reload and not ready yet.
  let next: Worker | undefined;

  const launch = (): Worker => {
    const worker = deps.spawn();
    live.add(worker);
    void worker.exited.then((code) => {
      live.delete(worker);
      if (stopping) {
        if (live.size === 0) deps.exit(0);
      } else if (worker === serving) {
        // Nothing asked it to go: a failed start (a bad routes file, an old
        // Bun) or a crash. Exit with it, so the service fails as it would
        // without a parent, and systemd restarts or reports it.
        deps.exit(code === 0 ? 1 : code);
      } else if (worker === next) {
        next = undefined;
        deps.log(`ithildin: reload failed (exit ${code}), still serving the rules from before it`);
      }
    });
    return worker;
  };
  serving = launch();

  return {
    reload: () => {
      if (stopping) return;
      // A second edit before the first one's worker is ready: that worker
      // read rules already out of date.
      const stale = next;
      const worker = (next = launch());
      stale?.kill("SIGTERM");
      void worker.ready.then(() => {
        if (stopping || next !== worker) return;
        const old = serving;
        serving = worker;
        next = undefined;
        old.kill("SIGTERM");
        deps.log(`ithildin: reloaded, ${live.size - 1} draining`);
      });
    },
    stop: () => {
      if (stopping) return;
      stopping = true;
      for (const worker of live) worker.kill("SIGTERM");
      deps.later(() => {
        for (const worker of live) worker.kill("SIGKILL");
        deps.exit(0);
      }, deps.stopMs);
    },
  };
}

// What a worker sends its parent when it is ready to take over.
export const READY = "ready";

// The worker's command line: this one, without the flag that made a parent of
// it, and with the one that lets it share the port.
export function workerArgs(argv: string[]): string[] {
  return [...argv.filter((arg) => arg !== "--supervise"), "--handover"];
}
