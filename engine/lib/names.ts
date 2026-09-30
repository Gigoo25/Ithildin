// Names and paths shared by the engine and the proxy.
import os from "node:os";
import path from "node:path";

export const NAME = "ithildin";

type Env = Record<string, string | undefined>;

// ITHILDIN_<name>.
export function setting(name: string, env: Env = process.env): string | undefined {
  return env[`ITHILDIN_${name}`];
}

function home(env: Env): string {
  return env.HOME || os.homedir();
}

export function configHome(env: Env = process.env): string {
  return env.XDG_CONFIG_HOME || path.join(home(env), ".config");
}

export function stateHome(env: Env = process.env): string {
  return env.XDG_STATE_HOME || path.join(home(env), ".local", "state");
}

// ~/.config/ithildin/<file>.
export function configFile(file: string, env: Env = process.env): string {
  return path.join(configHome(env), NAME, file);
}

// ~/.local/state/ithildin: data this project alone writes (the stand-in key,
// counters, caches).
export function stateDir(env: Env = process.env): string {
  return path.join(stateHome(env), NAME);
}

// <session>.ithildin-<kind> beside a transcript (the stand-in key, the scan
// cache).
export function sessionFile(session: string, kind: string): string {
  return `${session}.ithildin-${kind}`;
}
