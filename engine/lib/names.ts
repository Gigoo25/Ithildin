// Ithildin was first released here as sensitive-canary (the engine) and
// canary-proxy (the proxy). A setup from before the rename keeps working:
// the old variable names are read after the new ones, config is read from
// the old directory when only that one has it, and state moves to the new
// directory the first time it is used.
import { existsSync, renameSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export const NAME = "ithildin";
export const LEGACY_ENGINE = "sensitive-canary";
export const LEGACY_PROXY = "canary-proxy";

type Env = Record<string, string | undefined>;

// ITHILDIN_<name>, else the SENSITIVE_CANARY_<name> it replaced.
export function setting(name: string, env: Env = process.env): string | undefined {
  return env[`ITHILDIN_${name}`] ?? env[`SENSITIVE_CANARY_${name}`];
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

// ~/.config/ithildin/<file>, or the same file in the directory it replaced
// when only that one has it. Config is often a link Home Manager owns, so it
// is read where it is, never moved.
export function configFile(file: string, legacyDir: string, env: Env = process.env): string {
  const current = path.join(configHome(env), NAME, file);
  const legacy = path.join(configHome(env), legacyDir, file);
  return !existsSync(current) && existsSync(legacy) ? legacy : current;
}

// ~/.local/state/ithildin, moved from the engine's old directory the first
// time. State is data this project alone writes (the stand-in key, counters,
// caches), so it moves once instead of being read from two places. A move
// that fails leaves it where it was, and it is used there.
export function stateDir(env: Env = process.env): string {
  return moveOnce(path.join(stateHome(env), LEGACY_ENGINE), path.join(stateHome(env), NAME));
}

// <session>.ithildin-<kind> beside a transcript (the stand-in key, the scan
// cache), moved from the <session>.canary-<kind> it replaced the first time.
export function sessionFile(session: string, kind: string): string {
  return moveOnce(`${session}.canary-${kind}`, `${session}.ithildin-${kind}`);
}

function moveOnce(legacy: string, current: string): string {
  if (existsSync(current) || !existsSync(legacy)) return current;
  try {
    renameSync(legacy, current);
    return current;
  } catch {
    return legacy;
  }
}
