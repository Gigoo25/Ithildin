// Subscription plan usage, as a provider's reply headers carry it, so a client
// footer can draw it the way Claude Code's status line draws rate_limits. The
// shape is Claude Code's (five_hour / seven_day, a percentage and an epoch in
// seconds), so one renderer reads both providers.
//
// Anthropic, on a Claude subscription:
//   anthropic-ratelimit-unified-5h-utilization  0.42 (a fraction)
//   anthropic-ratelimit-unified-5h-reset        1793083173
//   …-7d-utilization, …-7d-reset                the weekly window
// ChatGPT's Codex backend, on a ChatGPT plan:
//   x-codex-primary-used-percent                42 (a percentage)
//   x-codex-primary-reset-at                    1793083173
//   x-codex-primary-window-minutes              300
//   x-codex-secondary-*                         the weekly window (10080)
// An API-key account sends neither, and gets nothing here.

export interface PlanWindow {
  used_percentage: number;
  resets_at?: number;
}

export interface PlanLimits {
  five_hour?: PlanWindow;
  seven_day?: PlanWindow;
}

function number(headers: Headers, name: string): number | undefined {
  const raw = headers.get(name);
  if (raw === null || raw.trim() === "") return undefined;
  const value = Number(raw);
  return Number.isFinite(value) ? value : undefined;
}

function window(used: number | undefined, reset: number | undefined): PlanWindow | undefined {
  if (used === undefined) return undefined;
  const percent = Math.min(100, Math.max(0, used));
  return reset === undefined
    ? { used_percentage: percent }
    : { used_percentage: percent, resets_at: reset };
}

function anthropic(headers: Headers, span: "5h" | "7d"): PlanWindow | undefined {
  const used = number(headers, `anthropic-ratelimit-unified-${span}-utilization`);
  const reset = number(headers, `anthropic-ratelimit-unified-${span}-reset`);
  return window(used === undefined ? undefined : used * 100, reset);
}

function codex(headers: Headers, slot: "primary" | "secondary"): PlanWindow | undefined {
  return window(
    number(headers, `x-codex-${slot}-used-percent`),
    number(headers, `x-codex-${slot}-reset-at`),
  );
}

// The windows a reply names, or undefined when it names none, so a reply
// without them (an error, a model list) leaves the last reading standing.
export function planLimits(headers: Headers): PlanLimits | undefined {
  const limits: PlanLimits = {};
  const five = anthropic(headers, "5h") ?? codex(headers, "primary");
  const seven = anthropic(headers, "7d") ?? codex(headers, "secondary");
  if (five) limits.five_hour = five;
  if (seven) limits.seven_day = seven;
  return five || seven ? limits : undefined;
}
