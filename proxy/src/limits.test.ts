import { describe, expect, it } from "bun:test";
import { planLimits } from "./limits.ts";

describe("planLimits", () => {
  it("reads a Claude subscription's windows, a fraction as a percentage", () => {
    const headers = new Headers({
      "anthropic-ratelimit-unified-5h-utilization": "0.42",
      "anthropic-ratelimit-unified-5h-reset": "1793083173",
      "anthropic-ratelimit-unified-7d-utilization": "0.07",
      "anthropic-ratelimit-unified-7d-reset": "1793669973",
    });
    const limits = planLimits(headers)!;
    expect(limits.five_hour!.used_percentage).toBeCloseTo(42);
    expect(limits.five_hour!.resets_at).toBe(1793083173);
    expect(limits.seven_day!.used_percentage).toBeCloseTo(7);
    expect(limits.seven_day!.resets_at).toBe(1793669973);
  });

  it("reads ChatGPT's Codex windows, primary as 5-hour and secondary as weekly", () => {
    const headers = new Headers({
      "x-codex-primary-used-percent": "34",
      "x-codex-primary-reset-at": "1793083173",
      "x-codex-primary-window-minutes": "300",
      "x-codex-secondary-used-percent": "0",
      "x-codex-secondary-reset-at": "1793669973",
      "x-codex-secondary-window-minutes": "10080",
    });
    expect(planLimits(headers)).toEqual({
      five_hour: { used_percentage: 34, resets_at: 1793083173 },
      seven_day: { used_percentage: 0, resets_at: 1793669973 },
    });
  });

  it("names nothing for a reply without them, or with junk in them", () => {
    expect(planLimits(new Headers({ "content-type": "application/json" }))).toBeUndefined();
    expect(planLimits(new Headers({ "x-codex-primary-used-percent": "lots" }))).toBeUndefined();
    expect(planLimits(new Headers({ "x-codex-primary-used-percent": " " }))).toBeUndefined();
  });

  it("keeps a window without a reset time, and clamps it to 0-100", () => {
    expect(planLimits(new Headers({ "x-codex-secondary-used-percent": "140" }))).toEqual({
      seven_day: { used_percentage: 100 },
    });
    expect(planLimits(new Headers({ "x-codex-primary-used-percent": "-3" }))).toEqual({
      five_hour: { used_percentage: 0 },
    });
  });
});
