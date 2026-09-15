// Run with Node, the production V8 runtime, not Bun's node:vm compatibility layer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { RULES, beginScanBudget, scanWindows, withScanBudget } from "./rules.ts";
import sensitiveCanary from "../index.ts";

function withRules(work: () => void): void {
  const saved = RULES.splice(0);
  const now = Date.now;
  try {
    work();
  } finally {
    RULES.splice(0, RULES.length, ...saved);
    Date.now = now;
    beginScanBudget(null);
  }
}

function rule(validate: () => boolean) {
  return { id: "budget-probe", description: "budget fixture", category: "pii" as const, regex: /probe/g, validate };
}

test("checks the envelope between rules and marks the unscanned suffix", () => withRules(() => {
  let clock = 0;
  let calls = 0;
  Date.now = () => clock;
  for (let i = 0; i < 3; i++) RULES.push(rule(() => { calls++; clock += 6; return true; }));
  beginScanBudget(10);
  const text = `probe ${" ".repeat(70_000)}`;
  const result = scanWindows(text);
  assert.equal(calls, 2);
  assert.equal(result.findings.length, 2);
  assert.deepEqual(result.trips, [{ start: 0, end: text.length }]);
}));

test("marks a final-rule overshoot even in a single window", () => withRules(() => {
  let clock = 0;
  Date.now = () => clock;
  RULES.push(rule(() => { clock += 11; return true; }));
  beginScanBudget(10);
  assert.deepEqual(scanWindows("probe").trips, [{ start: 0, end: 5 }]);
}));

test("V8 interrupts a running rule within the remaining budget, below the comfort floor", () => withRules(() => {
  let laterRuleRan = false;
  RULES.push(rule(() => {
    // Finite even if timeout enforcement regresses; the runner has a timeout too.
    const end = performance.now() + 2_000;
    while (performance.now() < end) { /* synchronous expensive validation */ }
    return true;
  }));
  RULES.push(rule(() => { laterRuleRan = true; return true; }));
  beginScanBudget(30);
  const started = performance.now();
  const result = scanWindows("probe");
  assert.ok(performance.now() - started < 1_000, "V8 timeout was not applied");
  assert.equal(laterRuleRan, false);
  assert.deepEqual(result.trips, [{ start: 0, end: 5 }]);
}));

test("scoped budgets share spending across strings and restore outer state on errors", () => withRules(() => {
  let clock = 0;
  Date.now = () => clock;
  RULES.push(rule(() => { clock += 6; return true; }));
  withScanBudget(() => {
    assert.deepEqual(scanWindows("probe").trips, []);
    withScanBudget(() => {
      assert.deepEqual(scanWindows("probe").trips, [{ start: 0, end: 5 }]);
    }, 1_000);
  }, 10);
  assert.throws(() => withScanBudget(() => { throw new Error("fixture"); }, 0));
  assert.deepEqual(scanWindows("probe").trips, []);
}));

test("provider hooks use one scan envelope across payload fields, renewed on the next hook", () => withRules(() => {
  let clock = 0;
  Date.now = () => clock;
  // Each field is cheaper than the per-rule cap, but their combined cost exceeds
  // the unchanged 10-second default. Fake time makes this test instantaneous.
  RULES.push(rule(() => { clock += 6_000; return true; }));
  const handlers: Record<string, Function> = {};
  sensitiveCanary({
    on: (name: string, fn: Function) => { handlers[name] = fn; },
    registerFlag() {},
    registerCommand() {},
    appendEntry() {},
    getFlag: () => false,
    events: { on() {}, emit() {} },
  } as any);
  handlers.session_shutdown(); // Clear memoized fixtures from other tests.
  try {
    const result = handlers.before_provider_request({ payload: { a: "probe one", b: "probe two", c: "probe three" } });
    assert.ok(!result.a.includes("scan budget exceeded"));
    assert.ok(result.b.includes("scan budget exceeded"));
    assert.ok(result.c.includes("scan budget exceeded"));
    const next = handlers.before_provider_request({ payload: { a: "probe four" } });
    assert.ok(!next.a.includes("scan budget exceeded"));
  } finally {
    handlers.session_shutdown();
  }
}));
