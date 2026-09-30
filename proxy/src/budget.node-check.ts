// Run with Node, the production V8 runtime, not Bun's node:vm compatibility layer.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RULES,
  beginScanBudget,
  clearWindowCache,
  exportWindowCache,
  importWindowCache,
  scanWindows,
  setScanBudgetMs,
  withScanBudget,
} from "../engine/lib/rules.ts";
import { createHooks } from "../bench/hooks.ts";

function withRules(work: () => void): void {
  const saved = RULES.splice(0);
  const now = Date.now;
  clearWindowCache();
  try {
    work();
  } finally {
    RULES.splice(0, RULES.length, ...saved);
    Date.now = now;
    beginScanBudget(null);
    setScanBudgetMs(null);
    clearWindowCache();
  }
}

function rule(validate: () => boolean) {
  return {
    id: "budget-probe",
    description: "budget fixture",
    category: "pii" as const,
    regex: /probe/g,
    validate,
  };
}

test("checks the envelope between rules and marks the unscanned suffix", () =>
  withRules(() => {
    let clock = 0;
    let calls = 0;
    Date.now = () => clock;
    for (let i = 0; i < 3; i++)
      RULES.push(
        rule(() => {
          calls++;
          clock += 6;
          return true;
        }),
      );
    beginScanBudget(10);
    const text = `probe ${" ".repeat(70_000)}`;
    const result = scanWindows(text);
    assert.equal(calls, 2);
    assert.equal(result.findings.length, 2);
    assert.deepEqual(result.trips, [{ start: 0, end: text.length }]);
  }));

test("marks a final-rule overshoot even in a single window", () =>
  withRules(() => {
    let clock = 0;
    Date.now = () => clock;
    RULES.push(
      rule(() => {
        clock += 11;
        return true;
      }),
    );
    beginScanBudget(10);
    assert.deepEqual(scanWindows("probe").trips, [{ start: 0, end: 5 }]);
  }));

test("V8 interrupts a running rule within the remaining budget, below the comfort floor", () =>
  withRules(() => {
    let laterRuleRan = false;
    RULES.push(
      rule(() => {
        // Finite even if timeout enforcement regresses. The runner has a timeout too.
        const end = performance.now() + 2_000;
        while (performance.now() < end) {
          /* synchronous expensive validation */
        }
        return true;
      }),
    );
    RULES.push(
      rule(() => {
        laterRuleRan = true;
        return true;
      }),
    );
    beginScanBudget(30);
    const started = performance.now();
    const result = scanWindows("probe");
    assert.ok(performance.now() - started < 1_000, "V8 timeout was not applied");
    assert.equal(laterRuleRan, false);
    assert.deepEqual(result.trips, [{ start: 0, end: 5 }]);
  }));

test("scoped budgets share spending across strings and restore outer state on errors", () =>
  withRules(() => {
    let clock = 0;
    let calls = 0;
    Date.now = () => clock;
    RULES.push(
      rule(() => {
        calls++;
        clock += 6;
        return true;
      }),
    );
    withScanBudget(() => {
      assert.deepEqual(scanWindows("probe one").trips, []);
      withScanBudget(() => {
        // A different window: a cached one would bypass the spent envelope.
        assert.deepEqual(scanWindows("probe two").trips, [{ start: 0, end: 9 }]);
      }, 1_000);
    }, 10);
    assert.throws(() =>
      withScanBudget(() => {
        throw new Error("fixture");
      }, 0),
    );
    // Fresh text so the cache cannot mask a leftover deadline.
    assert.deepEqual(scanWindows("probe three").trips, []);
    assert.ok(calls > 0);
  }));

test("provider hooks use one scan envelope across payload fields, renewed on the next hook", () =>
  withRules(() => {
    let clock = 0;
    Date.now = () => clock;
    // Each field is cheaper than the per-rule cap, but their combined cost exceeds
    // the unchanged 10-second default. Fake time makes this test instantaneous.
    RULES.push(
      rule(() => {
        clock += 6_000;
        return true;
      }),
    );
    const handlers = createHooks();
    handlers.session_shutdown(); // Clear memoized fixtures from other tests.
    // Keep the old envelope so the fixture costs below keep their meaning.
    setScanBudgetMs(10_000);
    try {
      const result = handlers.before_provider_request({
        payload: { a: "probe one", b: "probe two", c: "probe three" },
      });
      assert.ok(!result.a.includes("scan budget exceeded"));
      assert.ok(result.b.includes("scan budget exceeded"));
      assert.ok(result.c.includes("scan budget exceeded"));
      const next = handlers.before_provider_request({ payload: { a: "probe four" } });
      assert.ok(!next.a.includes("scan budget exceeded"));
    } finally {
      handlers.session_shutdown();
    }
  }));

test("resumes at the first unscanned window after the envelope dies", () =>
  withRules(() => {
    let clock = 0;
    let calls = 0;
    Date.now = () => clock;
    RULES.push(
      rule(() => {
        calls++;
        clock += 6;
        return true;
      }),
    );
    // One probe per window, placed clear of the overlap regions, so every
    // window costs one fake rule call no matter which pass reaches it.
    let text = "";
    let at = 0;
    for (const position of [1_000, 70_000, 130_000, 190_000]) {
      text += " ".repeat(position - at) + "probe";
      at = position + 5;
    }
    text += " ".repeat(200_000 - at);
    beginScanBudget(20);
    const first = scanWindows(text);
    assert.ok(first.trips.length > 0, "the first pass must trip");
    const callsAfterFirst = calls;
    beginScanBudget(20);
    const second = scanWindows(text);
    assert.deepEqual(second.trips, [], "the second pass completes the text");
    assert.equal(second.findings.length, 4);
    assert.ok(calls - callsAfterFirst < 4, "cached windows must not re-run rules");
  }));

test("exports completed windows without values and replays them", () => {
  clearWindowCache();
  try {
    const secret = "AKIA" + "A".repeat(16);
    const text = `key ${secret} ${"x".repeat(70_000)}`;
    const first = scanWindows(text);
    assert.deepEqual(first.trips, []);
    assert.equal(first.findings.length, 1);
    const snapshot = exportWindowCache();
    assert.ok(snapshot.entries.length > 0);
    assert.ok(!JSON.stringify(snapshot).includes(secret), "the snapshot must not carry the value");
    clearWindowCache();
    assert.ok(importWindowCache(snapshot) > 0);
    const replay = scanWindows(text);
    assert.deepEqual(replay.trips, []);
    assert.equal(replay.findings.length, 1);
    const [finding] = replay.findings;
    assert.ok(finding);
    assert.equal(finding.secretValue, secret);
    assert.ok(finding.description.length > 0);
  } finally {
    clearWindowCache();
  }
});
