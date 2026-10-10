import { describe, expect, it } from "bun:test";

import {
  BINDING_BETA,
  BODIES_MAX,
  DIAGNOSE_BETA,
  DIAGNOSED_MAX,
  Diagnoses,
  REPLIES_MAX,
  type Thread,
  diagnosingOn,
  heardIn,
} from "./diagnose.ts";
import type { Miss } from "./misses.ts";

describe("cache diagnostics", () => {
  it("asks against the session's last reply, and its last step's on a step", () => {
    const diagnoses = new Diagnoses();
    const headers = new Headers({ "anthropic-beta": "a-beta, b-beta" });
    const first = diagnoses.ask("s1", false, '{"model":"m"}', headers)!;
    expect(JSON.parse(first)).toEqual({ diagnostics: { previous_message_id: null }, model: "m" });
    expect(headers.get("anthropic-beta")).toBe(`a-beta,b-beta,${DIAGNOSE_BETA},${BINDING_BETA}`);
    // One the agent already sent is not sent twice.
    const own = new Headers({ "anthropic-beta": BINDING_BETA });
    diagnoses.ask("s1", false, '{"model":"m"}', own);
    expect(own.get("anthropic-beta")).toBe(`${BINDING_BETA},${DIAGNOSE_BETA}`);

    expect(diagnoses.answer("s1", true, { id: "msg_step1" })).toBe("");
    expect(diagnoses.answer("s1", false, { id: "msg_turn2" })).toBe("");
    const turn = JSON.parse(diagnoses.ask("s1", false, "{}x", new Headers()) ?? "null");
    expect(turn).toBeNull();
    const plain = JSON.parse(diagnoses.ask("s1", false, '{"a":1}', new Headers())!);
    expect(plain.diagnostics.previous_message_id).toBe("msg_turn2");
    // A step names the step before it: that is the request that wrote the
    // entry this one should read.
    const step = JSON.parse(diagnoses.ask("s1", true, '{"a":1}', new Headers())!);
    expect(step.diagnostics.previous_message_id).toBe("msg_step1");
    // A session with no step yet names its last reply.
    diagnoses.answer("s2", false, { id: "msg_other" });
    const early = JSON.parse(diagnoses.ask("s2", true, '{"a":1}', new Headers())!);
    expect(early.diagnostics.previous_message_id).toBe("msg_other");
  });

  it("names a miss in the journal, and remembers only so many sessions", () => {
    const diagnoses = new Diagnoses();
    expect(diagnoses.answer("s", false, { reason: "messages_changed" })).toBe(
      " cachemiss=messages_changed",
    );
    for (let at = 0; at <= DIAGNOSED_MAX; at++)
      diagnoses.answer(`s${at}`, false, { id: `msg_${at}` });
    const oldest = JSON.parse(diagnoses.ask("s0", false, '{"a":1}', new Headers())!);
    expect(oldest.diagnostics.previous_message_id).toBeNull();
    const newest = JSON.parse(diagnoses.ask(`s${DIAGNOSED_MAX}`, false, '{"a":1}', new Headers())!);
    expect(newest.diagnostics.previous_message_id).toBe(`msg_${DIAGNOSED_MAX}`);
  });

  it("reads the id and the miss from a reply, a stream's start, or a delta", () => {
    expect(heardIn({ id: "msg_1", diagnostics: null })).toEqual({ id: "msg_1" });
    expect(
      heardIn({
        type: "message_start",
        message: { id: "msg_2", diagnostics: { cache_miss_reason: { type: "x", at: 3 } } },
      }),
    ).toEqual({ id: "msg_2", reason: 'x{"at":3}' });
    expect(
      heardIn({ type: "message_delta", delta: { diagnostics: { cache_miss_reason: {} } } }),
    ).toEqual({ reason: "unknown" });
    expect(heardIn({ id: "toolu_1" })).toEqual({});
    expect(heardIn("text")).toEqual({});
    expect(heardIn(undefined)).toEqual({});
  });

  it("names the thinking blocks a reply says no longer match their conversation", () => {
    const allowed = (path: string) => ({
      type: "thinking_mismatch_allowed",
      path,
      reason: "prefix_binding_mismatch",
    });
    expect(
      heardIn({
        id: "msg_1",
        input_transformations: [
          allowed("messages.32.content.1"),
          allowed("messages.40.content.0"),
          { type: "thinking_dropped", path: "messages.50.content.0" },
          { reason: "no type or path" },
          "not an entry",
        ],
      }),
    ).toEqual({
      id: "msg_1",
      thinking:
        "mismatch_allowed:2@messages.32.content.1,dropped:1@messages.50.content.0,unknown:1@?",
    });
    // On a stream, beside usage on the delta event, or inside the delta.
    expect(heardIn({ type: "message_delta", input_transformations: [allowed("m.1")] })).toEqual({
      thinking: "mismatch_allowed:1@m.1",
    });
    expect(heardIn({ delta: { input_transformations: [allowed("m.2")] } })).toEqual({
      thinking: "mismatch_allowed:1@m.2",
    });
    // Nothing listed is nothing to say.
    expect(heardIn({ id: "msg_2", input_transformations: [] })).toEqual({ id: "msg_2" });
    expect(heardIn({ input_transformations: [7] })).toEqual({});

    const diagnoses = new Diagnoses();
    expect(diagnoses.answer("s", false, { thinking: "mismatch_allowed:1@m.1" })).toBe(
      " thinking=mismatch_allowed:1@m.1",
    );
    expect(
      diagnoses.answer("s", false, { reason: "messages_changed", thinking: "dropped:1@m.2" }),
    ).toBe(" cachemiss=messages_changed thinking=dropped:1@m.2");
  });

  it("stops asking for good once Anthropic refuses the question", () => {
    const diagnoses = new Diagnoses();
    expect(diagnoses.refused(400, "max_tokens: too large")).toBe(false);
    expect(diagnoses.refused(500, "diagnostics")).toBe(false);
    expect(diagnoses.ask("s", false, '{"a":1}', new Headers())).toBeDefined();
    expect(diagnoses.refused(400, '{"message":"diagnostics: unknown field"}')).toBe(true);
    expect(diagnoses.ask("s", false, '{"a":1}', new Headers())).toBeUndefined();
    // Refusing the thinking-binding beta stops it too.
    const binding = new Diagnoses();
    expect(binding.refused(400, `unknown beta: ${BINDING_BETA}`)).toBe(true);
    expect(binding.ask("s", false, '{"a":1}', new Headers())).toBeUndefined();
  });

  it("keeps a miss with the body it was compared with: the last step's, on a step", () => {
    const kept: Miss[] = [];
    const diagnoses = new Diagnoses((miss) => kept.push(miss));
    // Nothing to compare with yet: nothing kept.
    diagnoses.answer("s", false, { id: "msg_1", reason: "messages_changed" }, "turn1");
    expect(kept).toEqual([]);
    diagnoses.answer("s", true, { id: "msg_2" }, "step1");
    diagnoses.answer("s", false, { id: "msg_3" }, "turn2");
    diagnoses.answer("s", true, { id: "msg_4", reason: "messages_changed" }, "step2");
    diagnoses.answer("s", false, { reason: 'system_changed{"at":1}' }, "turn3");
    // Not a divergence, or no body: nothing kept.
    diagnoses.answer("s", false, { reason: "previous_message_not_found" }, "turn4");
    diagnoses.answer("s", false, { reason: "messages_changed" });
    expect(kept).toEqual([
      { session: "s", step: true, reason: "messages_changed", previous: "step1", missed: "step2" },
      {
        session: "s",
        step: false,
        reason: 'system_changed{"at":1}',
        previous: "step2",
        missed: "turn3",
      },
    ]);
  });

  it("compares a request with its own thread's reply, not a fork's beside it", () => {
    const kept: Miss[] = [];
    const diagnoses = new Diagnoses((miss) => kept.push(miss));
    const key = "s\0opus\0first";
    const asked = (digests: string[], step = false) => {
      const thread: Thread = { key, digests };
      const body = JSON.parse(diagnoses.ask(thread, step, '{"a":1}', new Headers())!);
      return { thread, id: body.diagnostics.previous_message_id };
    };
    diagnoses.answer({ key, digests: ["a", "b"] }, true, { id: "msg_step" }, "step");
    diagnoses.answer({ key, digests: ["a", "b", "c"] }, false, { id: "msg_main" }, "main");
    diagnoses.answer({ key, digests: ["a", "b", "x"] }, false, { id: "msg_fork" }, "fork");
    expect(asked(["a", "b", "c", "d"]).id).toBe("msg_main");
    expect(asked(["a", "b", "x", "y"]).id).toBe("msg_fork");
    // Sharing as much with each, the newest.
    expect(asked(["a", "b", "z"]).id).toBe("msg_fork");
    expect(asked(["a", "q"], true).id).toBe("msg_step");
    // Another key is another conversation: a subagent has nothing to compare.
    const sub = { key: "s\0haiku\0other", digests: ["a"] };
    expect(JSON.parse(diagnoses.ask(sub, false, "{}", new Headers()) ?? "null")).toBeNull();
    const fresh = JSON.parse(diagnoses.ask(sub, false, '{"a":1}', new Headers())!);
    expect(fresh.diagnostics.previous_message_id).toBeNull();
    // A miss is kept with the reply it was asked against, filed by session.
    const { thread } = asked(["a", "b", "c", "e"]);
    diagnoses.answer(thread, false, { reason: "messages_changed" }, "missed");
    expect(kept).toEqual([
      { session: "s", step: false, reason: "messages_changed", previous: "main", missed: "missed" },
    ]);
    // Only so many replies per key: the oldest goes.
    for (let at = 0; at < REPLIES_MAX; at++)
      diagnoses.answer({ key, digests: [`n${at}`] }, false, { id: `msg_n${at}` });
    expect(asked(["a", "b", "c"]).id).toBe(`msg_n${REPLIES_MAX - 1}`);
  });

  it("keeps bodies for only so many sessions", () => {
    const kept: Miss[] = [];
    const diagnoses = new Diagnoses((miss) => kept.push(miss));
    for (let at = 0; at <= BODIES_MAX; at++)
      diagnoses.answer(`s${at}`, false, { id: `msg_${at}` }, `body${at}`);
    diagnoses.answer("s0", false, { reason: "messages_changed" }, "later");
    diagnoses.answer(`s${BODIES_MAX}`, false, { reason: "messages_changed" }, "later");
    expect(kept.map((miss) => miss.previous)).toEqual([`body${BODIES_MAX}`]);
  });

  it("is on unless ITHILDIN_DIAGNOSE turns it off", () => {
    expect(diagnosingOn({})).toBe(true);
    expect(diagnosingOn({ ITHILDIN_DIAGNOSE: "off" })).toBe(false);
    expect(diagnosingOn({ ITHILDIN_DIAGNOSE: " 0 " })).toBe(false);
    expect(diagnosingOn({ ITHILDIN_DIAGNOSE: "on" })).toBe(true);
  });
});
