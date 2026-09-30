import { beforeAll, describe, expect, it } from "bun:test";
import path from "node:path";
import type { InventoryEntry } from "../engine/lib/rules.ts";
import {
  IDENTITY_ENTRIES_MAX,
  initEngine,
  mergeIdentity,
  redactRequest,
  swapToolJson,
  WITHHELD_NOTICE,
} from "./redact.ts";
import { argsKey, recordOriginal, replayOriginal } from "./replay.ts";

beforeAll(() => initEngine());

// A private key path, spelled in pieces so this file is not itself one.
const KEY = path.join("~", ".ssh", "id_" + "ed25519");
const readKey = JSON.stringify({ command: `cat ${KEY}` });

describe("replayed turns", () => {
  it("sends the provider's original text back for an Anthropic assistant turn", () => {
    recordOriginal("text", "harness form one", "provider form one");
    const { body } = redactRequest("anthropic", {
      messages: [{ role: "assistant", content: "harness form one" }],
    });
    expect(body.messages).toEqual([{ role: "assistant", content: "provider form one" }]);
  });

  it("sends back original Chat text parts and tool arguments", () => {
    recordOriginal("text", "harness form two", "provider form two");
    const harnessArgs = JSON.stringify({ command: "ls harness" });
    const originalArgs = JSON.stringify({ command: "ls provider" });
    recordOriginal("args", argsKey(harnessArgs)!, originalArgs);
    const { body } = redactRequest("chat", {
      messages: [
        {
          role: "assistant",
          content: [{ type: "text", text: "harness form two" }],
          tool_calls: [
            { id: "c1", type: "function", function: { name: "bash", arguments: harnessArgs } },
          ],
        },
      ],
    });
    const [message] = body.messages as Array<Record<string, any>>;
    expect(message!.content).toEqual([{ type: "text", text: "provider form two" }]);
    expect(message!.tool_calls[0].function.arguments).toBe(originalArgs);
  });
});

describe("Anthropic shapes the redactor does not expect", () => {
  it("passes through odd content and a non-array message list", () => {
    const odd = { role: "user", content: 42 };
    expect(redactRequest("anthropic", { messages: [odd] }).body.messages).toEqual([odd]);
    expect(redactRequest("anthropic", { messages: "none" }).body.messages).toBe("none");
  });
});

describe("secret reads", () => {
  it("withholds a Chat tool result for a call that read a secret file", () => {
    const { body } = redactRequest("chat", {
      messages: [
        {
          role: "assistant",
          tool_calls: [
            { id: "c1", type: "function", function: { name: "bash", arguments: readKey } },
            { id: "c2", type: "function", function: { name: "bash", arguments: "{not json" } },
          ],
        },
        { role: "tool", tool_call_id: "c1", content: "key material" },
        { role: "tool", tool_call_id: "c2", content: "fine" },
      ],
    });
    const [, first, second] = body.messages as Array<Record<string, unknown>>;
    expect(first!.content).toBe(WITHHELD_NOTICE);
    expect(second!.content).toBe("fine");
  });

  it("withholds a Responses function output for a call that read a secret file", () => {
    const { body } = redactRequest("responses", {
      input: [
        { type: "function_call", call_id: "c1", name: "bash", arguments: readKey },
        { type: "function_call_output", call_id: "c1", output: "key material" },
      ],
    });
    const [, output] = body.input as Array<Record<string, unknown>>;
    expect(output!.output).toBe(WITHHELD_NOTICE);
  });
});

describe("swapToolJson", () => {
  it("returns arguments it cannot parse unchanged", () => {
    expect(swapToolJson("bash", "{not json", new Set())).toEqual({
      json: "{not json",
      swapped: 0,
    });
  });
});

describe("replay store", () => {
  it("forgets the oldest turn past 50,000 entries", () => {
    recordOriginal("text", "oldest harness", "oldest provider");
    for (let i = 0; i < 50_000; i++) recordOriginal("text", `filler ${i}`, `original ${i}`);
    expect(replayOriginal("text", "oldest harness")).toBeUndefined();
    expect(replayOriginal("text", "filler 49999")).toBe("original 49999");
  });

  it("has no key for arguments that are not JSON", () => {
    expect(argsKey("{not json")).toBeUndefined();
  });
});

describe("identity refresh", () => {
  const entry = (id: string, literal: string, caseSensitive = true): InventoryEntry => ({
    id,
    literal,
    match: "token",
    caseSensitive,
  });

  it("keeps every value it has seen, and reports only growth", () => {
    const known = new Map<string, InventoryEntry>();
    expect(mergeIdentity(known, [entry("runtime-ssid-1", "ZqxHome")])).toBe(true);
    expect(mergeIdentity(known, [entry("runtime-ssid-1", "ZqxHome")])).toBe(false);
    // Out of range now, another network in: both stay.
    expect(mergeIdentity(known, [entry("runtime-ssid-1", "ZqxCafe")])).toBe(true);
    expect([...known.values()].map((e) => [e.id, e.literal])).toEqual([
      ["runtime-ssid-1", "ZqxHome"],
      ["runtime-ssid-2", "ZqxCafe"],
    ]);
  });

  it("numbers a taken id without changing its kind, and folds caseless names", () => {
    const known = new Map<string, InventoryEntry>();
    mergeIdentity(known, [
      entry("runtime-host", "zqxbox"),
      entry("runtime-ssh-ip-1", "10.9.8.7", false),
    ]);
    mergeIdentity(known, [
      entry("runtime-host", "zqxnew"),
      entry("runtime-ssh-ip-1", "10.9.8.6", false),
      entry("runtime-ssh-host-1", "ZQXBOX", false),
    ]);
    expect([...known.values()].map((e) => e.id)).toEqual([
      "runtime-host",
      "runtime-ssh-ip-1",
      "runtime-host-2",
      "runtime-ssh-ip-2",
    ]);
  });

  it("stops at its bound instead of growing without limit", () => {
    const known = new Map<string, InventoryEntry>();
    const many = Array.from({ length: IDENTITY_ENTRIES_MAX + 5 }, (_, n) =>
      entry(`runtime-ssid-${n + 1}`, `zqxnet${n}`),
    );
    mergeIdentity(known, many);
    expect(known.size).toBe(IDENTITY_ENTRIES_MAX);
  });
});
