import { beforeAll, describe, expect, it } from "bun:test";
import path from "node:path";
import { type InventoryEntry, scan } from "../engine/lib/rules.ts";
import {
  IDENTITY_ENTRIES_MAX,
  initEngine,
  mergeIdentity,
  redactPath,
  redactQuery,
  redactRequest,
  refreshIdentity,
  swapToolArguments,
  swapToolJson,
  WITHHELD_NOTICE,
} from "./redact.ts";
import { formatSse, parseSseBlock } from "./streams.ts";
import { aliases } from "../engine/core.ts";
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

  it("withholds a notebook edit's output when the notebook path is a secret", () => {
    const args = JSON.stringify({ notebook_path: KEY, new_source: "x" });
    const { body } = redactRequest("chat", {
      messages: [
        {
          role: "assistant",
          tool_calls: [
            { id: "n1", type: "function", function: { name: "NotebookEdit", arguments: args } },
          ],
        },
        { role: "tool", tool_call_id: "n1", content: "key material" },
      ],
    });
    expect((body.messages as Array<Record<string, unknown>>)[1]!.content).toBe(WITHHELD_NOTICE);
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
  it("blocks arguments it cannot parse: no guard has read them", () => {
    expect(swapToolJson("bash", "{not json", new Set())).toEqual({
      json: "{}",
      swapped: 0,
      blocked: true,
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

  it("installs what joined on a refresh, and keeps it when it is gone", () => {
    const found = () => scan("joined ZqxRefreshNet").some((f) => f.secretValue === "ZqxRefreshNet");
    expect(found()).toBe(false);
    expect(refreshIdentity(() => [entry("runtime-ssid-1", "ZqxRefreshNet")])).toBe(true);
    expect(found()).toBe(true);
    expect(refreshIdentity(() => [entry("runtime-ssid-1", "ZqxRefreshNet")])).toBe(false);
    expect(refreshIdentity(() => [])).toBe(false);
    expect(found()).toBe(true);
  });
});

describe("invented stand-ins by shape", () => {
  // Stand-in shaped, never minted, never in real input.
  const INVENTED = "user-0a1b2c";
  const blocked = (name: string, args: unknown) =>
    swapToolArguments(name, args, new Set()).blocked === true;

  it("drops a shell write or an unlisted write tool naming one", () => {
    expect(blocked("bash", { command: `cat > notes.md <<EOF\n${INVENTED}\nEOF` })).toBe(true);
    expect(blocked("run", { command: `echo ${INVENTED} >> notes.md` })).toBe(true);
    expect(blocked("write_file", { path: "notes.md", content: INVENTED })).toBe(true);
  });

  it("lets a shell read naming one through", () => {
    expect(blocked("bash", { command: `grep -r ${INVENTED} .` })).toBe(false);
  });
});

describe("reworded stand-ins in writes", () => {
  // Built from pieces so no rule matches this source.
  const NAME = ["Zq", "xina ", "Vel", "marr"].join("");
  const blocked = (name: string, args: unknown, tags = new Set<string>()) =>
    swapToolArguments(name, args, tags).blocked === true;

  it("drops a write that glues, slugs or re-spaces one", () => {
    const standIn = aliases().standIn("pii-gazetteer-name", NAME);
    const slug = standIn.toLowerCase().replace(/\s+/g, "-");
    expect(blocked("write", { path: "a.md", content: `by ${standIn}s` })).toBe(true);
    expect(blocked("write", { path: `${slug}.md`, content: "x" })).toBe(true);
    expect(blocked("bash", { command: `echo "${standIn.replace(" ", "  ")}" > a.md` })).toBe(true);
  });

  it("lets exact, all-caps and possessive forms through, swapped", () => {
    const standIn = aliases().standIn("pii-gazetteer-name", NAME);
    for (const content of [standIn, standIn.toUpperCase(), `${standIn}'s`]) {
      const result = swapToolArguments("write", { path: "a.md", content }, new Set());
      expect(result.blocked).toBeUndefined();
      expect((result.args as { content: string }).content.toLowerCase()).toContain(
        NAME.toLowerCase(),
      );
    }
  });

  it("is lifted by [allow-pii], and ignores reads", () => {
    const standIn = aliases().standIn("pii-gazetteer-name", NAME);
    const args = { path: "a.md", content: `${standIn}s` };
    expect(blocked("write", args, new Set(["pii"]))).toBe(false);
    expect(blocked("bash", { command: `grep -r "${standIn}s" .` })).toBe(false);
  });
});

describe("query and stream fidelity", () => {
  it("passes a provider's key in the query, and still scans the rest", () => {
    const key = "AIzaSyD3x4mpl3K3yV4lu3F0rT3st1ngOnly0";
    const email = "jane.doe@acme-corp.com";
    const { search, hits } = redactQuery(
      `?alt=sse&key=${key}&note=${encodeURIComponent(email)}`,
      new Set(),
    );
    expect(hits).toBeGreaterThan(0);
    const params = new URLSearchParams(search);
    expect(params.get("key")).toBe(key);
    expect(params.get("alt")).toBe("sse");
    expect(params.get("note")).not.toBe(email);
  });

  it("keeps every value of a repeated query key", () => {
    const email = "jane.doe@acme-corp.com";
    const { search, hits } = redactQuery(`?a=1&a=${encodeURIComponent(email)}&b=2`, new Set());
    expect(hits).toBeGreaterThan(0);
    const params = new URLSearchParams(search);
    expect(params.getAll("a")).toHaveLength(2);
    expect(params.getAll("a")[0]).toBe("1");
    expect(params.get("b")).toBe("2");
    expect(search).not.toContain("acme-corp");
  });

  it("keeps an event's id and retry lines", () => {
    const event = parseSseBlock("id: 7\nretry: 500\nevent: ping\ndata: {}");
    expect(event).toEqual({ event: "ping", data: "{}", id: "7", retry: "500" });
    expect(formatSse(event!)).toBe("event: ping\nid: 7\nretry: 500\ndata: {}\n\n");
    expect(formatSse(parseSseBlock("id: 9")!)).toBe("id: 9\n\n");
    expect(parseSseBlock(": comment")).toBeUndefined();
  });

  it("leaves invalid percent-encoding in paths as it is", () => {
    expect(redactPath("/v1/%", new Set()).path).toBe("/v1/%");
  });

  it("ignores non-string leaves when swapping tool arguments", () => {
    const result = swapToolArguments("write", { path: "a.md", content: 42 }, new Set());
    expect(result.blocked).toBeUndefined();
  });

  it("collects infra inventory when not off", () => {
    const saved = process.env.ITHILDIN_INFRA_INVENTORY;
    process.env.ITHILDIN_INFRA_INVENTORY = "on";
    try {
      refreshIdentity();
    } finally {
      if (saved === undefined) delete process.env.ITHILDIN_INFRA_INVENTORY;
      else process.env.ITHILDIN_INFRA_INVENTORY = saved;
    }
  });
});
