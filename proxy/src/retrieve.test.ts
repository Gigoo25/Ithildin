import { describe, expect, it } from "bun:test";
import { CRUSH_MIN_ITEMS, crushJson } from "./crush.ts";
import { answerMcp, offeredTool, Originals, outputId } from "./retrieve.ts";
import { createHandler, DEFAULT_ROUTES } from "./server.ts";
import { MASK_THRESHOLD_TOKENS, shapeRequest } from "./shape.ts";

// Pods that are all alike but for one failing and one slow, with ids and
// names unique to each, as a cluster tool lists them.
function pods(count: number): Array<Record<string, unknown>> {
  return Array.from({ length: count }, (_, index) => ({
    id: `pod-${index}`,
    name: `web-${index.toString(36)}-${(index * 7919).toString(36)}`,
    status: index === 17 ? "CrashLoopBackOff" : "Running",
    restarts: 0,
    latency: index === 23 ? 9_000 : 40 + (index % 5),
  }));
}

describe("crushJson", () => {
  it("keeps the head, the tail and the items that differ, and marks the gaps", () => {
    const list = pods(60);
    const out = crushJson(JSON.stringify(list, null, 2));
    expect(out?.omitted).toBe(53);
    const kept = JSON.parse(out!.text) as unknown[];
    const ids = kept.map((item) => (typeof item === "string" ? item : (item as { id: string }).id));
    expect(ids).toEqual([
      "pod-0",
      "pod-1",
      "pod-2",
      "[14 similar items omitted]",
      "pod-17",
      "[5 similar items omitted]",
      "pod-23",
      "[34 similar items omitted]",
      "pod-58",
      "pod-59",
    ]);
  });

  it("reaches an array inside an object, and names a single omitted item", () => {
    const list = pods(CRUSH_MIN_ITEMS);
    const out = crushJson(JSON.stringify({ items: list, total: list.length }));
    expect(out?.text).toContain('"total":30');
    expect(out?.text).toContain('"pod-17"');
  });

  it("leaves a short array, a mixed one, prose, broken JSON and too small a gain", () => {
    expect(crushJson(JSON.stringify(pods(CRUSH_MIN_ITEMS - 1)))).toBeUndefined();
    expect(crushJson(JSON.stringify([...pods(40), 1]))).toBeUndefined();
    expect(crushJson("not json")).toBeUndefined();
    expect(crushJson("{ broken")).toBeUndefined();
    // The items that must stay hold nearly all the text, so cutting the rest
    // saves too little to be worth the loss.
    const heavy = pods(40).map((pod, index) =>
      index < 3 ? { ...pod, log: "x".repeat(5_000) } : pod,
    );
    expect(crushJson(JSON.stringify(heavy))).toBeUndefined();
  });

  it("drops the middle of a uniform array", () => {
    const same = Array.from({ length: 50 }, (_, index) => ({ n: index, ok: true }));
    expect(crushJson(JSON.stringify(same))?.omitted).toBe(45);
  });
});

describe("the retrieve tool's offer", () => {
  it("is found under each agent's spelling, and not under others", () => {
    expect(offeredTool({ tools: [{ name: "Bash" }, { name: "mcp__ithildin__retrieve" }] })).toBe(
      "mcp__ithildin__retrieve",
    );
    const chat = { tools: [{ type: "function", function: { name: "ithildin_retrieve" } }] };
    expect(offeredTool(chat)).toBe("ithildin_retrieve");
    expect(offeredTool({ tools: [{ name: "retrieve" }, null] })).toBeUndefined();
    expect(offeredTool({})).toBeUndefined();
  });
});

describe("Originals", () => {
  it("gives back what it kept, and lets the oldest go past its limits", () => {
    const store = new Originals();
    store.keep("a", "first");
    store.keep("a", "again");
    expect(store.get("a")).toBe("again");
    expect(store.get("missing")).toBeUndefined();
    const big = "x".repeat(40 * 1024 * 1024);
    store.keep("b", big);
    store.keep("c", big);
    expect(store.get("b")).toBeUndefined();
    expect(store.get("c")).toBe(big);
    for (let index = 0; index <= 10_000; index++) store.keep(`n${index}`, "");
    expect(store.get("c")).toBeUndefined();
  });
});

describe("the MCP endpoint", () => {
  const call = (body: unknown, init: RequestInit = {}) =>
    new Request("http://127.0.0.1/mcp", {
      method: "POST",
      body: typeof body === "string" ? body : JSON.stringify(body),
      ...init,
    });
  const answer = async (store: Originals, body: unknown) =>
    (await (await answerMcp(call(body), store)).json()) as Record<string, any>;

  it("introduces itself, lists the tool and answers a ping", async () => {
    const store = new Originals();
    const hello = await answer(store, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-03-26" },
    });
    expect(hello.result.protocolVersion).toBe("2025-03-26");
    expect(hello.result.serverInfo.name).toBe("ithildin");
    const plain = await answer(store, { jsonrpc: "2.0", id: 0, method: "initialize" });
    expect(plain.result.protocolVersion).toBe("2025-06-18");
    const list = await answer(store, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(list.result.tools[0].name).toBe("retrieve");
    expect((await answer(store, { jsonrpc: "2.0", id: 3, method: "ping" })).result).toEqual({});
    const note = await answerMcp(
      call({ jsonrpc: "2.0", method: "notifications/initialized" }),
      store,
    );
    expect(note.status).toBe(202);
  });

  it("returns a kept output, and says when one is gone", async () => {
    const store = new Originals();
    store.keep("id1", "the whole output");
    const found = await answer(store, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "retrieve", arguments: { id: "id1" } },
    });
    expect(found.result.content[0].text).toBe("the whole output");
    const gone = await answer(store, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "retrieve", arguments: { id: "nope" } },
    });
    expect(gone.result.isError).toBe(true);
    const bad = await answer(store, {
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "other" },
    });
    expect(bad.error.code).toBe(-32602);
  });

  it("refuses what is not one JSON-RPC message", async () => {
    const store = new Originals();
    expect((await answerMcp(new Request("http://127.0.0.1/x"), store)).status).toBe(405);
    expect((await answer(store, "{ broken")).error.code).toBe(-32700);
    expect((await answer(store, [1])).error.code).toBe(-32600);
    expect((await answer(store, { jsonrpc: "2.0", id: 7, method: "nope" })).error.code).toBe(
      -32601,
    );
    const huge = call("{}", { headers: { "content-length": String(1 << 20) } });
    expect(((await (await answerMcp(huge, store)).json()) as any).error.code).toBe(-32600);
    // A chunked body declares no length, and is cut off as it is read.
    const chunked = new Request("http://127.0.0.1/mcp", {
      method: "POST",
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(1 << 20).fill(32));
          controller.close();
        },
      }),
    });
    expect(chunked.headers.get("content-length")).toBeNull();
    expect(((await (await answerMcp(chunked, store)).json()) as any).error.code).toBe(-32600);
  });
});

describe("shaping with the retrieve tool", () => {
  const kept = new Map<string, string>();
  const retrieval = {
    tool: "mcp__ithildin__retrieve",
    keep: (text: string) => {
      const id = outputId(text);
      kept.set(id, text);
      return id;
    },
  };
  const pad = "word ".repeat(Math.ceil(MASK_THRESHOLD_TOKENS / 10));
  const conversation = (output: string, position: "early" | "late") => {
    const messages: unknown[] = [];
    for (let i = 0; i < 20; i++)
      messages.push({ role: "user", content: "go" }, { role: "assistant", content: pad });
    const pair = [
      { role: "assistant", content: [{ type: "tool_use", id: "p", name: "pods", input: {} }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "p", content: output }] },
    ];
    if (position === "early") messages.splice(2, 0, ...pair);
    else messages.push(...pair);
    return { messages };
  };
  const last = (body: Record<string, unknown>, from: "early" | "late") => {
    const list = body.messages as Array<{ content: Array<{ content: string }> }>;
    return list[from === "early" ? 3 : list.length - 1]!.content[0]!.content;
  };

  it("names the tool and an id in a mask, and keeps the output under it", () => {
    const output = "line of log\n".repeat(200);
    const shaped = shapeRequest("anthropic", conversation(output, "early"), retrieval);
    const stub = last(shaped!.body, "early");
    expect(stub).toContain(`Call mcp__ithildin__retrieve with id "${outputId(output)}"`);
    expect(kept.get(outputId(output))).toBe(output);
  });

  it("crushes a recent JSON array, and does not without the tool", () => {
    const output = JSON.stringify(pods(80), null, 2);
    const shaped = shapeRequest("anthropic", conversation(output, "late"), retrieval);
    const text = last(shaped!.body, "late");
    expect(text).toContain("CrashLoopBackOff");
    expect(text).toContain(
      `similar array items omitted to save context. Call mcp__ithildin__retrieve`,
    );
    const plain = shapeRequest("anthropic", conversation(output, "late"));
    expect(last(plain!.body, "late")).not.toContain("omitted");
  });

  it("leaves a small JSON output to the lossless passes", () => {
    const output = JSON.stringify(pods(CRUSH_MIN_ITEMS)).slice(0, 900);
    const shaped = shapeRequest("anthropic", conversation(output, "late"), retrieval);
    expect(shaped).toBeUndefined();
  });
});

describe("the proxy serves the retrieve tool", () => {
  const big = "row of a query result\n".repeat(400);
  const messages = () => {
    const list: unknown[] = [];
    for (let i = 0; i < 22; i++)
      list.push(
        { role: "user", content: "go" },
        { role: "assistant", content: "word ".repeat(MASK_THRESHOLD_TOKENS / 10) },
      );
    list.splice(
      2,
      0,
      { role: "assistant", content: [{ type: "tool_use", id: "q", name: "query", input: {} }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "q", content: big }] },
    );
    return list;
  };

  it("keeps a masked output, and hands it back only to this machine", async () => {
    let sent = "";
    const handler = createHandler(DEFAULT_ROUTES, (async (_url: string, init: RequestInit) => {
      sent = String(init.body);
      return Response.json({ content: [] });
    }) as never);
    const body = {
      model: "m",
      tools: [{ name: "mcp__ithildin__retrieve", input_schema: { type: "object" } }],
      messages: messages(),
    };
    await (
      await handler(
        new Request("http://127.0.0.1/anthropic/v1/messages", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
      )
    ).text();
    const id = /with id \\"([^"\\]+)\\"/.exec(sent)?.[1];
    expect(id).toBe(outputId(big));
    const rpc = (host: string) =>
      handler(
        new Request(`http://${host}/mcp`, {
          method: "POST",
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "tools/call",
            params: { name: "retrieve", arguments: { id } },
          }),
        }),
      );
    const back = (await (await rpc("127.0.0.1")).json()) as any;
    expect(back.result.content[0].text).toBe(big);
    expect((await rpc("example.com")).status).toBe(403);
  });
});
