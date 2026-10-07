// Getting back what shaping left out. A masked result says "re-run the call",
// which works for `cat` and fails for anything that changed since, cost money,
// or cannot run twice: a fetch, a query, an MCP call. So the proxy keeps the
// whole output of what it shortens and serves it back as an MCP tool,
// `retrieve`, which the agent adds like any other server:
//
//   claude mcp add --transport http ithildin http://127.0.0.1:18733/mcp
//
// Shaping only mentions the tool, and only does the lossy things that need it
// (crush.ts), when the request offers it: an agent without it gets exactly the
// behaviour it had before.
//
// The id is a digest of the output, so a stub that names it is still a pure
// function of the request and the prompt cache holds. What is kept is the
// output as it was forwarded, redacted; the tool swaps the stand-ins back,
// like any reply, so the agent sees what its own tool returned. Memory only,
// and bounded: a restart or a long session lets old outputs go, and the tool
// says so rather than failing.

import { createHash } from "node:crypto";
import { swapText } from "./redact.ts";
import { errorReply, readCapped } from "./reply.ts";

export const TOOL_NAME = "retrieve";
const SERVER_NAME = "ithildin";
// The tool's name as the agents spell an MCP server's tool: Claude Code and
// Codex `mcp__ithildin__retrieve`, opencode `ithildin_retrieve`.
const OFFERED = /(?:^|_)ithildin_{1,2}retrieve$/;
const ID_CHARS = 12;
const BYTES_MAX = 64 * 1024 * 1024;
const ENTRIES_MAX = 10_000;
const MCP_BYTES_MAX = 64 * 1024;
const PROTOCOL = "2025-06-18";

export function outputId(text: string): string {
  return createHash("sha256").update(text).digest("base64url").slice(0, ID_CHARS);
}

// The retrieve tool's name in this request's tool list, or undefined when the
// agent does not have it.
export function offeredTool(body: Record<string, unknown>): string | undefined {
  if (!Array.isArray(body.tools)) return;
  for (const tool of body.tools as Array<Record<string, unknown> | null>) {
    const fn = tool?.function as Record<string, unknown> | undefined;
    const name = tool?.name ?? fn?.name;
    if (typeof name === "string" && OFFERED.test(name)) return name;
  }
  return undefined;
}

// Outputs by id, oldest first; a read moves one to the end.
export class Originals {
  private readonly texts = new Map<string, string>();
  private bytes = 0;
  constructor() {}

  keep(id: string, text: string): void {
    const known = this.texts.get(id);
    if (known !== undefined) this.bytes -= known.length;
    this.texts.delete(id);
    this.texts.set(id, text);
    this.bytes += text.length;
    while (this.texts.size > ENTRIES_MAX || (this.bytes > BYTES_MAX && this.texts.size > 1)) {
      const [oldest, value] = this.texts.entries().next().value!;
      this.texts.delete(oldest);
      this.bytes -= value.length;
    }
  }

  get(id: string): string | undefined {
    const text = this.texts.get(id);
    if (text === undefined) return;
    this.texts.delete(id);
    this.texts.set(id, text);
    return text;
  }
}

const TOOL = {
  name: TOOL_NAME,
  description:
    "Read back a tool output that the ithildin proxy shortened or removed from this " +
    "conversation to save context. Pass the id quoted in the note that replaced it.",
  inputSchema: {
    type: "object",
    properties: { id: { type: "string", description: "The id from the note." } },
    required: ["id"],
  },
};

const GONE =
  "No output is kept under that id: the proxy restarted, or let it go to bound its memory. " +
  "Re-run the call that produced it.";

function rpc(id: unknown, body: { result: unknown } | { error: unknown }): Response {
  return Response.json({ jsonrpc: "2.0", id: id ?? null, ...body });
}

function failure(id: unknown, code: number, message: string): Response {
  return rpc(id, { error: { code, message } });
}

function called(params: Record<string, unknown> | undefined, originals: Originals): unknown {
  if (params?.name !== TOOL_NAME) return;
  const id = (params.arguments as Record<string, unknown> | undefined)?.id;
  const text = typeof id === "string" ? originals.get(id) : undefined;
  if (text === undefined) return { content: [{ type: "text", text: GONE }], isError: true };
  return { content: [{ type: "text", text: swapText(text, new Set()).text }] };
}

// One JSON-RPC message of MCP's streamable HTTP transport, answered as plain
// JSON: the tool is one call and one answer, so nothing here needs a stream.
export async function answerMcp(request: Request, originals: Originals): Promise<Response> {
  if (request.method !== "POST")
    return errorReply(405, `${request.method} not allowed`, { allow: "POST" });
  if (Number(request.headers.get("content-length") ?? 0) > MCP_BYTES_MAX)
    return failure(null, -32600, "request too large");
  // Capped as it is read too: a chunked body declares no length.
  const raw = await readCapped(request.body, MCP_BYTES_MAX);
  if (raw === undefined) return failure(null, -32600, "request too large");
  let message: Record<string, unknown>;
  try {
    message = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return failure(null, -32700, "parse error");
  }
  if (!message || typeof message !== "object" || Array.isArray(message))
    return failure(null, -32600, "one JSON-RPC message per request");
  const { id, method } = message;
  const params = message.params as Record<string, unknown> | undefined;
  // A notification gets no answer, only an acknowledgement.
  if (id === undefined) return new Response(null, { status: 202 });
  if (method === "initialize") {
    const version = typeof params?.protocolVersion === "string" ? params.protocolVersion : PROTOCOL;
    const serverInfo = { name: SERVER_NAME, version: "1" };
    return rpc(id, {
      result: { protocolVersion: version, capabilities: { tools: {} }, serverInfo },
    });
  }
  if (method === "ping") return rpc(id, { result: {} });
  if (method === "tools/list") return rpc(id, { result: { tools: [TOOL] } });
  if (method === "tools/call") {
    const result = called(params, originals);
    if (result === undefined) return failure(id, -32602, `unknown tool ${String(params?.name)}`);
    return rpc(id, { result });
  }
  return failure(id, -32601, `method not found: ${String(method)}`);
}
