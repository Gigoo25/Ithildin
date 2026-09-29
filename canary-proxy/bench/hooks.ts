// Test-only: the proxy's request path behind the hook names the engine's
// suites were written against (they predate the proxy and drove Pi's
// extension). Every call goes through redactBody as a chat request, so the
// suites measure exactly what the proxy sends upstream.
import { clearCaches } from "../engine/core.ts";
import { setRuntimeInventory } from "../engine/lib/rules.ts";
import { redactBody, requestAllowTags } from "../src/canary.ts";

type Chunk = { type: string; text?: string };
// Results are loosely typed: suites index into them the way the old hook
// payloads were shaped. `_ctx` is the old hook context, accepted and unused.
type Result = any;

export type Hooks = {
  agent_start(_event?: unknown, _ctx?: unknown): void;
  session_shutdown(_event?: unknown, _ctx?: unknown): void;
  context(event: { messages: unknown[] }, _ctx?: unknown): Result;
  before_provider_request(event: { payload: Record<string, unknown> }, _ctx?: unknown): Result;
  message_end(event: { message: Record<string, unknown> }, _ctx?: unknown): Result;
  tool_result(event: { toolName: string; input?: unknown; content: Chunk[] }, _ctx?: unknown): Result;
};

export function createHooks(): Hooks {
  // The proxy reads allow tags from the latest typed prompt of each request.
  // Here that prompt arrives through `context`, and later calls reuse it.
  let tags = new Set<string>();
  const chat = (messages: unknown[]) => redactBody("chat", { messages }, tags);
  return {
    agent_start() {
      tags = new Set();
    },
    session_shutdown() {
      tags = new Set();
      setRuntimeInventory([]);
      clearCaches();
    },
    context(event) {
      tags = requestAllowTags("chat", { messages: event.messages });
      if (tags.has("all")) return undefined;
      const out = chat(event.messages);
      return out.hits === 0 ? undefined : { messages: out.body.messages };
    },
    before_provider_request(event) {
      if (tags.has("all")) return undefined;
      const out = redactBody("chat", event.payload, tags);
      return out.hits === 0 ? undefined : out.body;
    },
    message_end(event) {
      const out = chat([event.message]);
      return out.hits === 0 ? undefined : { message: (out.body.messages as unknown[])[0] };
    },
    // A tool result travels with the call that produced it, which decides
    // whether it is withheld (secret files, the inventory).
    tool_result(event) {
      if (tags.has("all")) return undefined;
      // Without an input, only the result is sent: every scanned string is
      // then the fixture itself, which the bench's coordinate audit requires.
      const call = event.input === undefined ? [] : [
        { role: "assistant", content: null, tool_calls: [{ id: "call", type: "function", function: { name: event.toolName, arguments: JSON.stringify(event.input) } }] },
      ];
      const out = chat([...call, { role: "tool", tool_call_id: "call", content: event.content }]);
      if (out.hits === 0) return undefined;
      const content = (out.body.messages as Array<{ content: unknown }>).at(-1)!.content;
      return { content: typeof content === "string" ? [{ type: "text", text: content }] : content };
    },
  };
}
