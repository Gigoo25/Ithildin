// canary-proxy: sensitive-canary as a local HTTP proxy in front of model
// providers, for any agent that lets you set its base URL (Claude Code's
// ANTHROPIC_BASE_URL, Pi's per-provider baseUrl). It is the only redaction
// layer: agents run no canary of their own, local models included.
//
//   http://127.0.0.1:<port>/<route>/<rest>  ->  <upstream><rest>
//
// Requests: every JSON body is redacted by the canary engine before it
// leaves (prompts, tool output, system prompts, compaction, subagents), and
// tool results that read a secret file are withheld whole (canary.ts). The
// user's own credentials pass through untouched; the proxy holds none.
// Responses: tool-call arguments get stand-ins swapped back to real values
// (see streams.ts), so tools run against real hosts and paths.
//
// It fails closed: an unknown route, an unreadable JSON body, a compressed
// request body, or a WebSocket upgrade is refused instead of forwarded raw.

import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { type Counts, type Format, initEngine, redactQuery, redactRequest, saveScanCache, typedPromptCount } from "./canary.ts";
import { createStatusBook } from "./status.ts";
import { type SelfTest, selfTest } from "./selftest.ts";
import { createRewriter, formatSse, parseSseBlock, swapResponseBody } from "./streams.ts";

export interface Route {
  upstream: string;
  // Path prefix rewrites, first match wins: {"/chat/": "/v1/chat/"}.
  rewrite?: Record<string, string>;
}

// Upstreams for the subscriptions in use. A routes file adds to the table
// (local and LAN model servers, config/canary-proxy/routes.json) and can
// override an entry.
export const DEFAULT_ROUTES: Record<string, Route> = {
  anthropic: { upstream: "https://api.anthropic.com" },
  "openai-codex": { upstream: "https://chatgpt.com/backend-api" },
  // One Pi provider, three wire formats: Anthropic models append /v1/messages
  // to the base URL; OpenAI-compatible ones /chat/completions or /responses
  // to base + /v1.
  "opencode-go": { upstream: "https://opencode.ai/zen/go", rewrite: { "/chat/": "/v1/chat/", "/responses": "/v1/responses" } },
};

export function loadRoutes(file: string | undefined): Record<string, Route> {
  if (!file) return DEFAULT_ROUTES;
  const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, string | Route>;
  return { ...DEFAULT_ROUTES, ...Object.fromEntries(Object.entries(parsed).map(([name, route]) => [name, typeof route === "string" ? { upstream: route } : route])) };
}

export function formatForPath(pathname: string): Format | undefined {
  if (/\/v1\/messages(?:\/count_tokens)?$/.test(pathname)) return "anthropic";
  if (pathname.endsWith("/chat/completions")) return "chat";
  if (pathname.endsWith("/responses")) return "responses";
  return undefined;
}

export function upstreamUrl(route: Route, rest: string, search: string): string {
  let tail = rest;
  for (const [from, to] of Object.entries(route.rewrite ?? {})) {
    if (tail.startsWith(from)) {
      tail = to + tail.slice(from.length);
      break;
    }
  }
  return route.upstream.replace(/\/+$/, "") + tail + search;
}

// Pi's footer tags its requests with its session id (the proxy's own header,
// never forwarded); Claude sends X-Claude-Code-Session-Id itself.
const SESSION_HEADER = "x-canary-session";

const HOP_HEADERS = ["host", "connection", "content-length", "accept-encoding", "transfer-encoding", "keep-alive", "upgrade", "te", "trailer", "proxy-connection", "proxy-authorization"];

// Largest request body scanned. Anthropic's own limit is 32 MB; a bigger one
// would be refused upstream anyway, and holding it would cost that much memory
// per request here.
export const REQUEST_BYTES_MAX = 32 * 1024 * 1024;

// Deepest JSON nesting scanned. Provider requests nest about 20 deep (tool
// schemas included); redaction recurses, and 20,000 levels overflowed the
// stack. Refused up front, so no scan starts that cannot finish.
export const JSON_DEPTH_MAX = 256;

// Nesting depth of a parsed value, without recursion; stops past `limit`.
export function jsonDepth(value: unknown, limit: number): number {
  let deepest = 0;
  const stack: Array<[unknown, number]> = [[value, 1]];
  while (stack.length > 0) {
    const [item, depth] = stack.pop()!;
    if (!item || typeof item !== "object") continue;
    if (depth > deepest) deepest = depth;
    if (deepest > limit) return deepest;
    for (const child of Object.values(item)) stack.push([child, depth + 1]);
  }
  return deepest;
}

function log(line: string): void {
  process.stderr.write(`canary-proxy: ${line}\n`);
}

function refuse(status: number, message: string): Response {
  log(`refused (${status}): ${message}`);
  return Response.json({ type: "error", error: { type: "canary_proxy_error", message: `canary-proxy: ${message}` } }, { status });
}

function rewriteSse(body: ReadableStream<Uint8Array>, format: Format, tags: Set<string>, done: (swapped: number) => void): ReadableStream<Uint8Array> {
  const rewriter = createRewriter(format, tags);
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffer = "";
  const emit = (block: string, controller: TransformStreamDefaultController<Uint8Array>) => {
    const event = parseSseBlock(block);
    if (!event) {
      if (block.trim() !== "") controller.enqueue(encoder.encode(`${block}\n\n`));
      return;
    }
    for (const out of rewriter.push(event)) controller.enqueue(encoder.encode(formatSse(out)));
  };
  return body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      buffer += decoder.decode(chunk, { stream: true });
      const blocks = buffer.split(/\r?\n\r?\n/);
      buffer = blocks.pop() ?? "";
      for (const block of blocks) emit(block, controller);
    },
    flush(controller) {
      buffer += decoder.decode();
      if (buffer.trim() !== "") emit(buffer, controller);
      done(rewriter.swapped);
    },
  }));
}

// The scanners the handler calls; tests pass ones that fail, to show a
// failed scan refuses the request instead of forwarding it.
export type Redactors = { request: typeof redactRequest; query: typeof redactQuery };
const REDACTORS: Redactors = { request: redactRequest, query: redactQuery };

// `gated`: refuse model requests until a self-test passes (selftest.ts). The
// server's handler is gated; the self-test's own and the tests' are not.
export function createHandler(routes: Record<string, Route>, fetchUpstream: typeof fetch = fetch, redact: Redactors = REDACTORS, gated = false) {
  // What redaction did per conversation, for the status badges (status.ts):
  // only this machine learns that swapping happens.
  const book = createStatusBook();
  let proof: SelfTest | undefined;
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname === "/_canary/selftest") {
      proof = await selfTest((upstream) => createHandler(routes, upstream, redact));
      log(proof.ok ? `self-test passed (${proof.ms}ms)` : `self-test FAILED: ${proof.failures.join("; ")}`);
      return Response.json(proof, { status: proof.ok ? 200 : 503 });
    }
    if (url.pathname === "/_canary/health") {
      // A failed self-test reads as down: both badges turn red on a non-200.
      if (proof && !proof.ok) return Response.json({ ok: false, selftest: proof }, { status: 503 });
      const status = book.lookup(url.searchParams.get("session") ?? undefined, url.searchParams.get("route") ?? undefined);
      return Response.json({ ok: true, routes: Object.keys(routes), badge: status?.badge ?? "CANARY ON", status, selftest: proof });
    }
    if (gated && !proof?.ok) {
      return refuse(503, proof ? `self-test failed (${proof.failures.join("; ")}), refusing to forward` : "self-test has not run yet");
    }
    const match = /^\/([^/]+)(\/.*)?$/.exec(url.pathname);
    const route = match ? routes[match[1]!] : undefined;
    if (!match || !route) return refuse(404, `no route for ${url.pathname.split("/")[1] ?? ""}`);
    // A socket's frames cannot be scanned one request at a time.
    if (request.headers.get("upgrade")) return refuse(501, "WebSocket upgrades cannot be scanned");
    const rest = match[2] ?? "";
    const format = formatForPath(rest);

    const session = request.headers.get(SESSION_HEADER) ?? request.headers.get("x-Claude-Code-Session-Id") ?? undefined;
    const headers = new Headers(request.headers);
    for (const name of HOP_HEADERS) headers.delete(name);
    headers.delete(SESSION_HEADER);
    headers.set("accept-encoding", "identity");

    let body: RequestInit["body"];
    let tags = new Set<string>();
    let hits = 0;
    let counts: Counts | undefined;
    let prompts = 0;
    let scanMs = 0;
    if (request.method !== "GET" && request.method !== "HEAD") {
      const encoding = request.headers.get("content-encoding");
      if (encoding && encoding !== "identity") return refuse(415, `compressed request bodies (${encoding}) cannot be scanned`);
      const declared = Number(request.headers.get("content-length") ?? 0);
      if (declared > REQUEST_BYTES_MAX) return refuse(413, `request body over ${REQUEST_BYTES_MAX} bytes`);
      const raw = await request.text();
      if (Buffer.byteLength(raw) > REQUEST_BYTES_MAX) return refuse(413, `request body over ${REQUEST_BYTES_MAX} bytes`);
      const type = request.headers.get("content-type") ?? "";
      if (type.includes("json") || (format !== undefined && raw.trimStart().startsWith("{"))) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(raw);
        } catch {
          return refuse(400, "request body is not valid JSON, refusing to forward it unscanned");
        }
        // Every provider API takes an object; anything else was forwarded
        // unscanned before.
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return refuse(400, "request body is not a JSON object, refusing to forward it unscanned");
        if (jsonDepth(parsed, JSON_DEPTH_MAX) > JSON_DEPTH_MAX) return refuse(400, `request body nests deeper than ${JSON_DEPTH_MAX} levels`);
        {
          try {
            const started = performance.now();
            const redacted = redact.request(format ?? "chat", parsed as Record<string, unknown>);
            scanMs = Math.round(performance.now() - started);
            tags = redacted.tags;
            hits = redacted.hits;
            // Single-message side requests (titles, quota probes) are not the
            // conversation, so they do not set its badge.
            const record = parsed as { messages?: unknown; input?: unknown };
            const turns = Array.isArray(record.messages) ? record.messages : record.input;
            if (Array.isArray(turns) && turns.length > 1) {
              counts = redacted.counts;
              prompts = typedPromptCount(format ?? "chat", parsed as Record<string, unknown>);
            }
            body = JSON.stringify(redacted.body);
          } catch (error) {
            return refuse(500, `redaction failed (${(error as Error).name}), refusing to forward unscanned`);
          }
        }
      } else if (raw.length > 0) {
        return refuse(415, `non-JSON request body (${type || "no content-type"}) cannot be scanned`);
      }
    }
    let search: string;
    try {
      const query = redact.query(url.search, tags);
      search = query.search;
      hits += query.hits;
      if (counts) counts.masked += query.values;
    } catch (error) {
      return refuse(500, `query redaction failed (${(error as Error).name}), refusing to forward unscanned`);
    }
    const target = upstreamUrl(route, rest, search);
    if (counts) book.record(session, match[1]!, counts, prompts);

    let upstream: Response;
    try {
      upstream = await fetchUpstream(target, { method: request.method, headers, body, redirect: "manual", signal: request.signal });
    } catch (error) {
      return refuse(502, `upstream unreachable (${(error as Error).message})`);
    }

    const outHeaders = new Headers(upstream.headers);
    outHeaders.delete("content-encoding");
    outHeaders.delete("content-length");
    const contentType = upstream.headers.get("content-type") ?? "";
    // scan= is the redaction time this proxy adds to each request; allow=
    // names the tags the user's latest prompt carried ([allow-pii] → pii), so
    // the journal shows when masking or a guard was lifted.
    const allowed = tags.size > 0 ? ` allow=${[...tags].sort().join(",")}` : "";
    const tag = `${match[1]}${rest} ${upstream.status} scan=${scanMs}ms${allowed}`;

    if (format && upstream.body && contentType.includes("text/event-stream")) {
      const stream = rewriteSse(upstream.body, format, tags, (swapped) => log(`${tag} redacted=${hits} swapped=${swapped} (stream)`));
      return new Response(stream, { status: upstream.status, headers: outHeaders });
    }
    if (format && contentType.includes("json") && upstream.ok) {
      const text = await upstream.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        return refuse(502, "upstream reply is not valid JSON, refusing to pass unchecked tool calls");
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return refuse(502, "upstream reply is not a JSON object, refusing to pass it unchecked");
      let swapped: number;
      try {
        swapped = swapResponseBody(format, parsed as Record<string, unknown>, tags);
      } catch (error) {
        // Half-swapped, with blocked calls maybe still intact: never pass on.
        return refuse(502, `reply rewriting failed (${(error as Error).name}), refusing to pass unchecked tool calls`);
      }
      log(`${tag} redacted=${hits} swapped=${swapped}`);
      // Always re-serialized: a blocked call changes arguments without a swap.
      return new Response(JSON.stringify(parsed), { status: upstream.status, headers: outHeaders });
    }
    // A successful model reply in a shape not read here could carry tool
    // calls no guard saw. Errors and non-model routes pass as they are.
    if (format && upstream.ok && upstream.body) {
      await upstream.body.cancel();
      return refuse(502, `upstream reply type ${contentType.split(";")[0]} cannot be checked`);
    }
    log(`${tag} redacted=${hits}`);
    return new Response(upstream.body, { status: upstream.status, headers: outHeaders });
  };
}

// Longest a stop waits for in-flight replies. modules/canary-proxy.nix sets
// TimeoutStopSec above it.
const DRAIN_MS = 300_000;

export type Options = { port: number; routesFile: string | undefined };

// Settings from flags, then environment, then defaults. A port that is not
// a whole number in range stops startup: listening somewhere unexpected
// would leave agents pointed at nothing, or at something else.
export function readOptions(argv: string[], env: Record<string, string | undefined>, exists: (file: string) => boolean): Options {
  const arg = (name: string): string | undefined => {
    const index = argv.indexOf(`--${name}`);
    return index >= 0 ? argv[index + 1] : undefined;
  };
  const text = arg("port") ?? env.CANARY_PROXY_PORT ?? "18733";
  const port = Number(text);
  if (!/^\d+$/.test(text) || port < 1 || port > 65_535) throw new Error(`canary-proxy: invalid port ${JSON.stringify(text)}`);
  const home = env.HOME ?? os.homedir();
  const defaultRoutes = path.join(env.XDG_CONFIG_HOME || path.join(home, ".config"), "canary-proxy", "routes.json");
  const routesFile = arg("routes") ?? env.CANARY_PROXY_ROUTES ?? (exists(defaultRoutes) ? defaultRoutes : undefined);
  return { port, routesFile };
}

// Port 0 picks a free port (tests); the bound one is on the server.
export function start(options: Options, fetchUpstream: typeof fetch = fetch): { server: ReturnType<typeof Bun.serve>; drain: () => Promise<void>; proven: Promise<void> } {
  const routes = loadRoutes(options.routesFile);
  initEngine();
  const saving = setInterval(saveScanCache, 30_000);
  saving.unref();
  const handler = createHandler(routes, fetchUpstream, REDACTORS, true);
  const server = Bun.serve({ hostname: "127.0.0.1", port: options.port, idleTimeout: 255, fetch: handler });
  log(`listening on http://127.0.0.1:${server.port} (routes: ${Object.keys(routes).join(", ")})`);
  // Requests are refused until this passes; agents retry refused requests.
  const proven = handler(new Request("http://127.0.0.1/_canary/selftest")).then(() => undefined);
  // A rules edit restarts the proxy. Stop taking requests but let streaming
  // replies finish, so the edit does not cut a response off mid-turn; agents
  // retry the refused connections.
  const drain = async (): Promise<void> => {
    clearInterval(saving);
    saveScanCache();
    log("draining in-flight requests");
    await server.stop(false);
  };
  return { server, drain, proven };
}

// `canary-proxy selftest`: runs the self-test inside the proxy that is
// running now, so a pass means that process masks, not a fresh copy.
export async function selfTestCli(port: number, fetchProxy: typeof fetch = fetch): Promise<number> {
  let report: SelfTest;
  try {
    report = (await (await fetchProxy(`http://127.0.0.1:${port}/_canary/selftest`)).json()) as SelfTest;
  } catch (error) {
    process.stdout.write(`canary-proxy is not answering on port ${port} (${(error as Error).message})\n`);
    return 1;
  }
  process.stdout.write(report.ok
    ? `ok: an AWS key, a GitHub token and an email were masked before the provider, and a tool call got the real email back (${report.ms}ms)\n`
    : `FAILED: ${report.failures.join("; ")}\n`);
  return report.ok ? 0 : 1;
}

if (import.meta.main && process.argv[2] === "selftest") {
  process.exit(await selfTestCli(readOptions(process.argv, process.env, existsSync).port));
} else if (import.meta.main) {
  const { drain } = start(readOptions(process.argv, process.env, existsSync));
  // systemd's TimeoutStopSec is the backstop past DRAIN_MS.
  process.on("SIGTERM", () => {
    void drain().then(() => process.exit(0));
    setTimeout(() => process.exit(0), DRAIN_MS).unref();
  });
}
