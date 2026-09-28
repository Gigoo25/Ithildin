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
// It fails closed: an unknown route, an unreadable JSON body, or a compressed
// request body is refused instead of forwarded raw.

import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { type Format, initEngine, redactRequest, saveScanCache } from "./canary.ts";
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

const HOP_HEADERS = ["host", "connection", "content-length", "accept-encoding", "transfer-encoding", "keep-alive"];

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

export function createHandler(routes: Record<string, Route>, fetchUpstream: typeof fetch = fetch) {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname === "/_canary/health") return Response.json({ ok: true, routes: Object.keys(routes) });
    const match = /^\/([^/]+)(\/.*)?$/.exec(url.pathname);
    const route = match ? routes[match[1]!] : undefined;
    if (!match || !route) return refuse(404, `no route for ${url.pathname.split("/")[1] ?? ""}`);
    const rest = match[2] ?? "";
    const format = formatForPath(rest);
    const target = upstreamUrl(route, rest, url.search);

    const headers = new Headers(request.headers);
    for (const name of HOP_HEADERS) headers.delete(name);
    headers.set("accept-encoding", "identity");

    let body: BodyInit | undefined;
    let tags = new Set<string>();
    let hits = 0;
    let scanMs = 0;
    if (request.method !== "GET" && request.method !== "HEAD") {
      const encoding = request.headers.get("content-encoding");
      if (encoding && encoding !== "identity") return refuse(415, `compressed request bodies (${encoding}) cannot be scanned`);
      const raw = await request.text();
      const type = request.headers.get("content-type") ?? "";
      if (type.includes("json") || (format !== undefined && raw.trimStart().startsWith("{"))) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(raw);
        } catch {
          return refuse(400, "request body is not valid JSON, refusing to forward it unscanned");
        }
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          try {
            const started = performance.now();
            const redacted = redactRequest(format ?? "chat", parsed as Record<string, unknown>);
            scanMs = Math.round(performance.now() - started);
            tags = redacted.tags;
            hits = redacted.hits;
            body = JSON.stringify(redacted.body);
          } catch (error) {
            return refuse(500, `redaction failed (${(error as Error).name}), refusing to forward unscanned`);
          }
        } else {
          body = raw;
        }
      } else if (raw.length > 0) {
        return refuse(415, `non-JSON request body (${type || "no content-type"}) cannot be scanned`);
      }
    }

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
    // scan= is the redaction time this proxy adds to each request.
    const tag = `${match[1]}${rest} ${upstream.status} scan=${scanMs}ms`;

    if (format && upstream.body && contentType.includes("text/event-stream")) {
      const stream = rewriteSse(upstream.body, format, tags, (swapped) => log(`${tag} redacted=${hits} swapped=${swapped} (stream)`));
      return new Response(stream, { status: upstream.status, headers: outHeaders });
    }
    if (format && contentType.includes("json") && upstream.ok) {
      const text = await upstream.text();
      let swapped = 0;
      let out = text;
      try {
        const parsed = JSON.parse(text) as Record<string, unknown>;
        swapped = swapResponseBody(format, parsed, tags);
        if (swapped > 0) out = JSON.stringify(parsed);
      } catch {
        // Not JSON after all: pass it on as is.
      }
      log(`${tag} redacted=${hits} swapped=${swapped}`);
      return new Response(out, { status: upstream.status, headers: outHeaders });
    }
    log(`${tag} redacted=${hits}`);
    return new Response(upstream.body, { status: upstream.status, headers: outHeaders });
  };
}

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

if (import.meta.main) {
  const port = Number(arg("port") ?? process.env.CANARY_PROXY_PORT ?? 18733);
  const defaultRoutes = path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), ".config"), "canary-proxy", "routes.json");
  const routesFile = arg("routes") ?? process.env.CANARY_PROXY_ROUTES ?? (() => {
    try {
      readFileSync(defaultRoutes);
      return defaultRoutes;
    } catch {
      return undefined;
    }
  })();
  const routes = loadRoutes(routesFile);
  initEngine();
  setInterval(saveScanCache, 30_000).unref();
  process.on("SIGTERM", () => {
    saveScanCache();
    process.exit(0);
  });
  Bun.serve({ hostname: "127.0.0.1", port, idleTimeout: 255, fetch: createHandler(routes) });
  log(`listening on http://127.0.0.1:${port} (routes: ${Object.keys(routes).join(", ")})`);
}
