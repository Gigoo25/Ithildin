// ithildin: the engine as a local HTTP proxy in front of model
// providers, for any agent that lets you set its base URL (Claude Code's
// ANTHROPIC_BASE_URL, Pi's per-provider baseUrl). It is the only redaction
// layer: agents run no redaction of their own, local models included.
//
//   http://127.0.0.1:<port>/<route>/<rest>  ->  <upstream><rest>
//
// Requests: every JSON body is redacted by the engine before it
// leaves (prompts, tool output, system prompts, compaction, subagents), and
// tool results that read a secret file are withheld whole (redact.ts). The
// user's own credentials pass through untouched; the proxy holds none.
// Responses: tool-call arguments get stand-ins swapped back to real values
// (see streams.ts), so tools run against real hosts and paths.
//
// It fails closed: an unknown route, an unreadable JSON body, a compressed
// request body, or a WebSocket upgrade is refused instead of forwarded raw.

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  type Counts,
  type Format,
  initEngine,
  redactHeaders,
  redactQuery,
  redactRequest,
  refreshIdentity,
  saveScanCache,
  typedPromptCount,
} from "./redact.ts";
import { configHome, NAME } from "../engine/lib/names.ts";
import { aliasStyle } from "../engine/lib/rules.ts";
import { createStatusBook } from "./status.ts";
import { type SelfTest, selfTest } from "./selftest.ts";
import { createRewriter, formatSse, parseSseBlock, swapResponseBody } from "./streams.ts";
import type { Label } from "./trust.ts";
import { runCheck } from "./check.ts";

export interface Route {
  upstream: string;
  // Path prefix rewrites, first match wins: {"/chat/": "/v1/chat/"}.
  rewrite?: Record<string, string>;
}

// Upstreams for the subscriptions in use. A routes file adds to the table
// (local and LAN model servers, config/ithildin/routes.json) and can
// override an entry.
export const DEFAULT_ROUTES: Record<string, Route> = {
  anthropic: { upstream: "https://api.anthropic.com" },
  "openai-codex": { upstream: "https://chatgpt.com/backend-api" },
  // One Pi provider, three wire formats: Anthropic models append /v1/messages
  // to the base URL; OpenAI-compatible ones /chat/completions or /responses
  // to base + /v1.
  "opencode-go": {
    upstream: "https://opencode.ai/zen/go",
    rewrite: { "/chat/": "/v1/chat/", "/responses": "/v1/responses" },
  },
};

export function loadRoutes(file: string | undefined): Record<string, Route> {
  if (!file) return DEFAULT_ROUTES;
  const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, string | Route>;
  return {
    ...DEFAULT_ROUTES,
    ...Object.fromEntries(
      Object.entries(parsed).map(([name, route]) => [
        name,
        typeof route === "string" ? { upstream: route } : route,
      ]),
    ),
  };
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
// opencode sends x-opencode-session-id.
const SESSION_HEADER = "x-ithildin-session";
const OWN_PATH = /^\/_ithildin\/(selftest|health)$/;

const HOP_HEADERS = [
  "host",
  "connection",
  "content-length",
  "accept-encoding",
  "transfer-encoding",
  "keep-alive",
  "upgrade",
  "te",
  "trailer",
  "proxy-connection",
  "proxy-authorization",
];

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
  process.stderr.write(`ithildin: ${line}\n`);
}

// Each tool no guard reads, named once, so the badge's ?Nt can be traced.
const UNGUARDED_MAX = 1000;
const unguardedSeen = new Set<string>();

function noteUnguarded(names: string[]): void {
  for (const name of names) {
    if (unguardedSeen.has(name) || unguardedSeen.size >= UNGUARDED_MAX) continue;
    unguardedSeen.add(name);
    log(`tool ${name} acts, and no guard reads its calls`);
  }
}

function refuse(status: number, message: string): Response {
  log(`refused (${status}): ${message}`);
  return Response.json(
    { type: "error", error: { type: "ithildin_error", message: `ithildin: ${message}` } },
    { status },
  );
}

function rewriteSse(
  body: ReadableStream<Uint8Array>,
  format: Format,
  tags: Set<string>,
  done: (swapped: number) => void,
): ReadableStream<Uint8Array> {
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
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        buffer += decoder.decode(chunk, { stream: true });
        const blocks = buffer.split(/\r?\n\r?\n/);
        buffer = blocks.pop() ?? "";
        for (const block of blocks) emit(block, controller);
      },
      flush(controller) {
        buffer += decoder.decode();
        if (buffer.trim() !== "") emit(buffer, controller);
        for (const out of rewriter.flush()) controller.enqueue(encoder.encode(formatSse(out)));
        done(rewriter.swapped);
      },
    }),
  );
}

// The scanners the handler calls; tests pass ones that fail, to show a
// failed scan refuses the request instead of forwarding it.
export type Redactors = {
  request: typeof redactRequest;
  query: typeof redactQuery;
  headers: typeof redactHeaders;
};
const REDACTORS: Redactors = {
  request: redactRequest,
  query: redactQuery,
  headers: redactHeaders,
};

// What scanning a request body gave: the body to forward and what it found.
type Scanned = {
  body: string | undefined;
  tags: Set<string>;
  hits: number;
  counts: Counts | undefined;
  prompts: number;
  scanMs: number;
  label: Label;
  unguarded: string[];
};

function unscanned(): Scanned {
  return {
    body: undefined,
    tags: new Set(),
    hits: 0,
    counts: undefined,
    prompts: 0,
    scanMs: 0,
    label: { untrusted: false, private: false },
    unguarded: [],
  };
}

// The body as text, read no further than the cap: a chunked body declares no
// length. Undefined when it runs over.
async function readCapped(request: Request): Promise<string | undefined> {
  if (!request.body) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of request.body) {
    size += chunk.byteLength;
    // Leaving the loop cancels the rest of the stream.
    if (size > REQUEST_BYTES_MAX) return undefined;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

// The request body redacted, or the refusal. Bodies not read as JSON pass
// only when empty.
async function scanRequest(
  request: Request,
  format: Format | undefined,
  redact: Redactors,
  session: string | null,
): Promise<Scanned | Response> {
  if (request.method === "GET" || request.method === "HEAD") return unscanned();
  const encoding = request.headers.get("content-encoding");
  if (encoding && encoding !== "identity")
    return refuse(415, `compressed request bodies (${encoding}) cannot be scanned`);
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > REQUEST_BYTES_MAX)
    return refuse(413, `request body over ${REQUEST_BYTES_MAX} bytes`);
  const raw = await readCapped(request);
  if (raw === undefined) return refuse(413, `request body over ${REQUEST_BYTES_MAX} bytes`);
  const type = request.headers.get("content-type") ?? "";
  if (type.includes("json") || (format !== undefined && raw.trimStart().startsWith("{"))) {
    const parsed = parseRequestObject(raw);
    if (parsed instanceof Response) return parsed;
    return redactBody(parsed, format ?? "chat", redact, session);
  }
  if (raw.length > 0)
    return refuse(415, `non-JSON request body (${type || "no content-type"}) cannot be scanned`);
  return unscanned();
}

function parseRequestObject(raw: string): Record<string, unknown> | Response {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return refuse(400, "request body is not valid JSON, refusing to forward it unscanned");
  }
  // Every provider API takes an object; anything else was forwarded
  // unscanned before.
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    return refuse(400, "request body is not a JSON object, refusing to forward it unscanned");
  if (jsonDepth(parsed, JSON_DEPTH_MAX) > JSON_DEPTH_MAX)
    return refuse(400, `request body nests deeper than ${JSON_DEPTH_MAX} levels`);
  return parsed as Record<string, unknown>;
}

function redactBody(
  parsed: Record<string, unknown>,
  format: Format,
  redact: Redactors,
  session: string | null,
): Scanned | Response {
  try {
    const started = performance.now();
    const redacted = redact.request(format, parsed, session);
    const scanMs = Math.round(performance.now() - started);
    noteUnguarded(redacted.unguarded);
    // Single-message side requests (titles, quota probes) are not the
    // conversation, so they do not set its badge.
    const turns = Array.isArray(parsed.messages) ? parsed.messages : parsed.input;
    const conversation = Array.isArray(turns) && turns.length > 1;
    return {
      body: JSON.stringify(redacted.body),
      tags: redacted.tags,
      hits: redacted.hits,
      counts: conversation ? redacted.counts : undefined,
      prompts: conversation ? typedPromptCount(format, parsed) : 0,
      scanMs,
      label: redacted.label,
      unguarded: redacted.unguarded,
    };
  } catch (error) {
    return refuse(
      500,
      `redaction failed (${(error as Error).name}), refusing to forward unscanned`,
    );
  }
}

// The query string redacted and the headers redacted in place, their hits
// added to the body's; or the refusal.
function redactSearch(
  search: string,
  headers: Headers,
  scanned: Scanned,
  redact: Redactors,
): string | Response {
  try {
    const query = redact.query(search, scanned.tags);
    const sent = redact.headers(headers, scanned.tags);
    scanned.hits += query.hits + sent.hits;
    if (scanned.counts) scanned.counts.masked += query.values + sent.values;
    return query.search;
  } catch (error) {
    return refuse(
      500,
      `query or header redaction failed (${(error as Error).name}), refusing to forward unscanned`,
    );
  }
}

async function runSelfTest(routes: Record<string, Route>, redact: Redactors): Promise<SelfTest> {
  const proof = await selfTest((upstream) => createHandler(routes, upstream, redact));
  log(
    proof.ok
      ? `self-test passed (${proof.ms}ms)`
      : `self-test FAILED: ${proof.failures.join("; ")}`,
  );
  return proof;
}

function refuseUnproven(proof: SelfTest | undefined): Response {
  return refuse(
    503,
    proof
      ? `self-test failed (${proof.failures.join("; ")}), refusing to forward`
      : "self-test has not run yet",
  );
}

// Why a gated handler is not serving, for the badge; undefined while it is.
function downBadge(proof: SelfTest | undefined, gated: boolean): string | undefined {
  if (proof && !proof.ok) {
    const [first, ...rest] = proof.failures;
    return `ITHILDIN DOWN · self-test: ${first}${rest.length > 0 ? ` (+${rest.length})` : ""}`;
  }
  return gated && !proof ? "ITHILDIN DOWN · self-test pending" : undefined;
}

function health(
  url: URL,
  routes: Record<string, Route>,
  book: ReturnType<typeof createStatusBook>,
  proof: SelfTest | undefined,
  gated: boolean,
): Response {
  // Not serving reads as down: both badges turn red on a non-200, and show
  // the badge text it carries.
  const down = downBadge(proof, gated);
  if (down) return Response.json({ ok: false, badge: down, selftest: proof }, { status: 503 });
  const status = book.lookup(
    url.searchParams.get("session") ?? undefined,
    url.searchParams.get("route") ?? undefined,
  );
  return Response.json({
    ok: true,
    routes: Object.keys(routes),
    badge: status?.badge ?? "ITHILDIN ON",
    status,
    selftest: proof,
  });
}

// `gated`: refuse model requests until a self-test passes (selftest.ts). The
// server's handler is gated; the self-test's own and the tests' are not.
export function createHandler(
  routes: Record<string, Route>,
  fetchUpstream: typeof fetch = fetch,
  redact: Redactors = REDACTORS,
  gated = false,
) {
  // What redaction did per conversation, for the status badges (status.ts):
  // only this machine learns that swapping happens.
  const book = createStatusBook();
  let proof: SelfTest | undefined;
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const own = OWN_PATH.exec(url.pathname)?.[1];
    if (own === "selftest") {
      proof = await runSelfTest(routes, redact);
      return Response.json(proof, { status: proof.ok ? 200 : 503 });
    }
    if (own === "health") return health(url, routes, book, proof, gated);
    if (gated && !proof?.ok) return refuseUnproven(proof);
    const match = /^\/([^/]+)(\/.*)?$/.exec(url.pathname);
    const route = match ? routes[match[1]!] : undefined;
    if (!match || !route) return refuse(404, `no route for ${url.pathname.split("/")[1] ?? ""}`);
    // A socket's frames cannot be scanned one request at a time.
    if (request.headers.get("upgrade")) return refuse(501, "WebSocket upgrades cannot be scanned");
    const rest = match[2] ?? "";
    const format = formatForPath(rest);

    const session =
      request.headers.get(SESSION_HEADER) ??
      request.headers.get("x-Claude-Code-Session-Id") ??
      request.headers.get("x-opencode-session-id") ??
      undefined;
    const headers = new Headers(request.headers);
    for (const name of HOP_HEADERS) headers.delete(name);
    headers.delete(SESSION_HEADER);
    headers.set("accept-encoding", "identity");

    const scanned = await scanRequest(request, format, redact, session ?? null);
    if (scanned instanceof Response) return scanned;
    const { body, tags, counts, prompts, scanMs, label, unguarded } = scanned;
    const search = redactSearch(url.search, headers, scanned, redact);
    if (typeof search !== "string") return search;
    const target = upstreamUrl(route, rest, search);
    const trust = { ...label, unguarded: unguarded.length };
    if (counts) book.record(session, match[1]!, counts, prompts, tags, trust);

    let upstream: Response;
    try {
      upstream = await fetchUpstream(target, {
        method: request.method,
        headers,
        body,
        redirect: "manual",
        signal: request.signal,
      });
    } catch (error) {
      return refuse(502, `upstream unreachable (${(error as Error).message})`);
    }

    // scan= is the redaction time this proxy adds to each request; allow=
    // names the tags the user's latest prompt carried ([allow-pii] → pii), so
    // the journal shows when masking or a guard was lifted.
    const allowed = tags.size > 0 ? ` allow=${[...tags].sort().join(",")}` : "";
    const line =
      `${match[1]}${rest} ${upstream.status} scan=${scanMs}ms${allowed}` +
      ` redacted=${scanned.hits}`;
    return relayReply(upstream, format, tags, line);
  };
}

// The upstream reply with stand-ins in tool calls swapped back, or a refusal
// when a model reply cannot be checked. `line` is the start of its log line.
async function relayReply(
  upstream: Response,
  format: Format | undefined,
  tags: Set<string>,
  line: string,
): Promise<Response> {
  // A client following a redirect resends its original, unredacted body to
  // the new URL, around the proxy: refuse it, and never pass its Location.
  if (upstream.status >= 300 && upstream.status < 400) {
    await upstream.body?.cancel();
    return refuse(502, `upstream redirected (${upstream.status}), refusing to pass it on`);
  }
  const headers = new Headers(upstream.headers);
  headers.delete("content-encoding");
  headers.delete("content-length");
  const init = { status: upstream.status, headers };
  const contentType = upstream.headers.get("content-type") ?? "";
  if (format && upstream.body && contentType.includes("text/event-stream")) {
    const stream = rewriteSse(upstream.body, format, tags, (swapped) =>
      log(`${line} swapped=${swapped} (stream)`),
    );
    return new Response(stream, init);
  }
  if (format && contentType.includes("json") && upstream.ok) {
    const parsed = await swapJsonReply(upstream, format, tags);
    if (parsed instanceof Response) return parsed;
    log(`${line} swapped=${parsed.swapped}`);
    // Always re-serialized: a blocked call changes arguments without a swap.
    return new Response(JSON.stringify(parsed.body), init);
  }
  // A successful model reply in a shape not read here could carry tool
  // calls no guard saw. Errors and non-model routes pass as they are.
  if (format && upstream.ok && upstream.body) {
    await upstream.body.cancel();
    return refuse(502, `upstream reply type ${contentType.split(";")[0]} cannot be checked`);
  }
  if (!format && upstream.ok && upstream.body) return relayUnread(upstream, init, line);
  log(line);
  return new Response(upstream.body, init);
}

// Top-level keys of model replies in the formats not read here: completions
// and Ollama (choices, message, response), Gemini (candidates), Anthropic and
// Responses lookalikes (content, output).
const MODEL_REPLY_KEYS = ["choices", "message", "response", "candidates", "content", "output"];

// A successful reply on a path formatForPath does not know. A model reply
// there (a stream, or JSON shaped like one) is refused: no guard read its
// tool calls. Anything else (model lists, health checks) passes.
async function relayUnread(upstream: Response, init: ResponseInit, line: string) {
  const contentType = upstream.headers.get("content-type") ?? "";
  if (/event-stream|ndjson/.test(contentType)) {
    await upstream.body?.cancel();
    return refuse(502, "streamed reply on a path this proxy does not read, refusing it unchecked");
  }
  if (!contentType.includes("json")) {
    log(line);
    return new Response(upstream.body, init);
  }
  const text = await upstream.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (parsed && typeof parsed === "object" && MODEL_REPLY_KEYS.some((key) => key in parsed))
    return refuse(502, "model reply on a path this proxy does not read, refusing it unchecked");
  log(line);
  return new Response(text, init);
}

async function swapJsonReply(
  upstream: Response,
  format: Format,
  tags: Set<string>,
): Promise<{ body: Record<string, unknown>; swapped: number } | Response> {
  const text = await upstream.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return refuse(502, "upstream reply is not valid JSON, refusing to pass unchecked tool calls");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    return refuse(502, "upstream reply is not a JSON object, refusing to pass it unchecked");
  const body = parsed as Record<string, unknown>;
  try {
    return { body, swapped: swapResponseBody(format, body, tags) };
  } catch (error) {
    // Half-swapped, with blocked calls maybe still intact: never pass on.
    return refuse(
      502,
      `reply rewriting failed (${(error as Error).name}), refusing to pass unchecked tool calls`,
    );
  }
}

// Longest a stop waits for in-flight replies. modules/ithildin.nix sets
// TimeoutStopSec above it.
const DRAIN_MS = 300_000;

export type Options = { port: number; routesFile: string | undefined };

// Settings from flags, then environment, then defaults. A port that is not
// a whole number in range stops startup: listening somewhere unexpected
// would leave agents pointed at nothing, or at something else.
export function readOptions(
  argv: string[],
  env: Record<string, string | undefined>,
  exists: (file: string) => boolean,
): Options {
  const arg = (name: string): string | undefined => {
    const index = argv.indexOf(`--${name}`);
    return index >= 0 ? argv[index + 1] : undefined;
  };
  const text = arg("port") ?? env.ITHILDIN_PORT ?? "18733";
  const port = Number(text);
  if (!/^\d+$/.test(text) || port < 1 || port > 65_535)
    throw new Error(`ithildin: invalid port ${JSON.stringify(text)}`);
  const defaultRoutes = path.join(configHome(env), NAME, "routes.json");
  const routesFile =
    arg("routes") ?? env.ITHILDIN_ROUTES ?? (exists(defaultRoutes) ? defaultRoutes : undefined);
  return { port, routesFile };
}

// Networks and clones change under a running proxy; values only join. The
// self-test re-runs on the same beat, so a rule or inventory that stops
// masking mid-run closes the gate (and turns the badges red) within minutes.
const IDENTITY_REFRESH_MS = 300_000;

// Port 0 picks a free port (tests); the bound one is on the server.
export function start(
  options: Options,
  fetchUpstream: typeof fetch = fetch,
): { server: ReturnType<typeof Bun.serve>; drain: () => Promise<void>; proven: Promise<void> } {
  const routes = loadRoutes(options.routesFile);
  initEngine();
  if (aliasStyle() === "tokens")
    log("aliases are tokens: nothing is swapped back, tools run with the tokens the model wrote");
  const saving = setInterval(saveScanCache, 30_000);
  saving.unref();
  const handler = createHandler(routes, fetchUpstream, REDACTORS, true);
  const selfTestRequest = () => new Request("http://127.0.0.1/_ithildin/selftest");
  const refreshing = setInterval(() => {
    if (refreshIdentity()) log("identity inventory grew");
    void handler(selfTestRequest());
  }, IDENTITY_REFRESH_MS);
  refreshing.unref();
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: options.port,
    idleTimeout: 255,
    fetch: handler,
  });
  log(`listening on http://127.0.0.1:${server.port} (routes: ${Object.keys(routes).join(", ")})`);
  // Requests are refused until this passes; agents retry refused requests.
  const proven = handler(selfTestRequest()).then(() => undefined);
  // A rules edit restarts the proxy. Stop taking requests but let streaming
  // replies finish, so the edit does not cut a response off mid-turn; agents
  // retry the refused connections.
  const drain = async (): Promise<void> => {
    clearInterval(saving);
    clearInterval(refreshing);
    saveScanCache();
    log("draining in-flight requests");
    await server.stop(false);
  };
  return { server, drain, proven };
}

// `ithildin selftest`: runs the self-test inside the proxy that is
// running now, so a pass means that process masks, not a fresh copy.
export async function selfTestCli(port: number, fetchProxy: typeof fetch = fetch): Promise<number> {
  let report: SelfTest;
  try {
    report = (await (
      await fetchProxy(`http://127.0.0.1:${port}/_ithildin/selftest`)
    ).json()) as SelfTest;
  } catch (error) {
    process.stdout.write(
      `ithildin is not answering on port ${port} (${(error as Error).message})\n`,
    );
    return 1;
  }
  process.stdout.write(
    report.ok
      ? `ok: an AWS key, a GitHub token and an email were masked before the provider, and a tool ` +
          `call got the real email back (${report.ms}ms)\n`
      : `FAILED: ${report.failures.join("; ")}\n`,
  );
  return report.ok ? 0 : 1;
}

if (import.meta.main && process.argv[2] === "check") {
  process.exit(runCheck(process.argv.slice(3), (text) => process.stdout.write(text)));
} else if (import.meta.main && process.argv[2] === "selftest") {
  process.exit(await selfTestCli(readOptions(process.argv, process.env, existsSync).port));
} else if (import.meta.main) {
  const { drain } = start(readOptions(process.argv, process.env, existsSync));
  // systemd's TimeoutStopSec is the backstop past DRAIN_MS.
  process.on("SIGTERM", () => {
    void drain().then(() => process.exit(0));
    setTimeout(() => process.exit(0), DRAIN_MS).unref();
  });
}
