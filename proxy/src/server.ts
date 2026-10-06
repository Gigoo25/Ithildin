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

import { readFileSync } from "node:fs";
import path from "node:path";
import {
  type Counts,
  type Format,
  initEngine,
  redactHeaders,
  redactPath,
  redactQuery,
  redactRequest,
  refreshIdentity,
  saveScanCache,
  typedPromptCount,
} from "./redact.ts";
import { configHome, NAME } from "../engine/lib/names.ts";
import { aliasStyle } from "../engine/lib/rules.ts";
import { type ActivityEvent, observeActivity } from "../engine/lib/activity.ts";
import { DASHBOARD_CSP, DASHBOARD_HTML, DASHBOARD_PATH } from "./dashboard.ts";
import { type Context, EventLog } from "./events.ts";
import { SentRequests } from "./requests.ts";
import {
  firstPrompt,
  looksLikeNaming,
  renamedIn,
  replyText,
  type TitleAsk,
  titleAsk,
  titleFrom,
} from "./titles.ts";
import { AGENT, GUESS, SessionNames, USER } from "./sessions.ts";
import { createStatusBook } from "./status.ts";
import { findWatched, knownValues, watchPolicy } from "./watch.ts";
import { type SelfTest, selfTest } from "./selftest.ts";
import { createRewriter, formatSse, parseSseBlock, swapResponseBody } from "./streams.ts";
import type { Label } from "./trust.ts";

export interface Route {
  upstream: string;
  // Path prefix rewrites, first match wins: {"/chat/": "/v1/chat/"}.
  rewrite?: Record<string, string>;
  // A proxy in front of the provider (Headroom, on 127.0.0.1:8787). The
  // request goes to this host with the endpoint suffix on the path and the
  // upstream in x-headroom-base-url, which is how Headroom learns where to
  // send it. Without it the request goes straight to `upstream`.
  via?: string;
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
  const routes: Record<string, Route> = { ...DEFAULT_ROUTES };
  for (const [name, route] of Object.entries(parsed)) {
    const over = typeof route === "string" ? { upstream: route } : route;
    // Field by field, not route by route: a file that says how to reach a
    // provider through a proxy should not have to repeat where its paths live,
    // and silently losing the rewrites turns every request into a refusal.
    routes[name] = { ...routes[name], ...over } as Route;
  }
  return routes;
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

// The endpoints a via host recognises at the end of a path. It appends a path
// of its own to whatever base it is given, so the proxy sends the suffix on and
// the upstream in a header. Longest first: /v1/messages/count_tokens must not
// be read as a /v1/messages request with a tail.
// Where a request goes, and what the headers say about it. Rewrites run first,
// so a via host is named the upstream the request would really have gone to. A
// path it would not recognise is refused rather than sent on: letting it
// through would leave the host to choose the upstream, which is the one thing
// the proxy has just decided.
function routeFor(
  route: Route,
  name: string,
  rest: string,
  search: string,
  headers: Headers,
): { target: string } | Response {
  const split = splitVia(route, rest, search);
  if (route.via && !split)
    return refuse(502, `route ${name} goes via ${route.via}, which cannot serve ${rest}`);
  if (split) headers.set(BASE_URL_HEADER, split.base);
  return { target: split?.url ?? upstreamUrl(route, rest, search) };
}

// How a via host is told where to send a request.
const BASE_URL_HEADER = "x-headroom-base-url";

const VIA_SUFFIXES = [
  "/v1/messages/count_tokens",
  "/v1/messages",
  "/v1/chat/completions",
  "/chat/completions",
  "/v1/responses",
];

// Where a request goes when its route names a via host: the endpoint suffix on
// the path, and the upstream to reach behind it. Undefined when the route has
// no via, or when the path ends in something a via host would not recognise —
// which is refused rather than guessed at, since sending it on would let the
// host pick the upstream itself.
export function splitVia(
  route: Route,
  rest: string,
  search: string,
): { url: string; base: string } | undefined {
  if (!route.via) return undefined;
  const full = upstreamUrl(route, rest, search);
  const at = full.indexOf("?");
  const path = at < 0 ? full : full.slice(0, at);
  const query = at < 0 ? "" : full.slice(at);
  const suffix = VIA_SUFFIXES.find((end) => path.endsWith(end));
  if (!suffix) return undefined;
  return {
    url: route.via.replace(/\/+$/, "") + suffix + query,
    base: path.slice(0, path.length - suffix.length),
  };
}

// Pi's footer tags its requests with its session id (the proxy's own header,
// never forwarded); Claude sends X-Claude-Code-Session-Id itself. opencode
// sends x-opencode-session to its own providers, with x-opencode-client
// naming the agent (Pi sends it too, as "pi"), and x-session-affinity to the
// rest.
const SESSION_HEADERS: [string, string][] = [
  ["x-ithildin-session", "pi"],
  ["x-claude-code-session-id", "claude"],
  ["x-opencode-session", "opencode"],
  ["x-session-affinity", "opencode"],
];
const CLIENT_HEADER = "x-opencode-client";
const OWN_PATH =
  /^\/(?:_ithildin\/(selftest|health)|(dashboard)(?:\/(activity|requests|request))?)$/;
// Set by refuse() and removed by the handler, which logs the refusal for the
// dashboard. It never reaches the client.
const REFUSED_HEADER = "x-ithildin-refused";
// The dashboard answers only to a local name: a page on another site that
// points its own name at 127.0.0.1 (DNS rebinding) is turned away.
const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

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
// A JSON reply is read whole before it is parsed and checked.
export const REPLY_BYTES_MAX = 32 * 1024 * 1024;

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
    { status, headers: { [REFUSED_HEADER]: message } },
  );
}

function rewriteSse(
  body: ReadableStream<Uint8Array>,
  format: Format,
  tags: Set<string>,
  done: (swapped: number) => void,
  tap: (event: ActivityEvent) => unknown,
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
    const outs = observeActivity(tap, () => rewriter.push(event));
    for (const out of outs) controller.enqueue(encoder.encode(formatSse(out)));
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
        for (const out of observeActivity(tap, () => rewriter.flush()))
          controller.enqueue(encoder.encode(formatSse(out)));
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
  path: typeof redactPath;
  headers: typeof redactHeaders;
};
const REDACTORS: Redactors = {
  request: redactRequest,
  query: redactQuery,
  path: redactPath,
  headers: redactHeaders,
};

// What scanning a request body gave: the body to forward and what it found.
type Scanned = {
  body: string | undefined;
  // The body as parsed JSON, for the watch list (watch.ts).
  object: unknown;
  tags: Set<string>;
  hits: number;
  counts: Counts | undefined;
  prompts: number;
  scanMs: number;
  label: Label;
  unguarded: string[];
  // What the engine masked, for the dashboard (events.ts).
  activity: ActivityEvent[];
};

function unscanned(): Scanned {
  return {
    body: undefined,
    object: undefined,
    tags: new Set(),
    hits: 0,
    counts: undefined,
    prompts: 0,
    scanMs: 0,
    label: { untrusted: false, private: false },
    unguarded: [],
    activity: [],
  };
}

// A body as text, read no further than the cap: a chunked body declares no
// length. Undefined when it runs over.
async function readCapped(
  body: ReadableStream<Uint8Array> | null,
  max: number,
): Promise<string | undefined> {
  if (!body) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of body) {
    size += chunk.byteLength;
    // Leaving the loop cancels the rest of the stream.
    if (size > max) return undefined;
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
  const raw = await readCapped(request.body, REQUEST_BYTES_MAX);
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
    const activity: ActivityEvent[] = [];
    const redacted = observeActivity(
      (event) => activity.push(event),
      () => redact.request(format, parsed, session),
    );
    const scanMs = Math.round(performance.now() - started);
    noteUnguarded(redacted.unguarded);
    // Single-message side requests (titles, quota probes) are not the
    // conversation, so they do not set its badge.
    const turns = Array.isArray(parsed.messages) ? parsed.messages : parsed.input;
    const conversation = Array.isArray(turns) && turns.length > 1;
    return {
      body: JSON.stringify(redacted.body),
      object: redacted.body,
      tags: redacted.tags,
      hits: redacted.hits,
      counts: conversation ? redacted.counts : undefined,
      prompts: conversation ? typedPromptCount(format, parsed) : 0,
      scanMs,
      label: redacted.label,
      unguarded: redacted.unguarded,
      activity,
    };
  } catch (error) {
    return refuse(
      500,
      `redaction failed (${(error as Error).name}), refusing to forward unscanned`,
    );
  }
}

// The path and query string redacted and the headers redacted in place,
// their hits added to the body's; or the refusal.
function redactUrl(
  rest: string,
  search: string,
  headers: Headers,
  scanned: Scanned,
  redact: Redactors,
): { rest: string; search: string } | Response {
  try {
    const { path, query, sent } = observeActivity(
      (event) => scanned.activity.push(event),
      () => ({
        path: redact.path(rest, scanned.tags),
        query: redact.query(search, scanned.tags),
        sent: redact.headers(headers, scanned.tags),
      }),
    );
    scanned.hits += path.hits + query.hits + sent.hits;
    if (scanned.counts) scanned.counts.masked += path.values + query.values + sent.values;
    return { rest: path.path, search: query.search };
  } catch (error) {
    return refuse(
      500,
      `URL or header redaction failed (${(error as Error).name}), refusing to forward unscanned`,
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
  const message = proof
    ? `self-test failed (${proof.failures.join("; ")}), refusing to forward`
    : "self-test has not run yet";
  return refuse(503, message);
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
// What the proxy keeps between requests, and the turn counter it numbers them
// with. One object, so the request path can be handed over whole.
interface Stores {
  book: ReturnType<typeof createStatusBook>;
  events: EventLog;
  kept: SentRequests;
  names: SessionNames;
  turns: number;
}

// A request for a provider: scan it, mask it, send it, and check the reply on
// the way back. Everything the proxy knows about one request happens here, and
// nothing above it decides anything but which of the proxy's own endpoints the
// path names.
async function forward(
  stores: Stores,
  deps: { routes: Record<string, Route>; fetchUpstream: typeof fetch; redact: Redactors },
  request: Request,
  url: URL,
  name: string,
  route: Route,
  rest: string,
  format: Format | undefined,
): Promise<Response> {
  const { book, events, kept, names } = stores;
  const { fetchUpstream, redact } = deps;
  const session = sessionOf(request);
  const headers = forwardedHeaders(request);

  const scanned = await scanRequest(request, format, redact, session?.id ?? null);
  if (scanned instanceof Response) return scanned;
  const { body, tags, scanMs } = scanned;
  const sent = redactUrl(rest, url.search, headers, scanned, redact);
  if (sent instanceof Response) return sent;
  const routed = routeFor(route, name, sent.rest, sent.search, headers);
  if (routed instanceof Response) return routed;
  const { target } = routed;
  const context = {
    route: name,
    endpoint: sent.rest,
    session: session?.id,
    ...(session ? { sessionName: names.name(session.client, session.id) } : {}),
    turn: ++stores.turns,
  };
  recordScan({ book, events, kept }, context, scanned);
  const stopped = watchOutgoing(events, context, scanned, sent);
  if (stopped) return stopped;
  const renamed = nameSession(names, session, scanned);
  const ask = session ? titleAsk(scanned.object) : undefined;

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
  if (session && ask && upstream.ok) noteTitle(upstream.clone(), ask, session.id, names, renamed);

  const line = journalLine(name, sent.rest, upstream.status, scanMs, tags, scanned.hits);
  return relayReply(upstream, format, tags, line, (event) => events.record(context, event));
}

export function createHandler(
  routes: Record<string, Route>,
  fetchUpstream: typeof fetch = fetch,
  redact: Redactors = REDACTORS,
  gated = false,
) {
  // What redaction did per conversation, for the status badges (status.ts):
  // only this machine learns that swapping happens.
  const stores: Stores = {
    book: createStatusBook(),
    events: new EventLog(),
    kept: new SentRequests(),
    names: new SessionNames(),
    turns: 0,
  };
  const { book, events, kept, names } = stores;
  let proof: SelfTest | undefined;
  const respond = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const found = OWN_PATH.exec(url.pathname);
    const own = found?.[1] ?? (found?.[2] ? (found[3] ?? "dashboard") : undefined);
    if (own === "selftest") {
      proof = await runSelfTest(routes, redact);
      return Response.json(proof, { status: proof.ok ? 200 : 503 });
    }
    if (own === "health") return health(url, routes, book, proof, gated);
    if (own === "dashboard" || own === "activity" || own === "requests" || own === "request")
      return dashboard(own, url, { events, kept, names });
    if (gated && !proof?.ok) return refuseUnproven(proof);
    const match = /^\/([^/]+)(\/.*)?$/.exec(url.pathname);
    const route = match ? routes[match[1]!] : undefined;
    if (!match || !route) return refuse(404, `no route for ${url.pathname.split("/")[1] ?? ""}`);
    // A socket's frames cannot be scanned one request at a time.
    if (request.headers.get("upgrade")) return refuse(501, "WebSocket upgrades cannot be scanned");
    const rest = match[2] ?? "";
    const deps = { routes, fetchUpstream, redact };
    return forward(stores, deps, request, url, match[1]!, route, rest, formatForPath(rest));
  };
  return async (request: Request): Promise<Response> => logRefusal(events, await respond(request));
}

// One line in the journal: what was asked, what came back, what it cost, and
// what was changed. scan= is the redaction time this proxy adds to each
// request; allow= names the tags the user's latest prompt carried ([allow-pii]
// → pii), so the journal shows when masking or a guard was lifted.
export function journalLine(
  route: string,
  rest: string,
  status: number,
  scanMs: number,
  tags: ReadonlySet<string>,
  hits: number,
): string {
  const allowed = tags.size > 0 ? ` allow=${[...tags].sort().join(",")}` : "";
  return `${route}${rest} ${status} scan=${scanMs}ms${allowed} redacted=${hits}`;
}

// The oldest Bun the engine's per-rule scan deadlines work on. Before this they
// do not fire in time: a scan that should take a second takes minutes, with no
// error anywhere, which reads as a hung proxy rather than an old runtime.
export const MIN_BUN = "1.4.2";

// Whether `version` is older than `min`, compared part by part so 1.10 is newer
// than 1.4 and 1.4.10 is newer than 1.4.2.
export function bunTooOld(version: string, min = MIN_BUN): boolean {
  const parts = (text: string) => text.split(".").map((part) => Number(part) || 0);
  const at = parts(version);
  const want = parts(min);
  for (let part = 0; part < Math.max(at.length, want.length); part++) {
    const got = at[part] ?? 0;
    const need = want[part] ?? 0;
    if (got !== need) return got < need;
  }
  return false;
}

// The session id, and the agent that sent it, by the header it used.
function sessionOf(request: Request): { id: string; client: string } | undefined {
  for (const [header, client] of SESSION_HEADERS) {
    const id = request.headers.get(header);
    if (!id) continue;
    const named = header === "x-opencode-session" ? request.headers.get(CLIENT_HEADER) : null;
    return { id, client: named === "pi" ? "pi" : client };
  }
  return undefined;
}

// The request's headers as the upstream gets them.
function forwardedHeaders(request: Request): Headers {
  const headers = new Headers(request.headers);
  for (const name of HOP_HEADERS) headers.delete(name);
  headers.delete(SESSION_HEADERS[0]![0]);
  // The proxy names the upstream, never the agent: a client's own routing
  // header is dropped whether or not this route goes through a via host.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-headroom-")) headers.delete(name);
  }
  headers.set("accept-encoding", "identity");
  return headers;
}

// A refusal for the dashboard; its marker header stays inside the proxy.
function logRefusal(events: EventLog, response: Response): Response {
  const refusal = response.headers.get(REFUSED_HEADER);
  if (refusal === null) return response;
  response.headers.delete(REFUSED_HEADER);
  events.refused(response.status, refusal);
  return response;
}

// A naming request's reply, read beside the client's copy: the session's
// title, with stand-ins, as the provider sent it (titles.ts). The user's own
// name stands: a later model title does not replace it.
function noteTitle(
  // Only the body is wanted, and asking for that rather than for a Response
  // keeps clear of the two Response types the runtime declares: `fetch` gives
  // back one, and the global constructor is the other.
  reply: { text(): Promise<string> },
  ask: TitleAsk,
  id: string,
  names: SessionNames,
  renamed: string | undefined,
): void {
  reply
    .text()
    .then((raw) => {
      const title = titleFrom(ask, replyText(raw));
      if (!title) return;
      names.title(id, title, renamed ? USER : ask === "name" ? USER : AGENT);
      log(`session naming: ${id.slice(0, 8)} is now "${title}"`);
    })
    .catch(() => undefined);
}

// The dashboard page, or what it polls: the events after `?since=` with the
// sessions' names, the list of requests kept, or one request's text.
function dashboard(
  own: "dashboard" | "activity" | "requests" | "request",
  url: URL,
  { events, kept, names }: { events: EventLog; kept: SentRequests; names: SessionNames },
): Response {
  if (!LOCAL_HOSTS.has(url.hostname)) return new Response("forbidden", { status: 403 });
  const headers = { "cache-control": "no-store" };
  if (own === "dashboard") {
    const page = {
      ...headers,
      "content-type": "text/html",
      "content-security-policy": DASHBOARD_CSP,
    };
    return new Response(DASHBOARD_HTML, { headers: page });
  }
  if (own === "requests") return Response.json(kept.list(), { headers });
  if (own === "request") {
    const text = kept.text(Number(url.searchParams.get("id")));
    if (text === undefined) return new Response("no such request", { status: 404 });
    return new Response(text, { headers: { ...headers, "content-type": "text/plain" } });
  }
  const since = Number(url.searchParams.get("since") ?? 0);
  const snapshot = events.snapshot(Number.isSafeInteger(since) ? since : 0);
  const policy = watchPolicy();
  const known = policy.known ? knownValues().length : 0;
  const watch = { terms: policy.terms.length, action: policy.action, known };
  return Response.json({ ...snapshot, watch, sessions: names.list() }, { headers });
}

// What the session is called, from the traffic around it (titles.ts): the
// user's own name first, then the agent's naming request, then nothing, for an
// agent that names none. Returns what the user named, so a model title never
// stands over it.
function nameSession(
  names: SessionNames,
  session: { id: string; client: string } | undefined,
  scanned: Scanned,
): string | undefined {
  if (!session) return undefined;
  const renamed = renamedIn(scanned.object);
  if (renamed) {
    names.title(session.id, renamed, USER);
    return renamed;
  }
  // An agent that names no session of its own still gets one, from what was
  // asked first. A real title replaces this when it arrives.
  const about = firstPrompt(scanned.object);
  // A title reaches the dashboard, which must never carry a real value, so one
  // taken from a prompt the watch list is not satisfied with is not taken. A
  // name is worth less than the promise it would break.
  if (about && !watchHits(scanned, about)) names.title(session.id, about, GUESS);
  // A naming request no pattern recognised: say so, so a reworded agent costs
  // titles out loud rather than in silence. The prompt itself is not logged.
  if (!titleAsk(scanned.object) && looksLikeNaming(scanned.object))
    log("session naming: a naming request was not recognised; session left unnamed");
  return undefined;
}

// Whether the watch list finds anything in text that is about to be shown
// rather than sent: a session name from a prompt, say. Known values are not
// counted: they were masked already, so the prompt holds their stand-ins.
function watchHits(scanned: Scanned, text: string): boolean {
  const policy = watchPolicy();
  const known = policy.known ? knownValues() : [];
  const target = { body: scanned.object, path: "", search: "" };
  return findWatched(policy, known, target).some((hit) => text.includes(hit.value));
}

// The watch list's check of what is about to go out (watch.ts). The refusal,
// when the list says to block; undefined when the request may go. The log and
// the dashboard name the place, never the string.
function watchOutgoing(
  events: EventLog,
  context: Context,
  scanned: Scanned,
  sent: { rest: string; search: string },
): Response | undefined {
  if (scanned.tags.has("pii") || scanned.tags.has("all")) return undefined;
  const policy = watchPolicy();
  const known = policy.known ? knownValues() : [];
  const target = { body: scanned.object, path: sent.rest, search: sent.search };
  const hits = findWatched(policy, known, target);
  if (hits.length === 0) return undefined;
  const places = [...new Set(hits.map((hit) => hit.where))].join(", ");
  for (const hit of hits) {
    const action = hit.source === "watch" ? policy.action : "flag";
    events.leaked(context, { term: hit.value, source: hit.source, where: hit.where }, action);
  }
  log(`watch list: ${hits.length} hit(s) in the request to ${context.route} (${places})`);
  const blocking = policy.action === "block" && hits.some((hit) => hit.source === "watch");
  if (!blocking) return undefined;
  return refuse(403, `watch list: a watched string is in the request (${places}), not sending it`);
}

// A turn of the conversation itself, not a side request beside it (a title,
// a summary, a quota check): one that offers the agent's tools.
function isMainRequest(body: unknown): boolean {
  const tools = (body as { tools?: unknown } | undefined)?.tools;
  return Array.isArray(tools) && tools.length > 0 && titleAsk(body) === undefined;
}

// A scanned request: the status badge, what it masked, the request itself, and the
// text as sent.
function recordScan(
  stores: { book: ReturnType<typeof createStatusBook>; events: EventLog; kept: SentRequests },
  context: Context,
  scanned: Scanned,
): void {
  const { counts, prompts, tags, label, unguarded } = scanned;
  const trust = { ...label, unguarded: unguarded.length };
  if (counts) stores.book.record(context.session, context.route, counts, prompts, tags, trust);
  let fresh = 0;
  const standIns = scanned.activity.flatMap((event) =>
    event.type === "masked" ? [event.standIn] : [],
  );
  for (const event of scanned.activity)
    if (stores.events.record(context, event, scanned.body, standIns)) fresh++;
  stores.events.request(context, scanned.scanMs, fresh);
  if (scanned.body !== undefined)
    stores.kept.record(context, scanned.body, isMainRequest(scanned.object));
}

// The upstream reply with stand-ins in tool calls swapped back, or a refusal
// when a model reply cannot be checked. `line` is the start of its log line;
// `tap` gets what the swaps did, for the dashboard.
async function relayReply(
  upstream: Response,
  format: Format | undefined,
  tags: Set<string>,
  line: string,
  tap: (event: ActivityEvent) => unknown,
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
    const stream = rewriteSse(
      upstream.body,
      format,
      tags,
      (swapped) => log(`${line} swapped=${swapped} (stream)`),
      tap,
    );
    return new Response(stream, init);
  }
  if (format && contentType.includes("json") && upstream.ok) {
    const parsed = await swapJsonReply(upstream, format, tags, tap);
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
  const text = await readCapped(upstream.body, REPLY_BYTES_MAX);
  if (text === undefined) return refuse(502, `upstream reply over ${REPLY_BYTES_MAX} bytes`);
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
  tap: (event: ActivityEvent) => unknown,
): Promise<{ body: Record<string, unknown>; swapped: number } | Response> {
  const text = await readCapped(upstream.body, REPLY_BYTES_MAX);
  if (text === undefined) return refuse(502, `upstream reply over ${REPLY_BYTES_MAX} bytes`);
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
    return { body, swapped: observeActivity(tap, () => swapResponseBody(format, body, tags)) };
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
export const DRAIN_MS = 300_000;

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
  log(`dashboard on http://127.0.0.1:${server.port}${DASHBOARD_PATH}`);
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
