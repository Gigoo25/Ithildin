# Working in this repo

A redaction engine (`engine/`) and the local proxy in front of model APIs
(`proxy/`). Bun + TypeScript, **no runtime dependencies** — Node built-ins only.
The README is the user-facing spec; this file is what the README does not tell you.

## Commands

Run from the repo root unless noted.

```sh
bun test                                    # everything: 854 tests
bun test proxy/src/requests.test.ts         # one file
bun test proxy/src/requests.test.ts -t "name"   # one test
bun x tsc --noEmit                          # typecheck (needs a typescript; see below)
```

The gates that are easy to get wrong locally:

| Gate | Command | Notes |
|---|---|---|
| function length | `TYPESCRIPT=<path> bun checks/function-length.ts .` | **fails without `TYPESCRIPT`** |
| coverage | `cd proxy && bun test src bench engine --coverage --coverage-reporter=lcov` then `bun checks/coverage.ts proxy/coverage/lcov.info` | floors: 99% total, 97% lines/file, 90% functions/file |
| format | `prettier --check '**/*.ts'` + no line over 100 cols | `LC_ALL=C.UTF-8 find … -exec awk 'length > 100 …'` |
| placeholder literals | `bash checks/placeholder-literals.sh .` | no literal `__ITHILDIN_*__` outside `engine/core.ts` |

`nix flake check` runs all of them plus `engine`/`proxy`/`package`, and is the
real gate. `checks/*.nix` each become a check named after the file.

## Traps

**`bun.lock` must stay at exactly 4 packages.** `checks/typecheck.nix` asserts
`grep -c '"sha512-' bun.lock` equals the length of its `types` list, and checks
each version and integrity hash. So `bun add` anything — including `typescript`,
which you want for the gates above — **breaks the typecheck gate**. Install it
outside the repo instead, and pass it in:

```sh
mkdir /tmp/ts && cd /tmp/ts && bun init -y && bun add typescript@5
cd - # back to the repo
TYPESCRIPT=/tmp/ts/node_modules/typescript bun checks/function-length.ts .
```

Pin `@5`: unpinned pulls TypeScript 7, whose package layout the check cannot
load. Also note `bun add` in a directory with no `package.json` silently does
nothing, hence the `bun init -y`. If you must add a real dependency, add it to
that list too.

**Bun 1.4.2 minimum**, enforced in `proxy/src/cli.ts`. Below it the engine's
per-rule scan deadlines do not fire, so redaction of a large body takes minutes
instead of seconds with nothing logged. The test suite passes on older Bun;
large-payload work hangs. Getting typescript also needs network, so `bun x tsc`
is the usual path.

**The dashboard is one string.** `DASHBOARD_HTML` in `proxy/src/dashboard.ts`
holds the whole page — HTML, CSS and vanilla JS — with no build step or
bundler. Its tests pull functions out of that string by regex
(`/function turns[\s\S]*?\n\}/`) and run them through `new Function`, so
renaming or moving a page function breaks tests that match it by name. The page
must never contain `innerHTML`; all DOM goes through `textContent`
(`dashboard.test.ts` asserts it).

**The README must survive redaction unchanged.** `engine/lib/garble.test.ts`
asserts `redactText(readme).text === readme`. The engine rewrites
internal-looking hostnames (`*.lan`, `*.local`, `*.internal`, tailnet names) and
real-looking names, so a plausible example like `http://myserver.lan:4000` in
prose breaks the suite. Use `example.com`/`example.invalid`.

**Bun counts a class's implicit constructor as a function that is never
called**, which fails the 90% function floor on its own. Spell out
`constructor() {}` when adding a class (see `proxy/src/sessions.ts`).

**Functions are capped at 70 lines**, first line to closing brace, tests exempt.
Check it before you finish, not after.

## Shape of the code

- `engine/` is standalone and has no idea the proxy exists; `proxy/` depends on
  it. `proxy/engine` is a **symlink** to `../engine` — edit `engine/`, and note
  that tsc, prettier and the function-length check all skip the symlink.
- `proxy/src/cli.ts` is the only process entry, deliberately kept out of
  coverage (`import.meta.main` never runs under `bun test`). Library behaviour
  lives in `server.ts` so it can be tested.
- Entry points: `server.ts` (`createHandler`, `start`, the request path),
  `redact.ts` (the request-shaped redaction), `requests.ts` (what the dashboard
  keeps), `titles.ts` + `sessions.ts` (session naming), `dashboard.ts` (the page).
- State is in memory only; a restart clears it. `SentRequests` caps a body at
  `BODY_BYTES_MAX` (8 MiB) and **clamps a longer one so it still parses**, which
  is what keeps the conversation view working on very large bodies.
- `EventLog.scan` is bounded by per-rule deadlines and windows
  (`SCAN_WINDOW_CHARS` in `engine/lib/rules.ts`); a completed window is cached
  by content digest. `MAX_SCAN_BYTES` skips regex scanning on very large strings.

## Conventions

- Comments explain *why*, in the same voice as the code; the repo is heavily
  commented and that is deliberate, not noise.
- No `git` assumptions: nothing is committed on your behalf, and `stash` is not
  safe if another session has one in flight.
- Routes: `~/.config/ithildin/routes.json` merges **field by field** over
  `DEFAULT_ROUTES`, so overriding `via` keeps the built-in `rewrite`. A plain
  string value means "upstream only".
- Requests for a provider are scanned before anything is sent, including through
  a `via` proxy. Anything the engine holds back (`x-headroom-*`) is stripped from
  what the agent sent.