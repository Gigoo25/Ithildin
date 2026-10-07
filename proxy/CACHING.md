# Prompt caching and shaping: where the investigation stands

For an agent picking up the cache work. `AGENTS.md` covers the repo; this
covers how context shaping (`shape.ts`) interacts with Anthropic's prompt
cache, what has been tried, what is known, and how to find out the rest.
Status as of 2026-10-07.

## The problem

Shaping stubs old tool results to make requests smaller. Anthropic caches a
prompt by prefix, so changing an old message invalidates everything after it.
Shaping therefore holds its cutoff still and moves it in steps of
`MASK_STEP_TURNS` (10) turns; each move is a **step**, and a step rewrites the
cache from the first changed message on.

Over 14 days of journal (before any of the work below), Claude cache writes
split roughly:

| Cause | Share |
|---|---|
| Shaping steps | 45% |
| New turns | 38% |
| The agent editing its own recent messages | 11% |
| Restarts, side requests, expired entries | 6% |

Between steps, caching is already at its ceiling: a request reads the whole
conversation and writes only the new turn (93.7% of input tokens were cache
reads). Steps are the one lever left.

## Why a step re-wrote everything

Claude Code puts `cache_control` markers on the system prompt and on the newest
message. A step changes messages from the old cutoff on, so the only cached
prefix it can match ends at the system prompt (~11K tokens). It then writes
the whole conversation again (110–180K tokens at the 1h price, 2x input).

## What was built (`mark.ts`, `shape.ts`)

- `markBoundaries` adds a marker at the **previous** cutoff (the last message
  of the turns the previous request had masked), so a step can read back to
  there.
- On a step it also marks the **new** cutoff. Anthropic writes an entry at a
  marker only for a request that actually processes that part of the prompt;
  requests between steps read it all from cache, so only the step itself can
  write the entry the next step needs. (The first version, `23eafdb`, marked
  only the previous cutoff, and nothing was ever written there.)
- At most 4 markers per request (`MARKERS_MAX`). On a step, when there is no
  room, it removes the first of two adjacent system markers: the second covers
  the same prefix, so that costs nothing.
- It adds markers only when the agent already uses them, copies the agent's
  TTL, and never marks a thinking block.
- Marker placement is a pure function of the body, so it is byte-stable across
  requests and restarts.

The gate (`pays` in `shape.ts`) briefly priced a step as rewriting only from
the previous cutoff (`9efbe86`). That approved far more steps (9 in an hour vs
22 in a day) while the read-back was failing, so `0647461` went back to
pricing every step as a whole rewrite. The markers stay: a hit is a bonus.

## What the live data showed

Steps in one session on 2026-10-07, after `9efbe86` was deployed:

| Time | Previous cutoff | Read | Written | |
|---|---|---|---|---|
| 15:38:22 | 899 | 11K | 171K | expected miss: nothing cached at 899 yet |
| 15:44:34 | 929 | 11K | 171K | **miss** |
| 15:46:45 | 959 | 11K | 178K | **miss** |
| 15:51:01 | 989 | 180K | 15K | **hit**: the design working |

Ruled out for the two misses:

- **The bytes:** re-shaping the kept requests gives a body byte-identical to
  the previous step's up to the marker: system, tools and messages.
- **Top-level fields:** `thinking` (adaptive), `output_config` (effort),
  `context_management` (`clear_thinking` with `keep: "all"`), model and tools
  are identical on every request in two sessions. `safeguards` changes on
  almost every request but is not part of the cached prompt: ordinary
  requests read the whole cache despite it.
- **Thinking blocks:** none remain in the old part of the conversation.
- **The 20-block lookback:** every step was 36–43 positions from its last
  marker, the hit included.
- **A permanent miss:** replaying the 15:44 and 15:46 requests later read 176K
  and 180K, so the entries did exist.
- **The mechanism:** a controlled test (small conversations through a borrowed
  `claude -p` login, with and without thinking blocks, with Claude Code's real
  system prompt) read back to the old-boundary marker every time.

Still open: why a step sometimes finds the entry the previous step wrote and
sometimes does not. The leading guess is Anthropic's side (best-effort cache,
eviction or routing), but that is unconfirmed. Two misses and one hit is too
small a sample to say how often it happens.

## Instruments now in the proxy

Both go into the journal (`journalctl --user -u ithildin`), which survives
restarts; the dashboard and the proxy's memory do not.

- **`step=from>to`** on a request whose shaping moved the cutoff, in turns.
  Read from the body alone, so steps are named after a restart too, where
  `cachebreak=…(shaping)` needs the previous request in memory.
- **`cachemiss=<reason>`** from Anthropic's cache diagnostics
  (`diagnose.ts`). Every main Claude request to `api.anthropic.com` with a
  session gets the beta header (`DIAGNOSE_BETA`) and a top-level
  `diagnostics: { previous_message_id }`. A normal request names the session's
  last reply; a step names the session's **last step**, which is the request
  that should have written the entry this step reads. The reply's
  `diagnostics.cache_miss_reason.type` (and any other fields, short) is
  logged. `previous_message_not_found` means the proxy's id was unknown
  upstream: after a restart, or more than the server keeps.
- `ITHILDIN_DIAGNOSE=off` turns diagnostics off. The first 400 that mentions
  diagnostics turns them off for the life of the process, logs once, and
  resends that request without them.

To list steps and their outcome:

```sh
journalctl --user -u ithildin --since today --no-pager -o short-iso \
  | grep 'step=' | sed -E 's/scan=[^ ]+ (allow=[^ ]+ )?redacted=[^ ]+ //'
```

`usage=in/read/write/out`: a hit reads most of the conversation and writes a
little; a miss reads ~11K (the system prompt) and writes the rest.

## How to read the answers

- **A divergence reason on a miss** (something in model, system, tools or
  messages changed against the previous step): the miss is in our bytes.
  Compare the two bodies around where it says, starting with what the proxy
  adds (markers, `diagnostics` itself) and what shaping changes.
- **No reason, or only `previous_message_not_found`, on a miss whose previous
  step was answered:** nothing in the request explains it. Treat misses as
  Anthropic's, and stop chasing.
- **Misses rare:** nothing to do; the conservative gate already prices them.
- **Hits common:** the gate could go back to pricing a step from the previous
  cutoff, but only when the previous step in that session was a hit (a
  `step=` line with a large read), so a miss streak cannot run up writes.

## Gotchas

- **The proxy redacts `msg_…` ids in request bodies** (rule
  `lone-token-line`, as a secret). A test script that sends
  `previous_message_id` through the proxy gets a 400 ("must be the id from a
  prior response"). The proxy's own field is added after redaction.
- **The beta header's name gets partly masked** in an agent's context when
  the agent runs through ithildin. Do not retype it: use `DIAGNOSE_BETA` in
  `diagnose.ts`, which was filled in from Anthropic's docs by script.
- **Kept bodies (`/dashboard/request?id=`) are as they arrived**, before
  shaping. Re-run `shapeRequest` on them to see what was sent.
- **Borrowing the login for live tests:** run `claude -p` with
  `--settings '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:<port>"}}'`
  pointed at a local script that forwards to ithildin and reuses the headers
  of the first request in memory. Each test costs a little of the user's
  usage; ask first.
- **`ITHILDIN_SHAPE`** is read from the service environment. On
  2026-10-07 the user turned shaping off with
  `systemctl --user set-environment ITHILDIN_SHAPE=off`, which outlives a
  nix switch. Turn it back on with
  `systemctl --user unset-environment ITHILDIN_SHAPE && systemctl --user restart ithildin`.
  Check with `tr '\0' '\n' < /proc/$(systemctl --user show ithildin -p MainPID --value)/environ | grep ITHILDIN`.
