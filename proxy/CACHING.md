# Prompt caching and shaping: where the investigation stands

For an agent picking up the cache work. `AGENTS.md` covers the repo; this
covers how context shaping (`shape.ts`) interacts with Anthropic's prompt
cache, what has been tried, what is known, and how to find out the rest.
Status as of 2026-10-08: the open question below is mostly answered (see
[Saved misses on 2026-10-08](#saved-misses-on-2026-10-08)).

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
small a sample to say how often it happens. (Answered on 2026-10-08, below:
mostly the proxy's own note dropping, plus entries that expire between steps
an hour or more apart.)

## Diagnostics on the first evening (2026-10-07, 21:08–22:51)

Shaping was on for this whole process (no `ITHILDIN_SHAPE` in its
environment), with diagnostics on every main Claude request. All five
Anthropic steps missed:

| Time | Step | Read | Written | `cache_missed_input_tokens` |
|---|---|---|---|---|
| 21:58:42 | 10>20 | 23K | 16K | 33120 |
| 21:58:57 | 0>20 | 13K | 26K | 33120 |
| 22:04:02 | 20>50 | 13K | 41K | 33120 |
| 22:17:00 | 0>10 | 13K | 32K | 24173 |
| 22:48:28 | 0>20 | 13K | 26K | 21898 |

- Every one says **`messages_changed`**, which by the guide below puts the
  miss in our bytes, not Anthropic's. None said `previous_message_not_found`.
- The three in one session report the **same** 33120 missed tokens, yet read
  only ~13K (the system prompt). The diverging message is the same each time,
  and nothing past the system prompt was read back. That points at the entry
  the previous step should have written at its new cutoff (`mark.ts`), or at
  the bytes before it, not at eviction.
- Steps `0>N` come from a session's first shaped request: there was no
  earlier step to read from, so those misses were expected.
- The kept bodies were lost to a restart before anyone compared them. Next
  time: save `/dashboard/request?id=` for a step **and** the session's
  previous step as soon as the miss is logged, re-shape both, and diff the
  messages up to the reported divergence.

Other misses that evening: 8 `messages_changed`, 7 `model_changed`,
3 `system_changed`, 11 `unavailable`. `unavailable` came on requests that
broke at an early message, mostly side requests.

### Learned values re-mask old messages

Not the cause of the misses above, but it breaks the cache the same way, and
the journal blames it on the agent.

Every request redacts the whole conversation again with what the engine
knows *now* (`redact.ts`), and learned values (`rememberSwapped`, the rules'
learned usernames) are shared by every session in the process. Once a value
is learned, the next request masks it in old messages that earlier requests
sent in the clear: the old bytes change, and the cache breaks from the first
occurrence on. The journal reports that as `cachebreak=messageN(agent)`, so
part of the "agent editing its own recent messages" share above may be the
proxy's.

It is worst when a common word is learned: a false positive in
`pii-user-at-host` (`fb3da02`) took two ordinary words for usernames from a
symbol at a hex address (`name@0x836a824`) and masked them in every later
message, in every session, until a restart. On this evening's timeline no
learning event lined up with a non-step miss, so the cost was small.

A fix would hold a value back from messages older than the turn it was
learned in, at the price of leaving those messages unmasked. Not built.

## Saved misses on 2026-10-08

The first day with kept misses (`misses.ts`). Ten were saved between the
14:05 restart and 17:00; four were steps with an earlier step to compare
against. Compared block by block, markers aside (`firstChangedBlock`):

| Time | Step | Read | Written | First changed block | Cause |
|---|---|---|---|---|---|
| 15:04 | 10>50 | 11K | 39K | `m0[2]`, a harness note removed | **note dropping** |
| 16:17 | 110>180 | 60K | 29K | `m327[0]`, thinking removed, just past the m325 marker | none: a hit at the marker |
| 16:40 | 80>120 | 11K | 84K | `m241[0]`, thinking removed | **entry expired** |
| 16:52 | 120>150 | 11K | 100K | `m0[2]`, a harness note removed | **note dropping** |

**Note dropping (fixed).** The "superseded harness notes" pass (`674ccc0`,
2026-10-07 10:56) dropped a note in the old part when a newer note of the
same kind was also in the old part. A step that brought a newer note in
removed the older one wherever it was, as far back as the first message:
here a commit-attribution `<system-reminder>` at turn 0, superseded by one at
turn 30 (15:04) or 124 (16:52). Everything after the first message then
missed. That fits the earlier evidence: the intermittent misses all came
after `674ccc0`, a step missed only when a new note kind came into the old
part, and the first evening's misses all read only ~13K. The fix keeps the
newest note of each kind **per step chunk** (`MASK_STEP_TURNS` turns), so a
chunk's bytes depend only on that chunk and never change once it is in the
old part. `shape.test.ts` asserts that a step leaves every message before
the previous cutoff byte-identical; it fails on the old code.

**Entries expire between steps.** The entry at the previous cutoff is written
by one step and read back by the next. Requests in between read longer
entries at the tail, which likely do not refresh it, so it lasts the 1h TTL
from the step that wrote it. At 16:40 the previous step of that session was
over four hours earlier. Any step more than an hour after the last one
should be expected to read only the system prompt. Not fixed; the gate
(`pays`) already prices every step as a whole rewrite, so it does not
over-approve them.

**A hit can still say `messages_changed`.** At 16:17 Anthropic reported
`messages_changed` while the request read 60K, everything up to the
previous-cutoff marker. Messages past the marker did change: that is a step.
Read the count, not the reason.

The other six misses: three `system_changed` (the agent, or 0 missed
tokens), one `model_changed`, one `0>30` (a session's first step), one
`previous_message_not_found`.

### What shaping costs and saves

From the journal since 2026-09-24 (2108 Anthropic requests, 1388 shaped, 15
steps), against an estimate of the same requests unshaped (masked bytes read
from cache at four characters a token; a step's write beyond an ordinary
turn's read instead), in input-token units at 1h prices:

| | With shaping | Unshaped estimate |
|---|---|---|
| Share of input read from cache | 94.0% | 96.5% |
| Input tokens sent | 174M | 299M |
| Cost | 37.1M | 48.7M (shaping −24%) |

Shaping lowers the hit rate a little and the cost a lot: a stub that is never
sent costs nothing, where a cached one still costs a tenth. Steps' extra
writes came to 0.73M, 2% of the cost, so fixing note dropping recovers part
of that, not a step change. Since the 14:05 restart, a shorter sample with
more steps, the saving was 13%.

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
- **Kept misses** (`misses.ts`). On a miss whose reason names a change
  (`messages_changed`, `system_changed`, …) the proxy writes the request that
  missed and the one it was compared with, byte for byte as sent, to
  `~/.local/state/ithildin/cachemiss/<time>-<session>/`: `previous.json`,
  `missed.json`, and `meta.json` with the reason, `firstChangedBlock` (the
  first tools, system or message block the two do not share, markers aside,
  with the start of each side), the offset where the raw bodies first differ
  (`divergesAt`, usually in `safeguards`, which is not cached) and 300
  characters of each side of it. The
  journal says `cache miss kept: <dir>`. Bodies are kept in memory for the
  newest 16 sessions only, so a miss right after a restart, or in an older
  session, is not kept. On disk the oldest go first past any of three limits:
  20 misses (`ITHILDIN_CACHEMISS_KEEP`; 0 turns saving off and deletes what
  was kept), 14 days, or 200 MB in all. The limits are applied after each save
  and when the proxy starts, so a lowered count takes effect on restart; the
  journal says `cache misses dropped: N` then. Files other than the miss
  directories are left alone. This is the pair the first evening lost to a
  restart; start with `meta.json`.
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

- **First, the read count.** A step that read up to the previous-cutoff
  marker hit, whatever the reason says: its messages past the marker changed,
  so Anthropic still reports `messages_changed`.
- **A divergence reason on a step that read only the system prompt:** the
  miss is in our bytes, or the entry expired (previous step over an hour
  ago). `firstChangedBlock` in the kept miss's `meta.json` names the block;
  one before the previous cutoff is the proxy's (markers, `diagnostics`,
  shaping, learned values).
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
- **`ITHILDIN_SHAPE`** is read from the service environment. Earlier on
  2026-10-07 the user turned shaping off with
  `systemctl --user set-environment ITHILDIN_SHAPE=off`, which outlives a
  nix switch. Turn it back on with
  `systemctl --user unset-environment ITHILDIN_SHAPE && systemctl --user restart ithildin`.
  Check with `tr '\0' '\n' < /proc/$(systemctl --user show ithildin -p MainPID --value)/environ | grep ITHILDIN`.
  By 21:08 the same day it was back on.
