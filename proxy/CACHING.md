# Prompt caching and shaping: where the investigation stands

For an agent picking up the cache work. `AGENTS.md` covers the repo; this
covers how context shaping (`shape.ts`) interacts with Anthropic's prompt
cache, what has been tried, what is known, and how to find out the rest.
Status as of 2026-10-10: note dropping is fixed, and so is the cutoff moving
with the markers' TTL. A session's subagents and forks share its id, which
misled the diagnostics and let subagents step for nothing; both fixed (see
[Subagents and forks in one session](#subagents-and-forks-in-one-session-2026-10-10)).
Open: some main-thread steps still read only the system prompt, and the
kept pairs that would say why were lost before the fix; the next ones will
not be.

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
two of four step misses were the proxy's own note dropping; one is still
unexplained.)

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
| 16:40 | 80>120 | 11K | 84K | `m241[0]`, thinking removed, past the m239 marker | **unexplained** |
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

**16:40 is unexplained**, still, after the 2026-10-09 tests below. It first
looked like expiry: the session's previous step (to 80) was four hours
earlier, and the entry at the previous
cutoff is written only by a step. But the session had resumed at 16:39:26
with a cold request (read 0, wrote 119K), 43 seconds before the step, which
should have written that entry again; the two requests after it read
everything. Both kept bodies carry the previous-cutoff marker on the same
message (`m239`), two messages before the first change (`m241`), the same
shape as the 16:17 hit. The cold request itself was not kept, so whether it
carried that marker is unconfirmed. Open; the next kept step miss of this
shape is the place to look.

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

### Idea: step only when the cache is cold (not built)

A step changes bytes already cached, so it always costs some hit rate. A
request that writes the whole prompt anyway costs none: a session's first
after more than the TTL (1h) idle, the first after a restart, the first after
the agent compacts. Stepping only there would shape at no cost to the hit
rate, but a long busy session would seldom be shaped, so most of the saving
above would go. Middle ground: step mid-session only when the saving is
large, otherwise wait for a cold request. Worth building as a setting and
comparing on real sessions once the note-dropping fix has a few days of data.

### Idea: a keep-alive for the cutoff entry (not built; explains a minority)

The entry at the cutoff is written by a step (or a cold request, which
writes at every marker) and read only by the next step. A read refreshes
only the entry it hits, so ordinary turns, which read the newest entry,
never refresh it: it expires an hour after it was written however busy the
session is. The proxy could re-send a thread's last body cut after the
cutoff marker, with `max_tokens: 0` and `stream` off, about 55 minutes on:
a read at 0.05× instead of a rewrite at 2×.

Measured on 2026-10-10 against each main-thread step since 2026-10-09
15:00, with the entry's age taken from the last step or cold request in the
session:

| Outcome | Entry age at the step (minutes) |
|---|---|
| hit | 29, 35, 1 (cold), 32 (cold) |
| miss, entry over an hour old | 78, 98, 130 |
| miss, entry younger | 1, 4, 19, 9, 1, 26, 58, 19, 1, 20 |

Expiry fits the three old misses and every hit, but most misses came with a
young entry, several a minute after a cold request that had just written
it. Something before the old cutoff changes, or the marker lands elsewhere;
the per-thread kept pairs (from 2026-10-10 12:03) are where to look. Build
the keep-alive after that is fixed, if old-entry misses are still a share
worth it.

## Step misses after the fix (2026-10-09)

The note-dropping fix (`81b76c9`) did not stop step misses. Of 22 steps from
17:11 on 2026-10-08 to the next afternoon, about 15 read only the system
prompt (11–13K) and wrote the rest. Times here are local (EDT); kept-miss
directory names are UTC, four hours ahead.

| Time | Step | Read | Written |
|---|---|---|---|
| 13:55 | 0>20 | 13.5K | 29K (a first step; expected) |
| 14:05 | 20>40 | 13.5K | 30K |
| 15:03 | 110>140 | 13.4K | 80K |
| 15:03 | 130>160 | 13.5K | 85K |

For 14:05 the kept pair was compared up to the previous-cutoff marker
(`m60`): tools, thinking settings and `m0..m60` byte-identical, markers
included. The only difference before the entry was the first system marker,
which a two-boundary step takes off (`mark.ts`). That was ruled out the same
hour: the ordinary request right after the step, carrying both system
markers, read 43,928 tokens, exactly the step's read plus its write. Where the
system marker sits does not change the prefix Anthropic matches.

**Ruled out, each by a test:**

| Suspect | How it was tested | Result |
|---|---|---|
| First system marker taken off at a step | the request after the step read the step's whole prefix | harmless |
| Anthropic dropping old thinking (`thinking=dropped:N`) | toy steps that drop it read to the old cutoff | not it |
| Entries expiring after 5 minutes | `cache_creation` shows all writes `ephemeral_1h`; a 20-minute-old step entry was read | not it |
| Conversation size | a Haiku toy at real scale (`MASK_KEEP_TURNS` 10, step 20, 27 turns, ~200K) stepped 20>40 and read 33.9K, to the old cutoff | not it |
| Model | the small toys ran on Opus 5.5 (the kept bodies say so) and their steps hit | not it |

**The toy.** A copy of the proxy on another port with `MASK_THRESHOLD_TOKENS`
lowered, the step sizes set from the environment, and `pays()` forced true
(without that, a toy never steps: a short conversation never clears the cost
gate). Driven by `claude -p --resume` with `--settings` pointing
`ANTHROPIC_BASE_URL` at it, each turn running `seq` for a result of a known
size. A run tag in each prompt keeps one run from reading another's entries:
an untagged rerun read 37K from a run 20 minutes older and wrote nothing,
which is how the expiry test above came about. The scripts were scratch and
are not in the repo.

**What is left.** In real sessions a step reads nothing past the system prompt
even though its bytes up to the old cutoff match a body that was sent, the
markers there are the same, and entries live an hour. Toys reproduce none of
it, on either model or at real size. So it is something only real sessions
have; unknown is whether an entry was actually written at the old cutoff by
any request between steps. The journal's `markers=` (below) answers that
from now on: find the request that last carried a marker on the old cutoff
message, and see whether it was answered.

**Two fixes to try once it is known:**

- No request wrote an entry at the old cutoff: put the step's
  previous-cutoff marker on the message the ordinary requests between steps
  had marked, since those were read and written many times.
- Something else changes before the cutoff between steps: `firstChangedBlock`
  in a kept miss names it, as it did for note dropping.

### Found: the cutoff moved with the markers' TTL (2026-10-09, 15:12)

The first minutes of the new journal fields showed one session, three
requests in a row:

| Time | `markers=` | Step | Read | Written |
|---|---|---|---|---|
| 15:12:39 | `s1:5m,s2:5m,m502:5m,m582:5m` | — | 13.5K | 106K at 5m |
| 15:12:57 | `s1,s2,m444,m584` | (cutoff back) | 13.5K | 116K at 1h |
| 15:13:09 | `s1,s2,m444,m587` | — | 129K | 1K |

Claude Code sent one turn with 5-minute markers and the next with 1-hour
ones; why is its business. `shape.ts` priced a write by the markers it saw
(1.25x at 5m, 2x at 1h), and every past step is decided again on each
request, so the cheaper price put the cutoff further on (its cutoff marker
sat on message 502 instead of 444). That rewrote everything after the
system prompt, and so did the next turn when the price, and the cutoff, went
back. Nothing in the bytes before the old cutoff changed, which is why no
earlier test found it: the cutoff itself moved.

Fixed by always pricing an Anthropic write at the hour's 2x, whatever the
markers ask for. The step decision no longer depends on anything the client
can switch from one turn to the next. It makes steps slightly rarer when a
session really does use 5-minute markers, which is the safe direction.

Whether this explains every miss in the table above is not yet known: the
journal only started naming TTLs today, and kept misses never recorded them.
The next few days of `markers=` will say. A step miss with the same TTL on
both sides would still be open.

Read again on 2026-10-10: the "switch" was probably not one thread changing
TTL. Forks run beside the main thread with 5-minute markers and the session's
id, and the 5m request's last marker (`m582`) is not where the 1h thread's
was (`m584`), so they were likely two conversations interleaved. The fix
stands either way: a price read from the request still moved every past step.

### A read is not a tenth on every model

`pays()` priced a cache read at 0.1x input. Opus 5.5 reads at $0.20 against
$4 of input, 0.05x, so on it the gate counted each masked token as saving
twice what it does, and took steps whose rewrite cost more than they gave
back. Steps were 22% of the day's cache writes on 2026-10-09 (1.66M of 7.4M
tokens). The read price is now looked up by the request's `model`
(`prices.ts`). A model not in the table gets the lowest price in it and is
logged once, so a new release makes steps rarer rather than wasteful until
it is added; `"cacheReadPrices"` in `config.json` adds or overrides one.

A price change rewrites each long session once. Every past step is decided
again on each request, so a new price can undo steps already taken: on the
first turn after this shipped (2026-10-09 15:58), the session's cutoff went
back from message 802 to 711, nothing had written an entry ending at 711,
and the turn read 13.5K and wrote 220K. The next turn read 234K. The same
happens when a `cacheReadPrices` entry changes a model's price.

## A remembered common word rewrote every cache (2026-10-09 16:11)

At 16:11 two sessions and a side call read nothing from cache within half a
minute (`system_changed`, about 430K tokens written between them), and this
session did the same on its next turn. The system prompt differed at one
word, and so did every tool description and message: an ordinary English
word in the agent's instructions had become a masked value.

The path was the swap-back memory (`rememberSwapped` in `engine/core.ts`). A
value the proxy swaps back into a tool call is remembered and masked in every
later text, so output that echoes it is caught even where no rule would. One
swap of a common word put it there, for every session, until a restart:
every prefix changed at once, and the model read a stand-in in place of one
of the most common words in its instructions. It is the same failure as
`fb3da02` above, by a second path.

Three changes keep it from coming back:

- A single word made of letters only is never remembered, in any case. The
  memory is for values with a digit or a separator in them (a host, an
  address, a login); the name rules still find a name in prose without it.
  A list of common words was the first fix and was not enough: the test
  below remembered every word of the README and failed on words it lacked.
- `engine/core.test.ts` fills the memory the way a long session can (every
  word the README and AGENTS.md use, in every case, plus real-looking
  values) and requires both to come through as a fresh engine leaves them.
  Every earlier test started from an empty memory, which is why none saw it.
- The proxy says so when redaction changes a request's system prompt,
  instructions or tool list (`noteHarnessChange` in `redact.ts`), once per
  change, with the words: `redaction changed the agent's system: run -> …`.
  Nothing of the user's is in those, so any change there is the engine.

What first masked the word in one file of one session is not known: a fresh
engine leaves that file alone. The memory is what spread it everywhere.
The first deploy with the fix rewrites each session once more, as the word
comes back.

Reading the model is safe where reading the TTL was not: a cache belongs to
one model, so switching it rewrites everything whatever the cutoff does.

## Subagents and forks in one session (2026-10-10)

From the 16:40 deploy on 2026-10-09 to the next afternoon, one session
(`e3aa9649`) did all the stepping, and it ran forks and Haiku and Sonnet
subagents beside its main thread. Claude Code gives them all the session's
id: a subagent marks itself with `cc_is_subagent=true` in the billing header
that opens its system prompt, a fork does not mark itself at all (it carries
the parent's first message and 5-minute markers).

| Requests | Count | Read | Written | Steps | Step writes |
|---|---|---|---|---|---|
| Main thread and forks | 2739 | 233M | 7.96M | 29 | 1.31M (0.68M on misses) |
| Subagents | 56 | 0.32M | 1.86M | 36 | 1.29M, every one a miss |

Three things followed.

**The diagnostics compared unrelated requests.** `Diagnoses` kept one last
reply per session, so a subagent was asked about against the parent's last
reply and the other way round. Every one of the 20 kept pairs was such a
pair (a 750K Opus body against a 32K Haiku one, two subagents with different
first messages), and most `model_changed` and `messages_changed` that day
were these: the requests themselves read 60–110K. The 20 slots filled within
minutes, and the one real step miss of the day (`60>120` at 04:52Z) was
dropped before anyone read it. Now the diagnostics are keyed like
`PrefixWatch` (session, model, first message), keep the last few replies per
key with their messages' digests, and compare a request with the reply whose
messages it carries furthest, so a fork is compared with itself and a step
with the step it should read. A turn's kept miss is dropped before any
step's.

**Subagents stepped for nothing.** A subagent lives minutes. It crossed the
step threshold quickly (`0>10` to `0>30`), each step rewrote it from the
system prompt on, and it ended before a step could pay back. `shape.ts` now
holds a subagent's cutoff at zero (`isSubagent`). The header is the same on
every request of a conversation, so this cannot flap the way the TTL did.

**Forks repeat the parent's step, each at full price.** `60>120` ran four
times in a row, about 57K written each: parallel forks, none able to read
another's entry. `120>180` and `60>80` show the same. Not fixed: a fork has
no mark of its own, and keying shaping on the markers' TTL is what moved the
cutoff before. A fork that outlives the step pays for its own entry like any
thread.

Still open: of the main thread's steps, `30>60`, `60>120`, `180>270` and
`340>420` read only the system prompt, while `270>340` and `420>490` read
through to the old cutoff (129K and 183K). For `60>120` Anthropic counted
about 28K tokens missed, which puts a change before the old cutoff. Many of
those steps also had `swapped=2` or `swapped=4`, so the learned-values
re-masking above is a suspect, unproven. The next kept step pair should say.

## Instruments now in the proxy

Both go into the journal (`journalctl --user -u ithildin`), which survives
restarts; the dashboard and the proxy's memory do not.

- **`step=from>to`** on a request whose shaping moved the cutoff, in turns.
  Read from the body alone, so steps are named after a restart too, where
  `cachebreak=…(shaping)` needs the previous request in memory.
- **`cachemiss=<reason>`** from Anthropic's cache diagnostics
  (`diagnose.ts`). Every main Claude request to `api.anthropic.com` with a
  session gets the beta header (`DIAGNOSE_BETA`) and a top-level
  `diagnostics: { previous_message_id }`. Replies are kept per conversation
  (session, model, first message), the last few each. A normal request names
  the one whose messages it carries furthest; a step names the step it
  carries furthest, which is the request that should have written the entry
  this step reads. The reply's
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
  journal says `cache miss kept: <dir>`; a step's directory ends in `.step`.
  Bodies are kept in memory for the newest 16 conversations only, so a miss
  right after a restart, or in an older one, is not kept. On disk turns' misses
  go before steps', and within each the oldest first, past any of three limits:
  20 misses (`ITHILDIN_CACHEMISS_KEEP`; 0 turns saving off and deletes what
  was kept), 14 days, or 200 MB in all. The limits are applied after each save
  and when the proxy starts, so a lowered count takes effect on restart; the
  journal says `cache misses dropped: N` then. Files other than the miss
  directories are left alone. This is the pair the first evening lost to a
  restart; start with `meta.json`.
- **`session=<first 8> markers=<list>`** on every main Anthropic request:
  the session it belongs to, and where each `cache_control` marker sits in
  the body as sent (`t<i>` tool, `s<i>` system block, `m<i>` message), with
  the TTL after a colon when it is not `1h`. The entries a step can read are
  the ones earlier requests in its session wrote at these markers.
- **`written=1h:N,5m:N`** after `usage=` when the reply wrote to the cache:
  Anthropic's `cache_creation` split, which TTL each written token got. A
  marker asks for an hour; this is what it was granted.
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
  miss is in our bytes, or the entry is gone. `firstChangedBlock` in the
  kept miss's `meta.json` names the block; one before the previous cutoff
  is the proxy's (markers, `diagnostics`, shaping, learned values).
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
- **Toy runs push real kept misses out.** Every toy step is a kept miss, and
  only 20 are kept, so on 2026-10-09 the toys deleted the 13:55 and 14:05
  pairs above. Set `ITHILDIN_CACHEMISS_KEEP=0` on the toy's proxy, or copy the
  real pairs somewhere first.
- **Do not find markers by searching for the text `cache_control`.** A
  session about caching mentions it in its own messages, and a text search
  then finds eight or ten "markers" where Anthropic allows four. Walk the
  JSON for `cache_control` keys, as `markers()` in `mark.ts` does, or read
  `markers=` in the journal.
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
