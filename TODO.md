# TODO

## Check Pi's Gemini and NVIDIA providers

Run real Pi sessions through the proxy on the providers in
`~/.pi/agent/models.json` that are not covered yet, and check redaction,
swap-back, shaping and cache hits on the dashboard as for the others.

- `nvidia`: routed at `http://127.0.0.1:18733/nvidia`; no models are listed
  there, so Pi's built-in list for it applies.
- Gemini: the Gemini models under `opencode-go` (routed at
  `http://127.0.0.1:18733/opencode-go`), which use Gemini's own format
  (`:generateContent` / `:streamGenerateContent`).

## Verification runs on the committed code

Run when the machine is free (they start a process per session, so RAM is
the limit), one at a time:

- The full test suite: `bun test`.
- Hammer, all four formats: `bun proxy/sim/hammer.ts`.
- Restart sweep, all four formats: `bun proxy/sim/restart.ts`, then again
  with `--crash`.
- 2000-seed shaping run in smaller batches: done for `206cda5` (chat,
  gemini, responses clean; anthropic's 14 failures fixed in `fa2200e`, which
  passed seeds 1–400). Left: anthropic seeds 401–2000 on `fa2200e` or later:
  `bun proxy/sim/run.ts --seeds 250 --rounds 300 --from N --format anthropic`.
- Speed comparison against `7f99ed0`, the commit before the last batch of
  code commits (`057ed16`…`9be2929`): hammer's scan p50/p99 and the bench
  timings on the same seeds, each side in its own worktree.

## Check opencode's cheap-read models before restarting on 3b774f4

`3b774f4` prices `deepseek-v4.1-flash` and `muse-spark-1.3-contributor` on
`opencode-go` at their real 0.02x read, so a step there needs about five
times the saving it did. Nothing forces a step as a prompt grows (`pays`
only weighs cost), and opencode sends bodies up to 1.65 MB that shaping kept
small (CACHING.md). Replay an opencode session at the new prices and check
its prompts stay under the model's context; if not, force a step above some
size. Hold the proxy restart until this is done.

## Cap or label "cost saved" on opencode routes

The dashboard estimate (`c34971f`) assumes the unshaped request could have
been sent. On opencode many could not (CACHING.md: `saved=` came to four
times everything read), so there it overstates. Fine for Claude Code and
Codex.

## Measure a larger step on opencode chat

On `go/openai` chat a step came every 11 requests and steps were 48% of the
route's uncached input (CACHING.md). Measure a larger `MASK_STEP_TURNS`
there, together with the opencode check above, since the new prices change
how often it steps.

## Drop old reasoning on Anthropic outside the current loop

Shaped Anthropic still reads about 44% more than chat (369M against 256M
tokens over 20 sim sessions); about a third of its gap to the other formats.
Chat drops old reasoning outside the current agent loop and Anthropic does
not. Untested; the one lever left on Anthropic.

## Read Pi's user messages on Codex

Pi sends user messages to Codex without `type: "message"`, so `asksAt` does
not see them and treats a whole Pi session as one agent turn, which changes
what reasoning is kept. Count an item with `role: "user"` and no `type` as a
message, and judge it on real Pi sessions (the sim sends Codex CLI's shape).

## Main-thread Anthropic steps that read only the system prompt

Open since 2026-10-10 (CACHING.md); the 2026-10-23 lead (a typed user turn
after dropped thinking on the 5.5 models) is not confirmed.

## Routes and models in the sim

The sim sends no route and prices every format at fixed rates, so it cannot
show what per-route prices (`3b774f4`) do. Give its workloads a route and
real model names, so the opencode checks above can be measured there.

## Subagent steps at 1.25x

Claude Code's subagents cache for 5 minutes (942 of 950 writes in 14 days)
and their pauses are under 5 minutes, but `shape.ts` prices every Anthropic
write at 2x (`HOUR_WRITE`). Only forks step, so the gain may be small;
decide from the sim comparison of 2x against 1.25x step pricing.

## OpenCode Go's new endpoint

OpenCode Go's docs give `https://opencode.ai/inference/go/` (`openai/v1/...`,
`anthropic/v1/messages`, `google/v1beta/...`); the proxy routes to
`https://opencode.ai/zen/go` (`server.ts`). Still served today; untested
whether the new one takes the same paths.

## Untracked repro

`proxy/sim/repros/chat-5013.json` passes on HEAD; commit it so
`repros.test.ts` keeps it fixed, or delete it.
