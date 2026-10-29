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

opencode traffic goes through the `opencode-ai` route (`routes.json`), which
`prices.ts` does not know, so today it is priced at the common 0.1x read and
`3b774f4` changes nothing there; mapping it to `opencode-go` is what brings
the risk in. The sim can price a replay on either:
`bun proxy/sim/run.ts --route opencode-go --replay <captured.json>` prints
the largest prompt shaped and raw; seeded runs take `--route` and `--model`
too. Left: a long `mimo-v2.6-flash` session
(hundreds of tool calls, 0.02x read; `-free` is not in the table) captured
with `capture.ts`, replayed at both prices.

## Measure a larger step on opencode chat

On `go/openai` chat a step came every 11 requests and steps were 48% of the
route's uncached input (CACHING.md). Measure a larger `MASK_STEP_TURNS`
there, together with the opencode check above, since the new prices change
how often it steps.

## Check Pi's user messages on Codex on real sessions

`asksAt` now counts a Responses item with `role: "user"` and no `type` as a
user message, as Pi sends them, so a Pi session on Codex keeps reasoning only
in the loop its last message started. Judge it on real Pi sessions (the sim
sends Codex CLI's shape).

## Main-thread Anthropic steps that read only the system prompt

Open since 2026-10-10 (CACHING.md); the 2026-10-23 lead (a typed user turn
after dropped thinking on the 5.5 models) is not confirmed.

## OpenCode Go's new endpoint

OpenCode Go's docs give `https://opencode.ai/inference/go/` (`openai/v1/...`,
`anthropic/v1/messages`, `google/v1beta/...`); the proxy routes to
`https://opencode.ai/zen/go` (`server.ts`). Still served today. Through the
`opencode-ai` route, `inference/go/openai/v1/chat/completions` and
`.../responses` answered 200 (2026-10-29); `anthropic/v1/messages` and
`google/v1beta/...` are untested.

## Untracked repro

`proxy/sim/repros/chat-5013.json` passes on HEAD; commit it so
`repros.test.ts` keeps it fixed, or delete it.
