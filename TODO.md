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
- 2000-seed shaping run in smaller batches:
  `bun proxy/sim/run.ts --seeds 250 --rounds 300 --from N` for N = 1, 251, …, 1751.
- Speed comparison against `7f99ed0`, the commit before the last batch of
  code commits (`057ed16`…`9be2929`): hammer's scan p50/p99 and the bench
  timings on the same seeds, each side in its own worktree.
