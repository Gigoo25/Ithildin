# TODO

## A crash loses the swap memory's generations

`proxy/sim/restart.ts --seeds 15 --requests 120 --from 3200 --crash` fails at
`--seed 3204 --format responses`, crash before request 32: a value is masked
again in a tool output that already went out with it, so the cache is
written again from there.

`proxy-swapped.json` and `proxy-swapped-seen.json` are written by a clean stop
(`saveScanCache`), and between stops only by `saveLearned`, when a new value
is learned. `TEXT_SEEN` (`firstSeen` in `engine/core.ts`) changes on nearly
every request, so a crash loses the generations of texts seen since the last
learned value. Copying both files from a clean stop into the crashed state
makes the run match.

Open: saving the seen-file in `saveDecisive` writes it on almost every
request. Something cheaper is needed: append-only, or only the texts that
hold a remembered value.

To reproduce: the 3204 tape differs when recorded alone, so record
anthropic and responses 3200–3204 in one process, in that order, and keep
the responses 3204 tape. Then compare `trial.ts --upto 32 --crash` followed by
`--from 32 --dump-at 32` against an uninterrupted `--dump-at 32`.
Saving `saveDecisive` before streamed events reach the client did not help.

## Check Pi's Gemini and NVIDIA providers

Run real Pi sessions through the proxy on the providers in
`~/.pi/agent/models.json` that are not covered yet, and check redaction,
swap-back, shaping and cache hits on the dashboard as for the others.

- `nvidia`: routed at `http://127.0.0.1:18733/nvidia`; no models are listed
  there, so Pi's built-in list for it applies.
- Gemini: the Gemini models under `opencode-go` (routed at
  `http://127.0.0.1:18733/opencode-go`), which use Gemini's own format
  (`:generateContent` / `:streamGenerateContent`).

## Watch terms leak through the learned-value regex

The dashboard flags two watch terms at `messages[483]`. A profiler dump
pasted into a session printed the source of the regex `engine/core.ts`
builds from learned multi-word values, and those words went upstream in it.
The engine ignores `watch.terms` (the watch only detects), and it does not
mask a single word on its own from a multi-word value. The session's
history sends it again on every request.

Decide one:

- Mask watch terms as well as flag them.
- Mask single words from multi-word values (may hide ordinary words).
